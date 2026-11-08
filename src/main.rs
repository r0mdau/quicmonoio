//! Thread-per-core HTTP + QUIC server: one CPU-pinned monoio (io_uring) runtime per core.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    process::ExitCode,
    sync::{Arc, Barrier, mpsc},
    thread::{self, available_parallelism},
    time::Duration,
};

use anyhow::{Context, bail};
use clap::Parser;
use monoio::{
    IoUringDriver,
    buf::IoBufMut,
    io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt},
    net::{ListenerOpts, TcpListener, TcpStream},
    time::{sleep, timeout},
    utils::bind_to_cpu_set,
};

mod cli;
mod quic;

use cli::Config;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_SIZE: usize = 8 * 1024;
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const BAD_REQUEST: &str = "400 Bad Request";
const HEAD_TOO_LARGE: &str = "431 Request Header Fields Too Large";

fn main() -> ExitCode {
    let config = Config::parse();
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: Config) -> anyhow::Result<()> {
    let thread_count = config
        .threads
        .or_else(|| available_parallelism().ok())
        .map_or(1, NonZeroUsize::get);
    let Config { http_addr, quic_addr, .. } = config;
    log::info!(
        "Starting {thread_count} cores: HTTP on {http_addr}, QUIC on {quic_addr}"
    );

    // One cert for all cores: the kernel may route a client to any of them.
    let quic_config = quic::make_server_config(&config.cert_path)?;

    // Cores serve forever, so the first one to report back (error or panic)
    // is fatal.
    let (tx, rx) = mpsc::channel();
    let all_bound = Arc::new(Barrier::new(thread_count));
    for core in 0..thread_count {
        let (quic_config, all_bound, tx) =
            (quic_config.clone(), all_bound.clone(), tx.clone());
        thread::Builder::new()
            .name(format!("core-{core}"))
            .spawn(move || {
                let res = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_core(
                        core,
                        http_addr,
                        quic_addr,
                        quic_config,
                        all_bound,
                    )
                }));
                let _ = tx.send((core, res));
            })
            .with_context(|| {
                format!("failed to spawn thread for core {core}")
            })?;
    }
    drop(tx);

    let (core, res) = rx.recv().context("all cores stopped")?;
    match res {
        Ok(Ok(())) => bail!("core {core} stopped unexpectedly"),
        Ok(Err(err)) => Err(err.context(format!("core {core} failed"))),
        Err(_) => bail!("core {core} panicked"),
    }
}

fn run_core(
    core: usize,
    http_addr: SocketAddr,
    quic_addr: SocketAddr,
    quic_config: Arc<quinn_proto::ServerConfig>,
    all_bound: Arc<Barrier>,
) -> anyhow::Result<()> {
    bind_to_cpu_set([core])
        .with_context(|| format!("failed to pin thread to CPU {core}"))?;
    monoio::RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .build()
        .context("failed to build io_uring runtime")?
        .block_on(serve(core, http_addr, quic_addr, quic_config, all_bound))
}

async fn serve(
    core: usize,
    http_addr: SocketAddr,
    quic_addr: SocketAddr,
    quic_config: Arc<quinn_proto::ServerConfig>,
    all_bound: Arc<Barrier>,
) -> anyhow::Result<()> {
    let quic_socket = quic::bind_udp_socket(quic_addr)?;
    let opts = ListenerOpts::default().reuse_port(true).reuse_addr(true);
    let listener = TcpListener::bind_with_config(http_addr, &opts)
        .with_context(|| {
            format!("failed to bind HTTP listener on {http_addr}")
        })?;

    // A core joining the SO_REUSEPORT groups later would move live flows.
    all_bound.wait();
    monoio::spawn(quic::run_quic_on_core(core, quic_config, quic_socket));

    let mut backoff = Duration::ZERO;
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                backoff = Duration::ZERO;
                monoio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        log::warn!("[core {core}] {addr}: {e}");
                    }
                });
            }
            Err(e) => {
                backoff = next_accept_backoff(backoff);
                log::warn!(
                    "[core {core}] accept failed, retrying in {backoff:?}: {e}"
                );
                sleep(backoff).await;
            }
        }
    }
}

fn next_accept_backoff(previous: Duration) -> Duration {
    (previous * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX)
}

enum RequestHead {
    Complete(Vec<u8>),
    Empty,
    Truncated,
    TooLarge,
}

async fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    // One deadline for the whole head, so trickled bytes can't extend it.
    let Ok(head) = timeout(READ_TIMEOUT, read_head(&mut stream)).await else {
        log::debug!("timed out reading request");
        return Ok(());
    };
    let head = head?;
    let unread_input = matches!(head, RequestHead::TooLarge);
    let response = match head {
        RequestHead::Complete(buf) => respond(&String::from_utf8_lossy(&buf)),
        RequestHead::Empty => return Ok(()),
        RequestHead::Truncated => {
            build_response(400, "text/plain", BAD_REQUEST)
        }
        RequestHead::TooLarge => {
            build_response(431, "text/plain", HEAD_TOO_LARGE)
        }
    };

    let write = stream.write_all(response.into_bytes());
    let Ok((res, _)) = timeout(WRITE_TIMEOUT, write).await else {
        log::debug!("timed out writing response");
        return Ok(());
    };
    res?;
    if unread_input {
        let _ = timeout(READ_TIMEOUT, drain(&mut stream)).await;
    }
    Ok(())
}

/// Closing with unread input sends RST, and the client loses the response.
async fn drain(stream: &mut TcpStream) {
    if stream.shutdown().await.is_err() {
        return;
    }
    let mut buf = Vec::with_capacity(MAX_HEAD_SIZE);
    loop {
        let (res, returned) = stream.read(buf).await;
        buf = returned;
        if !matches!(res, Ok(n) if n > 0) {
            return;
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> std::io::Result<RequestHead> {
    let mut buf = Vec::with_capacity(MAX_HEAD_SIZE);
    loop {
        let start = buf.len();
        let (res, slice) =
            stream.read(buf.slice_mut(start..MAX_HEAD_SIZE)).await;
        buf = slice.into_inner();
        if res? == 0 {
            return Ok(if buf.is_empty() {
                RequestHead::Empty
            } else {
                RequestHead::Truncated
            });
        }
        // The terminator may straddle two reads.
        if head_is_complete(&buf[start.saturating_sub(2)..]) {
            return Ok(RequestHead::Complete(buf));
        }
        if buf.len() == MAX_HEAD_SIZE {
            return Ok(RequestHead::TooLarge);
        }
    }
}

/// True if `buf` holds a blank line; bare newlines count, as when parsing.
fn head_is_complete(buf: &[u8]) -> bool {
    buf.windows(2).any(|w| w == b"\n\n")
        || buf.windows(3).any(|w| w == b"\n\r\n")
}

fn respond(request: &str) -> String {
    if !is_valid_request_line(request) {
        return build_response(400, "text/plain", BAD_REQUEST);
    }
    let (method, path) = parse_request_line(request);
    let (status, content_type, body) = route(method, path);
    log::debug!("{method} {path} -> {status}");
    build_response(status, content_type, body)
}

/// (status, content type, body) for a request.
fn route(method: &str, path: &str) -> (u16, &'static str, &'static str) {
    match (method, path) {
        ("GET", "/") => (200, "text/html", WELCOME_HTML),
        ("GET", "/health") => (200, "application/json", r#"{"status":"ok"}"#),
        _ => (404, "text/plain", "404 Not Found"),
    }
}

/// Extract (method, path) from the first line of an HTTP request.
fn parse_request_line(raw: &str) -> (&str, &str) {
    let first_line = raw.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    (method, path)
}

fn is_valid_request_line(raw: &str) -> bool {
    let mut parts = raw.lines().next().unwrap_or("").split_whitespace();
    let version = parts.nth(2);
    version.is_some_and(|v| v.starts_with("HTTP/")) && parts.next().is_none()
}

/// Build a minimal HTTP/1.1 response.
fn build_response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

const WELCOME_HTML: &str = "\
<!DOCTYPE html>
<html>
<head><title>Monoio HTTP Server</title></head>
<body>
  <h1>Hello from Monoio!</h1>
  <p>Thread-per-core HTTP server powered by io_uring.</p>
</body>
</html>";

#[cfg(test)]
mod tests {
    use super::*;

    fn split_response(response: &str) -> (&str, &str) {
        response
            .split_once("\r\n\r\n")
            .expect("response has no header/body separator")
    }

    #[test]
    fn accept_backoff_grows_then_caps() {
        let first = next_accept_backoff(Duration::ZERO);
        assert_eq!(first, ACCEPT_BACKOFF_MIN);
        assert_eq!(next_accept_backoff(first), first * 2);
        assert_eq!(
            next_accept_backoff(ACCEPT_BACKOFF_MAX),
            ACCEPT_BACKOFF_MAX
        );
    }

    #[test]
    fn head_is_complete_needs_a_blank_line() {
        for head in ["a\r\n\r\n", "a\n\n", "a\n\r\n", "a\r\n\r\nbody"] {
            assert!(head_is_complete(head.as_bytes()), "{head:?}");
        }
        for head in ["", "a", "a\r\n", "a\r\n\r", "a\r\nb\r\n"] {
            assert!(!head_is_complete(head.as_bytes()), "{head:?}");
        }
    }

    #[test]
    fn is_valid_request_line_requires_three_parts_and_a_version() {
        assert!(is_valid_request_line("GET / HTTP/1.1\r\nHost: x\r\n"));
        for raw in
            ["", "\r\n", "GET", "GET /", "GET / FTP/1", "GET / a HTTP/1.1"]
        {
            assert!(!is_valid_request_line(raw), "{raw:?}");
        }
    }

    #[test]
    fn parse_request_line_extracts_method_and_path() {
        let raw =
            "GET /health HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n";
        assert_eq!(parse_request_line(raw), ("GET", "/health"));
    }

    #[test]
    fn parse_request_line_only_reads_first_line() {
        let raw =
            "POST /submit HTTP/1.1\r\nX-Fake: GET /other HTTP/1.1\r\n\r\nbody";
        assert_eq!(parse_request_line(raw), ("POST", "/submit"));
    }

    #[test]
    fn parse_request_line_accepts_bare_newlines_and_extra_whitespace() {
        assert_eq!(
            parse_request_line("GET   /a\tHTTP/1.0\nHost: x\n"),
            ("GET", "/a")
        );
        assert_eq!(parse_request_line("  GET / HTTP/1.1"), ("GET", "/"));
    }

    #[test]
    fn parse_request_line_keeps_query_string_in_path() {
        assert_eq!(
            parse_request_line("GET /health?x=1 HTTP/1.1\r\n"),
            ("GET", "/health?x=1")
        );
    }

    #[test]
    fn parse_request_line_defaults_on_missing_parts() {
        assert_eq!(parse_request_line(""), ("", "/"));
        assert_eq!(parse_request_line("\r\n"), ("", "/"));
        assert_eq!(parse_request_line("GET"), ("GET", "/"));
    }

    #[test]
    fn build_response_formats_status_headers_and_body() {
        let response = build_response(200, "text/plain", "hello");
        assert_eq!(
            response,
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: 5\r\n\
             Connection: close\r\n\
             \r\n\
             hello"
        );
    }

    #[test]
    fn build_response_reason_phrases() {
        assert!(
            build_response(200, "t", "").starts_with("HTTP/1.1 200 OK\r\n")
        );
        assert!(
            build_response(404, "t", "")
                .starts_with("HTTP/1.1 404 Not Found\r\n")
        );
        assert!(
            build_response(400, "t", "")
                .starts_with("HTTP/1.1 400 Bad Request\r\n")
        );
        assert!(
            build_response(431, "t", "").starts_with(
                "HTTP/1.1 431 Request Header Fields Too Large\r\n"
            )
        );
        assert!(
            build_response(500, "t", "")
                .starts_with("HTTP/1.1 500 Unknown\r\n")
        );
    }

    #[test]
    fn build_response_content_length_counts_bytes_not_chars() {
        let body = "héllo ✓"; // 7 chars, 10 bytes
        let response = build_response(200, "text/plain; charset=utf-8", body);
        let (head, got_body) = split_response(&response);
        assert!(head.contains("\r\nContent-Length: 10\r\n"), "{head}");
        assert_eq!(got_body, body);
    }

    #[test]
    fn build_response_empty_body() {
        let response = build_response(404, "text/plain", "");
        assert!(
            response
                .ends_with("Content-Length: 0\r\nConnection: close\r\n\r\n")
        );
    }

    #[test]
    fn route_root_serves_welcome_page() {
        assert_eq!(route("GET", "/"), (200, "text/html", WELCOME_HTML));
    }

    #[test]
    fn route_health_serves_json() {
        assert_eq!(
            route("GET", "/health"),
            (200, "application/json", r#"{"status":"ok"}"#)
        );
    }

    #[test]
    fn route_unknown_is_404() {
        for (method, path) in [
            ("GET", "/nope"),
            ("GET", "/health/"),
            ("GET", "/health?x=1"),
            ("POST", "/"),
            ("get", "/"),
            ("", "/"),
        ] {
            assert_eq!(
                route(method, path),
                (404, "text/plain", "404 Not Found"),
                "{method} {path}"
            );
        }
    }
}
