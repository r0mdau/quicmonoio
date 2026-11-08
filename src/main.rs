#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    process::ExitCode,
    sync::{Arc, mpsc},
    thread::{self, available_parallelism},
};

use anyhow::{Context, bail};
use clap::Parser;
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{ListenerOpts, TcpListener},
    utils::bind_to_cpu_set,
    IoUringDriver,
};

mod cli;
mod quic;

use cli::Config;

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

    let quic_config = quic::make_server_config(&config.cert_path)?;

    // Cores serve forever, so the first one to report back (error or panic)
    // is fatal.
    let (tx, rx) = mpsc::channel();
    for core in 0..thread_count {
        let (quic_config, tx) = (quic_config.clone(), tx.clone());
        thread::Builder::new()
            .name(format!("core-{core}"))
            .spawn(move || {
                let res = panic::catch_unwind(AssertUnwindSafe(|| {
                    run_core(core, http_addr, quic_addr, quic_config)
                }));
                let _ = tx.send((core, res));
            })
            .with_context(|| format!("failed to spawn thread for core {core}"))?;
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
) -> anyhow::Result<()> {
    bind_to_cpu_set([core])
        .with_context(|| format!("failed to pin thread to CPU {core}"))?;
    monoio::RuntimeBuilder::<IoUringDriver>::new()
        .enable_timer()
        .build()
        .context("failed to build io_uring runtime")?
        .block_on(serve(core, http_addr, quic_addr, quic_config))
}

async fn serve(
    core: usize,
    http_addr: SocketAddr,
    quic_addr: SocketAddr,
    quic_config: Arc<quinn_proto::ServerConfig>,
) -> anyhow::Result<()> {
    let quic_socket = quic::bind_udp_socket(quic_addr)?;
    let opts = ListenerOpts::default().reuse_port(true).reuse_addr(true);
    let listener = TcpListener::bind_with_config(http_addr, &opts)
        .with_context(|| format!("failed to bind HTTP listener on {http_addr}"))?;

    monoio::spawn(quic::run_quic_on_core(core, quic_config, quic_socket));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                monoio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        log::warn!("[core {core}] {addr}: {e}");
                    }
                });
            }
            Err(e) => log::warn!("[core {core}] accept failed: {e}"),
        }
    }
}

async fn handle_connection(
    mut stream: monoio::net::TcpStream,
) -> std::io::Result<()> {
    // 4 KiB is enough for the request line.
    let (res, buf) = stream.read(Vec::with_capacity(4096)).await;
    let n = res?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = parse_request_line(&request);
    let (status, content_type, body) = route(method, path);
    log::debug!("{method} {path} -> {status}");

    let response = build_response(status, content_type, body);
    let (res, _) = stream.write_all(response.into_bytes()).await;
    res?;
    Ok(())
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

/// Build a minimal HTTP/1.1 response.
fn build_response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
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
