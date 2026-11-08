#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    any::Any,
    num::NonZeroUsize,
    process::ExitCode,
    sync::{Arc, mpsc},
    thread::{self, JoinHandle, available_parallelism},
};

use anyhow::{Context, bail};
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{ListenerOpts, TcpListener},
    utils::bind_to_cpu_set,
    IoUringDriver,
};

mod quic;

const ADDR: &str = "0.0.0.0:8080";

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Printed directly (not via `log`) so a fatal error is never filtered out.
            // `{:?}` on anyhow::Error prints the full "Caused by:" chain.
            eprintln!("Error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let thread_count = available_parallelism().map_or(1, NonZeroUsize::get);
    log::info!("Starting server on {thread_count} threads (thread-per-core)");
    log::info!("  HTTP: {ADDR} (TCP)");
    log::info!("  QUIC: {} (UDP)", quic::QUIC_ADDR);

    // Generate the QUIC cert once, share it across all cores
    let quic_config = quic::make_server_config().context("failed to build QUIC server config")?;

    // Every core thread sends its id on this channel when it stops, whether it
    // returned an error (e.g. a bind failure during setup) or panicked.
    let (exit_tx, exit_rx) = mpsc::channel();
    let mut threads = Vec::with_capacity(thread_count);
    for core in 0..thread_count {
        threads.push(start_thread_on_core(core, quic_config.clone(), exit_tx.clone())?);
    }
    drop(exit_tx);

    // Core threads serve forever, so the first one to stop is a failure: report
    // it and exit (which also tears down the remaining cores).
    let core = exit_rx
        .recv()
        .context("all core threads stopped without reporting")?;
    let thread = threads
        .into_iter()
        .nth(core)
        .with_context(|| format!("unknown core id {core}"))?;
    match thread.join() {
        Ok(Ok(())) => bail!("core {core} stopped unexpectedly"),
        Ok(Err(err)) => Err(err.context(format!("core {core} failed"))),
        Err(payload) => bail!("core {core} panicked: {}", panic_message(&*payload)),
    }
}

/// Notifies the main thread (with the core id) when dropped, i.e. when the core
/// thread returns or unwinds from a panic.
struct NotifyOnExit {
    core: usize,
    tx: mpsc::Sender<usize>,
}

impl Drop for NotifyOnExit {
    fn drop(&mut self) {
        // Only fails if main has stopped listening, in which case the process is exiting anyway.
        let _ = self.tx.send(self.core);
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

fn start_thread_on_core(
    core: usize,
    quic_config: Arc<quinn_proto::ServerConfig>,
    exit_tx: mpsc::Sender<usize>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    thread::Builder::new()
        .name(format!("core-{core}"))
        .spawn(move || {
            let _notify = NotifyOnExit { core, tx: exit_tx };

            bind_to_cpu_set([core]).with_context(|| format!("failed to pin thread to CPU {core}"))?;

            monoio::RuntimeBuilder::<IoUringDriver>::new()
                .enable_timer()
                .build()
                .context("failed to build monoio io_uring runtime")?
                .block_on(serve(core, quic_config))
        })
        .with_context(|| format!("failed to spawn thread for core {core}"))
}

async fn serve(core: usize, quic_config: Arc<quinn_proto::ServerConfig>) -> anyhow::Result<()> {
    // Bind both sockets before serving anything, so a setup failure is returned
    // (and stops the process) instead of leaving this core half up.
    let quic_socket = quic::bind_udp_socket()
        .with_context(|| format!("failed to set up QUIC socket on {}", quic::QUIC_ADDR))?;

    let opts = ListenerOpts::default().reuse_port(true).reuse_addr(true);
    let listener = TcpListener::bind_with_config(ADDR, &opts)
        .with_context(|| format!("failed to bind HTTP listener on {ADDR}"))?;

    // Spawn QUIC server as a background task on this core
    monoio::spawn(quic::run_quic_on_core(core, quic_config, quic_socket));

    log::info!("[core {core}] HTTP listening on {ADDR}");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                monoio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        log::warn!("[core {core}] Error handling {addr}: {e}");
                    }
                });
            }
            Err(e) => {
                log::warn!("[core {core}] Accept error: {e}");
            }
        }
    }
}

async fn handle_connection(
    mut stream: monoio::net::TcpStream,
) -> std::io::Result<()> {
    // Read the request (up to 4 KiB is enough for the first line)
    let buf = Vec::with_capacity(4096);
    let (res, buf) = stream.read(buf).await;
    let n = res?;
    if n == 0 {
        return Ok(());
    }

    // Parse the request line: "METHOD /path HTTP/1.x\r\n..."
    let request = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = parse_request_line(&request);

    // Route
    let (status, response) = match (method, path) {
        ("GET", "/") => (200, build_response(200, "text/html", WELCOME_HTML)),
        ("GET", "/health") => {
            (200, build_response(200, "application/json", r#"{"status":"ok"}"#))
        }
        _ => (404, build_response(404, "text/plain", "404 Not Found")),
    };

    let thread_id = std::thread::current().id();
    log::debug!("[{thread_id:?}] {method} {path} -> {status}");

    let (res, _) = stream.write_all(response.into_bytes()).await;
    res?;

    Ok(())
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
