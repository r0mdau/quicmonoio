#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{num::NonZeroUsize, thread::available_parallelism};
use monoio::{
    io::{AsyncReadRent, AsyncWriteRentExt},
    net::{ListenerOpts, TcpListener},
    utils::bind_to_cpu_set,
    IoUringDriver,
};

mod quic;

const ADDR: &str = "0.0.0.0:8080";

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let thread_count = available_parallelism().map_or(1, NonZeroUsize::get);
    println!("Starting server on {thread_count} threads (thread-per-core)");
    println!("  HTTP: {ADDR} (TCP)");
    println!("  QUIC: 0.0.0.0:4433 (UDP)");

    // Generate the QUIC cert once, share it across all cores
    let quic_config = quic::make_server_config();

    let threads: Vec<_> = (0..thread_count)
        .map(|core| {
            let cfg = quic_config.clone();
            start_thread_on_core(core, cfg)
        })
        .collect();

    for thread in threads {
        thread.join().unwrap();
    }

    Ok(())
}

fn start_thread_on_core(
    core: usize,
    quic_config: std::sync::Arc<quinn_proto::ServerConfig>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        bind_to_cpu_set([core]).unwrap();

        monoio::RuntimeBuilder::<IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("Failed to build monoio runtime")
            .block_on(serve(core, quic_config));
    })
}

async fn serve(core: usize, quic_config: std::sync::Arc<quinn_proto::ServerConfig>) {
    // Spawn QUIC server as a background task on this core
    monoio::spawn(quic::run_quic_on_core(core, quic_config));

    // HTTP server
    let opts = ListenerOpts::default().reuse_port(true).reuse_addr(true);
    let listener = TcpListener::bind_with_config(ADDR, &opts)
        .expect("Failed to bind TcpListener");

    println!("[core {core}] HTTP listening on {ADDR}");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                monoio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        eprintln!("[core {core}] Error handling {addr}: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("[core {core}] Accept error: {e}");
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
    println!("[{thread_id:?}] {method} {path} -> {status}");

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
