//! HTTP routes over a real TCP connection.

use std::{
    io::{Read, Write},
    thread,
    time::{Duration, Instant},
};

use crate::util::{Server, connect, http_request, read_response};

#[test]
fn get_root_serves_welcome_page() {
    let server = Server::start("get_root_serves_welcome_page");
    let resp = server.get("/");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Type"), Some("text/html"));
    assert_eq!(resp.header("Connection"), Some("close"));
    assert_eq!(
        resp.header("Content-Length"),
        Some(resp.body.len().to_string().as_str())
    );
    assert!(
        resp.body.contains("<h1>Hello from Monoio!</h1>"),
        "{}",
        resp.body
    );
}

#[test]
fn get_health_is_ok_json() {
    let server = Server::start("get_health_is_ok_json");
    let resp = server.get("/health");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Type"), Some("application/json"));
    assert_eq!(resp.body, r#"{"status":"ok"}"#);
}

#[test]
fn unknown_path_is_404() {
    let server = Server::start("unknown_path_is_404");
    for path in ["/nope", "/health/", "/index.html"] {
        let resp = server.get(path);
        assert_eq!(resp.status, 404, "GET {path}");
        assert_eq!(
            resp.header("Content-Type"),
            Some("text/plain"),
            "GET {path}"
        );
        assert_eq!(resp.body, "404 Not Found", "GET {path}");
    }
}

#[test]
fn non_get_method_is_404() {
    let server = Server::start("non_get_method_is_404");
    let resp = http_request(
        server.http_addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(resp.status, 404);
}

#[test]
fn serves_many_sequential_connections() {
    let server = Server::start("serves_many_sequential_connections");
    for i in 0..50 {
        assert_eq!(server.get("/health").status, 200, "request {i}");
    }
}

#[test]
fn silent_client_is_disconnected() {
    let server = Server::start("silent_client_is_disconnected");
    let mut stream = connect(server.http_addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();

    let started = Instant::now();
    let n = stream.read(&mut [0; 1]).expect("server kept the connection");
    assert_eq!(n, 0);
    assert!(started.elapsed() > Duration::from_secs(3));
}

#[test]
fn request_in_pieces_is_answered() {
    let server = Server::start("request_in_pieces_is_answered");
    let mut stream = connect(server.http_addr()).unwrap();
    stream.set_nodelay(true).unwrap();

    // The last split falls inside the blank line ending the headers.
    for piece in
        ["GET /he", "alth HTTP/1.1\r\nHost: loc", "alhost\r\n\r", "\n"]
    {
        stream.write_all(piece.as_bytes()).unwrap();
        thread::sleep(Duration::from_millis(50));
    }

    let resp = read_response(&mut stream).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, r#"{"status":"ok"}"#);
}

fn request_of_size(size: usize) -> String {
    let prefix = "GET /health HTTP/1.1\r\nX-Fill: ";
    let padding = "a".repeat(size - prefix.len() - 4);
    format!("{prefix}{padding}\r\n\r\n")
}

#[test]
fn request_at_size_limit_is_answered() {
    let server = Server::start("request_at_size_limit_is_answered");
    let resp =
        http_request(server.http_addr(), &request_of_size(8 * 1024)).unwrap();
    assert_eq!(resp.status, 200);
}

#[test]
fn oversized_request_is_rejected() {
    let server = Server::start("oversized_request_is_rejected");
    for size in [8 * 1024 + 1, 64 * 1024] {
        let resp =
            http_request(server.http_addr(), &request_of_size(size)).unwrap();
        assert_eq!(resp.status, 431, "{size} bytes");
        assert_eq!(resp.body, "431 Request Header Fields Too Large");
    }
}

#[test]
fn malformed_request_line_is_400() {
    let server = Server::start("malformed_request_line_is_400");
    let resp = http_request(server.http_addr(), "nonsense\r\n\r\n").unwrap();
    assert_eq!(resp.status, 400);
}

#[test]
fn truncated_request_is_400() {
    let server = Server::start("truncated_request_is_400");
    let mut stream = connect(server.http_addr()).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(read_response(&mut stream).unwrap().status, 400);
}
