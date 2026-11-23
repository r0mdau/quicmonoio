//! SIGTERM/SIGINT drain behavior of the server process.

use std::{
    io::{ErrorKind, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use crate::util::{Server, ServerCommand, connect, read_response};

const ACCEPT_SETTLE: Duration = Duration::from_millis(200);

fn stalled_request(server: &Server) -> TcpStream {
    let mut stream = connect(server.http_addr()).unwrap();
    stream.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
    thread::sleep(ACCEPT_SETTLE);
    stream
}

fn wait_until_refused(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr) {
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => return,
            _ => assert!(Instant::now() < deadline, "listener still open"),
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_clean_exit(server: Server) {
    let (status, stderr) = server.wait_exit();
    assert!(status.success(), "{status}\n{stderr}");
    assert!(stderr.contains("Shutdown complete"), "{stderr}");
}

#[test]
fn sigterm_exits_cleanly() {
    let server = Server::start("sigterm_exits_cleanly");
    server.signal("TERM");
    assert_clean_exit(server);
}

#[test]
fn sigint_exits_cleanly() {
    let server = Server::start("sigint_exits_cleanly");
    server.signal("INT");
    assert_clean_exit(server);
}

#[test]
fn in_flight_request_finishes_after_listener_closes() {
    let mut server =
        Server::start("in_flight_request_finishes_after_listener_closes");
    let mut stream = stalled_request(&server);

    server.signal("TERM");
    server.wait_for_stderr("shutting down");
    wait_until_refused(server.http_addr());

    stream.write_all(b"\r\n").unwrap();
    let response = read_response(&mut stream).unwrap();
    assert_eq!(response.status, 200);
    assert_clean_exit(server);
}

#[test]
fn stalled_request_is_abandoned_at_the_deadline() {
    let server = ServerCommand::new("stalled_request_is_abandoned")
        .shutdown_grace(1)
        .start();
    let _stream = stalled_request(&server);

    let started = Instant::now();
    server.signal("TERM");
    let (status, stderr) = server.wait_exit();

    assert!(status.success(), "{status}\n{stderr}");
    assert!(stderr.contains("abandoning 1 HTTP"), "{stderr}");
    assert!(started.elapsed() < Duration::from_secs(4), "{stderr}");
}

#[test]
fn second_signal_forces_exit() {
    let mut server = ServerCommand::new("second_signal_forces_exit")
        .shutdown_grace(30)
        .start();
    let _stream = stalled_request(&server);

    server.signal("TERM");
    server.wait_for_stderr("shutting down");
    server.signal("TERM");

    let (status, stderr) = server.wait_exit();
    assert_eq!(status.code(), Some(143), "{stderr}");
}
