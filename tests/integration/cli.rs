use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};

use crate::util::{ServerCommand, bin};

fn assert_bind_failure(cmd: ServerCommand, expected: &str) {
    let (status, stderr) = cmd.spawn().wait_exit();
    assert!(
        !status.success(),
        "server exited successfully\nstderr:\n{stderr}"
    );
    assert!(stderr.contains(expected), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Address already in use"),
        "stderr:\n{stderr}"
    );
}

// std doesn't set SO_REUSEPORT, so the server can't share these ports.
fn localhost_any() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn http_bind_failure_exits_nonzero_with_message() {
    let blocker = TcpListener::bind(localhost_any()).unwrap();
    let addr = blocker.local_addr().unwrap();
    assert_bind_failure(
        ServerCommand::new("http_bind_failure").http_addr(addr),
        &format!("failed to bind HTTP listener on {addr}"),
    );
}

#[test]
fn quic_bind_failure_exits_nonzero_with_message() {
    let blocker = UdpSocket::bind(localhost_any()).unwrap();
    let addr = blocker.local_addr().unwrap();
    assert_bind_failure(
        ServerCommand::new("quic_bind_failure").quic_addr(addr),
        &format!("failed to bind QUIC socket on {addr}"),
    );
}

#[test]
fn invalid_address_is_a_usage_error() {
    let output = bin()
        .args(["--http-addr", "not-an-address"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(stderr.contains("--http-addr"), "stderr:\n{stderr}");
}

#[test]
fn cert_is_written_to_cert_path() {
    let cmd = ServerCommand::new("cert_is_written_to_cert_path");
    let cert_path = cmd.dir().join("nested-name.der");
    let _server = cmd.cert_path(&cert_path).start();
    assert!(!std::fs::read(&cert_path).unwrap().is_empty());
    assert!(!cert_path.with_file_name(".test-cert.der").exists());
}

#[test]
fn unwritable_cert_path_only_warns() {
    let cmd = ServerCommand::new("unwritable_cert_path_only_warns");
    let cert_path = cmd.dir().join("missing-dir").join("cert.der");
    let server = cmd.cert_path(&cert_path).start();
    assert_eq!(server.get("/health").status, 200);
    let stderr = server.stderr();
    let expected = format!("Could not write {}", cert_path.display());
    assert!(stderr.contains(&expected), "stderr:\n{stderr}");
}
