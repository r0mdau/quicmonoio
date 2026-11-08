//! QUIC echo through a quinn client.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};

use quinn::{Connection, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use tokio::time::{sleep, timeout};

use crate::{
    proxy::{Direction, LossyProxy},
    util::Server,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

fn client_endpoint(trusted_cert: Vec<u8>) -> Endpoint {
    client_endpoint_with_idle(trusted_cert, Duration::from_secs(5))
}

fn client_endpoint_with_idle(
    trusted_cert: Vec<u8>,
    idle: Duration,
) -> Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(trusted_cert)).unwrap();

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"echo".to_vec()];

    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).unwrap(),
    ));
    // So a stalled connection fails the test instead of hanging it.
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle.try_into().unwrap()));
    config.transport_config(Arc::new(transport));

    let mut endpoint =
        Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    endpoint
}

async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> Connection {
    endpoint.connect(addr, "localhost").unwrap().await.expect("QUIC handshake")
}

async fn echo_on(conn: &Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(message).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(64 * 1024).await.expect("read echo")
}

async fn echo(
    endpoint: &Endpoint,
    addr: SocketAddr,
    message: &[u8],
) -> Vec<u8> {
    let conn = connect(endpoint, addr).await;
    let reply = echo_on(&conn, message).await;
    conn.close(0u32.into(), b"done");
    reply
}

async fn wait_for_log(server: &Server, needle: &str) {
    let found = timeout(TEST_TIMEOUT, async {
        while !server.stderr().contains(needle) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(found.is_ok(), "no {needle:?} in:\n{}", server.stderr());
}

#[tokio::test]
async fn quic_echo() {
    let server = Server::start("quic_echo");
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());

    let reply =
        echo(&endpoint, server.quic_addr(), b"hello from the test").await;
    assert_eq!(reply, b"hello from the test");

    endpoint.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_echo_concurrent_connections() {
    let server = Server::start("quic_echo_concurrent_connections");
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());
    let addr = server.quic_addr();

    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let message = format!("message #{i}");
                let reply = echo(&endpoint, addr, message.as_bytes()).await;
                assert_eq!(String::from_utf8_lossy(&reply), message);
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }

    endpoint.wait_idle().await;
}

#[tokio::test]
async fn quic_rejects_untrusted_cert() {
    let server = Server::start("quic_rejects_untrusted_cert");
    let other =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let endpoint = client_endpoint(other.cert.der().to_vec());

    let result =
        endpoint.connect(server.quic_addr(), "localhost").unwrap().await;
    assert!(result.is_err(), "handshake with an untrusted cert succeeded");
}

#[tokio::test]
async fn quic_retransmits_lost_echo() {
    const MESSAGE: [u8; 1000] = [b'x'; 1000];

    let server = Server::start("quic_retransmits_lost_echo");
    let to_drop = Arc::new(AtomicUsize::new(0));
    let proxy = {
        let to_drop = to_drop.clone();
        LossyProxy::start(server.quic_addr(), move |dir, datagram| {
            let is_echo = dir == Direction::ToClient
                && (MESSAGE.len()..MESSAGE.len() + 100)
                    .contains(&datagram.len());
            !is_echo
                || to_drop
                    .fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1))
                    .is_err()
        })
    };
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());

    let conn = connect(&endpoint, proxy.addr()).await;
    to_drop.store(2, SeqCst);
    let reply = timeout(TEST_TIMEOUT, echo_on(&conn, &MESSAGE))
        .await
        .expect("lost echo was not retransmitted");

    assert_eq!(reply, MESSAGE);
    assert_eq!(to_drop.load(SeqCst), 0, "no echo was lost");
}

#[tokio::test]
async fn quic_removes_idle_connection() {
    let server = Server::start("quic_removes_idle_connection");
    let cert = std::fs::read(server.cert_path()).unwrap();
    let endpoint = client_endpoint_with_idle(cert, Duration::from_secs(1));

    // Kept open without a close: only the idle timer can remove it.
    let conn = connect(&endpoint, server.quic_addr()).await;
    assert_eq!(echo_on(&conn, b"idle").await, b"idle");
    wait_for_log(&server, "connection removed").await;
    drop(conn);
}

#[tokio::test]
async fn quic_removes_closed_connection_and_keeps_serving() {
    let server = Server::start("quic_removes_closed_connection");
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());

    assert_eq!(echo(&endpoint, server.quic_addr(), b"one").await, b"one");
    wait_for_log(&server, "connection removed").await;
    assert_eq!(echo(&endpoint, server.quic_addr(), b"two").await, b"two");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn quic_unvalidated_initial_gets_retry_and_no_connection() {
    let server = Server::start("quic_unvalidated_initial");
    let retries = Arc::new(AtomicUsize::new(0));
    // A spoofed source never answers the Retry.
    let proxy = {
        let retries = retries.clone();
        let to_server = AtomicUsize::new(0);
        LossyProxy::start(server.quic_addr(), move |dir, datagram| match dir {
            Direction::ToServer => to_server.fetch_add(1, SeqCst) == 0,
            Direction::ToClient => {
                if datagram[0] & 0xf0 == 0xf0 {
                    retries.fetch_add(1, SeqCst);
                }
                true
            }
        })
    };
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());

    let connecting = endpoint.connect(proxy.addr(), "localhost").unwrap();
    timeout(TEST_TIMEOUT, async {
        while retries.load(SeqCst) == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no Retry received");
    sleep(Duration::from_millis(200)).await;
    assert!(
        !server.stderr().contains("new connection"),
        "connection created for an unvalidated address:\n{}",
        server.stderr()
    );
    drop(connecting);

    // A client that answers the Retry does get a connection.
    assert_eq!(echo(&endpoint, server.quic_addr(), b"ok").await, b"ok");
    assert!(server.stderr().contains("new connection"));
}
