//! QUIC echo through a quinn client.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;

use crate::util::Server;

fn client_endpoint(trusted_cert: Vec<u8>) -> Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(trusted_cert)).unwrap();

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"echo".to_vec()];

    let mut config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    // So a stalled connection fails the test instead of hanging it.
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(5).try_into().unwrap()));
    config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    endpoint
}

async fn echo(endpoint: &Endpoint, addr: SocketAddr, message: &[u8]) -> Vec<u8> {
    let conn = endpoint
        .connect(addr, "localhost")
        .unwrap()
        .await
        .expect("QUIC handshake");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(message).await.unwrap();
    send.finish().unwrap();
    let reply = recv.read_to_end(64 * 1024).await.expect("read echo");
    conn.close(0u32.into(), b"done");
    reply
}

#[tokio::test]
async fn quic_echo() {
    let server = Server::start("quic_echo");
    let endpoint = client_endpoint(std::fs::read(server.cert_path()).unwrap());

    let reply = echo(&endpoint, server.quic_addr(), b"hello from the test").await;
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
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let endpoint = client_endpoint(other.cert.der().to_vec());

    let result = endpoint
        .connect(server.quic_addr(), "localhost")
        .unwrap()
        .await;
    assert!(
        result.is_err(),
        "handshake with an untrusted cert succeeded"
    );
}
