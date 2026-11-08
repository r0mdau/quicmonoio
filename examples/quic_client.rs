//! A simple QUIC client to test the echo server.
//!
//! Usage:
//!   cargo run --example quic_client                        # sends "Hello QUIC!"
//!   cargo run --example quic_client -- "custom message"    # sends custom text

use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;

const SERVER_ADDR: &str = "127.0.0.1:4433";
const SERVER_NAME: &str = "localhost";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Hello QUIC!".to_string());

    // Load the server's self-signed certificate from the local directory
    let cert_path = std::env::current_dir().unwrap().join(".test-cert.der");
    let cert_der = std::fs::read(&cert_path).map_err(|e| {
        format!(
            "Failed to read cert at {}: {e}\nMake sure the server is running first!",
            cert_path.display()
        )
    })?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der))?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"echo".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to the server
    println!("Connecting to {SERVER_ADDR}...");
    let connection = endpoint.connect(SERVER_ADDR.parse()?, SERVER_NAME)?.await?;
    println!("Connected!");

    // Open a bidirectional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send the message
    println!("Sending: {message}");
    send.write_all(message.as_bytes()).await?;
    send.finish()?;

    // Read the echoed response
    let response = recv.read_to_end(64 * 1024).await?;
    let response_str = String::from_utf8_lossy(&response);
    println!("Received echo: {response_str}");

    // Close gracefully
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}
