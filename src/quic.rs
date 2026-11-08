//! QUIC echo server using quinn-proto (runtime-agnostic) on monoio.
//!
//! Each monoio core runs its own `quinn_proto::Endpoint` + `UdpSocket`,
//! giving true thread-per-core QUIC handling with zero cross-thread state.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use bytes::BytesMut;
use monoio::net::udp::UdpSocket;
use quinn_proto::{
    self as quinn, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig,
    Event, ServerConfig, StreamEvent, Dir,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const QUIC_ADDR: &str = "0.0.0.0:4433";

/// Generate a self-signed certificate, save it to /tmp, and return a shared ServerConfig.
/// Call this ONCE in main, then pass the Arc to each core.
pub fn make_server_config() -> Arc<ServerConfig> {
    let cert_key =
        generate_simple_self_signed(vec!["localhost".into()]).expect("cert generation failed");

    let cert_der = CertificateDer::from(cert_key.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());

    // Save cert so the test client can load it
    let cert_path = std::env::current_dir().unwrap().join(".test-cert.der");
    let _ = std::fs::remove_file(&cert_path); // remove old root-owned file if able
    if let Err(e) = std::fs::write(&cert_path, cert_der.as_ref()) {
        eprintln!("[quic] Warning: could not write cert. Tests might fail. Err: {}", e);
    } else {
        println!("[quic] Self-signed cert written to {}", cert_path.display());
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .expect("TLS config failed");
    tls_config.alpn_protocols = vec![b"echo".to_vec()];

    let quic_server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .expect("QUIC server config failed");

    Arc::new(ServerConfig::with_crypto(Arc::new(quic_server_crypto)))
}

/// Send a UDP packet (monoio needs an owned buffer).
async fn udp_send(socket: &UdpSocket, data: &[u8], dest: SocketAddr) {
    let owned = data.to_vec();
    let _ = socket.send_to(owned, dest).await;
}

/// Drain all `poll_transmit` packets from a connection and send them via UDP.
async fn flush_transmits(
    socket: &UdpSocket,
    conn: &mut quinn::Connection,
    now: Instant,
) {
    let mut buf = Vec::new();
    while let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) {
        udp_send(socket, &buf[..transmit.size], transmit.destination).await;
        buf.clear();
    }
}

/// Run the QUIC echo server on a monoio core.
/// `server_config` is shared across all cores (same cert).
pub async fn run_quic_on_core(core: usize, server_config: Arc<ServerConfig>) {
    let endpoint_config = Arc::new(EndpointConfig::default());

    let mut endpoint = Endpoint::new(
        endpoint_config,
        Some(server_config),
        true,
        None,
    );

    // Bind monoio UdpSocket with SO_REUSEPORT via socket2
    let socket = {
        let sock2 = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).expect("socket creation failed");
        sock2.set_reuse_port(true).expect("SO_REUSEPORT failed");
        sock2.set_reuse_address(true).expect("SO_REUSEADDR failed");
        sock2.set_nonblocking(true).expect("set_nonblocking failed");
        sock2.bind(&QUIC_ADDR.parse::<SocketAddr>().unwrap().into()).expect("bind failed");
        UdpSocket::from_std(sock2.into()).expect("UdpSocket::from_std failed")
    };

    println!("[core {core}] QUIC listening on {QUIC_ADDR} (UDP)");

    let mut connections: HashMap<ConnectionHandle, quinn::Connection> = HashMap::new();
    let mut recv_buf = vec![0u8; 65536];
    let mut scratch_buf = Vec::new();

    loop {
        // Receive a UDP datagram (monoio: ownership-based BufResult)
        let (result, buf) = socket.recv_from(recv_buf).await;
        recv_buf = buf;
        let (n, remote) = match result {
            Ok((n, remote)) if n > 0 => (n, remote),
            _ => continue,
        };

        let now = Instant::now();
        let data = BytesMut::from(&recv_buf[..n]);

        // Feed the datagram into quinn-proto
        let event = endpoint.handle(now, remote, None, None, data, &mut scratch_buf);

        // If the endpoint produced a stateless response (in scratch_buf), send it
        if !scratch_buf.is_empty() {
            udp_send(&socket, &scratch_buf, remote).await;
            scratch_buf.clear();
        }

        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                match endpoint.accept(incoming, now, &mut scratch_buf, None) {
                    Ok((ch, conn)) => {
                        println!("[core {core}] New QUIC connection from {remote}");
                        connections.insert(ch, conn);

                        // Send initial handshake packets
                        if let Some(conn) = connections.get_mut(&ch) {
                            flush_transmits(&socket, conn, now).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("[core {core}] Accept failed: {e:?}");
                        if !scratch_buf.is_empty() {
                            udp_send(&socket, &scratch_buf, remote).await;
                            scratch_buf.clear();
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                if let Some(conn) = connections.get_mut(&ch) {
                    conn.handle_event(event);
                }

                // Process endpoint events
                drain_endpoint_events(&mut endpoint, &mut connections, ch);

                // Process application events (streams)
                let stream_data = drain_app_events(core, &mut connections, ch);

                // Echo back received data
                if let Some(conn) = connections.get_mut(&ch) {
                    for (id, data) in &stream_data {
                        let msg = String::from_utf8_lossy(data);
                        println!("[core {core}] Received: {msg}");

                        let mut send = conn.send_stream(*id);
                        let _ = send.write(data);
                        let _ = send.finish();
                        println!("[core {core}] Echoed {} bytes", data.len());
                    }

                    // Send any outgoing packets
                    flush_transmits(&socket, conn, now).await;
                }
            }
            Some(DatagramEvent::Response(transmit)) => {
                udp_send(&socket, &scratch_buf[..transmit.size], transmit.destination).await;
                scratch_buf.clear();
            }
            None => {}
        }
    }
}

/// Drain endpoint events from a connection and feed them back.
fn drain_endpoint_events(
    endpoint: &mut Endpoint,
    connections: &mut HashMap<ConnectionHandle, quinn::Connection>,
    ch: ConnectionHandle,
) {
    loop {
        let endpoint_event = connections
            .get_mut(&ch)
            .and_then(|conn| conn.poll_endpoint_events());
        match endpoint_event {
            Some(event) => {
                if let Some(conn_event) = endpoint.handle_event(ch, event) {
                    if let Some(conn) = connections.get_mut(&ch) {
                        conn.handle_event(conn_event);
                    }
                }
            }
            None => break,
        }
    }
}

/// Drain application events from a connection, collecting stream data to echo.
fn drain_app_events(
    core: usize,
    connections: &mut HashMap<ConnectionHandle, quinn::Connection>,
    ch: ConnectionHandle,
) -> Vec<(quinn_proto::StreamId, Vec<u8>)> {
    let mut stream_data = Vec::new();

    loop {
        let event = connections
            .get_mut(&ch)
            .and_then(|conn| conn.poll());
        match event {
            Some(Event::HandshakeDataReady | Event::Connected) => {
                println!("[core {core}] QUIC handshake complete");
            }
            Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi })) => {
                if let Some(conn) = connections.get_mut(&ch) {
                    let mut streams = conn.streams();
                    if let Some(id) = streams.accept(Dir::Bi) {
                        drop(streams);
                        read_stream_data(conn, id, &mut stream_data);
                    }
                }
            }
            Some(Event::Stream(StreamEvent::Readable { id })) => {
                if let Some(conn) = connections.get_mut(&ch) {
                    read_stream_data(conn, id, &mut stream_data);
                }
            }
            Some(Event::Stream(StreamEvent::Finished { id })) => {
                println!("[core {core}] Stream {id} finished");
            }
            Some(Event::ConnectionLost { reason }) => {
                println!("[core {core}] Connection lost: {reason}");
            }
            Some(_) => {}
            None => break,
        }
    }

    stream_data
}

/// Read all available data from a recv stream.
fn read_stream_data(
    conn: &mut quinn::Connection,
    id: quinn_proto::StreamId,
    out: &mut Vec<(quinn_proto::StreamId, Vec<u8>)>,
) {
    let mut data = Vec::new();
    let mut recv = conn.recv_stream(id);
    if let Ok(mut chunks) = recv.read(true) {
        while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
            data.extend_from_slice(&chunk.bytes);
        }
        let _ = chunks.finalize();
    }
    if !data.is_empty() {
        out.push((id, data));
    }
}
