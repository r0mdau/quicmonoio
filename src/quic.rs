//! QUIC echo server using quinn-proto (runtime-agnostic) on monoio.
//!
//! Each monoio core runs its own `quinn_proto::Endpoint` + `UdpSocket`,
//! giving true thread-per-core QUIC handling with zero cross-thread state.

use std::{
    collections::HashMap,
    io::ErrorKind,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use anyhow::Context;

use bytes::BytesMut;
use monoio::net::udp::UdpSocket;
use quinn_proto::{
    self as quinn, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig,
    Event, ReadError, ServerConfig, StreamEvent, Dir,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

pub const QUIC_ADDR: &str = "0.0.0.0:4433";

/// File (in the current working directory) the test client reads the server cert from.
const CERT_FILE: &str = ".test-cert.der";

/// Generate a self-signed certificate, write it to `./.test-cert.der` (in the
/// current working directory) for the test client, and return a shared ServerConfig.
/// Call this ONCE in main, then pass the Arc to each core.
///
/// Failing to write the cert file is only a warning: the server still works,
/// but the bundled test client won't be able to verify it.
pub fn make_server_config() -> anyhow::Result<Arc<ServerConfig>> {
    let cert_key = generate_simple_self_signed(vec!["localhost".into()])
        .context("failed to generate self-signed certificate")?;

    let cert_der = CertificateDer::from(cert_key.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());

    // Save cert so the test client can load it
    match write_cert(&cert_der) {
        Ok(path) => log::info!("[quic] Self-signed cert written to {}", path.display()),
        Err(e) => log::warn!("[quic] Could not write cert, the test client will fail: {e:#}"),
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .context("failed to build TLS config")?;
    tls_config.alpn_protocols = vec![b"echo".to_vec()];

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("failed to build QUIC server crypto config")?;

    Ok(Arc::new(ServerConfig::with_crypto(Arc::new(quic_server_crypto))))
}

/// Write the DER cert to `CERT_FILE` in the current directory, returning its path.
fn write_cert(cert_der: &[u8]) -> anyhow::Result<PathBuf> {
    let cert_path = std::env::current_dir()
        .context("failed to get current directory")?
        .join(CERT_FILE);
    // Remove first: an old file owned by another user (e.g. root) can't be
    // overwritten, but may still be unlinkable.
    if let Err(e) = std::fs::remove_file(&cert_path)
        && e.kind() != ErrorKind::NotFound
    {
        log::debug!("[quic] Could not remove old cert {}: {e}", cert_path.display());
    }
    std::fs::write(&cert_path, cert_der)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    Ok(cert_path)
}

/// Create the per-core UDP socket bound to `QUIC_ADDR` with SO_REUSEPORT
/// (via socket2), wrapped as a monoio socket. Must be called inside a monoio runtime.
pub fn bind_udp_socket() -> anyhow::Result<UdpSocket> {
    let addr: SocketAddr = QUIC_ADDR.parse().context("invalid QUIC address")?;
    let sock2 = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("failed to create UDP socket")?;
    sock2.set_reuse_port(true).context("failed to set SO_REUSEPORT")?;
    sock2.set_reuse_address(true).context("failed to set SO_REUSEADDR")?;
    sock2.set_nonblocking(true).context("failed to set O_NONBLOCK")?;
    sock2.bind(&addr.into()).with_context(|| format!("failed to bind {addr}"))?;
    UdpSocket::from_std(sock2.into()).context("failed to register UDP socket with monoio")
}

/// Send a UDP packet (monoio needs an owned buffer).
async fn udp_send(socket: &UdpSocket, data: &[u8], dest: SocketAddr) {
    let owned = data.to_vec();
    let (res, _) = socket.send_to(owned, dest).await;
    if let Err(e) = res {
        log::warn!("[quic] UDP send of {} bytes to {dest} failed: {e}", data.len());
    }
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
/// `server_config` is shared across all cores (same cert); `socket` comes from
/// [`bind_udp_socket`].
pub async fn run_quic_on_core(core: usize, server_config: Arc<ServerConfig>, socket: UdpSocket) {
    let endpoint_config = Arc::new(EndpointConfig::default());

    let mut endpoint = Endpoint::new(
        endpoint_config,
        Some(server_config),
        true,
        None,
    );

    log::info!("[core {core}] QUIC listening on {QUIC_ADDR} (UDP)");

    let mut connections: HashMap<ConnectionHandle, quinn::Connection> = HashMap::new();
    let mut recv_buf = vec![0u8; 65536];
    let mut scratch_buf = Vec::new();

    loop {
        // Receive a UDP datagram (monoio: ownership-based BufResult)
        let (result, buf) = socket.recv_from(recv_buf).await;
        recv_buf = buf;
        let (n, remote) = match result {
            Ok((0, _)) => continue, // empty datagram: nothing for quinn-proto
            Ok((n, remote)) => (n, remote),
            Err(e) => {
                log::warn!("[core {core}] UDP recv failed: {e}");
                continue;
            }
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
                        log::debug!("[core {core}] New QUIC connection from {remote}");
                        connections.insert(ch, conn);

                        // Send initial handshake packets
                        if let Some(conn) = connections.get_mut(&ch) {
                            flush_transmits(&socket, conn, now).await;
                        }
                    }
                    Err(e) => {
                        log::warn!("[core {core}] QUIC accept from {remote} failed: {e:?}");
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
                        log::debug!("[core {core}] Received on {id}: {msg}");

                        let mut send = conn.send_stream(*id);
                        match send.write(data) {
                            Ok(written) => {
                                if written < data.len() {
                                    log::warn!(
                                        "[core {core}] {id}: echo truncated, wrote {written}/{} bytes",
                                        data.len()
                                    );
                                } else {
                                    log::debug!("[core {core}] Echoed {written} bytes on {id}");
                                }
                                if let Err(e) = send.finish() {
                                    log::warn!("[core {core}] {id}: finish failed: {e}");
                                }
                            }
                            Err(e) => log::warn!("[core {core}] {id}: echo write failed: {e}"),
                        }
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
                if let Some(conn_event) = endpoint.handle_event(ch, event)
                    && let Some(conn) = connections.get_mut(&ch)
                {
                    conn.handle_event(conn_event);
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
                log::debug!("[core {core}] QUIC handshake complete");
            }
            Some(Event::Stream(StreamEvent::Opened { dir: Dir::Bi })) => {
                if let Some(conn) = connections.get_mut(&ch)
                    && let Some(id) = conn.streams().accept(Dir::Bi)
                {
                    read_stream_data(core, conn, id, &mut stream_data);
                }
            }
            Some(Event::Stream(StreamEvent::Readable { id })) => {
                if let Some(conn) = connections.get_mut(&ch) {
                    read_stream_data(core, conn, id, &mut stream_data);
                }
            }
            Some(Event::Stream(StreamEvent::Finished { id })) => {
                log::debug!("[core {core}] Stream {id} finished");
            }
            Some(Event::ConnectionLost { reason }) => {
                log::debug!("[core {core}] Connection lost: {reason}");
            }
            Some(_) => {}
            None => break,
        }
    }

    stream_data
}

/// Read all available data from a recv stream.
fn read_stream_data(
    core: usize,
    conn: &mut quinn::Connection,
    id: quinn_proto::StreamId,
    out: &mut Vec<(quinn_proto::StreamId, Vec<u8>)>,
) {
    let mut data = Vec::new();
    let mut recv = conn.recv_stream(id);
    let mut chunks = match recv.read(true) {
        Ok(chunks) => chunks,
        Err(e) => {
            log::debug!("[core {core}] {id} not readable: {e}");
            return;
        }
    };
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk.bytes),
            // Stream finished, or no more data buffered for now.
            Ok(None) | Err(ReadError::Blocked) => break,
            Err(e @ ReadError::Reset(_)) => {
                log::debug!("[core {core}] {id}: {e}");
                break;
            }
        }
    }
    // `finalize` reports whether a flow-control update was queued. The caller
    // always flushes the connection's transmits after handling events, so it
    // gets sent either way.
    if chunks.finalize().should_transmit() {
        log::trace!("[core {core}] {id}: flow-control update queued");
    }
    if !data.is_empty() {
        out.push((id, data));
    }
}
