//! QUIC echo server: one `quinn_proto::Endpoint` + `UdpSocket` per core.
//! quinn-proto does no I/O or timekeeping itself; [`run_quic_on_core`] drives it by hand.

use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    path::Path,
    pin::pin,
    sync::Arc,
    time::Instant,
};

use anyhow::Context;
use bytes::BytesMut;
use monoio::{net::udp::UdpSocket, time::timeout_at};
use quinn_proto::{
    self as quinn, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Event, Incoming, ServerConfig, StreamEvent, StreamId,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// Builds the config shared by all cores, with a fresh self-signed cert
/// written to `cert_path` for the test client.
pub fn make_server_config(
    cert_path: &Path,
) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_key = generate_simple_self_signed(vec!["localhost".into()])
        .context("failed to generate self-signed certificate")?;
    let cert_der = CertificateDer::from(cert_key.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der());

    // Unlink first: an old file owned by another user can't be overwritten.
    let _ = std::fs::remove_file(cert_path);
    match std::fs::write(cert_path, &cert_der) {
        Ok(()) => {
            log::info!("Self-signed cert written to {}", cert_path.display())
        }
        Err(e) => log::warn!("Could not write {}: {e}", cert_path.display()),
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .context("failed to build TLS config")?;
    tls_config.alpn_protocols = vec![b"echo".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("failed to build QUIC crypto config")?;
    Ok(Arc::new(ServerConfig::with_crypto(Arc::new(crypto))))
}

/// Binds a per-core UDP socket with SO_REUSEPORT. Needs a monoio runtime.
pub fn bind_udp_socket(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())
        .with_context(|| format!("failed to bind QUIC socket on {addr}"))?;
    Ok(UdpSocket::from_std(sock.into())?)
}

async fn udp_send(socket: &UdpSocket, data: &[u8], dest: SocketAddr) {
    // monoio needs an owned buffer.
    let (res, _) = socket.send_to(data.to_vec(), dest).await;
    if let Err(e) = res {
        log::warn!("UDP send to {dest} failed: {e}");
    }
}

async fn flush_transmits(
    socket: &UdpSocket,
    conn: &mut quinn::Connection,
    now: Instant,
) {
    let mut buf = Vec::new();
    // One datagram per transmit: no GSO.
    while let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) {
        udp_send(socket, &buf[..transmit.size], transmit.destination).await;
        buf.clear();
    }
}

struct TrackedConnection {
    conn: quinn::Connection,
    deadline: Option<Instant>,
}

/// The socket stays outside: the pending recv borrows it.
struct QuicCore {
    core: usize,
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, TrackedConnection>,
    deadlines: BTreeSet<(Instant, ConnectionHandle)>,
    scratch_buf: Vec<u8>,
}

impl QuicCore {
    async fn handle_datagram(
        &mut self,
        socket: &UdpSocket,
        data: BytesMut,
        remote: SocketAddr,
        now: Instant,
    ) {
        self.scratch_buf.clear();
        let event = self.endpoint.handle(
            now,
            remote,
            None,
            None,
            data,
            &mut self.scratch_buf,
        );
        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                self.handle_incoming(socket, incoming, now).await;
            }
            Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                if let Some(tracked) = self.connections.get_mut(&ch) {
                    tracked.conn.handle_event(event);
                    self.drive(socket, ch, now).await;
                }
            }
            // Stateless reply, e.g. version negotiation.
            Some(DatagramEvent::Response(t)) => {
                udp_send(socket, &self.scratch_buf[..t.size], t.destination)
                    .await;
            }
            None => {}
        }
    }

    async fn handle_incoming(
        &mut self,
        socket: &UdpSocket,
        incoming: Incoming,
        now: Instant,
    ) {
        let core = self.core;
        let remote = incoming.remote_address();
        if !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, &mut self.scratch_buf) {
                Ok(t) => {
                    udp_send(
                        socket,
                        &self.scratch_buf[..t.size],
                        t.destination,
                    )
                    .await;
                }
                Err(e) => self.endpoint.ignore(e.into_incoming()),
            }
            return;
        }
        match self.endpoint.accept(incoming, now, &mut self.scratch_buf, None)
        {
            Ok((ch, conn)) => {
                log::debug!("[core {core}] new connection from {remote}");
                self.connections
                    .insert(ch, TrackedConnection { conn, deadline: None });
                self.drive(socket, ch, now).await;
            }
            Err(e) => {
                log::warn!(
                    "[core {core}] accept from {remote} failed: {}",
                    e.cause
                );
                if let Some(t) = e.response {
                    udp_send(
                        socket,
                        &self.scratch_buf[..t.size],
                        t.destination,
                    )
                    .await;
                }
            }
        }
    }

    async fn handle_timeouts(&mut self, socket: &UdpSocket, now: Instant) {
        let expired: Vec<_> = self
            .deadlines
            .iter()
            .take_while(|(deadline, _)| *deadline <= now)
            .map(|&(_, ch)| ch)
            .collect();
        for ch in expired {
            if let Some(tracked) = self.connections.get_mut(&ch) {
                tracked.conn.handle_timeout(now);
                self.drive(socket, ch, now).await;
            }
        }
    }

    /// To run after anything that can change the state of connection `ch`.
    async fn drive(
        &mut self,
        socket: &UdpSocket,
        ch: ConnectionHandle,
        now: Instant,
    ) {
        let core = self.core;
        let Some(tracked) = self.connections.get_mut(&ch) else { return };
        let conn = &mut tracked.conn;
        drain_endpoint_events(&mut self.endpoint, ch, conn);
        for (id, data) in drain_app_events(core, conn) {
            echo(core, conn, id, &data);
        }
        flush_transmits(socket, conn, now).await;

        if let Some(old) = tracked.deadline.take() {
            self.deadlines.remove(&(old, ch));
        }
        if conn.is_drained() {
            self.connections.remove(&ch);
            log::debug!(
                "[core {core}] connection removed, {} left",
                self.connections.len()
            );
            return;
        }
        tracked.deadline = conn.poll_timeout();
        if let Some(deadline) = tracked.deadline {
            self.deadlines.insert((deadline, ch));
        }
    }
}

pub async fn run_quic_on_core(
    core: usize,
    server_config: Arc<ServerConfig>,
    socket: UdpSocket,
) {
    let mut state = QuicCore {
        core,
        endpoint: Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(server_config),
            true, // allow_mtud
            None, // rng_seed
        ),
        connections: HashMap::new(),
        deadlines: BTreeSet::new(),
        scratch_buf: Vec::new(),
    };
    // monoio moves the buffer into the operation and hands it back with the
    // result, so this future lives across timer wakeups.
    let mut recv = pin!(socket.recv_from(vec![0u8; 65536]));

    loop {
        let received = match state.deadlines.first() {
            Some(&(deadline, _)) => {
                timeout_at(deadline.into(), recv.as_mut()).await.ok()
            }
            None => Some(recv.as_mut().await),
        };
        let now = Instant::now();

        if let Some((result, buf)) = received {
            match result {
                Ok((0, _)) => {}
                Ok((n, remote)) => {
                    let data = BytesMut::from(&buf[..n]);
                    state.handle_datagram(&socket, data, remote, now).await;
                }
                Err(e) => log::warn!("[core {core}] UDP recv failed: {e}"),
            }
            recv.set(socket.recv_from(buf));
        }
        state.handle_timeouts(&socket, now).await;
    }
}

/// One write + finish: data arriving later on the stream is not echoed.
fn echo(core: usize, conn: &mut quinn::Connection, id: StreamId, data: &[u8]) {
    let mut send = conn.send_stream(id);
    match send.write(data) {
        Ok(n) if n == data.len() => {}
        Ok(n) => log::warn!(
            "[core {core}] {id}: echo truncated to {n}/{} bytes",
            data.len()
        ),
        Err(e) => {
            log::warn!("[core {core}] {id}: echo failed: {e}");
            return;
        }
    }
    if let Err(e) = send.finish() {
        log::warn!("[core {core}] {id}: finish failed: {e}");
    }
    log::debug!("[core {core}] echoed {} bytes on {id}", data.len());
}

fn drain_endpoint_events(
    endpoint: &mut Endpoint,
    ch: ConnectionHandle,
    conn: &mut quinn::Connection,
) {
    while let Some(event) = conn.poll_endpoint_events() {
        if let Some(event) = endpoint.handle_event(ch, event) {
            conn.handle_event(event);
        }
    }
}

/// Returns the data read from each readable stream.
fn drain_app_events(
    core: usize,
    conn: &mut quinn::Connection,
) -> Vec<(StreamId, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(event) = conn.poll() {
        let id = match event {
            Event::Connected => {
                log::debug!("[core {core}] handshake complete");
                continue;
            }
            Event::ConnectionLost { reason } => {
                log::debug!("[core {core}] connection lost: {reason}");
                continue;
            }
            // `Opened` may cover several streams, but only one is accepted per event.
            Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                match conn.streams().accept(Dir::Bi) {
                    Some(id) => id,
                    None => continue,
                }
            }
            Event::Stream(StreamEvent::Readable { id }) => id,
            _ => continue,
        };
        let data = read_stream(conn, id);
        if !data.is_empty() {
            out.push((id, data));
        }
    }
    out
}

fn read_stream(conn: &mut quinn::Connection, id: StreamId) -> Vec<u8> {
    let mut data = Vec::new();
    let mut recv = conn.recv_stream(id);
    // Errors here are normal stream lifecycle (closed, reset, blocked).
    let Ok(mut chunks) = recv.read(true) else { return data };
    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
        data.extend_from_slice(&chunk.bytes);
    }
    // Flow-control updates are sent by the caller's flush.
    let _ = chunks.finalize();
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!(
                "quicmonoio-unit-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn trust(path: &Path) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(std::fs::read(path).unwrap())).unwrap();
        roots
    }

    #[test]
    fn make_server_config_writes_a_trustable_cert() {
        let dir = TempDir::new("server-config");
        let path = dir.0.join("cert.der");
        make_server_config(&path).unwrap();
        assert_eq!(trust(&path).len(), 1);
    }

    #[test]
    fn make_server_config_replaces_an_existing_cert() {
        let dir = TempDir::new("server-config-replace");
        let path = dir.0.join("cert.der");
        std::fs::write(&path, b"stale").unwrap();
        make_server_config(&path).unwrap();
        assert_eq!(trust(&path).len(), 1);
    }
}
