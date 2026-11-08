//! QUIC echo server: one `quinn_proto::Endpoint` + `UdpSocket` per core.
//! quinn-proto does no I/O or timekeeping itself; [`run_quic_on_core`] drives it by hand.

use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::Path,
    pin::pin,
    slice,
    sync::Arc,
    time::Instant,
};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use monoio::{net::udp::UdpSocket, time::timeout_at};
use quinn_proto::{
    self as quinn, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Event, Incoming, ReadError, ServerConfig, StreamEvent,
    StreamId, VarInt, WriteError,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const MAX_CHUNK: usize = 64 * 1024;

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
    conn: EchoConnection,
    deadline: Option<Instant>,
}

struct QuicCore<'a> {
    core: usize,
    socket: &'a UdpSocket,
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, TrackedConnection>,
    deadlines: BTreeSet<(Instant, ConnectionHandle)>,
    scratch_buf: Vec<u8>,
}

impl QuicCore<'_> {
    async fn send_scratch(&self, t: quinn::Transmit) {
        udp_send(self.socket, &self.scratch_buf[..t.size], t.destination)
            .await;
    }

    async fn handle_datagram(
        &mut self,
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
                self.handle_incoming(incoming, now).await;
            }
            Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                self.drive(ch, now, |conn| conn.handle_event(event)).await;
            }
            // Stateless reply, e.g. version negotiation.
            Some(DatagramEvent::Response(t)) => self.send_scratch(t).await,
            None => {}
        }
    }

    async fn handle_incoming(&mut self, incoming: Incoming, now: Instant) {
        let core = self.core;
        let remote = incoming.remote_address();
        if !incoming.remote_address_validated() {
            match self.endpoint.retry(incoming, &mut self.scratch_buf) {
                Ok(t) => self.send_scratch(t).await,
                Err(e) => self.endpoint.ignore(e.into_incoming()),
            }
            return;
        }
        match self.endpoint.accept(incoming, now, &mut self.scratch_buf, None)
        {
            Ok((ch, conn)) => {
                log::debug!("[core {core}] new connection from {remote}");
                let conn = EchoConnection::new(conn);
                self.connections
                    .insert(ch, TrackedConnection { conn, deadline: None });
                self.drive(ch, now, |_| {}).await;
            }
            Err(e) => {
                log::warn!(
                    "[core {core}] accept from {remote} failed: {}",
                    e.cause
                );
                if let Some(t) = e.response {
                    self.send_scratch(t).await;
                }
            }
        }
    }

    async fn handle_timeouts(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .deadlines
            .iter()
            .take_while(|(deadline, _)| *deadline <= now)
            .map(|&(_, ch)| ch)
            .collect();
        for ch in expired {
            self.drive(ch, now, |conn| conn.handle_timeout(now)).await;
        }
    }

    /// Every change to a connection's state must go through here.
    async fn drive(
        &mut self,
        ch: ConnectionHandle,
        now: Instant,
        update: impl FnOnce(&mut quinn::Connection),
    ) {
        let core = self.core;
        let Some(tracked) = self.connections.get_mut(&ch) else { return };
        let conn = &mut tracked.conn;
        update(conn);
        drain_endpoint_events(&mut self.endpoint, ch, conn);
        conn.drain_app_events(core);
        flush_transmits(self.socket, conn, now).await;

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
        socket: &socket,
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
                    state.handle_datagram(data, remote, now).await;
                }
                Err(e) => log::warn!("[core {core}] UDP recv failed: {e}"),
            }
            recv.set(socket.recv_from(buf));
        }
        state.handle_timeouts(now).await;
    }
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

/// A connection plus the echo state of its open streams, dropped with it.
struct EchoConnection {
    inner: quinn::Connection,
    /// Bytes read from each open stream and not yet accepted for sending.
    pending: HashMap<StreamId, Bytes>,
}

impl Deref for EchoConnection {
    type Target = quinn::Connection;

    fn deref(&self) -> &quinn::Connection {
        &self.inner
    }
}

impl DerefMut for EchoConnection {
    fn deref_mut(&mut self) -> &mut quinn::Connection {
        &mut self.inner
    }
}

impl EchoConnection {
    fn new(inner: quinn::Connection) -> EchoConnection {
        EchoConnection { inner, pending: HashMap::new() }
    }

    fn drain_app_events(&mut self, core: usize) {
        while let Some(event) = self.inner.poll() {
            match event {
                Event::Connected => {
                    log::debug!("[core {core}] handshake complete");
                }
                Event::ConnectionLost { reason } => {
                    log::debug!("[core {core}] connection lost: {reason}");
                    self.pending.clear();
                }
                Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    while let Some(id) = self.inner.streams().accept(Dir::Bi) {
                        self.pending.insert(id, Bytes::new());
                        self.echo(core, id);
                    }
                }
                Event::Stream(
                    StreamEvent::Readable { id }
                    | StreamEvent::Writable { id },
                ) => self.echo(core, id),
                Event::Stream(StreamEvent::Stopped { id, error_code }) => {
                    self.abort(id, error_code);
                }
                _ => {}
            }
        }
    }

    /// Echoes `id` until reads or writes block or the stream ends. Reads only
    /// once `pending` is empty, so unread data stays under flow control.
    fn echo(&mut self, core: usize, id: StreamId) {
        let Some(pending) = self.pending.get_mut(&id) else { return };
        loop {
            while !pending.is_empty() {
                let mut send = self.inner.send_stream(id);
                let code = match send.write_chunks(slice::from_mut(pending)) {
                    Ok(_) => continue,
                    Err(WriteError::Blocked) => return,
                    Err(WriteError::Stopped(code)) => code,
                    Err(WriteError::ClosedStream) => 0u32.into(),
                };
                return self.abort(id, code);
            }

            let mut recv = self.inner.recv_stream(id);
            let Ok(mut chunks) = recv.read(true) else {
                return self.abort(id, 0u32.into());
            };
            let chunk = chunks.next(MAX_CHUNK);
            // Flow-control updates are sent by the caller's flush.
            let _ = chunks.finalize();
            match chunk {
                Ok(Some(chunk)) => *pending = chunk.bytes,
                Ok(None) => {
                    self.pending.remove(&id);
                    if let Err(e) = self.inner.send_stream(id).finish() {
                        log::debug!("[core {core}] {id}: finish failed: {e}");
                    }
                    return;
                }
                Err(ReadError::Blocked) => return,
                Err(ReadError::Reset(code)) => return self.abort(id, code),
            }
        }
    }

    fn abort(&mut self, id: StreamId, code: VarInt) {
        self.pending.remove(&id);
        // Either side may already be closed.
        let _ = self.inner.send_stream(id).reset(code);
        let _ = self.inner.recv_stream(id).stop(code);
    }
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
