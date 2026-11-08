//! UDP proxy between one client and the server that can lose datagrams.

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, PartialEq)]
pub enum Direction {
    ToServer,
    ToClient,
}

pub struct LossyProxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

fn bind_localhost() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.set_read_timeout(Some(POLL_INTERVAL)).unwrap();
    socket
}

impl LossyProxy {
    /// A datagram is forwarded when `forward` returns true.
    pub fn start(
        server: SocketAddr,
        forward: impl Fn(Direction, &[u8]) -> bool + Send + Sync + 'static,
    ) -> LossyProxy {
        let client_side = Arc::new(bind_localhost());
        let server_side = Arc::new(bind_localhost());
        server_side.connect(server).unwrap();
        let addr = client_side.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let client = Arc::new(Mutex::new(None));
        let forward = Arc::new(forward);

        let to_server = {
            let (from, to) = (client_side.clone(), server_side.clone());
            let (stop, client) = (stop.clone(), client.clone());
            let forward = forward.clone();
            thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, peer)) = from.recv_from(&mut buf) else {
                        continue;
                    };
                    *client.lock().unwrap() = Some(peer);
                    if forward(Direction::ToServer, &buf[..n]) {
                        let _ = to.send(&buf[..n]);
                    }
                }
            })
        };
        let to_client = {
            let stop = stop.clone();
            thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    let Ok(n) = server_side.recv(&mut buf) else { continue };
                    let peer = *client.lock().unwrap();
                    if let Some(peer) = peer
                        && forward(Direction::ToClient, &buf[..n])
                    {
                        let _ = client_side.send_to(&buf[..n], peer);
                    }
                }
            })
        };
        LossyProxy { addr, stop, threads: vec![to_server, to_client] }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for LossyProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
