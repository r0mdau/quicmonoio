//! UDP proxy between one client and the server that can lose datagrams.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::UdpSocket, task::JoinSet};

#[derive(Clone, Copy, PartialEq)]
pub enum Direction {
    ToServer,
    ToClient,
}

pub struct LossyProxy {
    addr: SocketAddr,
    _tasks: JoinSet<()>,
}

fn pump<F>(
    tasks: &mut JoinSet<()>,
    dir: Direction,
    from: Arc<UdpSocket>,
    to: Arc<UdpSocket>,
    forward: Arc<F>,
) where
    F: Fn(Direction, &[u8]) -> bool + Send + Sync + 'static,
{
    tasks.spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = from.recv_from(&mut buf).await else {
                continue;
            };
            if dir == Direction::ToServer {
                let _ = from.connect(peer).await;
            }
            if forward(dir, &buf[..n]) {
                let _ = to.send(&buf[..n]).await;
            }
        }
    });
}

async fn bind_localhost() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap())
}

impl LossyProxy {
    /// A datagram is forwarded when `forward` returns true.
    pub async fn start(
        server: SocketAddr,
        forward: impl Fn(Direction, &[u8]) -> bool + Send + Sync + 'static,
    ) -> LossyProxy {
        let client_side = bind_localhost().await;
        let server_side = bind_localhost().await;
        server_side.connect(server).await.unwrap();
        let addr = client_side.local_addr().unwrap();
        let forward = Arc::new(forward);

        let mut tasks = JoinSet::new();
        pump(
            &mut tasks,
            Direction::ToServer,
            client_side.clone(),
            server_side.clone(),
            forward.clone(),
        );
        pump(
            &mut tasks,
            Direction::ToClient,
            server_side,
            client_side,
            forward,
        );
        LossyProxy { addr, _tasks: tasks }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}
