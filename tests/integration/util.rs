//! Spawning the server binary on free ports, and a minimal HTTP client.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_quicmonoio"))
}

#[derive(Debug)]
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("quicmonoio-tests")
            .join(format!("{name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| {
            panic!("failed to create {}: {e}", path.display())
        });
        Dir(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// The server uses SO_REUSEPORT, so two servers given the same port would silently share it.
fn free_addr(udp: bool) -> SocketAddr {
    static HANDED_OUT: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    loop {
        let addr = if udp {
            UdpSocket::bind(any).and_then(|s| s.local_addr())
        } else {
            TcpListener::bind(any).and_then(|s| s.local_addr())
        }
        .expect("failed to get a free port from the OS");
        if HANDED_OUT.lock().unwrap().insert(addr.port()) {
            return addr;
        }
    }
}

#[derive(Debug)]
pub struct ServerCommand {
    dir: Dir,
    http_addr: SocketAddr,
    quic_addr: SocketAddr,
    cert_path: PathBuf,
}

impl ServerCommand {
    pub fn new(test_name: &str) -> ServerCommand {
        let dir = Dir::new(test_name);
        let cert_path = dir.0.join("cert.der");
        ServerCommand {
            dir,
            http_addr: free_addr(false),
            quic_addr: free_addr(true),
            cert_path,
        }
    }

    pub fn http_addr(mut self, addr: SocketAddr) -> Self {
        self.http_addr = addr;
        self
    }

    pub fn quic_addr(mut self, addr: SocketAddr) -> Self {
        self.quic_addr = addr;
        self
    }

    pub fn cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_path = path.into();
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir.0
    }

    fn stderr_path(&self) -> PathBuf {
        self.dir.0.join("stderr.log")
    }

    pub fn spawn(self) -> Server {
        // 2 threads exercise SO_REUSEPORT across cores; pinning needs that many CPUs.
        let threads = thread::available_parallelism()
            .map_or(1, NonZeroUsize::get)
            .min(2);
        let stderr = File::create(self.stderr_path())
            .expect("failed to create stderr log");
        let child = bin()
            .current_dir(self.dir())
            .env("RUST_LOG", "info")
            .arg("--http-addr")
            .arg(self.http_addr.to_string())
            .arg("--quic-addr")
            .arg(self.quic_addr.to_string())
            .arg("--cert-path")
            .arg(&self.cert_path)
            .arg("--threads")
            .arg(threads.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("failed to spawn quicmonoio");
        Server { child, cmd: self }
    }

    pub fn start(self) -> Server {
        let mut server = self.spawn();
        server.poll_until("not healthy", |server| {
            if let Some(status) = server.child.try_wait().unwrap() {
                panic!(
                    "server exited during startup ({status})\nserver stderr:\n{}",
                    server.stderr()
                );
            }
            http_get(server.http_addr(), "/health")
                .is_ok_and(|resp| resp.status == 200)
                .then_some(())
        });
        server
    }
}

#[derive(Debug)]
pub struct Server {
    child: Child,
    cmd: ServerCommand,
}

impl Server {
    pub fn start(test_name: &str) -> Server {
        ServerCommand::new(test_name).start()
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.cmd.http_addr
    }

    pub fn quic_addr(&self) -> SocketAddr {
        self.cmd.quic_addr
    }

    pub fn cert_path(&self) -> &Path {
        &self.cmd.cert_path
    }

    pub fn stderr(&self) -> String {
        std::fs::read_to_string(self.cmd.stderr_path()).unwrap_or_default()
    }

    pub fn get(&self, path: &str) -> Response {
        http_get(self.http_addr(), path).unwrap_or_else(|e| {
            panic!("GET {path} failed: {e}\nserver stderr:\n{}", self.stderr())
        })
    }

    pub fn wait_exit(mut self) -> (ExitStatus, String) {
        let status = self.poll_until("still running", |server| {
            server.child.try_wait().unwrap()
        });
        (status, self.stderr())
    }

    fn poll_until<T>(
        &mut self,
        what: &str,
        mut ready: impl FnMut(&mut Self) -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(value) = ready(self) {
                return value;
            }
            if Instant::now() > deadline {
                panic!(
                    "server {what} after {STARTUP_TIMEOUT:?}\nserver stderr:\n{}",
                    self.stderr()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    http_request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    )
}

pub fn http_request(addr: SocketAddr, raw: &str) -> std::io::Result<Response> {
    let mut stream = connect(addr)?;
    stream.write_all(raw.as_bytes())?;
    read_response(&mut stream)
}

pub fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

pub fn read_response(stream: &mut TcpStream) -> std::io::Result<Response> {
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    parse_response(&raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed response: {raw:?}"),
        )
    })
}

fn parse_response(raw: &str) -> Option<Response> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status =
        lines.next()?.strip_prefix("HTTP/1.1 ")?.get(..3)?.parse().ok()?;
    let headers = lines
        .map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect::<Option<_>>()?;
    Some(Response { status, headers, body: body.to_owned() })
}
