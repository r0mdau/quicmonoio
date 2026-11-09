//! SIGTERM/SIGINT handling: closing one end of a socketpair wakes every core.

use std::{io, os::unix::net::UnixStream, process, thread, time::Duration};

use anyhow::Context;
use monoio::io::AsyncReadRent;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};

const WATCHDOG_MARGIN: Duration = Duration::from_secs(3);
const EXIT_WATCHDOG: i32 = 1;
const EXIT_SECOND_SIGNAL: i32 = 143;

#[derive(Debug)]
pub struct Shutdown {
    socket: UnixStream,
    grace: Duration,
}

impl Shutdown {
    pub fn listen(grace: Duration) -> anyhow::Result<Shutdown> {
        let (trigger, socket) = UnixStream::pair()
            .context("failed to create shutdown socketpair")?;
        let signals = Signals::new([SIGTERM, SIGINT])
            .context("failed to register signal handlers")?;
        thread::Builder::new()
            .name("signals".into())
            .spawn(move || watch_signals(signals, trigger, grace))
            .context("failed to spawn signal thread")?;
        Ok(Shutdown { socket, grace })
    }

    pub fn try_clone(&self) -> anyhow::Result<Shutdown> {
        let socket =
            self.socket.try_clone().context("failed to clone shutdown fd")?;
        Ok(Shutdown { socket, grace: self.grace })
    }

    pub fn grace(&self) -> Duration {
        self.grace
    }

    /// Resolves once shutdown is requested. Needs a monoio runtime.
    pub async fn requested(self) -> io::Result<()> {
        let mut socket = monoio::net::UnixStream::from_std(self.socket)?;
        socket.read(vec![0u8; 1]).await.0.map(drop)
    }
}

fn watch_signals(mut signals: Signals, trigger: UnixStream, grace: Duration) {
    let mut received = signals.forever();
    let Some(signal) = received.next() else { return };
    log::info!("Received signal {signal}, shutting down (grace {grace:?})");
    drop(trigger);
    thread::spawn(move || {
        thread::sleep(grace + WATCHDOG_MARGIN);
        log::error!("Shutdown did not finish in time, exiting");
        process::exit(EXIT_WATCHDOG);
    });
    if let Some(signal) = received.next() {
        log::warn!("Received signal {signal} during shutdown, exiting now");
        process::exit(EXIT_SECOND_SIGNAL);
    }
}
