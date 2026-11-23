//! Command-line flags.

use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf};

use clap::Parser;

/// Thread-per-core HTTP + QUIC echo server on monoio (io_uring).
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Config {
    /// Address the HTTP server listens on (TCP).
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:8080")]
    pub http_addr: SocketAddr,

    /// Address the QUIC echo server listens on (UDP).
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:4433")]
    pub quic_addr: SocketAddr,

    /// Where to write the generated self-signed QUIC certificate (DER).
    #[arg(long, value_name = "PATH", default_value = "./.test-cert.der")]
    pub cert_path: PathBuf,

    /// Number of threads, pinned to CPUs 0..N [default: available parallelism].
    #[arg(long, value_name = "N")]
    pub threads: Option<NonZeroUsize>,

    /// Seconds to let in-flight work finish after SIGTERM or SIGINT.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(..=86400),
    )]
    pub shutdown_grace: u64,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(
            std::iter::once("quicmonoio").chain(args.iter().copied()),
        )
    }

    #[test]
    fn clap_definition_is_valid() {
        Config::command().debug_assert();
    }

    #[test]
    fn defaults_match_historical_behavior() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.http_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.quic_addr, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(config.cert_path, PathBuf::from("./.test-cert.der"));
        assert_eq!(config.threads, None);
        assert_eq!(config.shutdown_grace, 10);
    }

    #[test]
    fn all_flags_are_parsed() {
        let config = parse(&[
            "--http-addr",
            "127.0.0.1:1234",
            "--quic-addr",
            "[::1]:5678",
            "--cert-path",
            "/tmp/cert.der",
            "--threads",
            "3",
            "--shutdown-grace",
            "0",
        ])
        .unwrap();
        assert_eq!(config.shutdown_grace, 0);
        assert_eq!(config.http_addr, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(config.quic_addr, "[::1]:5678".parse().unwrap());
        assert_eq!(config.cert_path, PathBuf::from("/tmp/cert.der"));
        assert_eq!(config.threads, NonZeroUsize::new(3));
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse(&["--http-addr", "not-an-addr"]).is_err());
        assert!(parse(&["--quic-addr", "127.0.0.1"]).is_err());
        assert!(parse(&["--threads", "0"]).is_err());
        assert!(parse(&["--threads", "-1"]).is_err());
        assert!(parse(&["--shutdown-grace", "-1"]).is_err());
        assert!(parse(&["--shutdown-grace", "86401"]).is_err());
    }
}
