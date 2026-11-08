# quicmonoio

A thread-per-core HTTP + QUIC server built on [monoio](https://github.com/bytedance/monoio) (io_uring) and [quinn-proto](https://github.com/quinn-rs/quinn).

Each CPU core runs its own monoio runtime with its own TCP and UDP listeners. Threads share only the read-only QUIC config.

| Protocol | Transport | Default port | Engine |
|----------|-----------|------|--------|
| HTTP     | TCP       | 8080 | monoio `TcpListener` |
| QUIC     | UDP       | 4433 | quinn-proto state machine + monoio `UdpSocket` |

## Requirements

- Linux with io_uring support (kernel 5.6+)
- Rust 1.88+ (stable)

## Getting started

### 1. Start the server

```bash
cargo run
RUST_LOG=debug cargo run    # more verbose
cargo run -- --help         # flags
```

| Flag | Default | |
|------|---------|-|
| `--http-addr` | `0.0.0.0:8080` | HTTP listen address (IPv4 or IPv6) |
| `--quic-addr` | `0.0.0.0:4433` | QUIC listen address |
| `--cert-path` | `./.test-cert.der` | where the self-signed cert is written |
| `--threads` | available parallelism | cores, pinned to CPUs `0..N` |

### 2. Test HTTP

```bash
curl http://127.0.0.1:8080/           # HTML welcome page
curl http://127.0.0.1:8080/health     # {"status":"ok"}
```

### 3. Test QUIC

A bundled echo client connects to `127.0.0.1:4433` and trusts `./.test-cert.der` (the server's defaults):

```bash
cargo run --example quic_client                        # sends "Hello QUIC!"
cargo run --example quic_client -- "your message here" # custom message
```

Example output:

```
Connecting to 127.0.0.1:4433...
Connected!
Sending: Hello QUIC!
Received echo: Hello QUIC!
```

### Makefile shortcuts

```bash
make build              # release build of server + client
make run                # start the server
make client MSG="hi"    # QUIC echo against a running server
make test               # cargo test + end-to-end HTTP/QUIC check on a fresh server
make clean              # cargo clean + remove the generated cert
```

`cargo test` alone runs the unit tests and the integration tests in `tests/integration`, which start the real binary on free ports.

### Release profiles

`--release` keeps debug info for `perf`/flamegraphs; `cargo build --profile release-lto` (or `make build PROFILE=release-lto`) builds an optimized, stripped binary.

## How it works

- At startup the server generates a **self-signed TLS certificate** and writes it to `--cert-path` (failing to write it only warns).
- The test client loads that certificate from the same directory, so no manual setup is needed. Run both from the project root.
- Every core binds the HTTP (TCP) and QUIC (UDP) addresses with `SO_REUSEPORT`, and the kernel spreads incoming traffic across them.
- On the server, QUIC runs on `quinn-proto`, a runtime-agnostic state machine, driven entirely by monoio's event loop. The server does not use tokio; only the test client does.
- Logs go to stderr via `env_logger`; `RUST_LOG` sets the level (default `info`).
- Cores are meant to run forever. If one fails to start (e.g. a port is taken) or panics, the server prints the error and exits non-zero.

## Design: why run both protocols on every core?

HTTP and QUIC both run on **every** core. The alternative would be a static split, for example half the cores for HTTP and half for QUIC:

- **Better utilization**: when one protocol is idle, its cores still serve the other instead of sitting unused.
- **No tuning**: a static split means guessing a ratio, and the right ratio depends on the workload.
- **No interference**: each core has its own `TcpListener`, `UdpSocket` and `quinn_proto::Endpoint`, so the two protocols never compete for shared state.

A split would only pay off if one protocol used enough CPU to starve the other's event loop.

## jemalloc

The global allocator is [jemalloc](https://github.com/tikv/jemallocator). jemalloc gives each thread its own arena, which suits a thread-per-core design: every core allocates from its own pool without lock contention.

- **When it helps:** high concurrency (thousands of connections), many small allocations per request, and long-running processes where glibc malloc tends to fragment memory.
- **When it doesn't:** low traffic, or I/O-bound workloads where the allocator isn't the bottleneck.

## Known limitations

- **No QUIC timers**: `poll_timeout`/`handle_timeout` are never called, so there are no retransmissions of lost packets and no idle timeout.
- **Connections leak**: closed QUIC connections are never removed from the per-core connection map.
- **Echo is one-shot**: the server echoes the first read on each stream, then finishes it; partial writes are not retried.
- **Streams can be missed**: one bidirectional stream is accepted per `Opened` event; unidirectional streams are ignored.
- **Minimal HTTP**: only `GET /` and `GET /health`, always `Connection: close`.
- **Minimal QUIC I/O**: packets are sent one at a time (no GSO/batching), and a new self-signed certificate is generated on every start.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
