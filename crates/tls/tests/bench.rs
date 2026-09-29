//! Throughput and handshake rate against rustls's client, both talking to a rustls server over
//! loopback. Ignored by default; run it in release:
//! `cargo test --release -p jpm-tls --test bench -- --ignored --nocapture --test-threads 1`

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

use common::{KeyType, ServerOpts, pki, rustls_server, rustls_server_config};

const TOTAL: usize = 256 << 20;

fn rustls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(pki(KeyType::P256).root.clone())).unwrap();
    let provider = rustls::crypto::ring::default_provider();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A client stream: ours or rustls's.
fn client(ours: bool, tcp: TcpStream) -> Box<dyn ReadWrite> {
    if ours {
        Box::new(jpm_tls::Stream::connect(tcp, "localhost", &pki(KeyType::P256).config(&[])).unwrap())
    } else {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(rustls_client_config(), name).unwrap();
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).unwrap();
        }
        Box::new(s)
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn name(ours: bool) -> &'static str {
    if ours { "jpm-tls" } else { "rustls " }
}

/// MB/s for `TOTAL` bytes from the server to the client, and from the client to the server.
fn throughput(opts: &ServerOpts, ours: bool) -> (f64, f64) {
    let config = rustls_server_config(pki(KeyType::P256), opts);
    let (tcp, server) = rustls_server(config, |s| {
        let buf = vec![7u8; 1 << 16];
        let mut sent = 0;
        while sent < TOTAL {
            s.write_all(&buf).unwrap();
            sent += buf.len();
        }
        s.flush().unwrap();
        let mut got = 0;
        let mut buf = vec![0u8; 1 << 16];
        while got < TOTAL {
            got += s.read(&mut buf).unwrap();
        }
        s.write_all(b"!").unwrap();
        s.flush().unwrap();
    });
    let mut c = client(ours, tcp);
    let mut buf = vec![0u8; 1 << 16];
    let start = Instant::now();
    let mut got = 0;
    while got < TOTAL {
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0);
        got += n;
    }
    let down = TOTAL as f64 / start.elapsed().as_secs_f64() / 1e6;
    let start = Instant::now();
    let mut sent = 0;
    while sent < TOTAL {
        c.write_all(&buf).unwrap();
        sent += buf.len();
    }
    c.flush().unwrap();
    let mut end = [0; 1];
    c.read_exact(&mut end).unwrap();
    let up = TOTAL as f64 / start.elapsed().as_secs_f64() / 1e6;
    server.join().unwrap();
    (down, up)
}

#[test]
#[ignore = "a benchmark"]
fn bulk_throughput() {
    for (label, tls13, aead) in [
        ("TLS 1.3 AES-128-GCM", true, 0),
        ("TLS 1.3 AES-256-GCM", true, 1),
        ("TLS 1.3 ChaCha20-Poly1305", true, 2),
        ("TLS 1.2 AES-128-GCM", false, 0),
        ("TLS 1.2 ChaCha20-Poly1305", false, 2),
    ] {
        let opts = ServerOpts { tls13, aead, ..ServerOpts::default() };
        for ours in [true, false] {
            let (down, up) = throughput(&opts, ours);
            eprintln!("{label:28} {}: server->client {down:7.0} MB/s, client->server {up:7.0} MB/s", name(ours));
        }
    }
}

#[test]
#[ignore = "a benchmark"]
fn handshakes_per_second() {
    for (label, tls13, groups) in [
        ("TLS 1.3 X25519", true, vec!["x25519"]),
        ("TLS 1.3 P-256 (HelloRetryRequest)", true, vec!["secp256r1"]),
        ("TLS 1.2 X25519", false, vec!["x25519"]),
    ] {
        let opts = ServerOpts { tls13, groups, ..ServerOpts::default() };
        for ours in [true, false] {
            let n = 300;
            let start = Instant::now();
            for _ in 0..n {
                let config = rustls_server_config(pki(KeyType::P256), &opts);
                let (tcp, server) = rustls_server(config, |s| {
                    let mut b = [0; 1];
                    let _ = s.read(&mut b);
                });
                let mut c = client(ours, tcp);
                c.write_all(b"x").unwrap();
                c.flush().unwrap();
                server.join().unwrap();
            }
            let rate = f64::from(n) / start.elapsed().as_secs_f64();
            eprintln!("{label:34} {}: {rate:6.0} handshakes/s (server included)", name(ours));
        }
    }
}
