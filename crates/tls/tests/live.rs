//! Live servers: they need the network, so they are ignored by default.
//! `cargo test -p jpm-tls --test live -- --ignored --nocapture`

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use jpm_tls::{Anchor, Config, Stream};

fn config() -> Config {
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|ta| Anchor {
            subject: ta.subject.as_ref(),
            spki: ta.subject_public_key_info.as_ref(),
            name_constraints: ta.name_constraints.as_ref().map(|n| n.as_ref()),
        })
        .collect();
    Config { roots, alpn: vec![b"http/1.1".to_vec()], insecure_skip_verify: false }
}

fn connect(host: &str, port: u16) -> std::io::Result<Stream<TcpStream>> {
    let tcp = TcpStream::connect((host, port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    Stream::connect(tcp, host, &config())
}

/// A GET / over a fresh connection; the status line of the answer.
fn get(host: &str, port: u16) -> std::io::Result<String> {
    let mut s = connect(host, port)?;
    write!(s, "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: jpm-tls-test\r\n\r\n")?;
    let mut body = Vec::new();
    s.read_to_end(&mut body)?;
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("HTTP/1.1 "), "{host}: {}", &text[..text.len().min(100)]);
    Ok(text.lines().next().unwrap_or("").to_string())
}

#[test]
#[ignore = "needs the network"]
fn registries_and_code_hosts() {
    for host in [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "github.com",
        "codeload.github.com",
        "registry.npmmirror.com",
        "cloudflare.com",
    ] {
        match get(host, 443) {
            Ok(status) => eprintln!("{host}: {status}"),
            Err(e) => panic!("{host}: {e}"),
        }
    }
}

/// badssl.com hosts that must work.
#[test]
#[ignore = "needs the network"]
fn badssl_good() {
    for (host, port) in [
        ("tls-v1-2.badssl.com", 1012),
        ("sha256.badssl.com", 443),
        ("ecc256.badssl.com", 443),
        ("ecc384.badssl.com", 443),
        ("rsa2048.badssl.com", 443),
        ("rsa4096.badssl.com", 443),
    ] {
        match get(host, port) {
            Ok(status) => eprintln!("{host}:{port}: {status}"),
            Err(e) => panic!("{host}:{port}: {e}"),
        }
    }
    // Its certificate expired in March 2024: the handshake gets as far as the chain check.
    match get("rsa8192.badssl.com", 443) {
        Ok(status) => eprintln!("rsa8192.badssl.com: {status}"),
        Err(e) => assert_eq!(e.to_string(), "tls: bad certificate: certificate expired"),
    }
}

/// badssl.com hosts that must fail: old versions, no shared suite, and bad certificates (the
/// last need the real certificate checks in x509.rs).
#[test]
#[ignore = "needs the network"]
fn badssl_bad() {
    let mut passed = Vec::new();
    for (host, port) in [
        ("tls-v1-0.badssl.com", 1010),
        ("tls-v1-1.badssl.com", 1011),
        ("dh2048.badssl.com", 443),
        ("rc4.badssl.com", 443),
        ("3des.badssl.com", 443),
        ("null.badssl.com", 443),
        ("expired.badssl.com", 443),
        ("wrong.host.badssl.com", 443),
        ("self-signed.badssl.com", 443),
        ("untrusted-root.badssl.com", 443),
    ] {
        match connect(host, port) {
            Ok(_) => passed.push(format!("{host}:{port}")),
            Err(e) => {
                eprintln!("{host}:{port}: {e}");
                assert!(e.to_string().starts_with("tls: "), "{host}: {e}");
            }
        }
    }
    assert!(passed.is_empty(), "connected but should not have: {passed:?}");
}
