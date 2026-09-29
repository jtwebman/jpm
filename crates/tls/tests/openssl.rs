//! Interop with `openssl s_server`: ignored by default, as it needs the openssl command.
//! `cargo test -p jpm-tls --test openssl -- --ignored --nocapture`

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{KEY_TYPES, KeyType, Pki, pki};

fn pem(label: &str, der: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in der.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |a, (i, &b)| a | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            s.push(if i <= chunk.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    let lines: Vec<&str> = s.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// The certificate files for `pki`, written once per process.
fn files(pki: &Pki) -> [PathBuf; 3] {
    let dir = std::env::temp_dir().join(format!("jpm-tls-openssl-{}-{:?}", std::process::id(), pki.key_type));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = [dir.join("leaf.pem"), dir.join("chain.pem"), dir.join("key.pem")];
    std::fs::write(&paths[0], pem("CERTIFICATE", &pki.chain[0])).unwrap();
    std::fs::write(&paths[1], pem("CERTIFICATE", &pki.chain[1])).unwrap();
    std::fs::write(&paths[2], pem("PRIVATE KEY", &pki.key)).unwrap();
    paths
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `openssl s_server -www` with `args`, and its port once it listens.
fn s_server(pki: &Pki, args: &[&str]) -> (Server, u16) {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let [leaf, chain, key] = files(pki);
    let child = Command::new("openssl")
        .args(["s_server", "-www", "-accept"])
        .arg(port.to_string())
        .arg("-cert")
        .arg(&leaf)
        .arg("-cert_chain")
        .arg(&chain)
        .arg("-key")
        .arg(&key)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl");
    let mut server = Server(child);
    let start = Instant::now();
    // Wait for it to listen. The probe's failed handshake does not stop it.
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(server.0.try_wait().unwrap().is_none(), "s_server {args:?} exited");
        assert!(start.elapsed() < Duration::from_secs(10), "s_server {args:?} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    (server, port)
}

/// A GET over our client; the page s_server sends back.
fn get(pki: &Pki, args: &[&str]) -> std::io::Result<String> {
    let (_server, port) = s_server(pki, args);
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut s = jpm_tls::Stream::connect(tcp, "localhost", &pki.config(&[]))?;
    s.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
    let mut page = Vec::new();
    // s_server may close without close_notify; the page is what matters here.
    let _ = s.read_to_end(&mut page);
    Ok(String::from_utf8_lossy(&page).into_owned())
}

#[track_caller]
fn works(pki: &Pki, args: &[&str], want: &str) {
    match get(pki, args) {
        Ok(page) => {
            assert!(page.starts_with("HTTP/1.0 200 ok"), "{args:?}: {page}");
            assert!(page.contains(want), "{args:?}: wanted {want}");
            eprintln!("{:?} {args:?}: ok", pki.key_type);
        }
        Err(e) => panic!("{:?} {args:?}: {e}", pki.key_type),
    }
}

#[test]
#[ignore = "needs the openssl command"]
fn tls13_every_suite_and_key() {
    for key in KEY_TYPES {
        for suite in ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"] {
            works(pki(key), &["-tls1_3", "-ciphersuites", suite], &format!("Cipher is {suite}"));
            // P-256 only: a HelloRetryRequest first.
            works(pki(key), &["-tls1_3", "-ciphersuites", suite, "-groups", "P-256"], "TLSv1.3");
        }
        // No middlebox compatibility: no change_cipher_spec from the server.
        works(pki(key), &["-tls1_3", "-no_middlebox"], "TLSv1.3");
    }
}

#[test]
#[ignore = "needs the openssl command"]
fn tls12_every_suite_and_key() {
    for key in KEY_TYPES {
        let rsa = matches!(key, KeyType::Rsa2048 | KeyType::Rsa4096);
        let kx = if rsa { "ECDHE-RSA" } else { "ECDHE-ECDSA" };
        for aead in ["AES128-GCM-SHA256", "AES256-GCM-SHA384", "CHACHA20-POLY1305"] {
            let suite = format!("{kx}-{aead}");
            works(pki(key), &["-tls1_2", "-cipher", &suite], &format!("Cipher is {suite}"));
            works(pki(key), &["-tls1_2", "-cipher", &suite, "-groups", "P-256"], "TLSv1.2");
        }
    }
    // RSA signatures of both kinds in ServerKeyExchange, and ECDSA with SHA-384.
    for sigalgs in ["RSA+SHA256", "RSA+SHA384", "RSA+SHA512", "RSA-PSS+SHA256", "RSA-PSS+SHA512"] {
        works(pki(KeyType::Rsa2048), &["-tls1_2", "-sigalgs", sigalgs], "TLSv1.2");
    }
    works(pki(KeyType::P384), &["-tls1_2", "-sigalgs", "ECDSA+SHA384"], "TLSv1.2");
}

#[test]
#[ignore = "needs the openssl command"]
fn refused_by_openssl() {
    // Nothing in common: TLS 1.1, finite-field DHE, CBC.
    for args in [
        &["-tls1_1"][..],
        &["-tls1_2", "-cipher", "DHE-RSA-AES128-GCM-SHA256"],
        &["-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-SHA"],
    ] {
        let e = get(pki(KeyType::P256), args).unwrap_err().to_string();
        assert!(e.starts_with("tls: "), "{args:?}: {e}");
        eprintln!("{args:?}: {e}");
    }
    // A group we cannot do: X448 or P-384 only.
    for g in ["X448", "P-384"] {
        let e = get(pki(KeyType::P256), &["-tls1_3", "-groups", g]).unwrap_err().to_string();
        assert!(e.starts_with("tls: "), "{g}: {e}");
        eprintln!("{g}: {e}");
    }
}
