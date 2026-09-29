//! Trust anchors from certificates (`Anchor::from_cert`, for NODE_EXTRA_CA_CERTS and .npmrc's
//! `ca` and `cafile`), and `insecure_skip_verify` (.npmrc's `strict-ssl=false`).

mod common;
mod x509_util;

use std::io::{Read, Write};

use common::fake::{self, Script};
use common::{KeyType, Pki, RustlsStream, ServerOpts, connect, err_msg, pki, rustls_server, rustls_server_config};
use jpm_tls::x509::{self, Anchor};
use jpm_tls::{Config, Stream};
use rcgen::{GeneralSubtree, NameConstraints};
use x509_util::{Chain, Kind, NOW, anchor, ca_params, pem_certs, trust};

fn config(roots: Vec<Anchor<'static>>, insecure: bool) -> Config {
    Config { roots, alpn: Vec::new(), insecure_skip_verify: insecure }
}

fn mozilla() -> Vec<Anchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.iter().map(anchor).collect()
}

fn leak(der: &[u8]) -> &'static [u8] {
    Box::leak(der.to_vec().into_boxed_slice())
}

/// The same anchor webpki makes from a certificate, field for field.
#[track_caller]
fn same_as_webpki(der: &[u8]) {
    let ours = Anchor::from_cert(der).unwrap();
    let theirs = trust(der);
    let theirs = anchor(&theirs);
    assert_eq!(ours.subject, theirs.subject);
    assert_eq!(ours.spki, theirs.spki);
    assert_eq!(ours.name_constraints, theirs.name_constraints);
}

#[test]
fn matches_webpki() {
    for key in common::KEY_TYPES {
        same_as_webpki(&pki(key).root);
        same_as_webpki(&pki(key).chain[1]);
    }
    // The CA certificates the registries send, and the machine's own bundle where it has one.
    for host in ["registry.npmjs.org", "github.com", "registry.npmmirror.com"] {
        let path = format!("{}/tests/data/real/{host}.pem", env!("CARGO_MANIFEST_DIR"));
        for der in pem_certs(&std::fs::read_to_string(path).unwrap()).iter().skip(1) {
            same_as_webpki(der);
        }
    }
    if let Ok(pem) = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt") {
        for der in pem_certs(&pem) {
            same_as_webpki(&der);
        }
    }
    // Name constraints come along.
    let mut p = ca_params("constrained");
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("corp.test".into())],
        excluded_subtrees: Vec::new(),
    });
    let root = x509_util::Node::root(p, Kind::P256);
    same_as_webpki(&root.der);
    assert!(Anchor::from_cert(&root.der).unwrap().name_constraints.is_some());
}

/// A private CA's name constraints hold for the chains under it.
#[test]
fn keeps_name_constraints() {
    let check = |name: &str| {
        let chain = Chain::custom(0, &[name], &[Kind::P256], |level, p| {
            if level == 0 {
                p.name_constraints = Some(NameConstraints {
                    permitted_subtrees: vec![GeneralSubtree::DnsName("corp.test".into())],
                    excluded_subtrees: Vec::new(),
                });
            }
        });
        let anchors = [Anchor::from_cert(&chain.root.der).unwrap()];
        x509::verify_server(&chain.ders(), name, NOW, &anchors).map(|_| ()).map_err(|e| e.0)
    };
    assert_eq!(check("app.corp.test"), Ok(()));
    assert_eq!(check("registry.npmjs.org"), Err("certificate not allowed by name constraints"));
}

/// Junk, cut-short and padded certificates are refused, never a panic.
#[test]
fn refuses_malformed_certificates() {
    let der = &pki(KeyType::P256).root;
    assert!(Anchor::from_cert(&[]).is_err());
    assert!(Anchor::from_cert(b"-----BEGIN CERTIFICATE-----").is_err());
    for n in 0..der.len() {
        assert!(Anchor::from_cert(&der[..n]).is_err(), "cut at {n}");
    }
    let mut longer = der.clone();
    longer.push(0);
    assert!(Anchor::from_cert(&longer).is_err());
    // Every single-byte change either reads or is refused; none panics.
    for i in 0..der.len() {
        let mut d = der.clone();
        d[i] ^= 0xff;
        let _ = Anchor::from_cert(&d);
    }
}

fn handshake(s: &mut RustlsStream) -> std::io::Result<()> {
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    let mut got = [0; 4];
    s.read_exact(&mut got)?;
    s.write_all(&got)?;
    s.flush()
}

/// Connect to a rustls server for `server` with `config`, and echo four bytes.
fn talk(server: &Pki, host: &str, config: &Config) -> std::io::Result<()> {
    let (tcp, h) = rustls_server(rustls_server_config(server, &ServerOpts::default()), handshake);
    let mut s = connect(tcp, host, config)?;
    s.write_all(b"ping")?;
    let mut got = [0; 4];
    s.read_exact(&mut got)?;
    assert_eq!(&got, b"ping");
    drop(s);
    h.join().unwrap()
}

/// A server whose certificate comes from a private CA, as behind a TLS-inspecting proxy: refused
/// under Mozilla's roots, accepted once its root is an anchor, alone or in a bundle.
#[test]
fn trusts_a_private_ca() {
    let private = pki(KeyType::Rsa2048);
    let e = talk(private, "localhost", &config(mozilla(), false)).unwrap_err();
    assert_eq!(e.to_string(), "tls: bad certificate: unknown issuer");

    let root = Anchor::from_cert(leak(&private.root)).unwrap();
    talk(private, "localhost", &config(vec![root], false)).unwrap();
    // In a bundle: Mozilla's roots, another private CA, then this one.
    let other = Anchor::from_cert(leak(&pki(KeyType::P256).root)).unwrap();
    let mut bundle = mozilla();
    bundle.extend([other, root]);
    talk(private, "localhost", &config(bundle, false)).unwrap();
    // The CA is trusted for its chains, not for any name.
    let e = talk(private, "registry.npmjs.org", &config(vec![root], false)).unwrap_err();
    assert_eq!(e.to_string(), "tls: bad certificate: certificate is not valid for this host");
    // Another CA's anchor is no help.
    let e = talk(private, "localhost", &config(vec![other], false)).unwrap_err();
    assert!(e.to_string().starts_with("tls: bad certificate: "), "{e}");
}

/// A self-signed certificate for localhost, as a server of its own.
fn self_signed() -> Pki {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    Pki { root: der.clone(), chain: vec![der], key: key.serialize_der(), key_type: KeyType::P256 }
}

#[test]
fn insecure_takes_any_certificate() {
    let server = self_signed();
    let e = talk(&server, "localhost", &config(mozilla(), false)).unwrap_err();
    assert!(e.to_string().starts_with("tls: bad certificate: "), "{e}");
    talk(&server, "localhost", &config(Vec::new(), true)).unwrap();
    talk(&server, "another.test", &config(Vec::new(), true)).unwrap();
    // Every version and key type.
    for key in common::KEY_TYPES {
        for tls13 in [true, false] {
            let opts = ServerOpts { tls13, ..ServerOpts::default() };
            let (tcp, h) = rustls_server(rustls_server_config(pki(key), &opts), handshake);
            let mut s = connect(tcp, "wrong.test", &config(Vec::new(), true)).unwrap();
            s.write_all(b"ping").unwrap();
            s.read_exact(&mut [0; 4]).unwrap();
            drop(s);
            h.join().unwrap().unwrap();
        }
    }
}

/// Connect to the scripted server with `insecure_skip_verify` and no roots.
fn insecure(script: Script) -> std::io::Result<Stream<std::net::TcpStream>> {
    let (tcp, h) = fake::run(script);
    let keep = tcp.try_clone().unwrap();
    let r = connect(tcp, "wrong.test", &config(Vec::new(), true));
    let _ = keep.shutdown(std::net::Shutdown::Write);
    let _ = h.join();
    r
}

/// Without the certificate checks, the handshake is still checked: its signature by the
/// certificate's key and both Finished messages.
#[test]
fn insecure_still_checks_the_handshake() {
    let on = |name: &'static str, f: fn(&mut Vec<u8>)| {
        move |n: &str, m: &mut Vec<u8>| {
            if n == name {
                f(m)
            }
        }
    };
    insecure(Script::default()).unwrap();
    insecure(Script::tls12()).unwrap();
    let e = err_msg(insecure(Script::default().edit(on("CV", |m| *m.last_mut().unwrap() ^= 1))));
    assert_eq!(e, "tls: decrypt error: bad CertificateVerify signature");
    let e = err_msg(insecure(Script { key: KeyType::Rsa2048, ..Script::default() }.edit(on("CV", |m| m[20] ^= 1))));
    assert!(e.starts_with("tls: decrypt error"), "{e}");
    let e = err_msg(insecure(Script::tls12().edit(on("SKE", |m| *m.last_mut().unwrap() ^= 1))));
    assert_eq!(e, "tls: decrypt error: bad ServerKeyExchange signature");
    let e = err_msg(insecure(Script::default().edit(on("Fin", |m| *m.last_mut().unwrap() ^= 1))));
    assert_eq!(e, "tls: decrypt error: bad Finished");
    let e = err_msg(insecure(Script::tls12().edit(on("Fin", |m| m[4] ^= 0x80))));
    assert_eq!(e, "tls: decrypt error: bad Finished");
    // A certificate that does not read gives no key to check with.
    let e = err_msg(insecure(Script::default().edit(on("Cert", |m| m[11] = 0x31))));
    assert_eq!(e, "tls: bad certificate: invalid certificate encoding");
}
