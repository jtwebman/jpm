//! Chains the registries really send (captured by tests/data/real/capture.sh), checked against
//! the Mozilla roots of webpki-roots at the time they were captured.

mod x509_util;

use std::time::Instant;

use jpm_tls::x509::{self, Anchor, PublicKey};
use x509_util::*;

const HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "registry.npmmirror.com",
];

fn data(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/data/real/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn captured_at() -> u64 {
    data("captured-at").trim().parse().unwrap()
}

fn chain(host: &str) -> Vec<Vec<u8>> {
    pem_certs(&data(&format!("{host}.pem")))
}

fn roots() -> Vec<Anchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.iter().map(anchor).collect()
}

#[test]
fn registries() {
    let now = captured_at();
    let mozilla = webpki_roots::TLS_SERVER_ROOTS;
    const DAY: u64 = 86400;
    for host in HOSTS {
        let certs = chain(host);
        let refs: Vec<&[u8]> = certs.iter().map(|c| &c[..]).collect();
        assert_eq!(check(&refs, host, now, mozilla), Ok(()), "{host}");
        assert_eq!(check(&refs, &host.to_uppercase(), now, mozilla), Ok(()), "{host}");
        assert_eq!(check(&refs, "example.com", now, mozilla), Err("certificate is not valid for this host"), "{host}");
        // A name one label deeper: no wildcard reaches it.
        assert_eq!(
            check(&refs, &format!("x.{host}"), now, mozilla),
            Err("certificate is not valid for this host"),
            "{host}"
        );
        assert_eq!(check(&refs, host, now + 400 * DAY, mozilla), Err("certificate expired"), "{host}");
        assert_eq!(check(&refs, host, now - 400 * DAY, mozilla), Err("certificate not yet valid"), "{host}");
        // Without the intermediates, or with them reversed.
        assert_eq!(check(&refs[..1], host, now, mozilla), Err("unknown issuer"), "{host}");
        let mut reversed = refs.clone();
        reversed[1..].reverse();
        assert_eq!(check(&reversed, host, now, mozilla), Ok(()), "{host}");
        // No roots.
        assert_eq!(check(&refs, host, now, &[]), Err("unknown issuer"), "{host}");
        let key = x509::verify_server(&refs, host, now, &roots()).unwrap();
        let kind = match key {
            PublicKey::Rsa { n, .. } => format!("RSA {}", n.len() * 8),
            PublicKey::P256(_) => "P-256".into(),
            PublicKey::P384(_) => "P-384".into(),
        };
        eprintln!("{host}: {} certificates, server key {kind}", certs.len());
    }
}

#[test]
fn every_mozilla_root_is_usable() {
    // Each root's key is one jpm-tls can check signatures with, but for the few P-521 roots
    // (webpki with ring cannot use those either).
    let mut p521 = 0;
    for ta in webpki_roots::TLS_SERVER_ROOTS {
        let a = anchor(ta);
        let mut r = jpm_tls::der::Reader::new(a.spki);
        let alg = r.expect(0x30).unwrap();
        let supported = [
            &hex_bytes("06092a864886f70d0101010500")[..],
            &hex_bytes("06072a8648ce3d020106082a8648ce3d030107"),
            &hex_bytes("06072a8648ce3d020106052b81040022"),
        ];
        if alg == hex_bytes("06072a8648ce3d020106052b81040023") {
            p521 += 1;
        } else {
            assert!(supported.contains(&alg), "{}", hex(a.subject));
        }
    }
    eprintln!("{} Mozilla roots, {p521} with P-521 keys", webpki_roots::TLS_SERVER_ROOTS.len());
    assert!(p521 <= 3);
}

/// `cargo test -p jpm-tls --release --test x509_real -- --ignored --nocapture bench`
#[test]
#[ignore]
fn bench() {
    let now = captured_at();
    let roots = roots();
    for host in ["registry.npmjs.org", "github.com"] {
        let certs = chain(host);
        let refs: Vec<&[u8]> = certs.iter().map(|c| &c[..]).collect();
        let n = 1000;
        let start = Instant::now();
        for _ in 0..n {
            x509::verify_server(&refs, host, now, &roots).unwrap();
        }
        let ours = start.elapsed().as_secs_f64() * 1e6 / n as f64;
        let start = Instant::now();
        for _ in 0..n {
            theirs(&refs, host, now, webpki_roots::TLS_SERVER_ROOTS).unwrap();
        }
        let webpki = start.elapsed().as_secs_f64() * 1e6 / n as f64;
        eprintln!("{host}: jpm-tls {ours:.1} µs/verify, webpki (ring) {webpki:.1} µs/verify");
    }
}
