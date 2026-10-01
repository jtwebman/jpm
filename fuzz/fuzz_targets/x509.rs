//! Certificates as the TLS client reads them: a chain of DER certificates, each length-prefixed
//! (two bytes, big-endian), checked against an anchor made from the last of them.
#![no_main]

use jpm_tls::x509;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut chain: Vec<&[u8]> = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 && chain.len() < 4 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        chain.push(&rest[2..2 + n]);
        rest = &rest[2 + n..];
    }
    if chain.is_empty() {
        chain.push(data);
    }
    for c in &chain {
        let _ = x509::leaf_key(c);
        let _ = x509::Anchor::from_cert(c);
    }
    let anchors: Vec<x509::Anchor> = chain.last().and_then(|c| x509::Anchor::from_cert(c).ok()).into_iter().collect();
    let _ = x509::verify_server(&chain, "registry.npmjs.org", 1_750_000_000, &anchors);
});
