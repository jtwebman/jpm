//! Randomized and mutated chains: verify_server must decide as webpki does (with the
//! differences listed in x509_util::difference), never panic, and stay quick.
//!
//! Debug builds run fewer cases; `cargo test -p jpm-tls --release --test x509_fuzz` runs them
//! all. X509_FUZZ_SCALE multiplies the counts.

mod x509_util;

use std::time::{Duration, Instant};

use rcgen::{CidrSubnet, GeneralSubtree, NameConstraints};
use rustls::pki_types::TrustAnchor;
use x509_util::*;

fn scale(release: usize, debug: usize) -> usize {
    let n = if cfg!(debug_assertions) { debug } else { release };
    n * std::env::var("X509_FUZZ_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

/// Valid chains of every shape, with hosts they are for.
fn corpus() -> Vec<(Chain, &'static str)> {
    let nc = |dns: &str| NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName(dns.into()),
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([192, 0, 2, 0], 24)),
        ],
        excluded_subtrees: vec![GeneralSubtree::DnsName(format!("bad.{dns}"))],
    };
    vec![
        (Chain::new(0, &["example.com"], &[Kind::P256]), "example.com"),
        (Chain::new(1, &["example.com", "*.example.com"], &[Kind::P256]), "www.example.com"),
        (Chain::new(2, &["example.com", "192.0.2.1"], &[Kind::P384, Kind::P256]), "192.0.2.1"),
        (Chain::new(3, &["2001:db8::1", "example.com"], &[Kind::P256, Kind::P384]), "2001:db8::1"),
        (Chain::new(1, &["example.com"], &[Kind::Rsa4096, Kind::Rsa2048, Kind::P256]), "example.com"),
        (Chain::new(2, &["example.com"], &[Kind::Rsa3072, Kind::P256]), "example.com"),
        (
            Chain::custom(2, &["a.example.com", "192.0.2.5"], &[Kind::P256], |level, p| {
                if level == 0 {
                    p.name_constraints = Some(nc("example.com"));
                }
                if level == 2 {
                    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
                }
            }),
            "a.example.com",
        ),
        (
            Chain::custom(1, &["b.example.com"], &[Kind::P256], |level, p| {
                if level == 1 {
                    p.name_constraints = Some(nc("example.com"));
                    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
                }
            }),
            "b.example.com",
        ),
    ]
}

const HOSTS: &[&str] = &[
    "example.com",
    "www.example.com",
    "a.example.com",
    "b.example.com",
    "bad.example.com",
    "192.0.2.1",
    "192.0.2.5",
    "2001:db8::1",
    "[2001:db8::1]",
    "example.org",
    "EXAMPLE.COM.",
    "",
];

fn times(rng: &mut Rng) -> u64 {
    const T: [u64; 6] = [NOW, 1_577_836_800, 1_577_836_799, 2_208_988_800, 2_208_988_801, 0];
    match rng.below(4) {
        0 => rng.next() % 4_000_000_000,
        _ => T[rng.below(T.len())],
    }
}

/// One mutation of `der`: a bit flip, a byte set, a truncation, a byte inserted or removed,
/// or a length or tag changed at a TLV boundary. Returns the position touched.
fn mutate(rng: &mut Rng, der: &mut Vec<u8>) -> usize {
    if der.is_empty() {
        der.push(rng.next() as u8);
        return 0;
    }
    let i = rng.below(der.len());
    match rng.below(6) {
        0 => der[i] ^= 1 << rng.below(8),
        1 => der[i] = rng.next() as u8,
        2 => der.truncate(i),
        3 => der.insert(i, rng.next() as u8),
        4 => drop(der.remove(i)),
        _ => {
            // Find a TLV start near i and change its tag or length byte.
            let starts = tlv_starts(der);
            let s = starts[rng.below(starts.len())];
            let j = (s + rng.below(2)).min(der.len() - 1);
            der[j] = der[j].wrapping_add(if rng.below(2) == 0 { 1 } else { 0xff });
            return j;
        }
    }
    i
}

/// The key that signed `chain.ders()[k]`.
fn issuer_key(chain: &Chain, k: usize) -> &rcgen::KeyPair {
    // ders() is the leaf, then the intermediates from the bottom up; inters[0] is the top.
    let n = chain.inters.len();
    match n - k {
        0 => &chain.root.key,
        i => &chain.inters[i - 1].key,
    }
}

/// Where each TLV in `der` begins, nested ones included, as far as it parses.
fn tlv_starts(der: &[u8]) -> Vec<usize> {
    fn walk(base: &[u8], data: &[u8], out: &mut Vec<usize>) {
        let mut r = jpm_tls::der::Reader::new(data);
        while !r.is_empty() {
            out.push(range_of(base, r.rest()).start);
            let Some((tag, v)) = r.read() else { return };
            if tag & 0x20 != 0 || tag == 3 || tag == 4 {
                walk(base, if tag == 3 && !v.is_empty() { &v[1..] } else { v }, out);
            }
        }
    }
    let mut out = vec![0];
    walk(der, der, &mut out);
    out
}

#[test]
fn mutations_agree_with_webpki() {
    let corpus = corpus();
    let mut rng = Rng(0x5eed_1234_abcd);
    let (mut accepted, mut rejected, mut differences) = (0, 0, 0);
    let total = scale(20_000, 5_000);
    for _ in 0..total {
        let (chain, host) = &corpus[rng.below(corpus.len())];
        let mut certs: Vec<Vec<u8>> = chain.ders().iter().map(|c| c.to_vec()).collect();
        let mut anchors = chain.anchors();
        let mut allowed = Allowed::None;
        match rng.below(10) {
            // Mutate an anchor's fields.
            0 => {
                let a = &anchors[0];
                let mut subject = a.subject.to_vec();
                let mut spki = a.subject_public_key_info.to_vec();
                let mut nc = a.name_constraints.as_ref().map(|n| n.to_vec());
                match (rng.below(3), &mut nc) {
                    (0, _) => drop(mutate(&mut rng, &mut subject)),
                    (1, Some(nc)) if !nc.is_empty() => drop(mutate(&mut rng, nc)),
                    _ => drop(mutate(&mut rng, &mut spki)),
                }
                anchors = vec![TrustAnchor {
                    subject: subject.into(),
                    subject_public_key_info: spki.into(),
                    name_constraints: nc.map(Into::into),
                }];
            }
            // Mutate one or more certificates' TBS and sign again with the right key, so the
            // change reaches the checks past the signature.
            1..=6 => {
                for _ in 0..1 + rng.below(2) {
                    let k = rng.below(certs.len());
                    let Some(fields) = tbs_fields(&certs[k]).filter(|f| f.len() > 6) else {
                        mutate(&mut rng, &mut certs[k]);
                        continue;
                    };
                    let mut tbs = fields.iter().flat_map(|f| f.2.to_vec()).collect::<Vec<u8>>();
                    let spki = range_of(fields[0].2, fields[6].2);
                    let at = mutate(&mut rng, &mut tbs);
                    if k == 0 && spki.start <= at && at < spki.end {
                        allowed = Allowed::LeafKey;
                    }
                    let alg = fields[2].2.to_vec();
                    let tbs = tlv(0x30, &tbs);
                    let sig = rcgen::SigningKey::sign(issuer_key(chain, k), &tbs).unwrap();
                    certs[k] = seq(&[&tbs, &alg, &tlv(3, &[&[0][..], &sig].concat())]);
                }
            }
            // Mutate one or more certificates as they are.
            _ => {
                for _ in 0..1 + rng.below(2) {
                    let k = rng.below(certs.len());
                    let spki = spki(&certs[k]).map(|s| range_of(&certs[k], s));
                    let at = mutate(&mut rng, &mut certs[k]);
                    if k == 0 && spki.is_some_and(|r| r.start - 4 <= at && at < r.end) {
                        allowed = Allowed::LeafKey;
                    }
                }
            }
        }
        // Now and then, reorder, duplicate or drop intermediates.
        if rng.below(4) == 0 && certs.len() > 1 {
            let mut rest = certs.split_off(1);
            rng.shuffle(&mut rest);
            if rng.below(2) == 0 {
                rest.push(rest[0].clone());
            } else if rng.below(2) == 0 {
                rest.pop();
            }
            certs.extend(rest);
        }
        let host = if rng.below(3) == 0 { HOSTS[rng.below(HOSTS.len())] } else { host };
        let now = if rng.below(3) == 0 { times(&mut rng) } else { NOW };
        let refs: Vec<&[u8]> = certs.iter().map(|c| &c[..]).collect();
        let a = ours(&refs, host, now, &anchors);
        let b = theirs(&refs, host, now, &anchors);
        if a.is_ok() != b.is_ok() {
            differences += 1;
        }
        match check_allowing(&refs, host, now, &anchors, allowed) {
            Ok(()) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    eprintln!("mutations: {accepted} accepted, {rejected} rejected, {differences} intentional differences");
    assert!(accepted * 100 > total, "too few mutated chains still valid to be a useful test");
}

#[test]
fn random_times_hosts_and_orders_agree_with_webpki() {
    let corpus = corpus();
    let mut rng = Rng(42);
    let mut accepted = 0;
    let total = scale(5_000, 2_000);
    for _ in 0..total {
        let (chain, host) = &corpus[rng.below(corpus.len())];
        let mut chain_ders = chain.ders();
        let mut rest = chain_ders.split_off(1);
        rng.shuffle(&mut rest);
        // Mix in another chain's intermediates as junk.
        let (other, _) = &corpus[rng.below(corpus.len())];
        rest.extend(other.ders().into_iter().skip(1).take(rng.below(3)));
        chain_ders.extend(rest);
        let host = if rng.below(2) == 0 { HOSTS[rng.below(HOSTS.len())] } else { host };
        let now = times(&mut rng);
        // Sometimes several anchors, sometimes none that fit.
        let mut anchors: Vec<TrustAnchor> = match rng.below(4) {
            0 => other.anchors(),
            _ => chain.anchors(),
        };
        if rng.below(3) == 0 {
            anchors.extend(corpus[rng.below(corpus.len())].0.anchors());
        }
        if check(&chain_ders, host, now, &anchors).is_ok() {
            accepted += 1;
        }
    }
    eprintln!("random: {accepted} of {total} accepted");
    assert!(accepted > total / 10);
}

/// Error messages for the same input, compared loosely with webpki's: printed, not asserted,
/// as the ranking of reasons differs in ties.
#[test]
fn error_messages_mostly_agree() {
    let corpus = corpus();
    let mut rng = Rng(99);
    let (mut same, mut total) = (0, 0);
    for _ in 0..scale(3_000, 300) {
        let (chain, host) = &corpus[rng.below(corpus.len())];
        let mut certs: Vec<Vec<u8>> = chain.ders().iter().map(|c| c.to_vec()).collect();
        let k = rng.below(certs.len());
        mutate(&mut rng, &mut certs[k]);
        let refs: Vec<&[u8]> = certs.iter().map(|c| &c[..]).collect();
        let now = times(&mut rng);
        let (Err(a), Err(b)) = (ours(&refs, host, now, &chain.anchors()), theirs(&refs, host, now, &chain.anchors()))
        else {
            continue;
        };
        total += 1;
        let b = format!("{b:?}");
        let expected = match b.split(['(', ' ', '{']).next().unwrap() {
            "CertExpired" => "certificate expired",
            "CertNotValidYet" => "certificate not yet valid",
            "CertNotValidForName" => "certificate is not valid for this host",
            "InvalidSignatureForPublicKey" | "SignatureAlgorithmMismatch" => "bad signature",
            "UnknownIssuer" => "unknown issuer",
            "UnsupportedCriticalExtension" | "UnsupportedCertVersion" => "unsupported certificate",
            "UnsupportedSignatureAlgorithmContext" | "UnsupportedSignatureAlgorithmForPublicKeyContext" => {
                "unsupported certificate"
            }
            "InvalidCertValidity" => "invalid certificate validity",
            "CaUsedAsEndEntity" => "CA certificate used as a server certificate",
            "EndEntityUsedAsCa" => "issuer is not a CA",
            "NameConstraintViolation" => "certificate not allowed by name constraints",
            "RequiredEkuNotFoundContext" | "EmptyEkuExtension" => "certificate is not for server authentication",
            "PathLenConstraintViolated" => "path length constraint violated",
            "MaximumPathDepthExceeded" => "path too long",
            _ => "invalid certificate encoding",
        };
        if a == expected {
            same += 1;
        } else if total - same <= 10 {
            eprintln!("differs: ours {a:?}, webpki {b}");
        }
    }
    eprintln!("error messages: {same} of {total} the same");
    assert!(same * 10 >= total * 9, "{same} of {total}");
}

#[test]
fn robustness() {
    // Mutated chains and random bytes through verify_server alone: no panics, and each call
    // quick. The bound is for release builds; debug builds get more room.
    let limit = if cfg!(debug_assertions) { Duration::from_millis(1000) } else { Duration::from_millis(50) };
    let corpus = corpus();
    let mut rng = Rng(0xdead_beef);
    let mut slowest = Duration::ZERO;
    let total = scale(100_000, 20_000);
    for i in 0..total {
        let (chain, host) = &corpus[rng.below(corpus.len())];
        let mut certs: Vec<Vec<u8>> = chain.ders().iter().map(|c| c.to_vec()).collect();
        match i % 4 {
            // Random bytes, sometimes wrapped as a SEQUENCE.
            0 => {
                let len = rng.below(600);
                let junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                let k = rng.below(certs.len());
                certs[k] = if rng.below(2) == 0 { junk } else { seq(&[&junk]) };
            }
            // Many mutations at once.
            1 => {
                for _ in 0..1 + rng.below(20) {
                    let k = rng.below(certs.len());
                    if !certs[k].is_empty() {
                        mutate(&mut rng, &mut certs[k]);
                    }
                }
            }
            // Splices of one certificate into another.
            2 => {
                let (a, b) = (rng.below(certs.len()), rng.below(certs.len()));
                let cut = rng.below(certs[a].len().min(certs[b].len()));
                let tail = certs[b][cut..].to_vec();
                certs[a].truncate(cut);
                certs[a].extend(tail);
            }
            _ => {
                let k = rng.below(certs.len());
                mutate(&mut rng, &mut certs[k]);
            }
        }
        let refs: Vec<&[u8]> = certs.iter().map(|c| &c[..]).collect();
        let anchors: Vec<_> = chain.anchors();
        let a: Vec<_> = anchors.iter().map(anchor).collect();
        let start = Instant::now();
        let _ = jpm_tls::x509::verify_server(&refs, host, times(&mut rng), &a);
        let took = start.elapsed();
        slowest = slowest.max(took);
        assert!(took < limit, "call {i} took {took:?}");
    }
    eprintln!("robustness: {total} calls, slowest {slowest:?}");
}

#[test]
fn der_reader_never_panics() {
    let mut rng = Rng(3);
    for _ in 0..scale(200_000, 20_000) {
        let len = rng.below(12);
        let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if rng.below(2) == 0 && !data.is_empty() {
            data[1.min(len - 1)] = 0x80 | rng.below(6) as u8;
        }
        let mut r = jpm_tls::der::Reader::new(&data);
        let mut n = 0;
        while let Some((_, v)) = r.read() {
            assert!(v.len() <= data.len());
            n += 1;
        }
        assert!(n <= data.len() / 2);
    }
}
