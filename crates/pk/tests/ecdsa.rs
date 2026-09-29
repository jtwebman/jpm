mod common;

use common::{cases, hex, random, random_vec, rounds, time, wycheproof};
use jpm_pk::{p256, p384};
use ring::digest::{self, SHA256, SHA384, SHA512};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, UnparsedPublicKey, VerificationAlgorithm};

type Verify = fn(&[u8], &[u8], &[u8]) -> bool;

const N256: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const N384: &str =
    concat!("ffffffffffffffffffffffffffffffffffffffffffffffff", "c7634d81f4372ddf581a0db248b0a77aecec196accc52973");

fn hash(name: &str, msg: &[u8]) -> Vec<u8> {
    let alg = match name {
        "SHA-256" => &SHA256,
        "SHA-384" => &SHA384,
        "SHA-512" => &SHA512,
        _ => panic!("hash {name}"),
    };
    digest::digest(alg, msg).as_ref().to_vec()
}

/// Every case must come out as Wycheproof says. These files have no "acceptable" cases: BER
/// and other non-minimal encodings are "invalid", and are refused.
fn run_wycheproof(file: &str, verify: Verify, count: usize) {
    let v = wycheproof(file);
    let mut n = 0;
    for (g, t) in cases(&v) {
        let id = &t["tcId"];
        let public = hex(g["publicKey"]["uncompressed"].as_str().unwrap());
        let digest = hash(g["sha"].as_str().unwrap(), &hex(t["msg"].as_str().unwrap()));
        let sig = hex(t["sig"].as_str().unwrap());
        let want = match t["result"].as_str().unwrap() {
            "valid" => true,
            "invalid" => false,
            r => panic!("{file} tcId {id}: result {r}"),
        };
        assert_eq!(verify(&public, &digest, &sig), want, "{file} tcId {id} {}", t["comment"]);
        n += 1;
    }
    assert_eq!(n, count, "{file}");
}

#[test]
fn wycheproof_p256_sha256() {
    run_wycheproof("ecdsa_secp256r1_sha256_test", p256::verify, 484);
}

#[test]
fn wycheproof_p256_sha512() {
    run_wycheproof("ecdsa_secp256r1_sha512_test", p256::verify, 554);
}

#[test]
fn wycheproof_p384_sha384() {
    run_wycheproof("ecdsa_secp384r1_sha384_test", p384::verify, 504);
}

#[test]
fn wycheproof_p384_sha256() {
    run_wycheproof("ecdsa_secp384r1_sha256_test", p384::verify, 472);
}

#[test]
fn wycheproof_p384_sha512() {
    run_wycheproof("ecdsa_secp384r1_sha512_test", p384::verify, 542);
}

/// DER `INTEGER`, minimal: leading zeros dropped, one put back if the high bit is set.
fn der_int(v: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = v.iter().copied().skip_while(|&b| b == 0).collect();
    if v.first().is_none_or(|&b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    [&[2, v.len() as u8][..], &v].concat()
}

fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
    let body = [der_int(r), der_int(s)].concat();
    [&[0x30, body.len() as u8][..], &body].concat()
}

/// (r, s) from a DER signature ring made, as fixed-width big-endian numbers.
fn split(sig: &[u8], len: usize) -> (Vec<u8>, Vec<u8>) {
    let int = |b: &[u8]| -> (Vec<u8>, usize) {
        let l = b[1] as usize;
        let v = &b[2..2 + l];
        let mut out = vec![0; len];
        let v = if v.len() > len { &v[1..] } else { v };
        out[len - v.len()..].copy_from_slice(v);
        (out, 2 + l)
    };
    assert_eq!(sig[0], 0x30);
    let (r, used) = int(&sig[2..]);
    let (s, _) = int(&sig[2 + used..]);
    (r, s)
}

/// Big-endian a + b and a - b at a fixed width, wrapping.
fn add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0; a.len()];
    let mut carry = 0u16;
    for i in (0..a.len()).rev() {
        let v = a[i] as u16 + b[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    out
}

fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0; a.len()];
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let v = a[i] as i16 - b[i] as i16 - borrow;
        out[i] = v.rem_euclid(256) as u8;
        borrow = (v < 0) as i16;
    }
    out
}

fn small(v: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    out[len - 1] = v;
    out
}

struct Case {
    p: &'static str,
    alg: &'static EcdsaSigningAlgorithm,
    ring_verify: &'static dyn VerificationAlgorithm,
    hash: &'static str,
    verify: Verify,
    n: &'static str,
}

const P256_SHA256: Case = Case {
    alg: &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    ring_verify: &signature::ECDSA_P256_SHA256_ASN1,
    hash: "SHA-256",
    verify: p256::verify,
    n: N256,
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
};
const P384_SHA384: Case = Case {
    alg: &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    ring_verify: &signature::ECDSA_P384_SHA384_ASN1,
    hash: "SHA-384",
    verify: p384::verify,
    n: N384,
    p: concat!("ffffffffffffffffffffffffffffffffffffffffffffffff", "fffffffffffffffeffffffff0000000000000000ffffffff"),
};

/// A fresh ring key pair, a random message, and ring's signature over it:
/// (public key, digest, signature).
fn signed(c: &Case) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(c.alg, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(c.alg, pkcs8.as_ref(), &rng).unwrap();
    let msg = random_vec(random::<1>()[0] as usize);
    let sig = key.sign(&rng, &msg).unwrap();
    (key.public_key().as_ref().to_vec(), hash(c.hash, &msg), sig.as_ref().to_vec())
}

/// Our verify accepts ring's signatures, and rejects every single-bit change to the digest,
/// the signature and the public key.
fn differential(c: &Case, count: usize, flipped: usize) {
    for i in 0..count {
        let (public, digest, sig) = signed(c);
        assert!((c.verify)(&public, &digest, &sig), "{public:02x?} {digest:02x?} {sig:02x?}");
        if i >= flipped {
            continue;
        }
        for (what, v) in [("digest", &digest), ("signature", &sig), ("public key", &public)] {
            for bit in 0..v.len() * 8 {
                let mut v = v.clone();
                v[bit / 8] ^= 1 << (bit % 8);
                let (p, d, s) = match what {
                    "digest" => (&public, &v, &sig),
                    "signature" => (&public, &digest, &v),
                    _ => (&v, &digest, &sig),
                };
                assert!(!(c.verify)(p, d, s), "{what} bit {bit}: {public:02x?} {digest:02x?} {sig:02x?}");
            }
        }
    }
}

#[test]
fn differential_p256_sha256() {
    differential(&P256_SHA256, rounds(2000), rounds(50));
}

#[test]
fn differential_p384_sha384() {
    differential(&P384_SHA384, rounds(1000), rounds(50));
}

/// Out-of-range r and s, re-encodings of a good signature, and cut or padded DER.
fn edges(c: &Case) {
    let len = c.n.len() / 2;
    let n = hex(c.n);
    let (public, digest, sig) = signed(c);
    let (r, s) = split(&sig, len);
    let verify = |sig: &[u8]| (c.verify)(&public, &digest, sig);
    assert_eq!(der(&r, &s), sig);
    assert!(verify(&sig));
    // (r, n - s) is the other valid signature for the same R; ECDSA does not ask for low s.
    assert!(verify(&der(&r, &sub(&n, &s))));
    let one = small(1, len);
    let big = vec![0xff; len];
    for bad in [vec![0; len], n.clone(), add(&n, &one), big.clone(), add(&r, &n), sub(&n, &one)] {
        assert!(!verify(&der(&bad, &s)), "r = {bad:02x?}");
        assert!(!verify(&der(&r, &bad)), "s = {bad:02x?}");
    }
    // Values wider than the order.
    let wide = [&[1][..], &r].concat();
    assert!(!verify(&der(&wide, &s)));
    assert!(!verify(&der(&r, &[&[1][..], &s].concat())));
    // r and s swapped.
    assert!(!verify(&der(&s, &r)));
    // Every truncation, and trailing bytes.
    for i in 0..sig.len() {
        assert!(!verify(&sig[..i]));
    }
    assert!(!verify(&[&sig[..], &[0]].concat()));
    assert!(!verify(&[&sig[..], &[0x02, 0x01, 0x01]].concat()));
    // Non-minimal encodings of the same numbers.
    let ri = der_int(&r);
    let si = der_int(&s);
    let seq = |body: &[u8]| [&[0x30, body.len() as u8][..], body].concat();
    let padded = |int: &[u8]| [&[2, int[1] + 1, 0][..], &int[2..]].concat();
    let long_int = |int: &[u8]| [&[2, 0x81][..], &int[1..]].concat();
    let body = [&ri[..], &si].concat();
    for bad in [
        seq(&[padded(&ri), si.clone()].concat()),
        seq(&[ri.clone(), padded(&si)].concat()),
        seq(&[long_int(&ri), si.clone()].concat()),
        seq(&[ri.clone(), long_int(&si)].concat()),
        [&[0x30, 0x81, body.len() as u8][..], &body].concat(),
        [&[0x30, 0x80][..], &body, &[0, 0]].concat(),
        [&[0x31, body.len() as u8][..], &body].concat(),
        seq(&[&[0x03][..], &ri[1..], &si].concat()),
        seq(&[ri.clone(), si.clone(), vec![0x05, 0x00]].concat()),
        seq(&ri),
        seq(&[]),
        vec![0x30, 0x00],
        vec![0x30],
        vec![],
    ] {
        assert!(!verify(&bad), "{bad:02x?}");
    }
    // Negative r: the same bytes without the zero that keeps the sign bit clear.
    if ri[2] == 0 {
        assert!(!verify(&seq(&[&[2, ri[1] - 1][..], &ri[3..], &si].concat())));
    }
}

#[test]
fn edges_p256() {
    for _ in 0..rounds(100) {
        edges(&P256_SHA256);
    }
}

#[test]
fn edges_p384() {
    for _ in 0..rounds(100) {
        edges(&P384_SHA384);
    }
}

/// The digest is truncated to the order's length (64N bits) or, when shorter, read as a smaller
/// number: longer digests with the same prefix verify, shorter ones equal their zero-padded form.
#[test]
fn digest_lengths() {
    for c in [&P256_SHA256, &P384_SHA384] {
        let len = c.n.len() / 2;
        let (public, digest, sig) = signed(c);
        let verify = |d: &[u8]| (c.verify)(&public, d, &sig);
        assert!(verify(&digest));
        assert!(verify(&[&digest[..], &random::<16>()].concat()));
        assert!(verify(&[&digest[..], &[0; 64]].concat()));
        for l in [0, 1, 20, 32, 48, 64] {
            let d = random_vec(l);
            let padded = if l < len { [&vec![0; len - l][..], &d].concat() } else { d[..len].to_vec() };
            assert!(!verify(&d));
            assert_eq!(verify(&d), verify(&padded));
            let short = &digest[..len.min(l)];
            assert_eq!(verify(short), l >= len, "len {l}");
        }
    }
    // P-384 with a 32-byte digest: the valid Wycheproof signatures also verify with the
    // digest zero-padded to 48 bytes, and not with it padded on the right.
    let v = wycheproof("ecdsa_secp384r1_sha256_test");
    let mut n = 0;
    for (g, t) in cases(&v).filter(|(_, t)| t["result"] == "valid") {
        let public = hex(g["publicKey"]["uncompressed"].as_str().unwrap());
        let digest = hash("SHA-256", &hex(t["msg"].as_str().unwrap()));
        let sig = hex(t["sig"].as_str().unwrap());
        assert!(p384::verify(&public, &[&[0; 16][..], &digest].concat(), &sig));
        assert!(!p384::verify(&public, &[&digest[..], &[0; 16]].concat(), &sig));
        n += 1;
    }
    assert_eq!(n, 162);
}

#[test]
fn bad_public_keys() {
    for c in [&P256_SHA256, &P384_SHA384] {
        let (public, digest, sig) = signed(c);
        let len = c.n.len() / 2;
        let verify = |p: &[u8]| (c.verify)(p, &digest, &sig);
        assert!(verify(&public));
        let mut bad = vec![vec![], vec![0], vec![4], vec![0; 1 + 2 * len], public[..1 + len].to_vec()];
        bad.push([&public[..], &[0]].concat());
        bad.push(public[..public.len() - 1].to_vec());
        for prefix in [2, 3, 6, 7] {
            let mut p = public.clone();
            p[0] = prefix;
            bad.push(p);
        }
        // (x, p - y) is on the curve, but it is the negated key.
        let neg = sub(&hex(c.p), &public[1 + len..]);
        bad.push([&public[..1 + len], &neg].concat());
        // x or y at or above p.
        let p = hex(c.p);
        bad.push([&[4][..], &p, &public[1 + len..]].concat());
        bad.push([&public[..1 + len], &p].concat());
        bad.push([&[4][..], &add(&p, &public[1..1 + len]), &public[1 + len..]].concat());
        bad.push([&public[..1 + len], &add(&p, &neg)].concat());
        let mut ones = vec![0xff; 1 + 2 * len];
        ones[0] = 4;
        bad.push(ones);
        for p in &bad {
            assert!(!verify(p), "{p:02x?}");
        }
    }
}

/// Garbage must never panic, whatever the lengths.
#[test]
fn no_panics() {
    for _ in 0..rounds(20000) {
        let [a, b, c] = random::<3>();
        let (p, d, s) = (random_vec(a as usize % 140), random_vec(b as usize % 80), random_vec(c as usize % 120));
        assert!(!p256::verify(&p, &d, &s));
        assert!(!p384::verify(&p, &d, &s));
        let mut s = s;
        if s.len() >= 2 {
            s[0] = 0x30;
            s[1] = (s.len() - 2) as u8;
        }
        assert!(!p256::verify(&p, &d, &s));
        assert!(!p384::verify(&p, &d, &s));
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_ecdsa_verify() {
    for (name, c) in [("p256", &P256_SHA256), ("p384", &P384_SHA384)] {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(c.alg, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(c.alg, pkcs8.as_ref(), &rng).unwrap();
        let msg = b"benchmark";
        let sig = key.sign(&rng, msg).unwrap();
        let public = key.public_key().as_ref();
        let digest = hash(c.hash, msg);
        let ours = time(2000, || assert!((c.verify)(public, &digest, sig.as_ref())));
        let ring_key = UnparsedPublicKey::new(c.ring_verify, public);
        let ring = time(2000, || ring_key.verify(msg, sig.as_ref()).unwrap());
        println!("{name} verify: ours {ours:.1} µs, ring {ring:.1} µs");
    }
}
