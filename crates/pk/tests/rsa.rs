//! RSA verification against Wycheproof, signatures from ring, odd-shaped keys signed in Python
//! (tests/data/rsa_odd_keys.py), and hand-made edge cases. Message digests come from ring.

use jpm_crypto::hash::Alg;
use jpm_pk::rsa::{verify_pkcs1, verify_pss};
use ring::rand::SecureRandom;
use ring::signature::{self, RsaKeyPair};
use serde_json::Value;
use std::io::Read;

/// n, e, alg, digest, signature.
type Verify = fn(&[u8], &[u8], Alg, &[u8], &[u8]) -> bool;

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    if !name.ends_with(".gz") {
        return raw;
    }
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut out).unwrap();
    out
}

fn json(name: &str) -> Value {
    serde_json::from_slice(&data(name)).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Wycheproof writes "SHA-256", rsa_odd_keys.py "sha256".
fn alg(name: &str) -> Option<Alg> {
    match name.to_ascii_lowercase().replace('-', "").as_str() {
        "sha1" => Some(Alg::Sha1),
        "sha256" => Some(Alg::Sha256),
        "sha384" => Some(Alg::Sha384),
        "sha512" => Some(Alg::Sha512),
        _ => None,
    }
}

/// The reference hash of the concatenated parts.
fn ring_hash(alg: Alg, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(match alg {
        Alg::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        Alg::Sha256 => &ring::digest::SHA256,
        Alg::Sha384 => &ring::digest::SHA384,
        Alg::Sha512 => &ring::digest::SHA512,
    });
    parts.iter().for_each(|p| ctx.update(p));
    ctx.finish().as_ref().to_vec()
}

/// Runs a Wycheproof file; returns (checked, skipped). Valid cases must verify and all others
/// must not. The only "acceptable" cases are MissingNull, a legacy DigestInfo without the NULL
/// parameter: we compare against the one DER encoding, so they fail, as in ring and Go.
///
/// PSS cases with a salt length other than the digest length, a different MGF1 hash, or a hash we
/// do not offer (SHA-1, SHA-224) are skipped: there the signature must simply not verify under the
/// parameters we do use.
fn wycheproof(file: &str, verify: Verify) -> (usize, usize) {
    let doc = json(&format!("{file}.json.gz"));
    let (mut checked, mut skipped) = (0, 0);
    for g in doc["testGroups"].as_array().unwrap() {
        let key = &g["publicKey"];
        let (n, e) = (hex(key["modulus"].as_str().unwrap()), hex(key["publicExponent"].as_str().unwrap()));
        let sha = g["sha"].as_str().unwrap();
        let ours = alg(sha).filter(|&a| a != Alg::Sha1);
        let pss_ok = g.get("mgfSha").is_none_or(|m| m == sha)
            && g.get("sLen").is_none_or(|s| Some(s.as_u64().unwrap() as usize) == ours.map(Alg::len));
        for t in g["tests"].as_array().unwrap() {
            let (msg, sig) = (hex(t["msg"].as_str().unwrap()), hex(t["sig"].as_str().unwrap()));
            let id = t["tcId"].as_u64().unwrap();
            let result = t["result"].as_str().unwrap();
            let Some(a) = ours.filter(|_| pss_ok) else {
                // Try every hash we offer; none may accept.
                for a in [Alg::Sha1, Alg::Sha256, Alg::Sha384, Alg::Sha512] {
                    assert!(!verify(&n, &e, a, &ring_hash(a, &[&msg]), &sig), "{file} tcId {id} verified as {a:?}");
                }
                skipped += 1;
                continue;
            };
            let got = verify(&n, &e, a, &ring_hash(a, &[&msg]), &sig);
            assert_eq!(got, result == "valid", "{file} tcId {id} ({result}, {}): {}", t["flags"], t["comment"]);
            checked += 1;
        }
    }
    (checked, skipped)
}

/// Signatures for key shapes ring will not sign with (tests/data/rsa_odd_keys.py says which
/// must verify and why the others must not).
fn odd_keys(pss: bool, verify: Verify) -> usize {
    let mut count = 0;
    for v in json("rsa_odd_keys.json.gz").as_array().unwrap() {
        if (v["scheme"] == "pss") != pss {
            continue;
        }
        let s = |k: &str| hex(v[k].as_str().unwrap());
        let a = alg(v["hash"].as_str().unwrap()).unwrap();
        let bits = v["bits"].as_u64().unwrap();
        let digest = ring_hash(a, &[&s("msg")]);
        let want = v["valid"].as_bool().unwrap();
        assert_eq!(verify(&s("n"), &s("e"), a, &digest, &s("sig")), want, "{bits} bits {} {}", v["hash"], v["note"]);
        count += 1;
    }
    count
}

/// RSAPrivateKey DER from `openssl genpkey`. ring signs only with moduli of 2048 to 4096 bits in
/// steps of 512.
const KEYS: [&str; 3] = ["rsa2048.der", "rsa3072.der", "rsa4096.der"];

fn key(name: &str) -> (RsaKeyPair, Vec<u8>, Vec<u8>) {
    let kp = RsaKeyPair::from_der(&data(name)).unwrap();
    let c: signature::RsaPublicKeyComponents<Vec<u8>> = kp.public().into();
    (kp, c.n, c.e)
}

/// Signs random messages with ring under every hash and checks `verify` accepts them, and that
/// flipping one bit in each signature byte (every byte for the first key, 16 spread-out bytes
/// for the others) or any digest byte makes it fail.
fn differential(pss: bool, verify: Verify) -> usize {
    let rng = ring::rand::SystemRandom::new();
    let mut count = 0;
    for (ki, name) in KEYS.iter().enumerate() {
        let (kp, n, e) = key(name);
        for a in [Alg::Sha256, Alg::Sha384, Alg::Sha512] {
            let scheme: &dyn signature::RsaEncoding = match (pss, a) {
                (false, Alg::Sha256) => &signature::RSA_PKCS1_SHA256,
                (false, Alg::Sha384) => &signature::RSA_PKCS1_SHA384,
                (false, _) => &signature::RSA_PKCS1_SHA512,
                (true, Alg::Sha256) => &signature::RSA_PSS_SHA256,
                (true, Alg::Sha384) => &signature::RSA_PSS_SHA384,
                (true, _) => &signature::RSA_PSS_SHA512,
            };
            let mut msg = vec![0; 1 + ki * 37 + a.len()];
            rng.fill(&mut msg).unwrap();
            let mut sig = vec![0; kp.public().modulus_len()];
            kp.sign(scheme, &rng, &msg, &mut sig).unwrap();
            let mut digest = ring_hash(a, &[&msg]);
            assert!(verify(&n, &e, a, &digest, &sig), "{name} {a:?}");
            let step = if ki == 0 { 1 } else { sig.len() / 16 };
            for i in (0..sig.len()).step_by(step) {
                sig[i] ^= 1 << (i % 8);
                assert!(!verify(&n, &e, a, &digest, &sig), "{name} {a:?} signature byte {i}");
                sig[i] ^= 1 << (i % 8);
            }
            for i in 0..digest.len() {
                digest[i] ^= 0x80 >> (i % 8);
                assert!(!verify(&n, &e, a, &digest, &sig), "{name} {a:?} digest byte {i}");
                digest[i] ^= 0x80 >> (i % 8);
            }
            // Checked as another hash, the signature must fail.
            for b in [Alg::Sha256, Alg::Sha384, Alg::Sha512].into_iter().filter(|&b| b != a) {
                assert!(!verify(&n, &e, b, &ring_hash(b, &[&msg]), &sig), "{name} {a:?} as {b:?}");
            }
            count += 1;
        }
    }
    count
}

/// The encoded message for `digest` under a k-byte modulus with its top bit set: what s^e mod n
/// must equal. PSS uses an all-zero salt.
fn encode(pss: bool, k: usize, a: Alg, digest: &[u8]) -> Vec<u8> {
    let h_len = a.len();
    let mut em = vec![0xff; k];
    if !pss {
        let info = hex(match a {
            Alg::Sha256 => "3031300d060960864801650304020105000420",
            Alg::Sha384 => "3041300d060960864801650304020205000430",
            _ => "3051300d060960864801650304020305000440",
        });
        let t = k - info.len() - h_len;
        em[..2].copy_from_slice(&[0, 1]);
        em[t - 1] = 0;
        em[t..t + info.len()].copy_from_slice(&info);
        em[t + info.len()..].copy_from_slice(digest);
        return em;
    }
    let salt = vec![0; h_len];
    let h = ring_hash(a, &[&[0; 8], digest, &salt]);
    let db_len = k - h_len - 1;
    em[..db_len].fill(0);
    em[db_len - h_len - 1] = 1;
    for (i, chunk) in em[..db_len].chunks_mut(h_len).enumerate() {
        let mask = ring_hash(a, &[&h, &(i as u32).to_be_bytes()]);
        chunk.iter_mut().zip(mask).for_each(|(b, m)| *b ^= m);
    }
    em[0] &= 0x7f;
    em[db_len..k - 1].copy_from_slice(&h);
    em[k - 1] = 0xbc;
    em
}

/// Keys and signatures just outside the rules, built from one good signature by the 2048-bit key.
fn edge_cases(pss: bool, verify: Verify) {
    let (kp, n, e) = key(KEYS[0]);
    let a = Alg::Sha256;
    let digest = ring_hash(a, &[b"edge"]);
    let mut sig = vec![0; kp.public().modulus_len()];
    let scheme: &dyn signature::RsaEncoding =
        if pss { &signature::RSA_PSS_SHA256 } else { &signature::RSA_PKCS1_SHA256 };
    kp.sign(scheme, &ring::rand::SystemRandom::new(), b"edge", &mut sig).unwrap();
    let ok = |n: &[u8], e: &[u8], d: &[u8], s: &[u8]| verify(n, e, a, d, s);
    assert!(ok(&n, &e, &digest, &sig));
    assert_eq!(e, [1, 0, 1]);

    // Leading zero bytes on n and e are fine; the signature is as long as n without them.
    let n0 = [&[0, 0][..], &n].concat();
    assert!(ok(&n0, &e, &digest, &sig));
    assert!(ok(&n, &[0, 0, 0, 1, 0, 1], &digest, &sig));
    assert!(!ok(&n0, &e, &digest, &[&[0, 0][..], &sig].concat()));

    // A signature whose top byte is zero still takes its full length.
    let rng = ring::rand::SystemRandom::new();
    let mut short_sig = sig.clone();
    let mut msg = [0u8; 16];
    while short_sig[0] != 0 {
        rng.fill(&mut msg).unwrap();
        kp.sign(scheme, &rng, &msg, &mut short_sig).unwrap();
    }
    let msg_digest = ring_hash(a, &[&msg]);
    assert!(ok(&n, &e, &msg_digest, &short_sig));
    assert!(!ok(&n, &e, &msg_digest, &short_sig[1..]));

    // Signature length and value.
    assert!(!ok(&n, &e, &digest, &[&[0][..], &sig].concat()));
    assert!(!ok(&n, &e, &digest, &[&sig[..], &[0]].concat()));
    assert!(!ok(&n, &e, &digest, &sig[1..]));
    assert!(!ok(&n, &e, &digest, &sig[..sig.len() - 1]));
    assert!(!ok(&n, &e, &digest, &[]));
    assert!(!ok(&n, &e, &digest, &n));
    assert!(!ok(&n, &e, &digest, &vec![0xff; n.len()]));
    let mut n_minus_1 = n.clone();
    *n_minus_1.last_mut().unwrap() -= 1;
    assert!(!ok(&n, &e, &digest, &n_minus_1));
    let mut one = vec![0; n.len()];
    assert!(!ok(&n, &e, &digest, &one));
    *one.last_mut().unwrap() = 1;
    assert!(!ok(&n, &e, &digest, &one));

    // s + n has the same residue but is not below n: add n to the signature where it fits.
    let mut plus_n = sig.clone();
    let mut carry = 0u16;
    for (x, &y) in plus_n.iter_mut().zip(&n).rev() {
        let s = *x as u16 + y as u16 + carry;
        *x = s as u8;
        carry = s >> 8;
    }
    if carry == 0 {
        assert!(!ok(&n, &e, &digest, &plus_n));
    }

    // The modulus: even, empty, or cut to 2047 bits.
    let mut even = n.clone();
    *even.last_mut().unwrap() ^= 1;
    assert!(!ok(&even, &e, &digest, &sig));
    assert!(!ok(&[], &e, &digest, &[]));
    let mut short = n.clone();
    short[0] &= 0x7f;
    assert!(!ok(&short, &e, &digest, &sig));

    // The exponent. With e = 1 the encoded message itself would be a valid signature.
    let em = encode(pss, n.len(), a, &digest);
    assert!(!ok(&n, &[1], &digest, &em));
    assert!(!ok(&n, &[0, 1], &digest, &em));
    for bad in [&[][..], &[0], &[2], &[1, 0, 0], &[1, 0, 0, 0, 1], &[1, 0, 0, 0, 0, 1], &[0, 1, 0, 0, 0, 0, 1]] {
        assert!(!ok(&n, bad, &digest, &sig), "e = {bad:?}");
    }
    assert!(!ok(&n, &[0xff, 0xff, 0xff, 0xff], &digest, &sig));
    // 2^32 + 65537 must not be read as 65537.
    assert!(!ok(&n, &[1, 0, 1, 0, 1], &digest, &sig));

    // The digest must be as long as the hash's output.
    assert!(!ok(&n, &e, &digest[..31], &sig));
    assert!(!ok(&n, &e, &[&digest[..], &[0]].concat(), &sig));
    assert!(!ok(&n, &e, &[], &sig));
    assert!(!verify(&n, &e, Alg::Sha1, &digest[..20], &sig));
    assert!(!verify(&n, &e, Alg::Sha384, &digest, &sig));
}

/// Random keys and signatures of awkward lengths: nothing may panic, nothing may verify.
fn garbage(verify: Verify) {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..200 {
        let n_len: usize = [0, 1, 255, 256, 257, 384, 1024, 1025][rand() as usize % 8];
        let mut n: Vec<u8> = (0..n_len).map(|_| rand() as u8).collect();
        if let Some(last) = n.last_mut() {
            *last |= (rand() & 1) as u8;
        }
        let e: Vec<u8> = (0..rand() % 6).map(|_| rand() as u8).collect();
        let sig_len = (n_len + 1).saturating_sub(rand() as usize % 3);
        let sig: Vec<u8> = (0..sig_len).map(|_| (rand() as u8) >> (rand() % 2)).collect();
        let a = [Alg::Sha1, Alg::Sha256, Alg::Sha384, Alg::Sha512][rand() as usize % 4];
        let digest: Vec<u8> = (0..a.len()).map(|_| rand() as u8).collect();
        assert!(!verify(&n, &e, a, &digest, &sig));
    }
}

const PKCS1_FILES: [&str; 5] = [
    "rsa_signature_2048_sha256_test",
    "rsa_signature_3072_sha256_test",
    "rsa_signature_3072_sha384_test",
    "rsa_signature_4096_sha384_test",
    "rsa_signature_4096_sha512_test",
];

const PSS_FILES: [&str; 4] = [
    "rsa_pss_2048_sha256_mgf1_32_test",
    "rsa_pss_3072_sha256_mgf1_32_test",
    "rsa_pss_4096_sha512_mgf1_64_test",
    "rsa_pss_misc_test",
];

#[test]
fn wycheproof_pkcs1() {
    for f in PKCS1_FILES {
        let (checked, skipped) = wycheproof(f, verify_pkcs1);
        assert_eq!((checked, skipped), (259, 0), "{f}");
    }
}

#[test]
fn wycheproof_pss() {
    let counts: Vec<_> = PSS_FILES.iter().map(|f| wycheproof(f, verify_pss)).collect();
    // rsa_pss_misc_test: only SHA-256/384/512 with the same MGF1 hash and sLen = hLen apply.
    assert_eq!(counts, [(108, 0), (108, 0), (179, 0), (3, 147)]);
}

#[test]
fn odd_keys_pkcs1() {
    assert_eq!(odd_keys(false, verify_pkcs1), 28);
}

#[test]
fn odd_keys_pss() {
    assert_eq!(odd_keys(true, verify_pss), 31);
}

#[test]
fn ring_pkcs1() {
    assert_eq!(differential(false, verify_pkcs1), 9);
}

#[test]
fn ring_pss() {
    assert_eq!(differential(true, verify_pss), 9);
}

#[test]
fn edge_cases_pkcs1() {
    edge_cases(false, verify_pkcs1);
}

#[test]
fn edge_cases_pss() {
    edge_cases(true, verify_pss);
}

#[test]
fn garbage_in() {
    garbage(verify_pkcs1);
    garbage(verify_pss);
}

/// A PKCS#1 signature is not a PSS signature and the reverse.
#[test]
fn wrong_scheme() {
    for v in json("rsa_odd_keys.json.gz").as_array().unwrap() {
        let s = |k: &str| hex(v[k].as_str().unwrap());
        let a = alg(v["hash"].as_str().unwrap()).unwrap();
        let other = if v["scheme"] == "pss" { verify_pkcs1 } else { verify_pss };
        assert!(!other(&s("n"), &s("e"), a, &ring_hash(a, &[&s("msg")]), &s("sig")));
    }
}

/// cargo test -p jpm-crypto --release -- --ignored --nocapture bench_rsa
#[test]
#[ignore]
fn bench_rsa() {
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::time::Instant;
    for name in KEYS {
        let (kp, n, e) = key(name);
        let mut sig = vec![0; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), b"bench", &mut sig).unwrap();
        let digest = ring_hash(Alg::Sha256, &[b"bench"]);
        let ring_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, kp.public().as_ref());
        let iters = 2000;
        let t = Instant::now();
        for _ in 0..iters {
            assert!(verify_pkcs1(&n, &e, Alg::Sha256, std::hint::black_box(&digest), &sig));
        }
        let ours = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
        let t = Instant::now();
        for _ in 0..iters {
            ring_key.verify(std::hint::black_box(b"bench"), &sig).unwrap();
        }
        let theirs = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
        println!("{} bits: jpm-crypto {ours:.1} us/op, ring {theirs:.1} us/op (ring includes SHA-256)", n.len() * 8);
    }
}
