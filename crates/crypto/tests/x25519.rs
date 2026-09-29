mod common;

use common::{cases, hex, random, rounds, time, wycheproof};
use jpm_crypto::x25519::{public_key, shared_secret};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

fn h32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

#[test]
fn rfc7748_vectors() {
    // Section 5.2.
    let vectors = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (k, u, out) in vectors {
        assert_eq!(shared_secret(&h32(k), &h32(u)), Some(h32(out)));
    }
}

/// Section 5.2's iterated test: k = u = 9, then k, u = X25519(k, u), k.
fn iterate(n: usize) -> [u8; 32] {
    let (mut k, mut u) = ([0; 32], [0; 32]);
    k[0] = 9;
    u[0] = 9;
    for _ in 0..n {
        let r = shared_secret(&k, &u).unwrap();
        u = k;
        k = r;
    }
    k
}

#[test]
fn rfc7748_iterated() {
    assert_eq!(iterate(1), h32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
    assert_eq!(iterate(1000), h32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
}

#[test]
#[ignore = "slow: a million scalar multiplications"]
fn rfc7748_iterated_million() {
    assert_eq!(iterate(1_000_000), h32("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"));
}

#[test]
fn rfc7748_diffie_hellman() {
    // Section 6.1.
    let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let ka = public_key(&a);
    let kb = public_key(&b);
    assert_eq!(ka, h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    assert_eq!(kb, h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    let k = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(shared_secret(&a, &kb), Some(k));
    assert_eq!(shared_secret(&b, &ka), Some(k));
}

/// Every case must match exactly. "acceptable" cases (twist points, non-canonical u, low-order
/// points) are all computed as RFC 7748 says; the only difference allowed is that an all-zero
/// result is `None`.
#[test]
fn wycheproof_x25519() {
    let v = wycheproof("x25519_test");
    let mut n = 0;
    for (_, t) in cases(&v) {
        let id = &t["tcId"];
        let secret = h32(t["private"].as_str().unwrap());
        let public = h32(t["public"].as_str().unwrap());
        let shared = h32(t["shared"].as_str().unwrap());
        let want = if shared == [0; 32] { None } else { Some(shared) };
        assert_eq!(shared_secret(&secret, &public), want, "tcId {id}");
        n += 1;
    }
    assert_eq!(n, 518);
}

#[test]
fn zero_results() {
    let secret = random::<32>();
    // u = 0 and u = 1 have small order; so does p + 1 = 1 (non-canonical, top bit masked).
    assert_eq!(shared_secret(&secret, &[0; 32]), None);
    let mut one = [0; 32];
    one[0] = 1;
    assert_eq!(shared_secret(&secret, &one), None);
    let mut p1 = h32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    assert_eq!(shared_secret(&secret, &p1), None);
    p1[31] |= 0x80;
    assert_eq!(shared_secret(&secret, &p1), None);
}

/// Ring picks one side's key, we pick the other; both must arrive at the same secret.
#[test]
fn differential_ring() {
    let rng = SystemRandom::new();
    for _ in 0..rounds(3000) {
        let theirs = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let their_public = theirs.compute_public_key().unwrap();
        let ours = random::<32>();
        let our_public = public_key(&ours);
        let want =
            agreement::agree_ephemeral(theirs, &UnparsedPublicKey::new(&X25519, our_public), |k| k.to_vec()).unwrap();
        let got = shared_secret(&ours, their_public.as_ref().try_into().unwrap()).unwrap();
        assert_eq!(got.as_slice(), want);
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_x25519() {
    let rng = SystemRandom::new();
    let (secret, peer) = (random::<32>(), public_key(&random::<32>()));
    let ours = time(5000, || {
        std::hint::black_box(shared_secret(std::hint::black_box(&secret), &peer));
    });
    let ring_gen = time(5000, || {
        std::hint::black_box(EphemeralPrivateKey::generate(&X25519, &rng).unwrap());
    });
    let ring = time(5000, || {
        let k = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        agreement::agree_ephemeral(k, &UnparsedPublicKey::new(&X25519, &peer), |k| k[0]).unwrap();
    });
    println!("x25519 shared_secret: ours {ours:.1} µs, ring {:.1} µs (generate + agree {ring:.1})", ring - ring_gen);
}
