mod common;

use common::{cases, hex, random, rounds, time, wycheproof};
use jpm_crypto::p256::{public_key, shared_secret};
use ring::agreement::{self, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::SystemRandom;

const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const G: &str = concat!(
    "04",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
);

fn h32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

/// A 256-bit big-endian number plus a small delta.
fn plus(s: &str, delta: i64) -> [u8; 32] {
    let mut b = h32(s);
    let mut carry = delta as i128;
    for x in b.iter_mut().rev() {
        let v = *x as i128 + carry;
        *x = v.rem_euclid(256) as u8;
        carry = v.div_euclid(256);
    }
    b
}

fn scalar(n: u64) -> [u8; 32] {
    let mut k = [0; 32];
    k[24..].copy_from_slice(&n.to_be_bytes());
    k
}

/// Valid cases must give exactly the expected secret; invalid ones must fail. The only
/// "acceptable" cases are compressed points, which this API does not take: they must fail too,
/// and are counted so a change in the file shows up here.
#[test]
fn wycheproof_ecdh_ecpoint() {
    let v = wycheproof("ecdh_secp256r1_ecpoint_test");
    let (mut n, mut compressed) = (0, 0);
    for (_, t) in cases(&v) {
        let id = &t["tcId"];
        let public = hex(t["public"].as_str().unwrap());
        let mut private = hex(t["private"].as_str().unwrap());
        while private.len() > 32 && private[0] == 0 {
            private.remove(0);
        }
        let mut secret = [0; 32];
        secret[32 - private.len()..].copy_from_slice(&private);
        let got = shared_secret(&secret, &public);
        match t["result"].as_str().unwrap() {
            "valid" => assert_eq!(got.map(|k| k.to_vec()), Some(hex(t["shared"].as_str().unwrap())), "tcId {id}"),
            "invalid" => assert_eq!(got, None, "tcId {id}"),
            "acceptable" => {
                assert!(matches!(public.first(), Some(2 | 3)), "tcId {id}");
                assert_eq!(got, None, "tcId {id}");
            }
            r => panic!("tcId {id}: result {r}"),
        }
        if matches!(public.first(), Some(2 | 3)) {
            compressed += 1;
        }
        n += 1;
    }
    assert_eq!((n, compressed), (355, 8));
}

#[test]
fn small_scalars() {
    assert_eq!(public_key(&scalar(1)).unwrap().to_vec(), hex(G));
    let two = concat!(
        "04",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
    );
    assert_eq!(public_key(&scalar(2)).unwrap().to_vec(), hex(two));
    // (n - 1)G = -G = (Gx, p - Gy).
    let minus_g = concat!(
        "04",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"
    );
    assert_eq!(public_key(&plus(N, -1)).unwrap().to_vec(), hex(minus_g));
    // The shared secret with the generator is the x of the public key.
    for k in [scalar(1), scalar(2), plus(N, -1), random::<32>()] {
        let Some(public) = public_key(&k) else { continue };
        assert_eq!(shared_secret(&k, &hex(G)).unwrap(), public[1..33]);
    }
}

#[test]
fn bad_scalars() {
    let g = hex(G);
    for k in [[0; 32], h32(N), plus(N, 1), plus(N, 2), [0xff; 32], plus(P, 0)] {
        assert_eq!(public_key(&k), None);
        assert_eq!(shared_secret(&k, &g), None);
    }
}

#[test]
fn bad_points() {
    let k = scalar(7);
    let g = hex(G);
    let mut bad: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![4],
        vec![0; 65],
        [&[4][..], &[0; 64]].concat(),
        g[..64].to_vec(),
        [&g[..], &[0]].concat(),
        g[..33].to_vec(),
    ];
    // Other prefixes: compressed (2, 3), hybrid (6, 7), junk.
    for prefix in [0, 1, 2, 3, 5, 6, 7, 0x84] {
        let mut p = g.clone();
        p[0] = prefix;
        bad.push(p);
    }
    // (0, y0) is on the curve. (p, y0) is the same point mod p, but x = p is not a field
    // element: only the range check refuses it.
    let y0 = h32("66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4");
    assert!(shared_secret(&k, &[&[4][..], &[0; 32], &y0].concat()).is_some());
    bad.push([&[4][..], &h32(P), &y0].concat());
    // Other coordinates at or above p.
    for (x, y) in
        [(h32(P), h32(&G[66..])), (h32(&G[2..66]), h32(P)), (plus(P, 1), h32(&G[66..])), ([0xff; 32], [0xff; 32])]
    {
        bad.push([&[4][..], &x, &y].concat());
    }
    // Points off the curve: every single-bit flip of the generator's coordinates.
    for i in 8..g.len() * 8 {
        let mut p = g.clone();
        p[i / 8] ^= 1 << (i % 8);
        bad.push(p);
    }
    for p in &bad {
        assert_eq!(shared_secret(&k, p), None, "{p:02x?}");
    }
}

/// Ring draws one key, we draw the other; the secrets must agree, and both our functions are
/// checked against ring's.
#[test]
fn differential_ring() {
    let rng = SystemRandom::new();
    for _ in 0..rounds(3000) {
        let theirs = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let their_public = theirs.compute_public_key().unwrap();
        let ours = random::<32>();
        let our_public = public_key(&ours).unwrap();
        let want = agreement::agree_ephemeral(theirs, &UnparsedPublicKey::new(&ECDH_P256, our_public), |k| k.to_vec())
            .unwrap();
        assert_eq!(shared_secret(&ours, their_public.as_ref()).unwrap().as_slice(), want);
    }
}

#[test]
fn symmetric() {
    for _ in 0..rounds(500) {
        let (a, b) = (random::<32>(), random::<32>());
        let (pa, pb) = (public_key(&a).unwrap(), public_key(&b).unwrap());
        assert_eq!(shared_secret(&a, &pb), shared_secret(&b, &pa));
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_p256_ecdh() {
    let rng = SystemRandom::new();
    let (secret, peer) = (random::<32>(), public_key(&random::<32>()).unwrap());
    let ours = time(3000, || {
        std::hint::black_box(shared_secret(std::hint::black_box(&secret), &peer));
    });
    let ours_pub = time(3000, || {
        std::hint::black_box(public_key(std::hint::black_box(&secret)));
    });
    let ring_gen = time(3000, || {
        std::hint::black_box(EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap());
    });
    let ring_pub = time(3000, || {
        let k = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        std::hint::black_box(k.compute_public_key().unwrap());
    });
    let ring = time(3000, || {
        let k = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        agreement::agree_ephemeral(k, &UnparsedPublicKey::new(&ECDH_P256, &peer), |k| k[0]).unwrap();
    });
    println!(
        "p256 shared_secret: ours {ours:.1} µs, ring {:.1} µs; public_key: ours {ours_pub:.1} µs, ring {:.1} µs",
        ring - ring_gen,
        ring_pub - ring_gen
    );
}
