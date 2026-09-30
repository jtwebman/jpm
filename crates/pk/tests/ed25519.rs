mod common;

use common::{cases, hex, random, random_vec, rounds, time, wycheproof};
use jpm_pk::ed25519::verify;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// RFC 8032 section 7.1: TEST 1, 2, 3 and SHA(abc), as (public key, message, signature).
#[test]
fn rfc8032_vectors() {
    let vectors = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];
    for (public, msg, sig) in vectors {
        let (public, msg, sig) = (hex(public), hex(msg), hex(sig));
        assert!(verify(&public, &msg, &sig), "{msg:02x?}");
        // Any one bit flipped anywhere fails.
        for i in 0..(public.len() + msg.len() + sig.len()) * 8 {
            let (mut p, mut m, mut s) = (public.clone(), msg.clone(), sig.clone());
            let (buf, at) = match i / 8 {
                b if b < 32 => (&mut p, b),
                b if b < 32 + m.len() => (&mut m, b - 32),
                b => (&mut s, b - 32 - msg.len()),
            };
            buf[at] ^= 1 << (i % 8);
            assert!(!verify(&p, &m, &s), "bit {i}");
        }
    }
}

/// Every case as Wycheproof says: non-canonical points, s at or above the order, small-order
/// keys and the rest.
#[test]
fn wycheproof_ed25519() {
    let v = wycheproof("ed25519_test");
    let mut n = 0;
    for (g, t) in cases(&v) {
        let public = hex(g["publicKey"]["pk"].as_str().unwrap());
        let want = match t["result"].as_str().unwrap() {
            "valid" => true,
            "invalid" => false,
            r => panic!("tcId {}: result {r}", t["tcId"]),
        };
        let (msg, sig) = (hex(t["msg"].as_str().unwrap()), hex(t["sig"].as_str().unwrap()));
        assert_eq!(verify(&public, &msg, &sig), want, "tcId {} {}", t["tcId"], t["comment"]);
        n += 1;
    }
    assert_eq!(n, 151);
}

/// Ring signs, we check; then a byte changed anywhere, and both must say no.
#[test]
fn differential_ring() {
    for i in 0..rounds(2000) {
        let key = Ed25519KeyPair::from_seed_unchecked(&random::<32>()).unwrap();
        let public = key.public_key().as_ref().to_vec();
        let msg = random_vec(i % 300);
        let mut sig = key.sign(&msg).as_ref().to_vec();
        assert!(verify(&public, &msg, &sig));
        let at = random::<1>()[0] as usize % 64;
        sig[at] ^= 1 << (i % 8);
        let ring = UnparsedPublicKey::new(&ED25519, &public).verify(&msg, &sig).is_ok();
        assert_eq!(verify(&public, &msg, &sig), ring);
        assert!(!ring);
    }
}

/// Random bytes: never a panic, and the same answer as ring (which is always no).
#[test]
fn garbage_is_refused() {
    for i in 0..rounds(5000) {
        let (public, msg, sig) = (random_vec(32), random_vec(i % 64), random_vec(64));
        assert!(!verify(&public, &msg, &sig));
    }
    for len in [0, 31, 33, 63, 65] {
        assert!(!verify(&random_vec(len.min(40)), b"m", &random_vec(len)));
    }
}

#[test]
#[ignore = "benchmark"]
fn bench_ed25519() {
    let key = Ed25519KeyPair::from_seed_unchecked(&random::<32>()).unwrap();
    let public = key.public_key().as_ref().to_vec();
    let sig = key.sign(b"message").as_ref().to_vec();
    let ours = time(2000, || assert!(verify(&public, b"message", &sig)));
    let ring = time(2000, || UnparsedPublicKey::new(&ED25519, &public).verify(b"message", &sig).unwrap());
    println!("ed25519 verify: ours {ours:.1} µs, ring {ring:.1} µs");
}

/// Where RFC 8032's strict reading and ZIP-215 part, this is strict: `s` at or past the order
/// and a key or R not canonically encoded are refused, as ring refuses them, and the key -0 as
/// RFC 8032 section 5.1.3 says (ring reads it as 0). A small-order key is not refused: with the
/// identity as key, R the identity and s = 0 check for any message, in ring too. That forges
/// nothing here, where every key checked is pinned by its fingerprint.
#[test]
fn edge_encodings() {
    let (public, sig) = (
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
    );
    assert!(verify(&public, b"", &sig));
    let l = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    // s + L: the same signature, malleated.
    let mut plus_l = sig.clone();
    let mut carry = 0u16;
    for i in 0..32 {
        let v = plus_l[32 + i] as u16 + l[i] as u16 + carry;
        plus_l[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    assert!(!verify(&public, b"", &plus_l), "s + L");
    let mut s_is_l = sig.clone();
    s_is_l[32..].copy_from_slice(&l);
    assert!(!verify(&public, b"", &s_is_l), "s = L");
    let identity = hex("0100000000000000000000000000000000000000000000000000000000000000");
    // The identity with y = p + 1, and with its sign bit set (-0).
    let y_past_p = hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let minus_zero = hex("0100000000000000000000000000000000000000000000000000000000000080");
    let zero = [0u8; 32];
    let trivial = [identity.as_slice(), &zero].concat();
    // (key, signature, our answer, ring's).
    for (key, sig, want, ring_says, what) in [
        (&identity, trivial.clone(), true, true, "identity key, R and s = 0"),
        (&y_past_p, [y_past_p.as_slice(), &zero].concat(), false, false, "a key with y past p"),
        (&identity, [y_past_p.as_slice(), &zero].concat(), false, false, "an R with y past p"),
        (&minus_zero, trivial.clone(), false, true, "the key -0"),
    ] {
        assert_eq!(verify(key, b"any message", &sig), want, "{what}");
        let ring = UnparsedPublicKey::new(&ED25519, key).verify(b"any message", &sig).is_ok();
        assert_eq!(ring, ring_says, "ring: {what}");
    }
}
