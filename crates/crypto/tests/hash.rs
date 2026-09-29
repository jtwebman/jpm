//! SHA-1/2, HMAC, HKDF and the TLS 1.2 PRF: published vectors, and ring as a reference for
//! everything else.

use jpm_crypto::hash::{Alg, Hasher, digest, hkdf_expand, hkdf_extract, hmac, tls12_prf};
use std::time::Instant;

const ALGS: [Alg; 4] = [Alg::Sha1, Alg::Sha256, Alg::Sha384, Alg::Sha512];

fn unhex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}

/// Deterministic test data (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Fewer than `n` bytes.
    fn upto(&mut self, n: usize) -> Vec<u8> {
        let len = self.below(n);
        self.bytes(len)
    }
}

fn ring_digest_alg(alg: Alg) -> &'static ring::digest::Algorithm {
    match alg {
        Alg::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        Alg::Sha256 => &ring::digest::SHA256,
        Alg::Sha384 => &ring::digest::SHA384,
        Alg::Sha512 => &ring::digest::SHA512,
    }
}

fn ring_hmac(alg: Alg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let a = match alg {
        Alg::Sha1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        Alg::Sha256 => ring::hmac::HMAC_SHA256,
        Alg::Sha384 => ring::hmac::HMAC_SHA384,
        Alg::Sha512 => ring::hmac::HMAC_SHA512,
    };
    ring::hmac::sign(&ring::hmac::Key::new(a, key), msg).as_ref().to_vec()
}

fn ring_hkdf_alg(alg: Alg) -> ring::hkdf::Algorithm {
    match alg {
        Alg::Sha1 => ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
        Alg::Sha256 => ring::hkdf::HKDF_SHA256,
        Alg::Sha384 => ring::hkdf::HKDF_SHA384,
        Alg::Sha512 => ring::hkdf::HKDF_SHA512,
    }
}

struct Len(usize);

impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

// FIPS 180-4 examples (NIST CSRC "Examples with Intermediate Values").

const M448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const M896: &[u8] =
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

#[test]
fn fips_180_4_examples() {
    let cases: &[(Alg, &[u8], &str)] = &[
        (Alg::Sha1, b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (Alg::Sha1, b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (Alg::Sha1, M448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
        (Alg::Sha256, b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (Alg::Sha256, b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (Alg::Sha256, M448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (
            Alg::Sha384,
            b"",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            Alg::Sha384,
            b"abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            Alg::Sha384,
            M896,
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        ),
        (
            Alg::Sha512,
            b"",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            Alg::Sha512,
            b"abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            Alg::Sha512,
            M896,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ];
    for &(alg, msg, want) in cases {
        let d = digest(alg, msg);
        assert_eq!(d.len(), alg.len());
        assert_eq!(&d[..], unhex(want), "{alg:?} {msg:?}");
    }
}

#[test]
fn one_million_a() {
    let cases = [
        (Alg::Sha1, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
        (Alg::Sha256, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        (
            Alg::Sha384,
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        ),
        (
            Alg::Sha512,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        ),
    ];
    let a = vec![b'a'; 1_000_000];
    for (alg, want) in cases {
        assert_eq!(&digest(alg, &a)[..], unhex(want), "{alg:?}");
        // One byte at a time, as a transcript might arrive.
        let mut h = Hasher::new(alg);
        for _ in 0..1_000_000 {
            h.update(b"a");
        }
        assert_eq!(&h.finish()[..], unhex(want), "{alg:?} bytewise");
    }
}

#[test]
fn every_length_to_300_matches_ring() {
    let data = Rng(1).bytes(1100);
    for alg in ALGS {
        for n in (0..=300).chain(301..=1100) {
            let want = ring::digest::digest(ring_digest_alg(alg), &data[..n]);
            assert_eq!(&digest(alg, &data[..n])[..], want.as_ref(), "{alg:?} {n}");
        }
    }
}

#[test]
fn split_updates_match_one_shot() {
    let mut rng = Rng(2);
    for alg in ALGS {
        for _ in 0..500 {
            let data = rng.upto(2000);
            let want = digest(alg, &data);
            let mut h = Hasher::new(alg);
            assert_eq!(h.alg(), alg);
            let mut rest = &data[..];
            while !rest.is_empty() {
                let n = rng.below(rest.len().min(300) + 1);
                h.update(&rest[..n]);
                rest = &rest[n..];
            }
            assert_eq!(&h.finish()[..], &want[..], "{alg:?} {}", data.len());
        }
    }
}

#[test]
fn clone_takes_a_prefix_digest() {
    let data = Rng(3).bytes(1000);
    for alg in ALGS {
        let mut h = Hasher::new(alg);
        for (i, chunk) in data.chunks(77).enumerate() {
            h.update(chunk);
            let end = ((i + 1) * 77).min(data.len());
            assert_eq!(&h.clone().finish()[..], &digest(alg, &data[..end])[..], "{alg:?} {end}");
        }
        assert_eq!(&h.finish()[..], &digest(alg, &data)[..]);
    }
}

// HMAC: RFC 4231 for SHA-2, RFC 2202 for SHA-1.

#[test]
fn hmac_rfc4231() {
    let aa131 = "aa".repeat(131);
    // (key, data, SHA-256, SHA-384, SHA-512); test case 5 is truncated to 128 bits.
    let cases: [(&str, &[u8], &str, &str, &str); 7] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            "4a656665",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
        (
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            &[0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
        (
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            b"Test With Truncation",
            "a3b6167473100ee06e0c796c2955552b",
            "3abf34c3503b2a23a46efc619baef897",
            "415fad6271580a531d4179bc891d87a6",
        ),
        (
            &aa131,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
        (
            &aa131,
            b"This is a test using a larger than block-size key and a larger than block-size data. \
              The key needs to be hashed before being used by the HMAC algorithm.",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ];
    for (i, (key, data, s256, s384, s512)) in cases.into_iter().enumerate() {
        let key = unhex(key);
        for (alg, want) in [(Alg::Sha256, s256), (Alg::Sha384, s384), (Alg::Sha512, s512)] {
            let want = unhex(want);
            let mac = hmac(alg, &key, &[data]);
            assert_eq!(mac.len(), alg.len());
            assert_eq!(&mac[..want.len()], want, "test case {} {alg:?}", i + 1);
        }
    }
}

#[test]
fn hmac_rfc2202_sha1() {
    let cases: [(&str, &[u8], &str); 7] = [
        ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00"),
        ("4a656665", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &[0xdd; 50], "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        ("0102030405060708090a0b0c0d0e0f10111213141516171819", &[0xcd; 50], "4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
        (
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            b"Test With Truncation",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        ),
        (
            &"aa".repeat(80),
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
        (
            &"aa".repeat(80),
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        ),
    ];
    for (i, (key, data, want)) in cases.into_iter().enumerate() {
        assert_eq!(&hmac(Alg::Sha1, &unhex(key), &[data])[..], unhex(want), "test case {}", i + 1);
    }
}

#[test]
fn hmac_matches_ring() {
    let mut rng = Rng(4);
    for alg in ALGS {
        // Every key length through two blocks, so keys at, under and over the block length.
        for klen in 0..=260 {
            let key = rng.bytes(klen);
            let msg = rng.upto(400);
            let want = ring_hmac(alg, &key, &msg);
            assert_eq!(&hmac(alg, &key, &[&msg])[..], want, "{alg:?} key {klen}");
            // The same message in parts.
            let (a, b) = msg.split_at(rng.below(msg.len() + 1));
            let (b, c) = b.split_at(rng.below(b.len() + 1));
            assert_eq!(&hmac(alg, &key, &[a, b, &[], c])[..], want, "{alg:?} key {klen} parts");
        }
        assert_eq!(&hmac(alg, b"k", &[])[..], ring_hmac(alg, b"k", b""));
    }
}

// HKDF: RFC 5869 appendix A, test cases 1 to 3.

#[test]
fn hkdf_rfc5869() {
    let cases = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];
    for (i, (ikm, salt, info, prk, okm)) in cases.into_iter().enumerate() {
        let got_prk = hkdf_extract(Alg::Sha256, &unhex(salt), &unhex(ikm));
        assert_eq!(&got_prk[..], unhex(prk), "test case {}", i + 1);
        let want = unhex(okm);
        let mut out = vec![0; want.len()];
        hkdf_expand(Alg::Sha256, &got_prk, &[&unhex(info)], &mut out);
        assert_eq!(out, want, "test case {}", i + 1);
        // The same info in parts.
        let info = unhex(info);
        let (a, b) = info.split_at(info.len() / 3);
        let mut out2 = vec![0; want.len()];
        hkdf_expand(Alg::Sha256, &got_prk, &[a, &[], b], &mut out2);
        assert_eq!(out2, want, "test case {} parts", i + 1);
    }
}

#[test]
fn hkdf_matches_ring() {
    let mut rng = Rng(5);
    for alg in ALGS {
        let max = 255 * alg.len();
        let random: Vec<usize> = (0..20).map(|_| rng.below(max + 1)).collect();
        for n in (0..=3 * alg.len() + 1).chain([max - 1, max]).chain(random) {
            let salt = rng.upto(200);
            let ikm = rng.upto(200);
            let info = rng.upto(200);
            let prk = hkdf_extract(alg, &salt, &ikm);
            let mut got = vec![0; n];
            hkdf_expand(alg, &prk, &[&info], &mut got);

            let ring_prk = ring::hkdf::Salt::new(ring_hkdf_alg(alg), &salt).extract(&ikm);
            let mut want = vec![0; n];
            ring_prk.expand(&[&info], Len(n)).unwrap().fill(&mut want).unwrap();
            assert_eq!(got, want, "{alg:?} {n}");

            // Expand alone, from an arbitrary PRK.
            let prk = rng.upto(150);
            hkdf_expand(alg, &prk, &[&info], &mut got);
            let ring_prk = ring::hkdf::Prk::new_less_safe(ring_hkdf_alg(alg), &prk);
            ring_prk.expand(&[&info], Len(n)).unwrap().fill(&mut want).unwrap();
            assert_eq!(got, want, "{alg:?} {n} expand");
        }
    }
}

#[test]
#[should_panic(expected = "255 digests")]
fn hkdf_expand_rejects_too_long() {
    let mut out = vec![0; 255 * 32 + 1];
    hkdf_expand(Alg::Sha256, &[0; 32], &[], &mut out);
}

// The TLS 1.2 PRF.

/// P_hash from RFC 5246 section 5, written out the long way.
fn reference_prf(alg: Alg, secret: &[u8], label: &[u8], seed: &[u8], n: usize) -> Vec<u8> {
    let s = [label, seed].concat();
    let mut a = s.clone();
    let mut out = Vec::new();
    while out.len() < n {
        a = hmac(alg, secret, &[&a]).to_vec();
        out.extend_from_slice(&hmac(alg, secret, &[&a, &s]));
    }
    out.truncate(n);
    out
}

/// The vectors posted to the IETF TLS list for the TLS 1.2 PRF, and checked against Python's
/// hmac module.
#[test]
fn tls12_prf_vectors() {
    let cases = [
        (
            Alg::Sha256,
            "9bbe436ba940f017b17652849a71db35",
            "a0ba9f936cda311827a6f796ffd5198c",
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
             6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab\
             4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701\
             87347b66",
        ),
        (
            Alg::Sha384,
            "b80b733d6ceefcdc71566ea48e5567df",
            "cd665cf6a8447dd6ff8b27555edb7465",
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd\
             e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd\
             8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425\
             9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6\
             91c8f3a26854308d5eaa3be85e0990703d73e56f",
        ),
    ];
    for (alg, secret, seed, want) in cases {
        let want = unhex(want);
        let seed = unhex(seed);
        let mut out = vec![0; want.len()];
        tls12_prf(alg, &unhex(secret), b"test label", &[&seed], &mut out);
        assert_eq!(out, want, "{alg:?}");
        let (a, b) = seed.split_at(5);
        tls12_prf(alg, &unhex(secret), b"test label", &[a, b], &mut out);
        assert_eq!(out, want, "{alg:?} parts");
    }
}

#[test]
fn tls12_prf_matches_reference() {
    let mut rng = Rng(6);
    for alg in [Alg::Sha256, Alg::Sha384] {
        for n in (0..=200).chain([1000, 4096]) {
            let secret = rng.upto(200);
            let label = rng.upto(30);
            let seed = rng.upto(100);
            let mut out = vec![0; n];
            let (a, b) = seed.split_at(rng.below(seed.len() + 1));
            tls12_prf(alg, &secret, &label, &[a, b], &mut out);
            assert_eq!(out, reference_prf(alg, &secret, &label, &seed, n), "{alg:?} {n}");
        }
    }
}

/// Throughput against ring on 64 MiB. Run with
/// `cargo test -p jpm-crypto --release -- --ignored --nocapture bench_hash`.
#[test]
#[ignore]
fn bench_hash() {
    let data = Rng(7).bytes(64 << 20);
    let mb = data.len() as f64 / 1e6;
    for alg in ALGS {
        let best = |f: &dyn Fn() -> Vec<u8>| {
            let mut best = f64::MAX;
            let mut out = Vec::new();
            for _ in 0..5 {
                let t = Instant::now();
                out = f();
                best = best.min(t.elapsed().as_secs_f64());
            }
            (mb / best, out)
        };
        let (ours, a) = best(&|| digest(alg, &data).to_vec());
        let (ring, b) = best(&|| ring::digest::digest(ring_digest_alg(alg), &data).as_ref().to_vec());
        assert_eq!(a, b);
        println!("{alg:?}: jpm-crypto {ours:.0} MB/s, ring {ring:.0} MB/s, ratio {:.2}", ring / ours);
    }
}
