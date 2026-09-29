//! Known answers (FIPS-197, the GCM spec, RFC 8439, Wycheproof), differential tests against ring,
//! and the benchmarks. Every test runs each code path the CPU has: portable and hardware AES,
//! and scalar, SSE2/NEON and AVX2 ChaCha20.

use super::*;
use ring::aead as rg;

#[path = "../../tests/common/wycheproof.rs"]
mod wycheproof;

const ALGS: [Alg; 3] = [Alg::Aes128Gcm, Alg::Aes256Gcm, Alg::ChaCha20Poly1305];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The ChaCha20 code paths this CPU runs.
fn chacha_imps() -> Vec<chacha::Imp> {
    #[allow(unused_mut)]
    let mut v = vec![chacha::Imp::Scalar];
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    v.push(chacha::Imp::Simd);
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        v.push(chacha::Imp::Avx2);
    }
    v
}

/// The key on each code path.
fn keys(alg: Alg, key: &[u8]) -> Vec<Key> {
    if alg == Alg::ChaCha20Poly1305 {
        return chacha_imps().into_iter().map(|i| Key(Inner::ChaCha(chacha::Key::new(key, i)))).collect();
    }
    let mut v = vec![Key::with(alg, key, false).unwrap()];
    assert!(matches!(v[0].0, Inner::Soft(_)));
    if aes_hardware() {
        let k = Key::with(alg, key, true).unwrap();
        assert!(!matches!(k.0, Inner::Soft(_)));
        // With VAES, also the 128-bit AES-NI code.
        #[cfg(target_arch = "x86_64")]
        if let Inner::Hw(g) = &k.0
            && g.vaes
        {
            let mut k = Key::with(alg, key, true).unwrap();
            if let Inner::Hw(g) = &mut k.0 {
                g.vaes = false;
            }
            v.push(k);
        }
        v.push(k);
    }
    v
}

fn path(k: &Key) -> String {
    match &k.0 {
        Inner::Soft(_) => "portable".into(),
        Inner::ChaCha(c) => format!("{:?}", c.imp()),
        #[cfg(target_arch = "x86_64")]
        Inner::Hw(g) => if g.vaes { "vaes" } else { "aes-ni" }.into(),
        #[cfg(target_arch = "aarch64")]
        Inner::Hw(_) => "hardware".into(),
    }
}

/// splitmix64: reproducible test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    fn nonce(&mut self) -> [u8; 12] {
        self.bytes(12).try_into().unwrap()
    }
}

fn ring_seal(alg: Alg, key: &[u8], nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
    let a = match alg {
        Alg::Aes128Gcm => &rg::AES_128_GCM,
        Alg::Aes256Gcm => &rg::AES_256_GCM,
        Alg::ChaCha20Poly1305 => &rg::CHACHA20_POLY1305,
    };
    let k = rg::LessSafeKey::new(rg::UnboundKey::new(a, key).unwrap());
    let n = rg::Nonce::assume_unique_for_key(*nonce);
    k.seal_in_place_separate_tag(n, rg::Aad::from(aad), data).unwrap().as_ref().try_into().unwrap()
}

#[test]
fn aes_fips197() {
    // Appendix C.1 and C.3. The block to encrypt goes in as nonce and counter over zeros.
    let pt = hex("00112233445566778899aabbccddeeff");
    let nonce: [u8; 12] = pt[..12].try_into().unwrap();
    let ctr = u32::from_be_bytes(pt[12..].try_into().unwrap());
    for (alg, ct) in
        [(Alg::Aes128Gcm, "69c4e0d86a7b0430d8cdb78070b4c55a"), (Alg::Aes256Gcm, "8ea2b7ca516745bfeafc49904b496089")]
    {
        let key: Vec<u8> = (0..alg.key_len() as u8).collect();
        for k in keys(alg, &key) {
            let mut b = [0; 16];
            match &k.0 {
                Inner::Soft(g) => g.ctr(&nonce, ctr, &mut b),
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                Inner::Hw(g) => g.ctr(&nonce, ctr, &mut b),
                Inner::ChaCha(_) => unreachable!(),
            }
            assert_eq!(b.to_vec(), hex(ct), "{alg:?} {}", path(&k));
        }
    }
}

#[test]
fn gcm_spec() {
    // McGrew and Viega, "The Galois/Counter Mode of Operation", test cases 1-4 and 13-16.
    let k1 = "feffe9928665731c6d6a8f9467308308";
    let iv = "cafebabefacedbaddecaf888";
    let p = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    let a = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    let c3 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
              21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
    let c15 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
               8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
    let k15 = format!("{k1}{k1}");
    let zero16 = "00000000000000000000000000000000";
    let zero32 = format!("{zero16}{zero16}");
    let cases: [(Alg, &str, &str, &str, &str, &str, &str); 8] = [
        (Alg::Aes128Gcm, zero16, "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
        (
            Alg::Aes128Gcm,
            zero16,
            "000000000000000000000000",
            "",
            zero16,
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        (Alg::Aes128Gcm, k1, iv, "", p, c3, "4d5c2af327cd64a62cf35abd2ba6fab4"),
        (Alg::Aes128Gcm, k1, iv, a, &p[..120], &c3[..120], "5bc94fbc3221a5db94fae95ae7121a47"),
        (Alg::Aes256Gcm, &zero32, "000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
        (
            Alg::Aes256Gcm,
            &zero32,
            "000000000000000000000000",
            "",
            zero16,
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
        (Alg::Aes256Gcm, &k15, iv, "", p, c15, "b094dac5d93471bdec1a502270e3cc6c"),
        (Alg::Aes256Gcm, &k15, iv, a, &p[..120], &c15[..120], "76fc6ece0f4e1768cddf8853bb2d551b"),
    ];
    for (i, (alg, key, iv, aad, pt, ct, tag)) in cases.into_iter().enumerate() {
        let (iv, aad, tag): ([u8; 12], _, [u8; 16]) =
            (hex(iv).try_into().unwrap(), hex(aad), hex(tag).try_into().unwrap());
        for k in keys(alg, &hex(key)) {
            let mut data = hex(pt);
            assert_eq!(k.seal(&iv, &aad, &mut data), tag, "case {i} {}", path(&k));
            assert_eq!(data, hex(ct), "case {i} {}", path(&k));
            assert!(k.open(&iv, &aad, &mut data, &tag), "case {i} {}", path(&k));
            assert_eq!(data, hex(pt), "case {i} {}", path(&k));
        }
    }
}

#[test]
fn chacha20_rfc8439() {
    // Sections 2.3.2 and A.1: keystream blocks.
    for imp in chacha_imps() {
        let run = |key: &str, nonce: &str, ctr: u32, data: &mut [u8]| {
            chacha::Key::new(&hex(key), imp).apply(&hex(nonce).try_into().unwrap(), ctr, data)
        };
        for (key, nonce, ctr, ks) in CHACHA_BLOCKS {
            let mut b = [0; 64];
            run(key, nonce, *ctr, &mut b);
            assert_eq!(b.to_vec(), hex(ks), "{imp:?}");
        }
        // Sections 2.4.2 and A.2: encryption.
        for (key, nonce, ctr, pt, ct) in CHACHA_ENCRYPT {
            let mut b = hex(pt);
            run(key, nonce, *ctr, &mut b);
            assert_eq!(b, hex(ct), "{imp:?}");
        }
        // Section A.4: the Poly1305 key is the first 32 bytes of block 0.
        for (key, nonce, otk) in POLY1305_KEYGEN {
            let mut b = [0; 32];
            run(key, nonce, 0, &mut b);
            assert_eq!(b.to_vec(), hex(otk), "{imp:?}");
        }
    }
}

/// Poly1305 on its own: a final partial block gets a 1 byte and no 2^128 bit.
fn poly1305(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut p = chacha::Poly1305::new(key.try_into().unwrap());
    let (blocks, rest) = msg.as_chunks::<16>();
    for b in blocks {
        p.block(b, chacha::HIBIT);
    }
    if !rest.is_empty() {
        let mut b = [0; 16];
        b[..rest.len()].copy_from_slice(rest);
        b[rest.len()] = 1;
        p.block(&b, 0);
    }
    p.finish()
}

#[test]
fn poly1305_rfc8439() {
    // Sections 2.5.2 and A.3.
    for (i, (key, msg, tag)) in POLY1305.iter().enumerate() {
        assert_eq!(poly1305(&hex(key), &hex(msg)).to_vec(), hex(tag), "vector {i}");
    }
}

#[test]
fn chacha20_poly1305_rfc8439() {
    // Sections 2.8.2 and A.5.
    for (key, nonce, aad, pt, ct, tag) in CHACHA_POLY {
        let (nonce, aad, tag) = (hex(nonce).try_into().unwrap(), hex(aad), hex(tag).try_into().unwrap());
        for k in keys(Alg::ChaCha20Poly1305, &hex(key)) {
            let mut data = hex(pt);
            assert_eq!(k.seal(&nonce, &aad, &mut data), tag, "{}", path(&k));
            assert_eq!(data, hex(ct), "{}", path(&k));
            assert!(k.open(&nonce, &aad, &mut data, &tag), "{}", path(&k));
            assert_eq!(data, hex(pt), "{}", path(&k));
        }
    }
}

#[test]
fn wycheproof_every_path() {
    let aes = |k: &[u8]| if k.len() == 16 { Alg::Aes128Gcm } else { Alg::Aes256Gcm };
    let chacha = |_: &[u8]| Alg::ChaCha20Poly1305;
    for (file, bits, alg) in [
        ("aes_gcm_test.json.gz", &[128, 256][..], &aes as &dyn Fn(&[u8]) -> Alg),
        ("chacha20_poly1305_test.json.gz", &[256], &chacha),
    ] {
        let (cases, _) = wycheproof::load(file, bits);
        let paths = keys(alg(&cases[0].key), &cases[0].key).len();
        for p in 0..paths {
            wycheproof::run(&cases, |k| keys(alg(k), k).swap_remove(p), Key::seal, Key::open);
        }
    }
}

/// Seal must match ring; open must undo it and must fail after flipping any one bit (sampled
/// here, exhaustive in `every_bit_flip_fails`).
#[test]
fn matches_ring() {
    let mut rng = Rng(1);
    for alg in ALGS {
        for i in 0..1800 {
            // Every length up to 600, then random ones, with a big one now and then.
            let len = match i {
                0..=600 => i,
                _ if i % 250 == 0 => 65536 + rng.below(70000),
                _ => rng.below(601),
            };
            let key = rng.bytes(alg.key_len());
            let nonce = rng.nonce();
            let aad_len = rng.below(50);
            let aad = rng.bytes(aad_len);
            let pt = rng.bytes(len);
            let mut want = pt.clone();
            let want_tag = ring_seal(alg, &key, &nonce, &aad, &mut want);
            for k in keys(alg, &key) {
                let p = path(&k);
                let mut data = pt.clone();
                let tag = k.seal(&nonce, &aad, &mut data);
                assert!(data == want && tag == want_tag, "{alg:?} {p} case {i} len {len}");
                assert!(k.open(&nonce, &aad, &mut data, &tag), "{alg:?} {p} case {i}");
                assert!(data == pt, "{alg:?} {p} case {i}");

                let mut ct = want.clone();
                if !ct.is_empty() {
                    let bit = rng.below(ct.len() * 8);
                    ct[bit / 8] ^= 1 << (bit % 8);
                    assert!(!k.open(&nonce, &aad, &mut ct, &tag), "{alg:?} {p} case {i} ct bit {bit}");
                    // Nothing decrypted is left behind.
                    assert!(ct.iter().all(|&b| b == 0), "{alg:?} {p} case {i} not zeroed");
                }
                let mut t = tag;
                t[rng.below(16)] ^= 1 << rng.below(8);
                assert!(!k.open(&nonce, &aad, &mut want.clone(), &t), "{alg:?} {p} case {i} tag");
                let mut a = aad.clone();
                if !a.is_empty() {
                    let at = rng.below(a.len());
                    a[at] ^= 1 << rng.below(8);
                    assert!(!k.open(&nonce, &a, &mut want.clone(), &tag), "{alg:?} {p} case {i} aad");
                }
                let mut n = nonce;
                n[rng.below(12)] ^= 1 << rng.below(8);
                assert!(!k.open(&n, &aad, &mut want.clone(), &tag), "{alg:?} {p} case {i} nonce");
            }
        }
    }
}

#[test]
fn every_bit_flip_fails() {
    let mut rng = Rng(2);
    for alg in ALGS {
        for (len, aad_len) in [(0, 0), (0, 13), (1, 0), (15, 1), (16, 16), (17, 5), (64, 20), (129, 3), (300, 0)] {
            let key = rng.bytes(alg.key_len());
            let nonce = rng.nonce();
            let aad = rng.bytes(aad_len);
            let mut ct = rng.bytes(len);
            for k in keys(alg, &key) {
                let tag = k.seal(&nonce, &aad, &mut ct);
                let p = path(&k);
                for bit in 0..len * 8 {
                    let mut c = ct.clone();
                    c[bit / 8] ^= 1 << (bit % 8);
                    assert!(!k.open(&nonce, &aad, &mut c, &tag), "{alg:?} {p} len {len} ct bit {bit}");
                }
                for bit in 0..128 {
                    let mut t = tag;
                    t[bit / 8] ^= 1 << (bit % 8);
                    assert!(!k.open(&nonce, &aad, &mut ct.clone(), &t), "{alg:?} {p} len {len} tag bit {bit}");
                }
                for bit in 0..aad_len * 8 {
                    let mut a = aad.clone();
                    a[bit / 8] ^= 1 << (bit % 8);
                    assert!(!k.open(&nonce, &a, &mut ct.clone(), &tag), "{alg:?} {p} len {len} aad bit {bit}");
                }
                assert!(k.open(&nonce, &aad, &mut ct.clone(), &tag));
                // Decrypt, so the next key (other code path) starts from the same plaintext.
                assert!(k.open(&nonce, &aad, &mut ct, &tag));
            }
        }
    }
}

#[test]
fn round_trip_unaligned() {
    let mut rng = Rng(3);
    for alg in ALGS {
        let key = rng.bytes(alg.key_len());
        for k in keys(alg, &key) {
            for len in 0..=300 {
                for off in [1, 3, 8] {
                    let nonce = rng.nonce();
                    let aad = rng.bytes(len % 37);
                    let mut buf = rng.bytes(len + off);
                    let pt = buf[off..].to_vec();
                    let tag = k.seal(&nonce, &aad, &mut buf[off..]);
                    assert!(k.open(&nonce, &aad, &mut buf[off..], &tag), "{alg:?} {} len {len} off {off}", path(&k));
                    assert_eq!(buf[off..], pt[..], "{alg:?} {} len {len} off {off}", path(&k));
                }
            }
        }
    }
}

/// Past what the 32-bit block counter covers, `open` refuses and `seal` panics rather than
/// reuse keystream. The data is address space only, and read-only: a key that wrote to it would
/// crash the test rather than fill memory. `seal` goes first, as it writes at once.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[test]
fn too_long_for_the_counter() {
    unsafe extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
        fn munmap(addr: *mut u8, len: usize) -> i32;
    }
    const LEN: usize = 1 << 38;
    // PROT_READ; MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE.
    let p = unsafe { mmap(std::ptr::null_mut(), LEN, 1, 0x4022, -1, 0) };
    assert_ne!(p as isize, -1, "mmap");
    let data = unsafe { std::slice::from_raw_parts_mut(p, LEN) };
    for alg in ALGS {
        let n = if alg == Alg::ChaCha20Poly1305 { (1 << 38) - 63 } else { (1 << 36) - 31 };
        for k in keys(alg, &vec![0; alg.key_len()]) {
            let seal = std::panic::AssertUnwindSafe(|| k.seal(&[0; 12], b"", &mut data[..n]));
            assert!(std::panic::catch_unwind(seal).is_err(), "{alg:?} {}", path(&k));
            assert!(!k.open(&[0; 12], b"", &mut data[..n], &[0; 16]), "{alg:?} {}", path(&k));
        }
    }
    unsafe { munmap(p, LEN) };
}

#[test]
fn portable_matches_hardware_on_big_inputs() {
    // Lengths around the 8-block (128-byte) and 4-block (64-byte) batches and 1 MiB.
    let mut rng = Rng(4);
    for alg in [Alg::Aes128Gcm, Alg::Aes256Gcm] {
        let key = rng.bytes(alg.key_len());
        let ks = keys(alg, &key);
        for len in [127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 16384, 16384 + 17, 1 << 20] {
            let nonce = rng.nonce();
            let pt = rng.bytes(len);
            let mut want = pt.clone();
            let want_tag = ring_seal(alg, &key, &nonce, b"", &mut want);
            for k in &ks {
                let mut d = pt.clone();
                assert!(k.seal(&nonce, b"", &mut d) == want_tag && d == want, "{alg:?} {} {len}", path(k));
            }
        }
    }
}

/// MB/s over `bytes` for `f`, run for about a quarter second.
fn rate(bytes: usize, mut f: impl FnMut()) -> f64 {
    let start = std::time::Instant::now();
    let mut n = 0;
    while start.elapsed().as_millis() < 250 {
        f();
        n += 1;
    }
    (bytes * n) as f64 / start.elapsed().as_secs_f64() / 1e6
}

/// `cargo test -p jpm-crypto --release -- --ignored --nocapture bench_aead`
#[test]
#[ignore]
fn bench_aead() {
    for alg in ALGS {
        let key = [7; 32][..alg.key_len()].to_vec();
        let nonce = [9; 12];
        for len in [16384, 1 << 20] {
            let mut buf = vec![0u8; len];
            let rk = rg::LessSafeKey::new(
                rg::UnboundKey::new(
                    match alg {
                        Alg::Aes128Gcm => &rg::AES_128_GCM,
                        Alg::Aes256Gcm => &rg::AES_256_GCM,
                        Alg::ChaCha20Poly1305 => &rg::CHACHA20_POLY1305,
                    },
                    &key,
                )
                .unwrap(),
            );
            let ring = rate(len, || {
                let n = rg::Nonce::assume_unique_for_key(nonce);
                let _ =
                    std::hint::black_box(rk.seal_in_place_separate_tag(n, rg::Aad::from(b"hdr"), &mut buf).unwrap());
            });
            let mut line = format!("{alg:?} {len:>7} B  ring {ring:>7.0} MB/s");
            for k in keys(alg, &key) {
                let seal = rate(len, || {
                    std::hint::black_box(k.seal(&nonce, b"hdr", &mut buf));
                });
                let mut ct = buf.clone();
                let tag = k.seal(&nonce, b"hdr", &mut ct);
                // Includes copying the ciphertext back in each time.
                let open = rate(len, || {
                    buf.copy_from_slice(&ct);
                    assert!(k.open(&nonce, b"hdr", &mut buf, &tag));
                });
                line += &format!("  {} seal {seal:>7.0} open {open:>7.0}", path(&k));
            }
            eprintln!("{line}");
        }
    }
}

/// ChaCha20 and Poly1305 apart, to see which one limits the AEAD.
/// `cargo test -p jpm-crypto --release -- --ignored --nocapture bench_chacha_parts`
#[test]
#[ignore]
fn bench_chacha_parts() {
    let mut buf = vec![0u8; 16384];
    for imp in chacha_imps() {
        let k = chacha::Key::new(&[7; 32], imp);
        eprintln!("chacha20 {imp:?}: {:.0} MB/s", rate(buf.len(), || k.apply(&[1; 12], 1, &mut buf)));
    }
    let poly = rate(buf.len(), || {
        std::hint::black_box(poly1305(&[3; 32], &buf));
    });
    eprintln!("poly1305: {poly:.0} MB/s");
}

// RFC 8439 test vectors, copied from the RFC text by script.

const CHACHA_BLOCKS: &[(&str, &str, u32, &str)] = &[
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000090000004a00000000",
        1,
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d70\
         5d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        0,
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03\
         fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        1,
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b\
         074d839d531ed1f28510afb45ace10a1f4b794d6f",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000000",
        1,
        "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c\
         42f73f2fd4e273644c8b36125a64addeb006c13a0",
    ),
    (
        "00ff000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        2,
        "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1\
         be65b2c0924a66c54d545ec1b7374f4872e99f096",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000002",
        0,
        "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741\
         b97c286f75f8fc299e8148362fa198a39531bed6d",
    ),
];

const CHACHA_ENCRYPT: &[(&str, &str, u32, &str, &str)] = &[
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000000000004a00000000",
        1,
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496\
         6204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574\
         7572652c2073756e73637265656e20776f756c642062652069742e",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593da\
         bcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf8\
         06818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        0,
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
         00000000000000000000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03\
         fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000002",
        1,
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e64656420627920746865204\
         36f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f\
         6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e79207374617\
         4656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e2049455446206163\
         74697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222\
         e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e\
         20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c65637\
         4726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c\
         6163652c207768696368206172652061646472657373656420746f",
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d33\
         7f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881\
         a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8\
         449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966\
         e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c76598\
         9cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b\
         193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062b\
         ebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd9\
         02f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "000000000000000000000002",
        42,
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726\
         520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d7379207765726520746865\
         20626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb\
         14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ea\
         d6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
    ),
];

const POLY1305: &[(&str, &str, &str)] = &[
    (
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
        "a8061dc1305136c6c22b8baf0c0127a9",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
         00000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
    ),
    (
        "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e64656420627920746865204\
         36f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f\
         6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e79207374617\
         4656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e2049455446206163\
         74697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222\
         e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e\
         20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c65637\
         4726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c\
         6163652c207768696368206172652061646472657373656420746f",
        "36e5f6b5c5e06070f0efca96227a863e",
    ),
    (
        "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e64656420627920746865204\
         36f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f\
         6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e79207374617\
         4656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e2049455446206163\
         74697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222\
         e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e\
         20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c65637\
         4726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c\
         6163652c207768696368206172652061646472657373656420746f",
        "f3477e7cd95417af89a6b8794c310cf0",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726\
         520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d7379207765726520746865\
         20626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "4541669a7eaaee61e708dc7cbcc5eb62",
    ),
    (
        "0200000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "03000000000000000000000000000000",
    ),
    (
        "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
        "02000000000000000000000000000000",
        "03000000000000000000000000000000",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000\
         000000000",
        "05000000000000000000000000000000",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010\
         101010101",
        "00000000000000000000000000000000",
    ),
    (
        "0200000000000000000000000000000000000000000000000000000000000000",
        "fdffffffffffffffffffffffffffffff",
        "faffffffffffffffffffffffffffffff",
    ),
    (
        "0100000000000000040000000000000000000000000000000000000000000000",
        "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000\
         00000000001000000000000000000000000000000",
        "14000000000000005500000000000000",
    ),
    (
        "0100000000000000040000000000000000000000000000000000000000000000",
        "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000\
         000000000",
        "13000000000000000000000000000000",
    ),
];

const POLY1305_KEYGEN: &[(&str, &str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "000000000000000000000002",
        "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "000000000000000000000002",
        "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae",
    ),
];

const CHACHA_POLY: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "070000004041424344454647",
        "50515253c0c1c2c3c4c5c6c7",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496\
         6204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574\
         7572652c2073756e73637265656e20776f756c642062652069742e",
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb6\
         9da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675\
         945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    ),
    (
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "000000000102030405060708",
        "f33388860000000000004e91",
        "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666\
         f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465\
         642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747\
         320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e\
         7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f20636\
         97465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e\
         2fe2809d",
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94\
         e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33\
         bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166\
         c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc\
         546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a\
         6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb402\
         2b02709b",
        "eead9d67890cbb22392336fea1851f38",
    ),
];
