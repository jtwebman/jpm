//! The public AEAD API against the Wycheproof vectors. The unit tests in src/aead/tests.rs run
//! the same vectors through the portable AES code as well.

#[path = "common/wycheproof.rs"]
mod wycheproof;

use jpm_crypto::aead::{Alg, Key};

fn aes(key: &[u8]) -> Key {
    Key::new(if key.len() == 16 { Alg::Aes128Gcm } else { Alg::Aes256Gcm }, key).unwrap()
}

#[test]
fn wycheproof_aes_gcm() {
    let (cases, skipped) = wycheproof::load("aes_gcm_test.json.gz", &[128, 256]);
    wycheproof::run(&cases, aes, Key::seal, Key::open);
    eprintln!("aes_gcm: {} cases, {skipped} skipped (other IV, tag or key sizes)", cases.len());
    assert!(cases.len() >= 130);
}

#[test]
fn wycheproof_chacha20_poly1305() {
    let (cases, skipped) = wycheproof::load("chacha20_poly1305_test.json.gz", &[256]);
    wycheproof::run(&cases, |k| Key::new(Alg::ChaCha20Poly1305, k).unwrap(), Key::seal, Key::open);
    eprintln!("chacha20_poly1305: {} cases, {skipped} skipped (other IV sizes)", cases.len());
    assert!(cases.len() >= 300);
}

#[test]
fn key_length() {
    for alg in [Alg::Aes128Gcm, Alg::Aes256Gcm, Alg::ChaCha20Poly1305] {
        for len in 0..=64 {
            assert_eq!(Key::new(alg, &vec![7; len]).is_some(), len == alg.key_len(), "{alg:?} {len}");
        }
    }
}
