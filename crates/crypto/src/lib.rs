//! The cryptography jpm runs per byte: the hashes behind integrity strings and TLS, the two AEAD
//! ciphers TLS negotiates, and the operating system's random numbers. Built for speed; the
//! handshake's public-key code is in `jpm-pk`, built for size.
//!
//! Code that touches secrets (keys, plaintext) runs in constant time: no branch or memory index
//! depends on a secret. Nothing here panics on input from the network; bad input is `None` or
//! `false`.

pub mod aead;
pub mod hash;
pub mod rand;

/// Equal in constant time: the time taken says nothing about where two slices differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}
