//! The cryptography jpm needs and nothing more: the hashes behind integrity strings and TLS, the
//! two AEAD ciphers and three curves TLS negotiates, RSA and ECDSA signature checks, and the
//! operating system's random numbers.
//!
//! Code that touches secrets (keys, key-exchange scalars, plaintext) runs in constant time: no
//! branch or memory index depends on a secret. Signature checks only see public data and may
//! branch freely. Nothing here panics on input from the network; bad input is `None` or `false`.

pub mod aead;
pub mod hash;
pub mod p256;
pub mod p384;
pub mod rand;
pub mod rsa;
pub mod x25519;

/// Equal in constant time: the time taken says nothing about where two slices differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}
