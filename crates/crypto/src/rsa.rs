//! RSA signature verification: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017). Public keys only,
//! so nothing here needs constant time. Moduli of 2048 to 8192 bits; odd exponents of 3 to 2^32-1.

use crate::hash::Alg;

/// `n` and `e` big-endian as a key holds them (a leading zero byte allowed), `digest` the hash
/// of the message under `alg`, `signature` exactly as long as the modulus.
pub fn verify_pkcs1(n: &[u8], e: &[u8], alg: Alg, digest: &[u8], signature: &[u8]) -> bool {
    todo!("{} {} {alg:?} {} {}", n.len(), e.len(), digest.len(), signature.len())
}

/// PSS with MGF1 over the same hash and a salt as long as the digest, as TLS 1.3 and the Web
/// PKI use it.
pub fn verify_pss(n: &[u8], e: &[u8], alg: Alg, digest: &[u8], signature: &[u8]) -> bool {
    todo!("{} {} {alg:?} {} {}", n.len(), e.len(), digest.len(), signature.len())
}
