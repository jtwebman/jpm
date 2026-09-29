//! NIST P-384: ECDSA verification only (certificate chains use it; key exchange does not).

/// ECDSA: `public` an uncompressed point (`04 || x || y`), `digest` the message's hash (any
/// length; truncated to the order's bit length), `signature` DER `SEQUENCE { r, s }`.
pub fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    todo!("{} {} {}", public.len(), digest.len(), signature.len())
}
