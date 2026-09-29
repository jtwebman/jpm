//! NIST P-256: ECDH in constant time, and ECDSA verification.

/// The uncompressed public key (`04 || x || y`) for a secret scalar of 32 big-endian bytes, or
/// `None` when the scalar is 0 or not below the group order (the caller draws again).
pub fn public_key(secret: &[u8; 32]) -> Option<[u8; 65]> {
    todo!("{}", secret.len())
}

/// The x coordinate of `secret * peer`, or `None` when `peer` is not an uncompressed point on
/// the curve, or the result is the point at infinity.
pub fn shared_secret(secret: &[u8; 32], peer: &[u8]) -> Option<[u8; 32]> {
    todo!("{} {}", secret.len(), peer.len())
}

/// ECDSA: `public` an uncompressed point, `digest` the message's hash (any length; truncated to
/// the order's bit length as the standard says), `signature` DER `SEQUENCE { r, s }`.
pub fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    todo!("{} {} {}", public.len(), digest.len(), signature.len())
}
