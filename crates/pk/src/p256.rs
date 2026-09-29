//! NIST P-256: ECDH in constant time, and ECDSA verification.

use crate::ec::{Curve, Modulus, hex};

// SEC 2 version 2, section 2.4.2.
static P256: Curve<4> = Curve {
    p: Modulus::new(hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")),
    n: Modulus::new(hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")),
    b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    gx: hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    gy: hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
};

/// The uncompressed public key (`04 || x || y`) for a secret scalar of 32 big-endian bytes, or
/// `None` when the scalar is 0 or not below the group order (the caller draws again).
pub fn public_key(secret: &[u8; 32]) -> Option<[u8; 65]> {
    let mut out = [0; 65];
    P256.public_key(secret, &mut out)?;
    Some(out)
}

/// The x coordinate of `secret * peer`, or `None` when `peer` is not an uncompressed point on
/// the curve, or the result is the point at infinity.
pub fn shared_secret(secret: &[u8; 32], peer: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    P256.shared_secret(secret, peer, &mut out)?;
    Some(out)
}

/// ECDSA: `public` an uncompressed point, `digest` the message's hash (any length; truncated to
/// the order's bit length as the standard says), `signature` DER `SEQUENCE { r, s }`.
pub fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    P256.verify(public, digest, signature)
}
