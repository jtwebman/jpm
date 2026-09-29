//! NIST P-384: ECDSA verification only (certificate chains use it; key exchange does not).

use crate::ec::{Curve, Modulus, hex};

// SEC 2 version 2, section 2.5.1.
static P384: Curve<6> = Curve {
    p: Modulus::new(hex(concat!(
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "fffffffffffffffeffffffff0000000000000000ffffffff"
    ))),
    n: Modulus::new(hex(concat!(
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "c7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    ))),
    b: hex(concat!(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112",
        "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"
    )),
    gx: hex(concat!(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98",
        "59f741e082542a385502f25dbf55296c3a545e3872760ab7"
    )),
    gy: hex(concat!(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c",
        "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
    )),
};

/// ECDSA: `public` an uncompressed point (`04 || x || y`), `digest` the message's hash (any
/// length; truncated to the order's bit length), `signature` DER `SEQUENCE { r, s }`.
pub fn verify(public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    P384.verify(public, digest, signature)
}
