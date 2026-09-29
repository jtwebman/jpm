//! The public-key cryptography of jpm's TLS handshakes: X25519 and P-256 key exchange, and
//! ECDSA (P-256, P-384) and RSA signature checks. It runs a few times per connection, not per
//! byte, so it is built for size where `jpm-crypto`'s hashes and ciphers are built for speed.
//!
//! Key exchange touches secrets and runs in constant time: no branch or memory index depends on
//! a scalar. Signature checks only see public data and may branch freely. Nothing here panics
//! on input from the network; bad input is `None` or `false`.

mod ec;
pub mod p256;
pub mod p384;
pub mod rsa;
pub mod x25519;
