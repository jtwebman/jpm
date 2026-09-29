//! X25519 (RFC 7748), in constant time.

/// The public key for a secret of 32 random bytes (clamped here, as RFC 7748 says).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    todo!("{}", secret.len())
}

/// The shared secret, or `None` when it is all zeros (the peer sent a low-order point).
pub fn shared_secret(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    todo!("{} {}", secret.len(), peer.len())
}
