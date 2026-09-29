//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 (RFC 8439), sealing and opening in place.
//! AES and GHASH run on the CPU's instructions where it has them (AES-NI and PCLMULQDQ on
//! x86_64, the ARMv8 crypto extensions on aarch64) and on constant-time portable code otherwise.

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Alg {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

/// A key, expanded once for every record it seals or opens.
pub struct Key {
    _todo: (),
}

impl Key {
    /// `None` when `key` is not `alg.key_len()` bytes.
    pub fn new(alg: Alg, key: &[u8]) -> Option<Self> {
        todo!("{alg:?} {}", key.len())
    }

    /// Encrypt `data` in place and return the tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        todo!("{} {} {}", nonce.len(), aad.len(), data.len())
    }

    /// Check the tag, in constant time, then decrypt `data` in place. On `false` the contents of
    /// `data` are unspecified and must be dropped.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        todo!("{} {} {} {}", nonce.len(), aad.len(), data.len(), tag.len())
    }
}

/// Whether AES runs on CPU instructions here. Without them ChaCha20-Poly1305 is faster, so a
/// client offers it first.
pub fn aes_hardware() -> bool {
    todo!()
}
