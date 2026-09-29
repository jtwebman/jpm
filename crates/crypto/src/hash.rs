//! SHA-1 (legacy integrity strings only), SHA-256, SHA-384 and SHA-512, with HMAC, HKDF
//! (RFC 5869) and the TLS 1.2 PRF (RFC 5246 section 5) over them.

use std::ops::Deref;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// Output length in bytes.
    pub const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Block length in bytes, as HMAC pads keys to it.
    pub const fn block_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }
}

/// A digest, as long as its algorithm's output (at most 64 bytes).
#[derive(Clone, Copy)]
pub struct Digest {
    bytes: [u8; 64],
    len: u8,
}

impl Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// An incremental hash; clone it to take a digest of a prefix and keep going.
#[derive(Clone)]
pub struct Hasher {
    _todo: (),
}

impl Hasher {
    pub fn new(alg: Alg) -> Self {
        todo!("{alg:?}")
    }

    pub fn alg(&self) -> Alg {
        todo!()
    }

    pub fn update(&mut self, data: &[u8]) {
        todo!("{}", data.len())
    }

    pub fn finish(self) -> Digest {
        todo!()
    }
}

pub fn digest(alg: Alg, data: &[u8]) -> Digest {
    let mut h = Hasher::new(alg);
    h.update(data);
    h.finish()
}

/// HMAC over the concatenation of `parts`.
pub fn hmac(alg: Alg, key: &[u8], parts: &[&[u8]]) -> Digest {
    todo!("{alg:?} {} {}", key.len(), parts.len())
}

pub fn hkdf_extract(alg: Alg, salt: &[u8], ikm: &[u8]) -> Digest {
    hmac(alg, salt, &[ikm])
}

/// HKDF-Expand with `info` the concatenation of its parts. `out` is at most 255 digests long.
pub fn hkdf_expand(alg: Alg, prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    todo!("{alg:?} {} {} {}", prk.len(), info.len(), out.len())
}

/// The TLS 1.2 PRF: P_hash(secret, label + seed) with `seed` the concatenation of its parts.
pub fn tls12_prf(alg: Alg, secret: &[u8], label: &[u8], seed: &[&[u8]], out: &mut [u8]) {
    todo!("{alg:?} {} {} {} {}", secret.len(), label.len(), seed.len(), out.len())
}
