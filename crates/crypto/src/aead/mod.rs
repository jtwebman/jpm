//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 (RFC 8439), sealing and opening in place.
//! AES and GHASH run on the CPU's instructions where it has them (AES-NI and PCLMULQDQ on
//! x86_64, the ARMv8 crypto extensions on aarch64) and on constant-time portable code otherwise.
//!
//! GCM counters are 32 bits, so one record must stay under 64 GiB; TLS records are 16 KiB.

mod chacha;
mod soft;

#[cfg_attr(target_arch = "x86_64", path = "x86.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arm.rs")]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod hw;

#[cfg(test)]
mod tests;

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
pub struct Key(Inner);

enum Inner {
    Soft(Box<soft::Gcm>),
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Hw(Box<hw::Gcm>),
    ChaCha(chacha::Key),
}

impl Key {
    /// `None` when `key` is not `alg.key_len()` bytes.
    pub fn new(alg: Alg, key: &[u8]) -> Option<Self> {
        Self::with(alg, key, aes_hardware())
    }

    /// `new`, with the choice of AES code left to the caller; the tests use it to run the
    /// portable code on machines with AES instructions.
    fn with(alg: Alg, key: &[u8], hw: bool) -> Option<Self> {
        if key.len() != alg.key_len() {
            return None;
        }
        if alg == Alg::ChaCha20Poly1305 {
            return Some(Key(Inner::ChaCha(chacha::Key::new(key))));
        }
        let (mut w, nr) = soft::key_schedule(key);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let fast = if hw { hw::Gcm::new(&w, nr).map(|g| Inner::Hw(Box::new(g))) } else { None };
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let fast: Option<Inner> = {
            let _ = hw;
            None
        };
        let inner = fast.unwrap_or_else(|| Inner::Soft(Box::new(soft::Gcm::new(&w, nr))));
        w.fill(0);
        std::hint::black_box(&w);
        Some(Key(inner))
    }

    /// Encrypt `data` in place and return the tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        match &self.0 {
            Inner::Soft(g) => gcm_seal(&**g, nonce, aad, data),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Inner::Hw(g) => gcm_seal(&**g, nonce, aad, data),
            Inner::ChaCha(k) => k.seal(nonce, aad, data),
        }
    }

    /// Check the tag, in constant time, then decrypt `data` in place. On `false` the contents of
    /// `data` are unspecified and must be dropped.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        match &self.0 {
            Inner::Soft(g) => gcm_open(&**g, nonce, aad, data, tag),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Inner::Hw(g) => gcm_open(&**g, nonce, aad, data, tag),
            Inner::ChaCha(k) => k.open(nonce, aad, data, tag),
        }
    }
}

/// Whether AES runs on CPU instructions here. Without them ChaCha20-Poly1305 is faster, so a
/// client offers it first.
pub fn aes_hardware() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        static HW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *HW.get_or_init(hw::supported)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    false
}

/// What GCM needs from an AES and GHASH implementation. One driver serves every implementation
/// and both key sizes.
trait Gcm {
    /// XOR `data` with the AES-CTR keystream of the blocks `nonce || ctr`, `nonce || ctr + 1`,
    /// ..., the counter big-endian and wrapping at 32 bits.
    fn ctr(&self, nonce: &[u8; 12], ctr: u32, data: &mut [u8]);

    /// Fold `data` into the GHASH state `y`, a final partial block padded with zeros.
    fn ghash(&self, y: &mut [u8; 16], data: &[u8]);
}

fn gcm_seal(g: &impl Gcm, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
    g.ctr(nonce, 2, data);
    gcm_tag(g, nonce, aad, data)
}

fn gcm_open(g: &impl Gcm, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
    let ok = crate::ct_eq(&gcm_tag(g, nonce, aad, data), tag);
    if ok {
        g.ctr(nonce, 2, data);
    }
    ok
}

/// The tag: GHASH over the padded AAD, the padded ciphertext and their lengths in bits,
/// encrypted with counter block 1.
fn gcm_tag(g: &impl Gcm, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0; 16];
    g.ghash(&mut y, aad);
    g.ghash(&mut y, ct);
    let mut lens = [0; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) << 3).to_be_bytes());
    g.ghash(&mut y, &lens);
    g.ctr(nonce, 1, &mut y);
    y
}
