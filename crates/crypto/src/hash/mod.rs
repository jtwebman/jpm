//! SHA-1 (legacy integrity strings only), SHA-256, SHA-384 and SHA-512, with HMAC, HKDF
//! (RFC 5869) and the TLS 1.2 PRF (RFC 5246 section 5) over them.

use std::ops::Deref;

mod sha1;
mod sha256;
mod sha512;

/// A hash algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// Output length in bytes.
    #[allow(clippy::len_without_is_empty, reason = "an algorithm is never empty")]
    pub const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Block length in bytes, as HMAC pads keys to it.
    pub(crate) const fn block_len(self) -> usize {
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

/// The chaining value. SHA-384 is SHA-512 with other initial values and a shorter output.
#[derive(Clone)]
enum State {
    Sha1([u32; 5]),
    Sha256([u32; 8]),
    Sha512([u64; 8]),
}

/// An incremental hash; clone it to take a digest of a prefix and keep going.
#[derive(Clone)]
pub struct Hasher {
    alg: Alg,
    state: State,
    /// Bytes hashed so far, including those waiting in `buf`.
    total: u64,
    /// A partial block; only the first `total % block_len` bytes count.
    buf: [u8; 128],
}

impl Hasher {
    /// Starts a hash.
    pub fn new(alg: Alg) -> Self {
        let state = match alg {
            Alg::Sha1 => State::Sha1(sha1::IV),
            Alg::Sha256 => State::Sha256(sha256::IV),
            Alg::Sha384 => State::Sha512(sha512::IV_384),
            Alg::Sha512 => State::Sha512(sha512::IV_512),
        };
        Self { alg, state, total: 0, buf: [0; 128] }
    }

    /// Hashes `data` after everything before it.
    pub fn update(&mut self, mut data: &[u8]) {
        let bl = self.alg.block_len();
        let used = self.total as usize & (bl - 1);
        self.total = self.total.wrapping_add(data.len() as u64);
        if used > 0 {
            let n = (bl - used).min(data.len());
            self.buf[used..used + n].copy_from_slice(&data[..n]);
            data = &data[n..];
            if used + n < bl {
                return;
            }
            let block = self.buf;
            self.compress(&block[..bl]);
        }
        let full = data.len() & !(bl - 1);
        if full > 0 {
            self.compress(&data[..full]);
        }
        let rest = &data[full..];
        self.buf[..rest.len()].copy_from_slice(rest);
    }

    /// Pads, and returns the digest.
    pub fn finish(mut self) -> Digest {
        let bl = self.alg.block_len();
        let used = self.total as usize & (bl - 1);
        let bits = u128::from(self.total) * 8;
        // 0x80, zeros, then the length in bits: 8 bytes for 64-byte blocks, 16 for 128.
        let mut pad = [0u8; 256];
        pad[used] = 0x80;
        let len_at = if used < bl - bl / 8 { bl } else { 2 * bl };
        if bl == 64 {
            pad[len_at - 8..len_at].copy_from_slice(&(bits as u64).to_be_bytes());
        } else {
            pad[len_at - 16..len_at].copy_from_slice(&bits.to_be_bytes());
        }
        pad[..used].copy_from_slice(&self.buf[..used]);
        self.compress(&pad[..len_at]);

        let mut d = Digest { bytes: [0; 64], len: self.alg.len() as u8 };
        match &self.state {
            State::Sha1(s) => be_words(&mut d.bytes, s.iter().map(|w| w.to_be_bytes())),
            State::Sha256(s) => be_words(&mut d.bytes, s.iter().map(|w| w.to_be_bytes())),
            State::Sha512(s) => be_words(&mut d.bytes, s.iter().map(|w| w.to_be_bytes())),
        }
        d
    }

    /// Runs the compression function over whole blocks.
    fn compress(&mut self, blocks: &[u8]) {
        match &mut self.state {
            State::Sha1(s) => sha1::compress(s, blocks),
            State::Sha256(s) => sha256::compress(s, blocks),
            State::Sha512(s) => sha512::compress(s, blocks),
        }
    }
}

fn be_words<const N: usize>(out: &mut [u8; 64], words: impl Iterator<Item = [u8; N]>) {
    for (chunk, w) in out.as_chunks_mut::<N>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&w);
    }
}

/// The hash of `data`.
pub fn digest(alg: Alg, data: &[u8]) -> Digest {
    let mut h = Hasher::new(alg);
    h.update(data);
    h.finish()
}

/// HMAC keyed once: the inner and outer hashes with the padded key already absorbed.
#[derive(Clone)]
struct Hmac {
    inner: Hasher,
    outer: Hasher,
}

impl Hmac {
    fn new(alg: Alg, key: &[u8]) -> Self {
        let bl = alg.block_len();
        // Branches only on the key's length, never on its bytes.
        let mut k = [0u8; 128];
        if key.len() > bl {
            k[..alg.len()].copy_from_slice(&digest(alg, key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Hasher::new(alg);
        let mut outer = Hasher::new(alg);
        for b in &mut k[..bl] {
            *b ^= 0x36;
        }
        inner.update(&k[..bl]);
        for b in &mut k[..bl] {
            *b ^= 0x36 ^ 0x5c;
        }
        outer.update(&k[..bl]);
        Self { inner, outer }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(self) -> Digest {
        let mut outer = self.outer;
        outer.update(&self.inner.finish());
        outer.finish()
    }
}

/// HMAC over the concatenation of `parts`.
pub fn hmac(alg: Alg, key: &[u8], parts: &[&[u8]]) -> Digest {
    let mut mac = Hmac::new(alg, key);
    for p in parts {
        mac.update(p);
    }
    mac.finish()
}

/// HKDF-Extract: the pseudorandom key from input keying material and a salt.
pub fn hkdf_extract(alg: Alg, salt: &[u8], ikm: &[u8]) -> Digest {
    hmac(alg, salt, &[ikm])
}

/// HKDF-Expand with `info` the concatenation of its parts. `out` is at most 255 digests long.
///
/// A longer `out` is a bug in the caller, not bad input, and panics.
pub fn hkdf_expand(alg: Alg, prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    assert!(out.len() <= 255 * alg.len(), "HKDF output longer than 255 digests");
    let key = Hmac::new(alg, prk);
    let mut t = Digest { bytes: [0; 64], len: 0 };
    for (i, chunk) in out.chunks_mut(alg.len()).enumerate() {
        let mut mac = key.clone();
        mac.update(&t);
        for p in info {
            mac.update(p);
        }
        mac.update(&[i as u8 + 1]);
        t = mac.finish();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// The TLS 1.2 PRF: P_hash(secret, label + seed) with `seed` the concatenation of its parts.
pub fn tls12_prf(alg: Alg, secret: &[u8], label: &[u8], seed: &[&[u8]], out: &mut [u8]) {
    let key = Hmac::new(alg, secret);
    let with_seed = |mut mac: Hmac| {
        mac.update(label);
        for p in seed {
            mac.update(p);
        }
        mac
    };
    // A(1) = HMAC(secret, label + seed); A(i + 1) = HMAC(secret, A(i)).
    let mut a = with_seed(key.clone()).finish();
    let mut chunks = out.chunks_mut(alg.len()).peekable();
    while let Some(chunk) = chunks.next() {
        let mut mac = key.clone();
        mac.update(&a);
        let block = with_seed(mac).finish();
        chunk.copy_from_slice(&block[..chunk.len()]);
        if chunks.peek().is_some() {
            let mut mac = key.clone();
            mac.update(&a);
            a = mac.finish();
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Set by tests to run the plain code instead of the CPU's SHA or AVX2 instructions.
    static PORTABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether to skip the CPU's instructions; only tests ever do.
#[cfg(test)]
fn portable() -> bool {
    PORTABLE.get()
}

#[cfg(not(test))]
const fn portable() -> bool {
    false
}

/// The CPU's code paths against the plain ones, through the whole hasher.
#[cfg(test)]
mod tests {
    use super::{Alg, Hasher, PORTABLE, digest};

    const ALGS: [Alg; 3] = [Alg::Sha256, Alg::Sha384, Alg::Sha512];

    fn plain<T>(f: impl FnOnce() -> T) -> T {
        PORTABLE.set(true);
        let out = f();
        PORTABLE.set(false);
        out
    }

    fn data(n: usize, mut x: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn every_length_to_1100() {
        let data = data(1100, 1);
        for alg in ALGS {
            for n in 0..=1100 {
                let fast = digest(alg, &data[..n]);
                assert_eq!(&fast[..], &plain(|| digest(alg, &data[..n]))[..], "{alg:?} {n}");
            }
        }
    }

    #[test]
    fn split_updates() {
        let data = data(5000, 2);
        let mut x = 0x2545f4914f6cdd1du64;
        for alg in ALGS {
            for _ in 0..200 {
                let mut splits = Vec::new();
                let mut left = data.len();
                while left > 0 {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let n = (x as usize % 700).min(left);
                    splits.push(n);
                    left -= n;
                }
                let run = || {
                    let mut h = Hasher::new(alg);
                    let mut rest = &data[..];
                    for &n in &splits {
                        h.update(&rest[..n]);
                        rest = &rest[n..];
                    }
                    h.finish()
                };
                assert_eq!(&run()[..], &plain(run)[..], "{alg:?}");
            }
        }
    }

    #[test]
    fn one_million_a() {
        let a = vec![b'a'; 1_000_000];
        for alg in ALGS {
            assert_eq!(&digest(alg, &a)[..], &plain(|| digest(alg, &a))[..], "{alg:?}");
        }
    }
}
