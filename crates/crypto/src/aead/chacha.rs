//! ChaCha20 and Poly1305 (RFC 8439) and the AEAD built from them. Plain integer arithmetic, so
//! constant time as written. ChaCha20 runs four blocks side by side, one array lane per block,
//! which the compiler turns into SIMD (SSE2, NEON) without any `unsafe`.

use crate::ct_eq;

pub(super) struct Key([u32; 8]);

impl Key {
    pub(super) fn new(key: &[u8]) -> Self {
        let mut k = [0; 8];
        for (k, b) in k.iter_mut().zip(key.as_chunks::<4>().0) {
            *k = u32::from_le_bytes(*b);
        }
        Key(k)
    }

    pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        // Block 0 gives the Poly1305 key; blocks 1-3 of the same batch start the keystream.
        let first = keystream(self, nonce, 0);
        let (head, rest) = data.split_at_mut(data.len().min(192));
        xor(head, &first[64..]);
        apply(self, nonce, 4, rest);
        mac(&first, aad, data)
    }

    pub(super) fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let first = keystream(self, nonce, 0);
        let ok = ct_eq(&mac(&first, aad, data), tag);
        if ok {
            let (head, rest) = data.split_at_mut(data.len().min(192));
            xor(head, &first[64..]);
            apply(self, nonce, 4, rest);
        }
        ok
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0 = [0; 8];
        std::hint::black_box(&self.0);
    }
}

/// Poly1305 over the AEAD's input: AAD and ciphertext each padded to 16 bytes, then their
/// lengths. The one-time key is the first 32 bytes of `block0`.
fn mac(block0: &[u8; 256], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(block0[..32].try_into().unwrap());
    p.update_padded(aad);
    p.update_padded(ct);
    let mut lens = [0; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    p.block(&lens, HIBIT);
    p.finish()
}

fn xor(data: &mut [u8], ks: &[u8]) {
    for (d, k) in data.iter_mut().zip(ks) {
        *d ^= k;
    }
}

/// XOR `data` with the keystream starting at block `ctr`.
pub(super) fn apply(key: &Key, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
    let mut ctr = ctr;
    for chunk in data.chunks_mut(256) {
        xor(chunk, &keystream(key, nonce, ctr));
        ctr = ctr.wrapping_add(4);
    }
}

type Lanes = [u32; 4];

/// Keystream blocks `ctr` to `ctr + 3`. State word `i` of all four blocks sits in `x[i]`.
fn keystream(key: &Key, nonce: &[u8; 12], ctr: u32) -> [u8; 256] {
    let n = nonce.as_chunks::<4>().0;
    let words: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key.0[0],
        key.0[1],
        key.0[2],
        key.0[3],
        key.0[4],
        key.0[5],
        key.0[6],
        key.0[7],
        0,
        u32::from_le_bytes(n[0]),
        u32::from_le_bytes(n[1]),
        u32::from_le_bytes(n[2]),
    ];
    let mut s: [Lanes; 16] = words.map(|w| [w; 4]);
    s[12] = [ctr, ctr.wrapping_add(1), ctr.wrapping_add(2), ctr.wrapping_add(3)];
    let mut x = s;
    for _ in 0..10 {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 1, 5, 9, 13);
        quarter(&mut x, 2, 6, 10, 14);
        quarter(&mut x, 3, 7, 11, 15);
        quarter(&mut x, 0, 5, 10, 15);
        quarter(&mut x, 1, 6, 11, 12);
        quarter(&mut x, 2, 7, 8, 13);
        quarter(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0; 256];
    for (i, block) in out.as_chunks_mut::<64>().0.iter_mut().enumerate() {
        for (w, o) in block.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            *o = x[w][i].wrapping_add(s[w][i]).to_le_bytes();
        }
    }
    out
}

// One lane per block, indexed so the four lanes line up for SIMD.
#[allow(clippy::needless_range_loop)]
#[inline(always)]
fn quarter(x: &mut [Lanes; 16], a: usize, b: usize, c: usize, d: usize) {
    for l in 0..4 {
        x[a][l] = x[a][l].wrapping_add(x[b][l]);
        x[d][l] = (x[d][l] ^ x[a][l]).rotate_left(16);
        x[c][l] = x[c][l].wrapping_add(x[d][l]);
        x[b][l] = (x[b][l] ^ x[c][l]).rotate_left(12);
        x[a][l] = x[a][l].wrapping_add(x[b][l]);
        x[d][l] = (x[d][l] ^ x[a][l]).rotate_left(8);
        x[c][l] = x[c][l].wrapping_add(x[d][l]);
        x[b][l] = (x[b][l] ^ x[c][l]).rotate_left(7);
    }
}

/// The 2^128 bit of a full block.
pub(super) const HIBIT: u64 = 1 << 40;
const M44: u64 = (1 << 44) - 1;
const M42: u64 = (1 << 42) - 1;

/// Poly1305 with 44-, 44- and 42-bit limbs, as in poly1305-donna-64.
pub(super) struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    s: [u64; 2],
}

impl Poly1305 {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        let t0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        // r, clamped (r &= 0x0ffffffc0ffffffc0ffffffc0fffffff), in limbs.
        let r = [t0 & 0xffc_0fff_ffff, ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff, (t1 >> 24) & 0x00f_ffff_fc0f];
        let s =
            [u64::from_le_bytes(key[16..24].try_into().unwrap()), u64::from_le_bytes(key[24..].try_into().unwrap())];
        Poly1305 { r, h: [0; 3], s }
    }

    /// h = (h + m + hibit * 2^128) * r, partly reduced modulo 2^130 - 5.
    pub(super) fn block(&mut self, m: &[u8; 16], hibit: u64) {
        let [r0, r1, r2] = self.r;
        // 2^130 = 5 mod p, and limb 2 is 42 bits: a product landing past 2^132 folds back times 20.
        let (s1, s2) = (r1 * 20, r2 * 20);
        let t0 = u64::from_le_bytes(m[..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(m[8..].try_into().unwrap());
        let h0 = self.h[0] + (t0 & M44);
        let h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & M44);
        let h2 = self.h[2] + ((t1 >> 24) & M42) + hibit;

        let mul = |a: u64, b: u64| a as u128 * b as u128;
        let d0 = mul(h0, r0) + mul(h1, s2) + mul(h2, s1);
        let d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s2);
        let d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

        let c = (d0 >> 44) as u64;
        let h0 = d0 as u64 & M44;
        let d1 = d1 + c as u128;
        let c = (d1 >> 44) as u64;
        let h1 = d1 as u64 & M44;
        let d2 = d2 + c as u128;
        let c = (d2 >> 42) as u64;
        let h2 = d2 as u64 & M42;
        let h0 = h0 + c * 5;
        self.h = [h0 & M44, h1 + (h0 >> 44), h2];
    }

    /// Full blocks of `data`, then any partial block padded with zeros to a full one.
    fn update_padded(&mut self, data: &[u8]) {
        let (blocks, rest) = data.as_chunks::<16>();
        for b in blocks {
            self.block(b, HIBIT);
        }
        if !rest.is_empty() {
            let mut b = [0; 16];
            b[..rest.len()].copy_from_slice(rest);
            self.block(&b, HIBIT);
        }
    }

    /// (h mod 2^130 - 5) + s, mod 2^128.
    pub(super) fn finish(self) -> [u8; 16] {
        let [mut h0, mut h1, mut h2] = self.h;
        let mut c;
        c = h1 >> 44;
        h1 &= M44;
        h2 += c;
        c = h2 >> 42;
        h2 &= M42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        c = h1 >> 44;
        h1 &= M44;
        h2 += c;
        c = h2 >> 42;
        h2 &= M42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= M44;
        h1 += c;

        // g = h + 5 - 2^130; keep it when it does not go negative, that is when h >= p.
        let mut g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= M44;
        let mut g1 = h1 + c;
        c = g1 >> 44;
        g1 &= M44;
        let g2 = (h2 + c).wrapping_sub(1 << 42);
        let keep_g = (g2 >> 63).wrapping_sub(1);
        h0 = (h0 & !keep_g) | (g0 & keep_g);
        h1 = (h1 & !keep_g) | (g1 & keep_g);
        h2 = (h2 & !keep_g) | (g2 & keep_g);

        let [s0, s1] = self.s;
        h0 += s0 & M44;
        c = h0 >> 44;
        h0 &= M44;
        h1 += (((s0 >> 44) | (s1 << 20)) & M44) + c;
        c = h1 >> 44;
        h1 &= M44;
        h2 += ((s1 >> 24) & M42) + c;
        h2 &= M42;

        let mut tag = [0; 16];
        tag[..8].copy_from_slice(&(h0 | (h1 << 44)).to_le_bytes());
        tag[8..].copy_from_slice(&((h1 >> 20) | (h2 << 24)).to_le_bytes());
        tag
    }
}
