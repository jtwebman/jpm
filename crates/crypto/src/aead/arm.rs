//! AES-GCM on the ARMv8 crypto extensions (AESE/AESMC and PMULL). The GHASH arithmetic is the
//! same as on x86_64 (see x86.rs): blocks as byte-reversed 128-bit integers, the key twisted by
//! x^-1, Karatsuba over up to eight blocks and one reduction by two carry-less multiplies; here on
//! u128 values, PMULL giving the 64x64-bit products.

use std::arch::aarch64::*;

pub(super) fn supported() -> bool {
    // "aes" covers both AES and PMULL.
    std::arch::is_aarch64_feature_detected!("aes")
}

pub(super) struct Gcm {
    rk: [uint8x16_t; 15],
    nr: usize,
    /// H^1 .. H^8, reflected and twisted.
    h: [u128; 8],
}

impl Gcm {
    /// `None` unless the CPU has the instructions; every other method relies on that check.
    pub(super) fn new(w: &[u32; 60], nr: usize) -> Option<Self> {
        if !super::aes_hardware() {
            return None;
        }
        // SAFETY: aes_hardware() found AES and PMULL.
        Some(unsafe { init(w, nr) })
    }
}

impl super::Gcm for Gcm {
    fn ctr(&self, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
        // SAFETY: a Gcm exists only when the CPU has the features (see `new`).
        unsafe { ctr8(self, nonce, ctr, data) }
    }

    fn ghash(&self, y: &mut [u8; 16], data: &[u8]) {
        // SAFETY: as above.
        unsafe { ghash(self, y, data) }
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        self.rk = [load(&[0; 16]); 15];
        self.h = [0; 8];
        std::hint::black_box(&self);
    }
}

fn load(b: &[u8; 16]) -> uint8x16_t {
    // SAFETY: a 16-byte read from a 16-byte array; vld1q_u8 needs no alignment.
    unsafe { vld1q_u8(b.as_ptr()) }
}

fn store(b: &mut [u8; 16], v: uint8x16_t) {
    // SAFETY: a 16-byte write to a 16-byte array.
    unsafe { vst1q_u8(b.as_mut_ptr(), v) }
}

#[target_feature(enable = "aes")]
fn init(w: &[u32; 60], nr: usize) -> Gcm {
    let mut rk = [vdupq_n_u8(0); 15];
    for (k, w) in rk.iter_mut().zip(w.as_chunks::<4>().0) {
        let mut b = [0; 16];
        for (b, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(w) {
            *b = w.to_le_bytes();
        }
        *k = load(&b);
    }
    let mut g = Gcm { rk, nr, h: [0; 8] };
    let mut e0 = [vdupq_n_u8(0)];
    aes(&g.rk[..=nr], &mut e0);
    let mut b = [0; 16];
    store(&mut b, e0[0]);
    // Twist, as in x86.rs.
    let h = u128::from_be_bytes(b);
    g.h[0] = (h << 1) ^ (0u128.wrapping_sub(h >> 127) & 0xC200_0000_0000_0000_0000_0000_0000_0001);
    for i in 1..8 {
        g.h[i] = mul(g.h[i - 1], g.h[0]);
    }
    g
}

#[target_feature(enable = "aes")]
#[inline]
fn aes<const N: usize>(rk: &[uint8x16_t], b: &mut [uint8x16_t; N]) {
    // AESE is AddRoundKey, SubBytes and ShiftRows; AESMC is MixColumns.
    let (last, rest) = rk.split_last().unwrap();
    let (second, mid) = rest.split_last().unwrap();
    for k in mid {
        for x in b.iter_mut() {
            *x = vaesmcq_u8(vaeseq_u8(*x, *k));
        }
    }
    for x in b.iter_mut() {
        *x = veorq_u8(vaeseq_u8(*x, *second), *last);
    }
}

#[target_feature(enable = "aes")]
fn counter(base: uint8x16_t, ctr: u32) -> uint8x16_t {
    vreinterpretq_u8_u32(vsetq_lane_u32::<3>(ctr.swap_bytes(), vreinterpretq_u32_u8(base)))
}

#[target_feature(enable = "aes")]
fn ctr8(g: &Gcm, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
    let rk = &g.rk[..=g.nr];
    let mut n = [0; 16];
    n[..12].copy_from_slice(nonce);
    let base = load(&n);
    let mut ctr = ctr;
    let (groups, rest) = data.as_chunks_mut::<128>();
    for group in groups {
        let mut b = [base; 8];
        for x in &mut b {
            *x = counter(base, ctr);
            ctr = ctr.wrapping_add(1);
        }
        aes(rk, &mut b);
        for (d, k) in group.as_chunks_mut::<16>().0.iter_mut().zip(b) {
            store(d, veorq_u8(load(d), k));
        }
    }
    for chunk in rest.chunks_mut(16) {
        let mut b = [counter(base, ctr)];
        ctr = ctr.wrapping_add(1);
        aes(rk, &mut b);
        let mut t = [0; 16];
        t[..chunk.len()].copy_from_slice(chunk);
        let v = veorq_u8(load(&t), b[0]);
        store(&mut t, v);
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[target_feature(enable = "aes")]
fn ghash(g: &Gcm, y: &mut [u8; 16], data: &[u8]) {
    let mut acc = u128::from_be_bytes(*y);
    let (groups, rest) = data.as_chunks::<128>();
    for group in groups {
        acc = mul_add(g, acc, group.as_chunks::<16>().0);
    }
    if !rest.is_empty() {
        let mut t = [0; 128];
        t[..rest.len()].copy_from_slice(rest);
        acc = mul_add(g, acc, &t.as_chunks::<16>().0[..rest.len().div_ceil(16)]);
    }
    *y = acc.to_be_bytes();
}

#[target_feature(enable = "aes")]
fn clmul(a: u64, b: u64) -> u128 {
    vmull_p64(a, b)
}

/// (acc + b[0]) H^n + b[1] H^(n-1) + ... + b[n-1] H, n <= 8, reduced once.
#[target_feature(enable = "aes")]
#[inline]
fn mul_add(g: &Gcm, acc: u128, blocks: &[[u8; 16]]) -> u128 {
    let n = blocks.len();
    let (mut lo, mut hi, mut mid) = (0, 0, 0);
    for (i, b) in blocks.iter().enumerate() {
        let mut x = u128::from_be_bytes(*b);
        if i == 0 {
            x ^= acc;
        }
        let h = g.h[n - 1 - i];
        lo ^= clmul(x as u64, h as u64);
        hi ^= clmul((x >> 64) as u64, (h >> 64) as u64);
        mid ^= clmul((x ^ (x >> 64)) as u64, (h ^ (h >> 64)) as u64);
    }
    reduce(lo, hi, mid)
}

#[target_feature(enable = "aes")]
fn mul(a: u128, b: u128) -> u128 {
    let lo = clmul(a as u64, b as u64);
    let hi = clmul((a >> 64) as u64, (b >> 64) as u64);
    let mid = clmul((a ^ (a >> 64)) as u64, (b ^ (b >> 64)) as u64);
    reduce(lo, hi, mid)
}

/// As `reduce` in x86.rs: X0 folds onto X1 and X2, then X1 onto X2 and X3.
#[target_feature(enable = "aes")]
#[inline]
fn reduce(lo: u128, hi: u128, mid: u128) -> u128 {
    const POLY: u64 = 0xC200_0000_0000_0000;
    let mid = mid ^ lo ^ hi;
    let lo = lo ^ (mid << 64);
    let hi = hi ^ (mid >> 64);
    let (x0, x1) = (lo as u64, (lo >> 64) as u64);
    let t = clmul(x0, POLY);
    let x1 = x1 ^ t as u64;
    let x2 = x0 ^ (t >> 64) as u64;
    let t = clmul(x1, POLY);
    hi ^ (((x1 ^ (t >> 64) as u64) as u128) << 64 | (x2 ^ t as u64) as u128)
}
