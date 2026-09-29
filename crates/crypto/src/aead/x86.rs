//! AES-GCM on x86_64 AES-NI and PCLMULQDQ.
//!
//! GHASH numbers the bits of a block from the top: the first byte's high bit is the constant
//! term. Byte-reversing a block and loading it as a 128-bit integer turns that into a plain bit
//! reversal, bit 127 holding the constant term. The carry-less product of two such reflected
//! numbers is the reflected product shifted right by one bit. Rather than shift each product
//! back, the key is stored "twisted", multiplied by x^-1 once up front, so the products come out
//! right. The 256-bit product is reduced modulo x^128 + x^7 + x^2 + x + 1 with two more carry-less
//! multiplies, 64 bits at a time; see `reduce`.
//!
//! The CTR loop encrypts eight blocks at a time to keep the AES unit busy; GHASH multiplies up to
//! eight blocks by H^8 .. H^1 and reduces once. Encryption and GHASH run in one pass, one GHASH
//! block per AES round. Where the CPU has VAES and VPCLMULQDQ, the same pass works on 256-bit
//! registers, two blocks per instruction: that halves the instruction count, which is what
//! limits it.

use std::arch::x86_64::*;

pub(super) fn supported() -> bool {
    is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3")
}

pub(super) struct Gcm {
    rk: [__m128i; 15],
    nr: usize,
    /// H^1 .. H^8, reflected and twisted.
    h: [__m128i; 8],
    /// The two halves of each `h` XORed, in the low half: the Karatsuba middle operand.
    hk: [__m128i; 8],
    /// Whether `crypt` may use VAES, VPCLMULQDQ and AVX2. The tests clear it to run the
    /// 128-bit code.
    pub(super) vaes: bool,
}

impl Gcm {
    /// `None` unless the CPU has the instructions; every other method relies on that check.
    pub(super) fn new(w: &[u32; 60], nr: usize) -> Option<Self> {
        if !super::aes_hardware() {
            return None;
        }
        // SAFETY: aes_hardware() found AES-NI, PCLMULQDQ and SSSE3.
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

    fn crypt(&self, nonce: &[u8; 12], y: &mut [u8; 16], data: &mut [u8], seal: bool) {
        if self.vaes {
            // SAFETY: `vaes` is only set once the CPU showed VAES, VPCLMULQDQ and AVX2.
            unsafe { crypt_vaes(self, nonce, y, data, seal) }
        } else {
            // SAFETY: as above.
            unsafe { crypt(self, nonce, y, data, seal) }
        }
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        let z = load(&[0; 16]);
        self.rk = [z; 15];
        self.h = [z; 8];
        self.hk = [z; 8];
        std::hint::black_box(&self);
    }
}

fn load(b: &[u8; 16]) -> __m128i {
    // SAFETY: an unaligned 16-byte read from a 16-byte array.
    unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
}

fn store(b: &mut [u8; 16], v: __m128i) {
    // SAFETY: an unaligned 16-byte write to a 16-byte array.
    unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn init(w: &[u32; 60], nr: usize) -> Gcm {
    let z = _mm_setzero_si128();
    let mut rk = [z; 15];
    for (k, w) in rk.iter_mut().zip(w.as_chunks::<4>().0) {
        let mut b = [0; 16];
        for (b, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(w) {
            *b = w.to_le_bytes();
        }
        *k = load(&b);
    }
    let vaes =
        is_x86_feature_detected!("vaes") && is_x86_feature_detected!("vpclmulqdq") && is_x86_feature_detected!("avx2");
    let mut g = Gcm { rk, nr, h: [z; 8], hk: [z; 8], vaes };

    let mut e0 = [z];
    aes(&g.rk[..=nr], &mut e0);
    let mut b = [0; 16];
    store(&mut b, bswap(e0[0]));
    // Twist: H * x^-1. In reflected form, dividing by x is a left shift; when the constant term
    // falls off the top, add x^-1 = x^127 + x^6 + x + 1 (bits 0, 121, 126 and 127).
    let h = u128::from_le_bytes(b);
    let h = (h << 1) ^ (0u128.wrapping_sub(h >> 127) & 0xC200_0000_0000_0000_0000_0000_0000_0001);
    g.h[0] = load(&h.to_le_bytes());
    // twist(a) * H = twist(a * H), so the powers stay twisted.
    for i in 1..8 {
        g.h[i] = mul(g.h[i - 1], g.h[0], fold(g.h[0]));
    }
    for i in 0..8 {
        g.hk[i] = fold(g.h[i]);
    }
    g
}

/// Reverse the bytes of a block.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn bswap(v: __m128i) -> __m128i {
    _mm_shuffle_epi8(v, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
}

/// Low half XOR high half, in the low half.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn fold(v: __m128i) -> __m128i {
    _mm_xor_si128(v, _mm_shuffle_epi32(v, 0x4e))
}

/// Encrypt `N` blocks side by side.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[inline]
fn aes<const N: usize>(rk: &[__m128i], b: &mut [__m128i; N]) {
    let (first, rest) = rk.split_first().unwrap();
    let (last, mid) = rest.split_last().unwrap();
    for x in b.iter_mut() {
        *x = _mm_xor_si128(*x, *first);
    }
    for k in mid {
        for x in b.iter_mut() {
            *x = _mm_aesenc_si128(*x, *k);
        }
    }
    for x in b.iter_mut() {
        *x = _mm_aesenclast_si128(*x, *last);
    }
}

/// The counter block `nonce || ctr`, given `base` = `nonce || 0`.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn counter(base: __m128i, ctr: u32) -> __m128i {
    _mm_xor_si128(base, _mm_set_epi32(ctr.swap_bytes() as i32, 0, 0, 0))
}

fn base(nonce: &[u8; 12]) -> __m128i {
    let mut n = [0; 16];
    n[..12].copy_from_slice(nonce);
    load(&n)
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn ctr8(g: &Gcm, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
    let rk = &g.rk[..=g.nr];
    let base = base(nonce);
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
            store(d, _mm_xor_si128(load(d), k));
        }
    }
    for chunk in rest.chunks_mut(16) {
        let mut b = [counter(base, ctr)];
        ctr = ctr.wrapping_add(1);
        aes(rk, &mut b);
        let mut t = [0; 16];
        t[..chunk.len()].copy_from_slice(chunk);
        let v = _mm_xor_si128(load(&t), b[0]);
        store(&mut t, v);
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn ghash(g: &Gcm, y: &mut [u8; 16], data: &[u8]) {
    store(y, bswap(ghash_acc(g, bswap(load(y)), data)));
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[inline]
fn ghash_acc(g: &Gcm, acc: __m128i, data: &[u8]) -> __m128i {
    let mut acc = acc;
    let (groups, rest) = data.as_chunks::<128>();
    for group in groups {
        acc = mul_add(g, acc, group.as_chunks::<16>().0);
    }
    if !rest.is_empty() {
        let mut t = [0; 128];
        t[..rest.len()].copy_from_slice(rest);
        acc = mul_add(g, acc, &t.as_chunks::<16>().0[..rest.len().div_ceil(16)]);
    }
    acc
}

/// CTR and GHASH in one pass, eight blocks at a time. Opening, GHASH takes each group of
/// ciphertext before it is decrypted; sealing, it takes the group encrypted one round before,
/// so either way the AES of one group and the GHASH of another are independent and overlap.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn crypt(g: &Gcm, nonce: &[u8; 12], y: &mut [u8; 16], data: &mut [u8], seal: bool) {
    let rk = &g.rk[..=g.nr];
    let base = base(nonce);
    let mut ctr = 2u32;
    let mut acc = bswap(load(y));
    let (groups, rest) = data.as_chunks_mut::<128>();
    for i in 0..groups.len() {
        let mut b = [base; 8];
        for x in &mut b {
            *x = counter(base, ctr);
            ctr = ctr.wrapping_add(1);
        }
        if !seal {
            acc = aes_ghash(g, rk, &mut b, acc, groups[i].as_chunks::<16>().0.try_into().unwrap());
        } else if i > 0 {
            acc = aes_ghash(g, rk, &mut b, acc, groups[i - 1].as_chunks::<16>().0.try_into().unwrap());
        } else {
            aes(rk, &mut b);
        }
        for (d, k) in groups[i].as_chunks_mut::<16>().0.iter_mut().zip(b) {
            store(d, _mm_xor_si128(load(d), k));
        }
    }
    if seal && let Some(last) = groups.last() {
        acc = mul_add(g, acc, last.as_chunks::<16>().0);
    }
    if !seal {
        acc = ghash_acc(g, acc, rest);
    }
    ctr8(g, nonce, ctr, rest);
    if seal {
        acc = ghash_acc(g, acc, rest);
    }
    store(y, bswap(acc));
}

/// Encrypt eight blocks and fold eight others into `acc`, one GHASH block in each AES round
/// (there are at least nine) so the two instruction streams interleave.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[inline]
fn aes_ghash(g: &Gcm, rk: &[__m128i], b: &mut [__m128i; 8], acc: __m128i, blocks: &[[u8; 16]; 8]) -> __m128i {
    let (first, rest) = rk.split_first().unwrap();
    let (last, mid) = rest.split_last().unwrap();
    for x in b.iter_mut() {
        *x = _mm_xor_si128(*x, *first);
    }
    let (mut lo, mut hi, mut md) = (_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128());
    for (r, k) in mid.iter().enumerate() {
        for x in b.iter_mut() {
            *x = _mm_aesenc_si128(*x, *k);
        }
        if r < 8 {
            let mut x = bswap(load(&blocks[r]));
            if r == 0 {
                x = _mm_xor_si128(x, acc);
            }
            let (h, hk) = (g.h[7 - r], g.hk[7 - r]);
            lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(x, h, 0x00));
            hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(x, h, 0x11));
            md = _mm_xor_si128(md, _mm_clmulepi64_si128(fold(x), hk, 0x00));
        }
    }
    for x in b.iter_mut() {
        *x = _mm_aesenclast_si128(*x, *last);
    }
    reduce(lo, hi, md)
}

/// `crypt` on 256-bit registers: each holds two blocks.
#[target_feature(enable = "aes,pclmulqdq,ssse3,avx2,vaes,vpclmulqdq")]
fn crypt_vaes(g: &Gcm, nonce: &[u8; 12], y: &mut [u8; 16], data: &mut [u8], seal: bool) {
    let mut rk = [_mm256_setzero_si256(); 15];
    for (r, k) in rk.iter_mut().zip(&g.rk[..=g.nr]) {
        *r = _mm256_broadcastsi128_si256(*k);
    }
    let rk = &rk[..=g.nr];
    // Block 2j in the low half and 2j + 1 in the high half meet H^(8-2j) and H^(7-2j).
    let mut h = [_mm256_setzero_si256(); 4];
    let mut hk = h;
    for j in 0..4 {
        h[j] = _mm256_set_m128i(g.h[6 - 2 * j], g.h[7 - 2 * j]);
        hk[j] = _mm256_set_m128i(g.hk[6 - 2 * j], g.hk[7 - 2 * j]);
    }
    let base = _mm256_broadcastsi128_si256(base(nonce));
    // Counters as little-endian words in the last lane of each half, byte-swapped into place.
    let mut ctr = _mm256_set_epi32(3, 0, 0, 0, 2, 0, 0, 0);
    let two = _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);
    #[rustfmt::skip]
    let swap = _mm256_set_epi8(
        12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    );
    let mut acc = bswap(load(y));
    let (groups, rest) = data.as_chunks_mut::<128>();
    for i in 0..groups.len() {
        let mut b = [base; 4];
        for x in &mut b {
            *x = _mm256_xor_si256(base, _mm256_shuffle_epi8(ctr, swap));
            ctr = _mm256_add_epi32(ctr, two);
        }
        let prev = match (seal, i) {
            (false, _) => Some(&groups[i]),
            (true, 0) => None,
            (true, _) => Some(&groups[i - 1]),
        };
        acc = aes_ghash_vaes(rk, &mut b, acc, prev.map(|p| p.as_chunks::<32>().0.try_into().unwrap()), &h, &hk);
        for (d, k) in groups[i].as_chunks_mut::<32>().0.iter_mut().zip(b) {
            store256(d, _mm256_xor_si256(load256(d), k));
        }
    }
    if seal && let Some(last) = groups.last() {
        acc = mul_add(g, acc, last.as_chunks::<16>().0);
    }
    if !seal {
        acc = ghash_acc(g, acc, rest);
    }
    ctr8(g, nonce, 2u32.wrapping_add(8 * groups.len() as u32), rest);
    if seal {
        acc = ghash_acc(g, acc, rest);
    }
    store(y, bswap(acc));
}

fn load256(b: &[u8; 32]) -> __m256i {
    // SAFETY: an unaligned 32-byte read from a 32-byte array; only called from AVX2 code.
    unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
}

fn store256(b: &mut [u8; 32], v: __m256i) {
    // SAFETY: an unaligned 32-byte write to a 32-byte array; only called from AVX2 code.
    unsafe { _mm256_storeu_si256(b.as_mut_ptr().cast(), v) }
}

/// Encrypt eight blocks in four registers and fold eight others (if any) into `acc`, one pair
/// of GHASH blocks in each of the first four AES rounds.
#[target_feature(enable = "aes,pclmulqdq,ssse3,avx2,vaes,vpclmulqdq")]
#[inline]
fn aes_ghash_vaes(
    rk: &[__m256i],
    b: &mut [__m256i; 4],
    acc: __m128i,
    blocks: Option<&[[u8; 32]; 4]>,
    h: &[__m256i; 4],
    hk: &[__m256i; 4],
) -> __m128i {
    let (first, rest) = rk.split_first().unwrap();
    let (last, mid) = rest.split_last().unwrap();
    for x in b.iter_mut() {
        *x = _mm256_xor_si256(*x, *first);
    }
    #[rustfmt::skip]
    let rev = _mm256_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    );
    let (mut lo, mut hi, mut md) = (_mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256());
    for (r, k) in mid.iter().enumerate() {
        for x in b.iter_mut() {
            *x = _mm256_aesenc_epi128(*x, *k);
        }
        if let Some(blocks) = blocks
            && r < 4
        {
            let mut x = _mm256_shuffle_epi8(load256(&blocks[r]), rev);
            if r == 0 {
                x = _mm256_xor_si256(x, _mm256_set_m128i(_mm_setzero_si128(), acc));
            }
            lo = _mm256_xor_si256(lo, _mm256_clmulepi64_epi128(x, h[r], 0x00));
            hi = _mm256_xor_si256(hi, _mm256_clmulepi64_epi128(x, h[r], 0x11));
            let f = _mm256_xor_si256(x, _mm256_shuffle_epi32(x, 0x4e));
            md = _mm256_xor_si256(md, _mm256_clmulepi64_epi128(f, hk[r], 0x00));
        }
    }
    for x in b.iter_mut() {
        *x = _mm256_aesenclast_epi128(*x, *last);
    }
    if blocks.is_none() {
        return acc;
    }
    let halves = |v: __m256i| _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256::<1>(v));
    reduce(halves(lo), halves(hi), halves(md))
}

/// Fold up to eight blocks into `acc`: (acc + b[0]) H^n + b[1] H^(n-1) + ... + b[n-1] H, with the
/// Karatsuba products summed unreduced and one reduction at the end.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[inline]
fn mul_add(g: &Gcm, acc: __m128i, blocks: &[[u8; 16]]) -> __m128i {
    let n = blocks.len();
    let (mut lo, mut hi, mut mid) = (_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128());
    for (i, b) in blocks.iter().enumerate() {
        let mut x = bswap(load(b));
        if i == 0 {
            x = _mm_xor_si128(x, acc);
        }
        let (h, hk) = (g.h[n - 1 - i], g.hk[n - 1 - i]);
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128(x, h, 0x00));
        hi = _mm_xor_si128(hi, _mm_clmulepi64_si128(x, h, 0x11));
        mid = _mm_xor_si128(mid, _mm_clmulepi64_si128(fold(x), hk, 0x00));
    }
    reduce(lo, hi, mid)
}

/// a * b for reflected a and twisted b (with `bk` = fold(b)).
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn mul(a: __m128i, b: __m128i, bk: __m128i) -> __m128i {
    let lo = _mm_clmulepi64_si128(a, b, 0x00);
    let hi = _mm_clmulepi64_si128(a, b, 0x11);
    let mid = _mm_clmulepi64_si128(fold(a), bk, 0x00);
    reduce(lo, hi, mid)
}

/// Finish Karatsuba and reduce the 256-bit reflected product X3:X2:X1:X0 (64-bit words, X0 the
/// highest powers of x). Reflected, x^128 = x^7 + x^2 + x + 1 says a word Xi folds onto the words
/// above it as Xi * (x^128 + 0xC2 << 56) shifted up one word, so X0 lands on X1 and X2, then X1
/// on X2 and X3. What is left in the high half is the reduced product.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[inline]
fn reduce(lo: __m128i, hi: __m128i, mid: __m128i) -> __m128i {
    let mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    let lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    let hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
    let poly = _mm_set_epi64x(0, 0xC200_0000_0000_0000u64 as i64);
    // Swapping the halves moves X0 up to where it is added (X2) and X1 down to where it gets
    // folded next; the product lands on X1 and X2.
    let t = _mm_clmulepi64_si128(lo, poly, 0x00);
    let lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4e), t);
    let t = _mm_clmulepi64_si128(lo, poly, 0x00);
    let lo = _mm_xor_si128(_mm_shuffle_epi32(lo, 0x4e), t);
    _mm_xor_si128(hi, lo)
}
