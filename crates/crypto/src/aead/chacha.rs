//! ChaCha20 and Poly1305 (RFC 8439) and the AEAD built from them. Plain integer arithmetic, so
//! constant time as written.
//!
//! ChaCha20 runs several blocks side by side: one value holds the same state word of every
//! block, so the rounds are the scalar rounds on vectors. `Lanes` is that value: four u32 in an
//! array (portable), an SSE2 or NEON register (four blocks) or an AVX2 register (eight blocks).
//! The compiler does not vectorize the array version on its own.

use crate::ct_eq;

/// Which ChaCha20 code runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Imp {
    Scalar,
    /// SSE2 on x86_64, NEON on aarch64: part of the base instruction set.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Simd,
    #[cfg(target_arch = "x86_64")]
    Avx2,
}

impl Imp {
    /// The fastest this CPU runs.
    pub(super) fn best() -> Imp {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            return Imp::Avx2;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let imp = Imp::Simd;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let imp = Imp::Scalar;
        imp
    }
}

pub(super) struct Key {
    k: [u32; 8],
    imp: Imp,
}

impl Key {
    pub(super) fn new(key: &[u8], imp: Imp) -> Self {
        let mut k = [0; 8];
        for (k, b) in k.iter_mut().zip(key.as_chunks::<4>().0) {
            *k = u32::from_le_bytes(*b);
        }
        Key { k, imp }
    }

    #[cfg(test)]
    pub(super) fn imp(&self) -> Imp {
        self.imp
    }

    pub(super) fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        self.crypt(nonce, aad, data, true)
    }

    /// Decrypts while it authenticates; on a bad tag, `data` is zeroed.
    pub(super) fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let ok = ct_eq(&self.crypt(nonce, aad, data, false), tag);
        if !ok {
            data.fill(0);
        }
        ok
    }

    /// Encrypt (`seal`) or decrypt `data` in place and return the tag. One pass: each batch of
    /// keystream is XORed in and the ciphertext fed to Poly1305 while it is in cache, and the
    /// CPU can run the vector ChaCha20 and the scalar Poly1305 side by side. Block 0 gives the
    /// Poly1305 key; the rest of that first batch starts the keystream.
    fn crypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], seal: bool) -> [u8; 16] {
        let mut ks = [0; 512];
        let n = self.batch(nonce, 0, &mut ks);
        let mut p = Poly1305::new(ks[..32].try_into().unwrap());
        p.update_padded(aad);
        // Chunks are multiples of 64 bytes but for the last, so only the end gets padded.
        let step = |p: &mut Poly1305, chunk: &mut [u8], ks: &[u8]| {
            if !seal {
                p.update_padded(chunk);
            }
            xor(chunk, ks);
            if seal {
                p.update_padded(chunk);
            }
        };
        let (first, rest) = data.split_at_mut(data.len().min(n - 64));
        step(&mut p, first, &ks[64..]);
        let mut ctr = (n / 64) as u32;
        for chunk in rest.chunks_mut(n) {
            self.batch(nonce, ctr, &mut ks);
            ctr = ctr.wrapping_add((n / 64) as u32);
            step(&mut p, chunk, &ks);
        }
        let mut lens = [0; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(data.len() as u64).to_le_bytes());
        p.block(&lens, HIBIT);
        p.finish()
    }

    /// XOR `data` with the keystream starting at block `ctr`.
    #[cfg(test)]
    pub(super) fn apply(&self, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
        let mut ks = [0; 512];
        let mut ctr = ctr;
        let mut data = data;
        while !data.is_empty() {
            let n = self.batch(nonce, ctr, &mut ks);
            let (chunk, rest) = data.split_at_mut(data.len().min(n));
            xor(chunk, &ks);
            data = rest;
            ctr = ctr.wrapping_add((n / 64) as u32);
        }
    }

    /// Keystream blocks `ctr`, `ctr + 1`, ... into `out`: four or eight of them. Returns the
    /// number of bytes.
    fn batch(&self, nonce: &[u8; 12], ctr: u32, out: &mut [u8; 512]) -> usize {
        let n = nonce.as_chunks::<4>().0;
        let n = [u32::from_le_bytes(n[0]), u32::from_le_bytes(n[1]), u32::from_le_bytes(n[2])];
        match self.imp {
            Imp::Scalar => blocks::<[u32; 4]>(&self.k, &n, ctr, out),
            #[cfg(target_arch = "x86_64")]
            Imp::Simd => blocks::<x86::Sse>(&self.k, &n, ctr, out),
            #[cfg(target_arch = "aarch64")]
            Imp::Simd => blocks::<arm::Neon>(&self.k, &n, ctr, out),
            // SAFETY: Imp::Avx2 is only chosen after detecting AVX2 (Imp::best, or the tests on
            // machines that have it).
            #[cfg(target_arch = "x86_64")]
            Imp::Avx2 => unsafe { x86::blocks_avx2(&self.k, &n, ctr, out) },
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.k = [0; 8];
        std::hint::black_box(&self.k);
    }
}

fn xor(data: &mut [u8], ks: &[u8]) {
    for (d, k) in data.iter_mut().zip(ks) {
        *d ^= k;
    }
}

/// The same state word of `BLOCKS` ChaCha20 blocks.
trait Lanes: Copy {
    const BLOCKS: usize;
    fn splat(x: u32) -> Self;
    /// `c`, `c + 1`, ... lane by lane.
    fn count(c: u32) -> Self;
    fn add(self, b: Self) -> Self;
    fn xor(self, b: Self) -> Self;
    /// Rotate left by `L`; `R` is 32 - `L`.
    fn rotl<const L: i32, const R: i32>(self) -> Self;
    fn rot16(self) -> Self {
        self.rotl::<16, 16>()
    }
    fn rot8(self) -> Self {
        self.rotl::<8, 24>()
    }
    /// Write state words `4g .. 4g + 4` (`v[0]` .. `v[3]`) of each block to its place in `out`.
    fn store(v: [Self; 4], g: usize, out: &mut [u8; 512]);
}

/// ChaCha20 blocks `ctr` .. `ctr + V::BLOCKS` into `out`; returns the byte count.
#[inline(always)]
fn blocks<V: Lanes>(key: &[u32; 8], nonce: &[u32; 3], ctr: u32, out: &mut [u8; 512]) -> usize {
    let mut s = [V::splat(0); 16];
    for (s, w) in s.iter_mut().zip([0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574].iter().chain(key)) {
        *s = V::splat(*w);
    }
    s[12] = V::count(ctr);
    for i in 0..3 {
        s[13 + i] = V::splat(nonce[i]);
    }
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
    for g in 0..4 {
        let w = 4 * g;
        V::store([x[w].add(s[w]), x[w + 1].add(s[w + 1]), x[w + 2].add(s[w + 2]), x[w + 3].add(s[w + 3])], g, out);
    }
    64 * V::BLOCKS
}

#[inline(always)]
fn quarter<V: Lanes>(x: &mut [V; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].add(x[b]);
    x[d] = x[d].xor(x[a]).rot16();
    x[c] = x[c].add(x[d]);
    x[b] = x[b].xor(x[c]).rotl::<12, 20>();
    x[a] = x[a].add(x[b]);
    x[d] = x[d].xor(x[a]).rot8();
    x[c] = x[c].add(x[d]);
    x[b] = x[b].xor(x[c]).rotl::<7, 25>();
}

impl Lanes for [u32; 4] {
    const BLOCKS: usize = 4;
    fn splat(x: u32) -> Self {
        [x; 4]
    }
    fn count(c: u32) -> Self {
        [c, c.wrapping_add(1), c.wrapping_add(2), c.wrapping_add(3)]
    }
    fn add(self, b: Self) -> Self {
        [self[0].wrapping_add(b[0]), self[1].wrapping_add(b[1]), self[2].wrapping_add(b[2]), self[3].wrapping_add(b[3])]
    }
    fn xor(self, b: Self) -> Self {
        [self[0] ^ b[0], self[1] ^ b[1], self[2] ^ b[2], self[3] ^ b[3]]
    }
    fn rotl<const L: i32, const R: i32>(self) -> Self {
        self.map(|x| x.rotate_left(L as u32))
    }
    fn store(v: [Self; 4], g: usize, out: &mut [u8; 512]) {
        for (j, block) in out.as_chunks_mut::<64>().0[..4].iter_mut().enumerate() {
            for (k, v) in v.iter().enumerate() {
                block[16 * g + 4 * k..][..4].copy_from_slice(&v[j].to_le_bytes());
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::Lanes;
    use std::arch::x86_64::*;

    /// Write 16 bytes at `out[at..]`.
    #[inline(always)]
    fn put(out: &mut [u8; 512], at: usize, v: __m128i) {
        let dst: &mut [u8; 16] = (&mut out[at..at + 16]).try_into().unwrap();
        // SAFETY: an unaligned 16-byte write to a 16-byte array; SSE2 is part of x86_64.
        unsafe { _mm_storeu_si128(dst.as_mut_ptr().cast(), v) }
    }

    /// 4x4 transpose of u32, within each 128-bit half.
    macro_rules! transpose {
        ($v:expr, $lo32:ident, $hi32:ident, $lo64:ident, $hi64:ident) => {{
            let [a, b, c, d] = $v;
            let (t0, t1) = ($lo32(a, b), $lo32(c, d));
            let (t2, t3) = ($hi32(a, b), $hi32(c, d));
            [$lo64(t0, t1), $hi64(t0, t1), $lo64(t2, t3), $hi64(t2, t3)]
        }};
    }

    #[derive(Clone, Copy)]
    pub(super) struct Sse(__m128i);

    // SAFETY, for every `unsafe` in this impl: SSE2 is part of every x86_64 CPU.
    impl Lanes for Sse {
        const BLOCKS: usize = 4;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            Sse(unsafe { _mm_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn count(c: u32) -> Self {
            let c = [c, c.wrapping_add(1), c.wrapping_add(2), c.wrapping_add(3)].map(|c| c as i32);
            Sse(unsafe { _mm_setr_epi32(c[0], c[1], c[2], c[3]) })
        }
        #[inline(always)]
        fn add(self, b: Self) -> Self {
            Sse(unsafe { _mm_add_epi32(self.0, b.0) })
        }
        #[inline(always)]
        fn xor(self, b: Self) -> Self {
            Sse(unsafe { _mm_xor_si128(self.0, b.0) })
        }
        #[inline(always)]
        fn rotl<const L: i32, const R: i32>(self) -> Self {
            Sse(unsafe { _mm_or_si128(_mm_slli_epi32::<L>(self.0), _mm_srli_epi32::<R>(self.0)) })
        }
        #[inline(always)]
        fn rot16(self) -> Self {
            Sse(unsafe { _mm_shufflehi_epi16::<0xb1>(_mm_shufflelo_epi16::<0xb1>(self.0)) })
        }
        #[inline(always)]
        fn store(v: [Self; 4], g: usize, out: &mut [u8; 512]) {
            let r = unsafe {
                transpose!(
                    v.map(|v| v.0),
                    _mm_unpacklo_epi32,
                    _mm_unpackhi_epi32,
                    _mm_unpacklo_epi64,
                    _mm_unpackhi_epi64
                )
            };
            for (j, r) in r.into_iter().enumerate() {
                put(out, 64 * j + 16 * g, r);
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Avx(__m256i);

    #[target_feature(enable = "avx2")]
    pub(super) fn blocks_avx2(key: &[u32; 8], nonce: &[u32; 3], ctr: u32, out: &mut [u8; 512]) -> usize {
        super::blocks::<Avx>(key, nonce, ctr, out)
    }

    // SAFETY, for every `unsafe` in this impl: Avx values exist only inside blocks_avx2, which
    // runs only on CPUs with AVX2.
    impl Lanes for Avx {
        const BLOCKS: usize = 8;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            Avx(unsafe { _mm256_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn count(c: u32) -> Self {
            let c: [i32; 8] = std::array::from_fn(|i| c.wrapping_add(i as u32) as i32);
            Avx(unsafe { _mm256_setr_epi32(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]) })
        }
        #[inline(always)]
        fn add(self, b: Self) -> Self {
            Avx(unsafe { _mm256_add_epi32(self.0, b.0) })
        }
        #[inline(always)]
        fn xor(self, b: Self) -> Self {
            Avx(unsafe { _mm256_xor_si256(self.0, b.0) })
        }
        #[inline(always)]
        fn rotl<const L: i32, const R: i32>(self) -> Self {
            Avx(unsafe { _mm256_or_si256(_mm256_slli_epi32::<L>(self.0), _mm256_srli_epi32::<R>(self.0)) })
        }
        #[inline(always)]
        fn rot16(self) -> Self {
            #[rustfmt::skip]
            let m = unsafe { _mm256_setr_epi8(
                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
            ) };
            Avx(unsafe { _mm256_shuffle_epi8(self.0, m) })
        }
        #[inline(always)]
        fn rot8(self) -> Self {
            #[rustfmt::skip]
            let m = unsafe { _mm256_setr_epi8(
                3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
                3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
            ) };
            Avx(unsafe { _mm256_shuffle_epi8(self.0, m) })
        }
        #[inline(always)]
        fn store(v: [Self; 4], g: usize, out: &mut [u8; 512]) {
            // The transpose works within 128-bit halves: the low half of `r[j]` is block `j`,
            // the high half block `j + 4`.
            let r = unsafe {
                transpose!(
                    v.map(|v| v.0),
                    _mm256_unpacklo_epi32,
                    _mm256_unpackhi_epi32,
                    _mm256_unpacklo_epi64,
                    _mm256_unpackhi_epi64
                )
            };
            for (j, r) in r.into_iter().enumerate() {
                let (lo, hi) = unsafe { (_mm256_castsi256_si128(r), _mm256_extracti128_si256::<1>(r)) };
                put(out, 64 * j + 16 * g, lo);
                put(out, 64 * (j + 4) + 16 * g, hi);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::Lanes;
    use std::arch::aarch64::*;

    #[derive(Clone, Copy)]
    pub(super) struct Neon(uint32x4_t);

    // SAFETY, for every `unsafe` in this impl: NEON is part of every aarch64 CPU.
    impl Lanes for Neon {
        const BLOCKS: usize = 4;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            Neon(unsafe { vdupq_n_u32(x) })
        }
        #[inline(always)]
        fn count(c: u32) -> Self {
            let c = [c, c.wrapping_add(1), c.wrapping_add(2), c.wrapping_add(3)];
            Neon(unsafe { vld1q_u32(c.as_ptr()) })
        }
        #[inline(always)]
        fn add(self, b: Self) -> Self {
            Neon(unsafe { vaddq_u32(self.0, b.0) })
        }
        #[inline(always)]
        fn xor(self, b: Self) -> Self {
            Neon(unsafe { veorq_u32(self.0, b.0) })
        }
        #[inline(always)]
        fn rotl<const L: i32, const R: i32>(self) -> Self {
            // Shift left, then shift right and insert into the vacated low bits.
            Neon(unsafe { vsriq_n_u32::<R>(vshlq_n_u32::<L>(self.0), self.0) })
        }
        #[inline(always)]
        fn rot16(self) -> Self {
            Neon(unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(self.0))) })
        }
        #[inline(always)]
        fn store(v: [Self; 4], g: usize, out: &mut [u8; 512]) {
            let [a, b, c, d] = v.map(|v| v.0);
            let r = unsafe {
                let (t0, t1) = (vtrn1q_u32(a, b), vtrn2q_u32(a, b));
                let (t2, t3) = (vtrn1q_u32(c, d), vtrn2q_u32(c, d));
                let q = |x| vreinterpretq_u64_u32(x);
                let u = |x| vreinterpretq_u32_u64(x);
                [
                    u(vtrn1q_u64(q(t0), q(t2))),
                    u(vtrn1q_u64(q(t1), q(t3))),
                    u(vtrn2q_u64(q(t0), q(t2))),
                    u(vtrn2q_u64(q(t1), q(t3))),
                ]
            };
            for (j, r) in r.into_iter().enumerate() {
                let dst: &mut [u8; 16] = (&mut out[64 * j + 16 * g..][..16]).try_into().unwrap();
                // SAFETY: a 16-byte write to a 16-byte array.
                unsafe { vst1q_u8(dst.as_mut_ptr(), vreinterpretq_u8_u32(r)) }
            }
        }
    }
}

/// The 2^128 bit of a full block.
pub(super) const HIBIT: u64 = 1;

/// Poly1305 in radix 2^64, as in OpenSSL's poly1305.c: h in two 64-bit words and a few bits
/// above, r in two words. Clamping clears the low two bits of r1, so the part of h1 * r1 at
/// 2^128 folds back exactly as h1 * (r1 + r1 / 4) (2^130 = 5 mod p). Four wide multiplies a
/// block, which also suits 32-bit CPUs.
pub(super) struct Poly1305 {
    r: [u64; 2],
    h: [u64; 3],
    s: [u64; 2],
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

impl Poly1305 {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        let r = [le64(&key[..8]) & 0x0fff_fffc_0fff_ffff, le64(&key[8..16]) & 0x0fff_fffc_0fff_fffc];
        Poly1305 { r, h: [0; 3], s: [le64(&key[16..24]), le64(&key[24..])] }
    }

    /// h = (h + m + hibit * 2^128) * r, partly reduced: h < 2^130 + 2^128 after.
    pub(super) fn block(&mut self, m: &[u8; 16], hibit: u64) {
        let [r0, r1] = self.r;
        let s1 = r1 + (r1 >> 2);
        let [h0, h1, h2] = self.h;
        let t = h0 as u128 + le64(&m[..8]) as u128;
        let h0 = t as u64;
        let t = h1 as u128 + le64(&m[8..]) as u128 + (t >> 64);
        let h1 = t as u64;
        let h2 = h2 + (t >> 64) as u64 + hibit;

        let mul = |a: u64, b: u64| a as u128 * b as u128;
        let d0 = mul(h0, r0) + mul(h1, s1);
        let d1 = mul(h0, r1) + mul(h1, r0) + (h2 * s1) as u128 + (d0 >> 64);
        let h2 = h2 * r0 + (d1 >> 64) as u64;

        // Fold the bits from 2^130 up back in, times 5.
        let c = (h2 >> 2) + (h2 & !3);
        let t = d0 as u64 as u128 + c as u128;
        let u = d1 as u64 as u128 + (t >> 64);
        self.h = [t as u64, u as u64, (h2 & 3) + (u >> 64) as u64];
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
        let [h0, h1, h2] = self.h;
        // g = h + 5; if that reaches 2^130, h >= p and the result is g's low 128 bits.
        let t = h0 as u128 + 5;
        let u = h1 as u128 + (t >> 64);
        let take_g = 0u64.wrapping_sub((h2 + (u >> 64) as u64) >> 2);
        let h0 = (h0 & !take_g) | (t as u64 & take_g);
        let h1 = (h1 & !take_g) | (u as u64 & take_g);
        let t = h0 as u128 + self.s[0] as u128;
        let h1 = h1.wrapping_add(self.s[1]).wrapping_add((t >> 64) as u64);
        let mut tag = [0; 16];
        tag[..8].copy_from_slice(&(t as u64).to_le_bytes());
        tag[8..].copy_from_slice(&h1.to_le_bytes());
        tag
    }
}
