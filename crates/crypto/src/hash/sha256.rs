//! SHA-256 (FIPS 180-4 section 6.2), with the x86 SHA extensions or the ARMv8 SHA-256
//! instructions when the CPU has them.

pub(super) const IV: [u32; 8] =
    [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Hashes whole 64-byte blocks into `state`, with the fastest code the CPU runs.
pub(super) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sha") && std::arch::is_x86_feature_detected!("sse4.1") {
        // SAFETY: the CPU has the SHA extensions and SSE4.1.
        return unsafe { x86::compress(state, blocks) };
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: the CPU has the SHA-256 instructions.
        return unsafe { arm::compress(state, blocks) };
    }
    compress_soft(state, blocks)
}

/// Plain Rust, for CPUs without SHA instructions.
fn compress_soft(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.as_chunks::<64>().0 {
        let mut w = [0u32; 16];
        for (w, b) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *w = u32::from_be_bytes(*b);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        // Sixteen rounds at a time; from round 16 on, w[j] is rewritten to hold W[i + j].
        for i in (0..64).step_by(16) {
            macro_rules! round {
                ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $j:literal) => {
                    if i > 0 {
                        let (w1, w14) = (w[($j + 1) & 15], w[($j + 14) & 15]);
                        let s0 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
                        let s1 = w14.rotate_right(17) ^ w14.rotate_right(19) ^ (w14 >> 10);
                        w[$j] = w[$j].wrapping_add(s0).wrapping_add(w[($j + 9) & 15]).wrapping_add(s1);
                    }
                    let s1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
                    let ch = $g ^ ($e & ($f ^ $g));
                    let t1 = $h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i + $j].wrapping_add(w[$j]));
                    let s0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
                    let maj = ($a & $b) | ($c & ($a | $b));
                    $d = $d.wrapping_add(t1);
                    $h = t1.wrapping_add(s0).wrapping_add(maj);
                };
            }
            round!(a, b, c, d, e, f, g, h, 0);
            round!(h, a, b, c, d, e, f, g, 1);
            round!(g, h, a, b, c, d, e, f, 2);
            round!(f, g, h, a, b, c, d, e, 3);
            round!(e, f, g, h, a, b, c, d, 4);
            round!(d, e, f, g, h, a, b, c, 5);
            round!(c, d, e, f, g, h, a, b, 6);
            round!(b, c, d, e, f, g, h, a, 7);
            round!(a, b, c, d, e, f, g, h, 8);
            round!(h, a, b, c, d, e, f, g, 9);
            round!(g, h, a, b, c, d, e, f, 10);
            round!(f, g, h, a, b, c, d, e, 11);
            round!(e, f, g, h, a, b, c, d, 12);
            round!(d, e, f, g, h, a, b, c, 13);
            round!(c, d, e, f, g, h, a, b, 14);
            round!(b, c, d, e, f, g, h, a, 15);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::K;
    use std::arch::x86_64::*;

    /// The Intel SHA extensions keep the state as ABEF and CDGH and run two rounds per
    /// instruction.
    ///
    /// # Safety
    ///
    /// The CPU must have the SHA extensions and SSE4.1.
    #[target_feature(enable = "sha,sse4.1")]
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        let bswap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        let p = state.as_mut_ptr().cast::<__m128i>();
        // SAFETY: `state` is 32 bytes; the loads are unaligned.
        let (dcba, hgfe) = unsafe { (_mm_loadu_si128(p), _mm_loadu_si128(p.add(1))) };
        let cdab = _mm_shuffle_epi32(dcba, 0xb1);
        let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
        let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
        let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);

        for block in blocks.as_chunks::<64>().0 {
            let (abef0, cdgh0) = (abef, cdgh);
            let b = block.as_ptr().cast::<__m128i>();
            // SAFETY: the block is 64 bytes; the loads are unaligned.
            let (mut w0, mut w1, mut w2, mut w3) = unsafe {
                (_mm_loadu_si128(b), _mm_loadu_si128(b.add(1)), _mm_loadu_si128(b.add(2)), _mm_loadu_si128(b.add(3)))
            };
            w0 = _mm_shuffle_epi8(w0, bswap);
            w1 = _mm_shuffle_epi8(w1, bswap);
            w2 = _mm_shuffle_epi8(w2, bswap);
            w3 = _mm_shuffle_epi8(w3, bswap);
            // Four rounds per step: w0 holds their message words, w1..w3 the next twelve.
            for i in 0..16 {
                // SAFETY: K has 64 words; the load is unaligned.
                let k = unsafe { _mm_loadu_si128(K.as_ptr().add(4 * i).cast()) };
                let wk = _mm_add_epi32(w0, k);
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
                let next = _mm_add_epi32(_mm_sha256msg1_epu32(w0, w1), _mm_alignr_epi8(w3, w2, 4));
                (w0, w1, w2, w3) = (w1, w2, w3, _mm_sha256msg2_epu32(next, w3));
            }
            abef = _mm_add_epi32(abef, abef0);
            cdgh = _mm_add_epi32(cdgh, cdgh0);
        }

        let feba = _mm_shuffle_epi32(abef, 0x1b);
        let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
        // SAFETY: `state` is 32 bytes; the stores are unaligned.
        unsafe {
            _mm_storeu_si128(p, _mm_blend_epi16(feba, dchg, 0xf0));
            _mm_storeu_si128(p.add(1), _mm_alignr_epi8(dchg, feba, 8));
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::K;
    use std::arch::aarch64::*;

    /// The ARMv8 SHA-256 instructions run four rounds per pair of instructions.
    ///
    /// # Safety
    ///
    /// The CPU must have the SHA-256 instructions.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: `state` is 8 words.
        let (mut abcd, mut efgh) = unsafe { (vld1q_u32(state.as_ptr()), vld1q_u32(state.as_ptr().add(4))) };
        for block in blocks.as_chunks::<64>().0 {
            let (abcd0, efgh0) = (abcd, efgh);
            let b = block.as_ptr();
            // SAFETY: the block is 64 bytes.
            let (w0, w1, w2, w3) =
                unsafe { (vld1q_u8(b), vld1q_u8(b.add(16)), vld1q_u8(b.add(32)), vld1q_u8(b.add(48))) };
            let mut w0 = vreinterpretq_u32_u8(vrev32q_u8(w0));
            let mut w1 = vreinterpretq_u32_u8(vrev32q_u8(w1));
            let mut w2 = vreinterpretq_u32_u8(vrev32q_u8(w2));
            let mut w3 = vreinterpretq_u32_u8(vrev32q_u8(w3));
            for i in 0..16 {
                // SAFETY: K has 64 words.
                let wk = vaddq_u32(w0, unsafe { vld1q_u32(K.as_ptr().add(4 * i)) });
                let abcd_in = abcd;
                abcd = vsha256hq_u32(abcd_in, efgh, wk);
                efgh = vsha256h2q_u32(efgh, abcd_in, wk);
                (w0, w1, w2, w3) = (w1, w2, w3, vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3));
            }
            abcd = vaddq_u32(abcd, abcd0);
            efgh = vaddq_u32(efgh, efgh0);
        }
        // SAFETY: `state` is 8 words.
        unsafe {
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
        }
    }
}

#[cfg(test)]
mod tests {
    /// The accelerated code, if this CPU has it, against the plain code.
    #[test]
    fn soft_matches_dispatch() {
        let mut data = vec![0u8; 64 * 40];
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in &mut data {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        for n in 0..=40 {
            let (mut a, mut b) = (super::IV, super::IV);
            super::compress(&mut a, &data[..64 * n]);
            super::compress_soft(&mut b, &data[..64 * n]);
            assert_eq!(a, b, "{n} blocks");
        }
    }
}
