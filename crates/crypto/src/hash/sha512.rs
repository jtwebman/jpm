//! SHA-512 and SHA-384 (FIPS 180-4 sections 6.4 and 6.5), which differ only in their initial
//! values and output length. The ARMv8.2 SHA-512 instructions run it when the CPU has them;
//! x86 has no such instructions before Arrow Lake, so it runs plain code there.

pub(super) const IV_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub(super) const IV_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// Hashes whole 128-byte blocks into `state`, with the fastest code the CPU runs.
pub(super) fn compress(state: &mut [u64; 8], blocks: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha3") {
        // SAFETY: the CPU has the SHA-512 instructions.
        return unsafe { arm::compress(state, blocks) };
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("bmi2") {
        // SAFETY: the CPU has BMI2.
        return unsafe { compress_bmi2(state, blocks) };
    }
    compress_soft(state, blocks)
}

/// The plain code again, compiled to use BMI2's flagless rotate (rorx): about 7% faster on the
/// tarball path for 4 KB of code.
///
/// # Safety
///
/// The CPU must have BMI2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2")]
unsafe fn compress_bmi2(state: &mut [u64; 8], blocks: &[u8]) {
    compress_soft(state, blocks)
}

/// Plain Rust. Always inlined, so `compress_bmi2` gets its own copy.
#[inline(always)]
fn compress_soft(state: &mut [u64; 8], blocks: &[u8]) {
    for block in blocks.as_chunks::<128>().0 {
        let mut w = [0u64; 16];
        for (w, b) in w.iter_mut().zip(block.as_chunks::<8>().0) {
            *w = u64::from_be_bytes(*b);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        // Sixteen rounds at a time; from round 16 on, w[j] is rewritten to hold W[i + j].
        for i in (0..80).step_by(16) {
            macro_rules! round {
                ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $j:literal) => {
                    if i > 0 {
                        let (w1, w14) = (w[($j + 1) & 15], w[($j + 14) & 15]);
                        let s0 = w1.rotate_right(1) ^ w1.rotate_right(8) ^ (w1 >> 7);
                        let s1 = w14.rotate_right(19) ^ w14.rotate_right(61) ^ (w14 >> 6);
                        w[$j] = w[$j].wrapping_add(s0).wrapping_add(w[($j + 9) & 15]).wrapping_add(s1);
                    }
                    let s1 = $e.rotate_right(14) ^ $e.rotate_right(18) ^ $e.rotate_right(41);
                    let ch = $g ^ ($e & ($f ^ $g));
                    let t1 = $h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i + $j].wrapping_add(w[$j]));
                    let s0 = $a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39);
                    let maj = ($a & $b) ^ ($c & ($a ^ $b));
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

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::K;
    use std::arch::aarch64::*;

    /// The ARMv8.2 SHA-512 instructions keep the state in pairs (ab, cd, ef, gh) and run two
    /// rounds per pair of instructions.
    ///
    /// # Safety
    ///
    /// The CPU must have the SHA-512 instructions (Rust's `sha3` feature).
    #[target_feature(enable = "sha3")]
    pub(super) unsafe fn compress(state: &mut [u64; 8], blocks: &[u8]) {
        let p = state.as_mut_ptr();
        // SAFETY: `state` is 8 words.
        let [mut ab, mut cd, mut ef, mut gh] = unsafe { [0, 2, 4, 6].map(|i| vld1q_u64(p.add(i))) };
        for block in blocks.as_chunks::<128>().0 {
            let orig = [ab, cd, ef, gh];
            let b = block.as_ptr();
            // SAFETY: the block is 128 bytes.
            let mut w = unsafe { [0, 1, 2, 3, 4, 5, 6, 7].map(|i| vld1q_u8(b.add(16 * i))) }
                .map(|v| vreinterpretq_u64_u8(vrev64q_u8(v)));

            // Two rounds on message words `w`: `x` takes the new pair and `z` is updated; the
            // roles rotate by one pair each time.
            macro_rules! rounds2 {
                ($w:expr, $k:expr, $x:ident, $y:ident, $z:ident, $v:ident) => {
                    // SAFETY: $k + 2 <= 80.
                    let wk = vaddq_u64($w, unsafe { vld1q_u64(K.as_ptr().add($k)) });
                    let sum = vaddq_u64(vextq_u64(wk, wk, 1), $x);
                    let t = vsha512hq_u64(sum, vextq_u64($y, $x, 1), vextq_u64($z, $y, 1));
                    $x = vsha512h2q_u64(t, $z, $v);
                    $z = vaddq_u64($z, t);
                };
            }
            for i in 0..5 {
                if i > 0 {
                    // Message words for the next sixteen rounds, two at a time.
                    for j in 0..8 {
                        let mid = vextq_u64(w[(j + 4) % 8], w[(j + 5) % 8], 1);
                        w[j] = vsha512su1q_u64(vsha512su0q_u64(w[j], w[(j + 1) % 8]), w[(j + 7) % 8], mid);
                    }
                }
                let k = 16 * i;
                rounds2!(w[0], k, gh, ef, cd, ab);
                rounds2!(w[1], k + 2, ef, cd, ab, gh);
                rounds2!(w[2], k + 4, cd, ab, gh, ef);
                rounds2!(w[3], k + 6, ab, gh, ef, cd);
                rounds2!(w[4], k + 8, gh, ef, cd, ab);
                rounds2!(w[5], k + 10, ef, cd, ab, gh);
                rounds2!(w[6], k + 12, cd, ab, gh, ef);
                rounds2!(w[7], k + 14, ab, gh, ef, cd);
            }
            ab = vaddq_u64(ab, orig[0]);
            cd = vaddq_u64(cd, orig[1]);
            ef = vaddq_u64(ef, orig[2]);
            gh = vaddq_u64(gh, orig[3]);
        }
        // SAFETY: `state` is 8 words.
        unsafe {
            vst1q_u64(p, ab);
            vst1q_u64(p.add(2), cd);
            vst1q_u64(p.add(4), ef);
            vst1q_u64(p.add(6), gh);
        }
    }
}

#[cfg(test)]
mod tests {
    /// The accelerated code, if this CPU has it, against the plain code.
    #[test]
    fn soft_matches_dispatch() {
        let mut data = vec![0u8; 128 * 20];
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in &mut data {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        for n in 0..=20 {
            let (mut a, mut b) = (super::IV_512, super::IV_512);
            super::compress(&mut a, &data[..128 * n]);
            super::compress_soft(&mut b, &data[..128 * n]);
            assert_eq!(a, b, "{n} blocks");
        }
    }
}
