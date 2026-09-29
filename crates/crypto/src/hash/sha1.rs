//! SHA-1 (FIPS 180-4 section 6.1). Only old lockfiles' integrity strings use it, so it stays
//! small rather than fast.

pub(super) const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Hashes whole 64-byte blocks into `state`.
pub(super) fn compress(state: &mut [u32; 5], blocks: &[u8]) {
    for block in blocks.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (w, b) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *w = u32::from_be_bytes(*b);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (t, &w) in w.iter().enumerate() {
            let (f, k) = match t / 20 {
                0 => (d ^ (b & (c ^ d)), 0x5a827999),
                1 => (b ^ c ^ d, 0x6ed9eba1),
                2 => ((b & c) | (d & (b | c)), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}
