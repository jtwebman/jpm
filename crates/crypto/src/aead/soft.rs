//! Portable, constant-time AES-GCM: AES bitsliced four blocks at a time after BearSSL's
//! aes_ct64, GHASH on integer multiplies after BearSSL's ghash_ctmul64. Also the AES key
//! schedule, which the hardware code shares.
//!
//! BearSSL is Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>, MIT licensed; see
//! THIRD_PARTY_NOTICES.md at the repository root.
//!
//! Bitsliced layout. Four blocks sit in eight u64 words `q`. Word `q[i]` holds bit `i` of every
//! byte of the four blocks, so one S-box circuit over the eight words substitutes all 64 bytes at
//! once, with no table and no branch. Within a word, bits `8 * b .. 8 * b + 8` come from byte
//! group `b`; bits 0-3 of the group are from blocks 0-3 and bits 4-7 from the same blocks' other
//! two columns. `interleave_in` spreads a block's bytes over two words so that `ortho`, an 8x8 bit
//! transpose within each byte position, reaches this layout; ShiftRows and MixColumns then become
//! shifts and rotations inside each word.

/// The AES key schedule for a 16- or 32-byte key: the round keys as little-endian words (the
/// standard byte order, four words a round) and the number of rounds.
pub(super) fn key_schedule(key: &[u8]) -> ([u32; 60], usize) {
    let nk = key.len() / 4;
    let nr = nk + 6;
    let mut w = [0u32; 60];
    for (w, k) in w.iter_mut().zip(key.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*k);
    }
    let mut rcon = 1;
    for i in nk..4 * (nr + 1) {
        let mut t = w[i - 1];
        if i % nk == 0 {
            // RotWord is a rotation by one byte; in a little-endian word, to the right.
            t = sub_word(t.rotate_right(8)) ^ rcon;
            rcon = (rcon << 1) ^ (0x11b & (rcon >> 7).wrapping_neg());
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        w[i] = t ^ w[i - nk];
    }
    (w, nr)
}

/// The S-box on each byte of `x`, through the bitsliced circuit.
fn sub_word(x: u32) -> u32 {
    let mut q = [0; 8];
    q[0] = x as u64;
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    q[0] as u32
}

pub(super) struct Gcm {
    /// Round keys, bitsliced: eight words a round, each key bit repeated for the four blocks.
    sk: [u64; 120],
    nr: usize,
    /// The GHASH key E(0), as two big-endian halves: `h[0]` the first eight bytes.
    h: [u64; 2],
}

impl Gcm {
    pub(super) fn new(w: &[u32; 60], nr: usize) -> Self {
        let mut sk = [0; 120];
        for (k, w) in sk.as_chunks_mut::<8>().0.iter_mut().zip(w.as_chunks::<4>().0).take(nr + 1) {
            let (a, b) = interleave_in(w);
            *k = [a, a, a, a, b, b, b, b];
            ortho(k);
        }
        let mut g = Gcm { sk, nr, h: [0; 2] };
        let mut h = [0; 16];
        super::Gcm::ctr(&g, &[0; 12], 0, &mut h);
        g.h = [be64(&h[..8]), be64(&h[8..])];
        g
    }

    /// Encrypt four blocks, given as little-endian words.
    fn encrypt4(&self, w: &[[u32; 4]; 4]) -> [u8; 64] {
        let mut q = [0; 8];
        for (i, w) in w.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(w);
        }
        ortho(&mut q);
        let rk = self.sk.as_chunks::<8>().0;
        add_round_key(&mut q, &rk[0]);
        for k in &rk[1..self.nr] {
            sbox(&mut q);
            shift_rows(&mut q);
            mix_columns(&mut q);
            add_round_key(&mut q, k);
        }
        sbox(&mut q);
        shift_rows(&mut q);
        add_round_key(&mut q, &rk[self.nr]);
        ortho(&mut q);
        let mut out = [0; 64];
        for (i, o) in out.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            for (o, w) in o.as_chunks_mut::<4>().0.iter_mut().zip(interleave_out(q[i], q[i + 4])) {
                *o = w.to_le_bytes();
            }
        }
        out
    }
}

impl super::Gcm for Gcm {
    fn ctr(&self, nonce: &[u8; 12], ctr: u32, data: &mut [u8]) {
        let n = nonce.as_chunks::<4>().0;
        let n = [u32::from_le_bytes(n[0]), u32::from_le_bytes(n[1]), u32::from_le_bytes(n[2])];
        let mut ctr = ctr;
        for chunk in data.chunks_mut(64) {
            let mut w = [[0; 4]; 4];
            for w in &mut w {
                *w = [n[0], n[1], n[2], ctr.swap_bytes()];
                ctr = ctr.wrapping_add(1);
            }
            for (d, k) in chunk.iter_mut().zip(self.encrypt4(&w)) {
                *d ^= k;
            }
        }
    }

    /// GHASH as in BearSSL's ghash_ctmul64. `bmul64` gives the low half of a 64x64 carry-less
    /// product; the high half is the low half of the product of the bit-reversed operands,
    /// reversed back. Three such products (Karatsuba) make the 256-bit product, which is shifted
    /// one bit (GHASH numbers bits from the top) and reduced modulo x^128 + x^7 + x^2 + x + 1.
    fn ghash(&self, y: &mut [u8; 16], data: &[u8]) {
        let [h1, h0] = self.h;
        let (h0r, h1r) = (h0.reverse_bits(), h1.reverse_bits());
        let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
        let (mut y1, mut y0) = (be64(&y[..8]), be64(&y[8..]));
        for block in data.chunks(16) {
            let mut b = [0; 16];
            b[..block.len()].copy_from_slice(block);
            y1 ^= be64(&b[..8]);
            y0 ^= be64(&b[8..]);
            let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
            let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
            let z0 = bmul64(y0, h0);
            let z1 = bmul64(y1, h1);
            let mut z2 = bmul64(y2, h2);
            let mut z0h = bmul64(y0r, h0r);
            let mut z1h = bmul64(y1r, h1r);
            let mut z2h = bmul64(y2r, h2r);
            z2 ^= z0 ^ z1;
            z2h ^= z0h ^ z1h;
            z0h = z0h.reverse_bits() >> 1;
            z1h = z1h.reverse_bits() >> 1;
            z2h = z2h.reverse_bits() >> 1;
            let (mut v0, mut v1, mut v2, mut v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
            v3 = (v3 << 1) | (v2 >> 63);
            v2 = (v2 << 1) | (v1 >> 63);
            v1 = (v1 << 1) | (v0 >> 63);
            v0 <<= 1;
            v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
            (y0, y1) = (v2, v3);
        }
        y[..8].copy_from_slice(&y1.to_be_bytes());
        y[8..].copy_from_slice(&y0.to_be_bytes());
    }
}

impl Drop for Gcm {
    fn drop(&mut self) {
        self.sk = [0; 120];
        self.h = [0; 2];
        std::hint::black_box(&self);
    }
}

fn be64(b: &[u8]) -> u64 {
    let mut a = [0; 8];
    a.copy_from_slice(b);
    u64::from_be_bytes(a)
}

/// Low 64 bits of the carry-less product of `x` and `y`, with plain multiplies: each operand is
/// split into four sparse masks, one bit in four, so carries of the integer products land in the
/// holes and are masked off.
fn bmul64(x: u64, y: u64) -> u64 {
    const M: [u64; 4] = [0x1111_1111_1111_1111, 0x2222_2222_2222_2222, 0x4444_4444_4444_4444, 0x8888_8888_8888_8888];
    let x = M.map(|m| x & m);
    let y = M.map(|m| y & m);
    let mut z = 0;
    for (i, m) in M.iter().enumerate() {
        let mut t = 0;
        for j in 0..4 {
            t ^= x[j].wrapping_mul(y[(i + 4 - j) % 4]);
        }
        z |= t & m;
    }
    z
}

fn add_round_key(q: &mut [u64; 8], k: &[u64; 8]) {
    for (q, k) in q.iter_mut().zip(k) {
        *q ^= k;
    }
}

/// Swap bits between pairs of words so that `q[i]` ends up with bit `i` of each byte of the
/// input words (an 8x8 transpose per byte position). Its own inverse.
fn ortho(q: &mut [u64; 8]) {
    fn swap(q: &mut [u64; 8], a: usize, b: usize, lo: u64, s: u32) {
        let hi = lo << s;
        let (x, y) = (q[a], q[b]);
        q[a] = (x & lo) | ((y & lo) << s);
        q[b] = ((x & hi) >> s) | (y & hi);
    }
    for i in [0, 2, 4, 6] {
        swap(q, i, i + 1, 0x5555_5555_5555_5555, 1);
    }
    for i in [0, 1, 4, 5] {
        swap(q, i, i + 2, 0x3333_3333_3333_3333, 2);
    }
    for i in 0..4 {
        swap(q, i, i + 4, 0x0F0F_0F0F_0F0F_0F0F, 4);
    }
}

/// Spread a block (four little-endian words) over two words: columns 0 and 2 (bytes 0-3 and 8-11)
/// to the first, byte by byte alternately, and columns 1 and 3 to the second.
fn interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let [x0, x1, x2, x3] = w.map(|w| {
        let x = w as u64;
        let x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
        (x | (x << 8)) & 0x00FF_00FF_00FF_00FF
    });
    (x0 | (x2 << 8), x1 | (x3 << 8))
}

fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    [q0, q1, q0 >> 8, q1 >> 8].map(|x| {
        let x = x & 0x00FF_00FF_00FF_00FF;
        let x = (x | (x >> 8)) & 0x0000_FFFF_0000_FFFF;
        x as u32 | (x >> 16) as u32
    })
}

fn shift_rows(q: &mut [u64; 8]) {
    for x in q {
        *x = (*x & 0x0000_0000_0000_FFFF)
            | ((*x & 0x0000_0000_FFF0_0000) >> 4)
            | ((*x & 0x0000_0000_000F_0000) << 12)
            | ((*x & 0x0000_FF00_0000_0000) >> 8)
            | ((*x & 0x0000_00FF_0000_0000) << 8)
            | ((*x & 0xF000_0000_0000_0000) >> 12)
            | ((*x & 0x0FFF_0000_0000_0000) << 4);
    }
}

fn mix_columns(q: &mut [u64; 8]) {
    let r = q.map(|x| x.rotate_right(16));
    let s = |i: usize| (q[i] ^ r[i]).rotate_right(32);
    let t = q[7] ^ r[7];
    *q = [
        t ^ r[0] ^ s(0),
        q[0] ^ r[0] ^ t ^ r[1] ^ s(1),
        q[1] ^ r[1] ^ r[2] ^ s(2),
        q[2] ^ r[2] ^ t ^ r[3] ^ s(3),
        q[3] ^ r[3] ^ t ^ r[4] ^ s(4),
        q[4] ^ r[4] ^ r[5] ^ s(5),
        q[5] ^ r[5] ^ r[6] ^ s(6),
        q[6] ^ r[6] ^ r[7] ^ s(7),
    ];
}

/// The AES S-box on all 64 bytes at once: the Boyar-Peralta circuit (eprint 2009/191), 113
/// gates. `x0` is the high bit.
fn sbox(q: &mut [u64; 8]) {
    let [x7, x6, x5, x4, x3, x2, x1, x0] = *q;

    // Top linear layer.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear middle: inversion in GF(2^8).
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear layer.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}
