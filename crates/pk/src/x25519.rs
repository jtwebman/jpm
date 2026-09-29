//! X25519 (RFC 7748), in constant time.
//!
//! A field element mod p = 2^255 - 19 is five 51-bit limbs, least significant first. Limbs may
//! run a few bits over 51 between operations; `mul` takes limbs up to about 2^54 and returns
//! limbs just over 2^51, so sums of two products can go straight into another product. Only
//! `to_bytes` reduces fully.

type Fe = [u64; 5];

const MASK: u64 = (1 << 51) - 1;

fn load(b: &[u8; 32]) -> Fe {
    let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3));
    // The top bit is ignored, as RFC 7748 says for u-coordinates.
    [
        w0 & MASK,
        (w0 >> 51 | w1 << 13) & MASK,
        (w1 >> 38 | w2 << 26) & MASK,
        (w2 >> 25 | w3 << 39) & MASK,
        (w3 >> 12) & MASK,
    ]
}

fn add(a: &Fe, b: &Fe) -> Fe {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]]
}

/// a - b, computed as a + 4p - b so no limb goes negative (b's limbs are below 2^53).
fn sub(a: &Fe, b: &Fe) -> Fe {
    const P4_0: u64 = 4 * ((1 << 51) - 19);
    const P4: u64 = 4 * MASK;
    carry([
        (a[0] + P4_0 - b[0]) as u128,
        (a[1] + P4 - b[1]) as u128,
        (a[2] + P4 - b[2]) as u128,
        (a[3] + P4 - b[3]) as u128,
        (a[4] + P4 - b[4]) as u128,
    ])
}

/// Carries 128-bit column sums back down to limbs just over 51 bits. 2^255 = 19 mod p, so the
/// carry out of the top limb comes back in at the bottom times 19.
fn carry(mut c: [u128; 5]) -> Fe {
    c[1] += c[0] >> 51;
    c[2] += c[1] >> 51;
    c[3] += c[2] >> 51;
    c[4] += c[3] >> 51;
    let low = (c[0] as u64 & MASK) as u128 + (c[4] >> 51) * 19;
    [
        low as u64 & MASK,
        (c[1] as u64 & MASK) + (low >> 51) as u64,
        c[2] as u64 & MASK,
        c[3] as u64 & MASK,
        c[4] as u64 & MASK,
    ]
}

fn mul(a: &Fe, b: &Fe) -> Fe {
    let m = |x: u64, y: u64| x as u128 * y as u128;
    let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
    carry([
        m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4),
        m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4),
        m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4),
        m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4),
        m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]),
    ])
}

fn sq(a: &Fe) -> Fe {
    let m = |x: u64, y: u64| x as u128 * y as u128;
    let (d0, d1, d2, d3) = (a[0] * 2, a[1] * 2, a[2] * 2, a[3] * 2);
    let (a3_19, a4_19) = (a[3] * 19, a[4] * 19);
    carry([
        m(a[0], a[0]) + m(d1, a4_19) + m(d2, a3_19),
        m(d0, a[1]) + m(d2, a4_19) + m(a[3], a3_19),
        m(d0, a[2]) + m(a[1], a[1]) + m(d3, a4_19),
        m(d0, a[3]) + m(d1, a[2]) + m(a[4], a4_19),
        m(d0, a[4]) + m(d1, a[3]) + m(a[2], a[2]),
    ])
}

fn sq_n(a: &Fe, n: usize) -> Fe {
    let mut r = sq(a);
    for _ in 1..n {
        r = sq(&r);
    }
    r
}

/// z^(p-2) = 1/z, with the addition chain from the curve25519 reference code.
fn invert(z: &Fe) -> Fe {
    let z2 = sq(z);
    let z9 = mul(&sq_n(&z2, 2), z);
    let z11 = mul(&z9, &z2);
    let z_5_0 = mul(&sq(&z11), &z9);
    let z_10_0 = mul(&sq_n(&z_5_0, 5), &z_5_0);
    let z_20_0 = mul(&sq_n(&z_10_0, 10), &z_10_0);
    let z_40_0 = mul(&sq_n(&z_20_0, 20), &z_20_0);
    let z_50_0 = mul(&sq_n(&z_40_0, 10), &z_10_0);
    let z_100_0 = mul(&sq_n(&z_50_0, 50), &z_50_0);
    let z_200_0 = mul(&sq_n(&z_100_0, 100), &z_100_0);
    let z_250_0 = mul(&sq_n(&z_200_0, 50), &z_50_0);
    mul(&sq_n(&z_250_0, 5), &z11)
}

fn to_bytes(a: &Fe) -> [u8; 32] {
    let mut l = carry(a.map(u128::from));
    // Now l < 2p. Add 19: the carry out of bit 255 is 1 exactly when l >= p, and then l - p is
    // l + 19 with bit 255 dropped.
    let mut q = (l[0] + 19) >> 51;
    for x in &l[1..] {
        q = (x + q) >> 51;
    }
    l[0] += 19 * q;
    for i in 0..4 {
        l[i + 1] += l[i] >> 51;
        l[i] &= MASK;
    }
    l[4] &= MASK;
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(l[0] | l[1] << 51).to_le_bytes());
    out[8..16].copy_from_slice(&(l[1] >> 13 | l[2] << 38).to_le_bytes());
    out[16..24].copy_from_slice(&(l[2] >> 26 | l[3] << 25).to_le_bytes());
    out[24..32].copy_from_slice(&(l[3] >> 39 | l[4] << 12).to_le_bytes());
    out
}

/// Swaps a and b when bit is 1, without a branch.
fn cswap(bit: u64, a: &mut Fe, b: &mut Fe) {
    let mask = std::hint::black_box(bit.wrapping_neg());
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// The Montgomery ladder of RFC 7748 section 5.
fn scalar_mult(secret: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *secret;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = load(u);
    let (mut x2, mut z2, mut x3, mut z3) = ([1, 0, 0, 0, 0], [0; 5], x1, [1, 0, 0, 0, 0]);
    let mut swap = 0;
    for t in (0..255).rev() {
        let bit = (k[t / 8] >> (t % 8) & 1) as u64;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;
        let a = add(&x2, &z2);
        let aa = sq(&a);
        let b = sub(&x2, &z2);
        let bb = sq(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = sq(&add(&da, &cb));
        z3 = mul(&x1, &sq(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        // a24 = (486662 - 2) / 4 = 121665.
        z2 = mul(&e, &add(&aa, &carry(e.map(|x| x as u128 * 121665))));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    to_bytes(&mul(&x2, &invert(&z2)))
}

/// The public key for a secret of 32 random bytes (clamped here, as RFC 7748 says).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut base = [0; 32];
    base[0] = 9;
    scalar_mult(secret, &base)
}

/// The shared secret, or `None` when it is all zeros (the peer sent a low-order point).
pub fn shared_secret(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let k = scalar_mult(secret, peer);
    if jpm_crypto::ct_eq(&k, &[0; 32]) { None } else { Some(k) }
}
