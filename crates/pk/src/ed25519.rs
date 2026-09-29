//! Ed25519 signature verification (RFC 8032), on X25519's field arithmetic. Public data only, so
//! nothing here needs constant time. Strict: `s` must be below the group order and the public
//! key a canonical encoding of a point on the curve; the check is the cofactorless equation
//! `[s]B = R + [k]A`, as ring and BoringSSL do it.

use crate::x25519::{Fe, add, invert, load, mul, pow22523, sq, sub, to_bytes};
use jpm_crypto::hash::{Alg, Hasher};

/// A point in extended coordinates (X:Y:Z:T): x = X/Z, y = Y/Z, xy = T/Z.
type Point = [Fe; 4];

const ONE: Fe = [1, 0, 0, 0, 0];
/// The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u8; 32] = le("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
/// The curve's d = -121665/121666, sqrt(-1), and the base point's encoding (y = 4/5).
const D: [u8; 32] = le("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352");
const SQRT_M1: [u8; 32] = le("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b");
const BASE: [u8; 32] = le("5866666666666666666666666666666666666666666666666666666666666666");

/// 32 bytes written as hex in the order they are stored.
const fn le(s: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
    }
    let s = s.as_bytes();
    let mut out = [0; 32];
    let mut i = 0;
    while i < 64 {
        out[i / 2] = digit(s[i]) << 4 | digit(s[i + 1]);
        i += 2;
    }
    out
}

/// `public` the 32-byte key, `signature` the 64 bytes R || s.
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Some(a), Some(base), Ok(signature)) = (decode(public), decode(&BASE), <&[u8; 64]>::try_from(signature)) else {
        return false;
    };
    let (r, s) = signature.split_at(32);
    if !s.iter().rev().cmp(L.iter().rev()).is_lt() {
        return false;
    }
    let mut h = Hasher::new(Alg::Sha512);
    [r, public, message].iter().for_each(|p| h.update(p));
    let k = reduce(&h.finish());
    // [s]B - [k]A, one doubling per bit for both scalars together, must encode as R.
    let minus_a = [neg(&a[0]), a[1], a[2], neg(&a[3])];
    let d2 = add(&load(&D), &load(&D));
    let mut p = [[0; 5], ONE, ONE, [0; 5]];
    let bit = |b: &[u8], i: usize| b[i / 8] >> (i % 8) & 1 == 1;
    for i in (0..253).rev() {
        p = plus(&p, &p, &d2);
        if bit(s, i) {
            p = plus(&p, &base, &d2);
        }
        if bit(&k, i) {
            p = plus(&p, &minus_a, &d2);
        }
    }
    let z = invert(&p[2]);
    let mut out = to_bytes(&mul(&p[1], &z));
    out[31] |= (to_bytes(&mul(&p[0], &z))[0] & 1) << 7;
    out == r
}

fn neg(a: &Fe) -> Fe {
    sub(&[0; 5], a)
}

/// p + q with the unified formulas for a = -1 (add-2008-hwcd-3), which double too.
fn plus(p: &Point, q: &Point, d2: &Fe) -> Point {
    let a = mul(&sub(&p[1], &p[0]), &sub(&q[1], &q[0]));
    let b = mul(&add(&p[1], &p[0]), &add(&q[1], &q[0]));
    let c = mul(&mul(&p[3], d2), &q[3]);
    let d = mul(&add(&p[2], &p[2]), &q[2]);
    let (e, f, g, h) = (sub(&b, &a), sub(&d, &c), add(&d, &c), add(&b, &a));
    [mul(&e, &f), mul(&g, &h), mul(&f, &g), mul(&e, &h)]
}

/// A point from its encoding (RFC 8032 section 5.1.3), `None` when y is not below p or no x
/// fits it.
fn decode(bytes: &[u8]) -> Option<Point> {
    let bytes: &[u8; 32] = bytes.try_into().ok()?;
    let y = load(bytes);
    let mut canonical = *bytes;
    canonical[31] &= 0x7f;
    if to_bytes(&y) != canonical {
        return None;
    }
    // x^2 = u/v with u = y^2 - 1 and v = d y^2 + 1; the candidate root is u v^3 (u v^7)^((p-5)/8).
    let yy = sq(&y);
    let u = sub(&yy, &ONE);
    let v = add(&mul(&yy, &load(&D)), &ONE);
    let v3 = mul(&sq(&v), &v);
    let mut x = mul(&mul(&u, &v3), &pow22523(&mul(&u, &mul(&sq(&v3), &v))));
    let vxx = to_bytes(&mul(&v, &sq(&x)));
    if vxx == to_bytes(&neg(&u)) {
        x = mul(&x, &load(&SQRT_M1));
    } else if vxx != to_bytes(&u) {
        return None;
    }
    let (sign, low) = (bytes[31] >> 7, to_bytes(&x)[0] & 1);
    if sign == 1 && to_bytes(&x) == [0; 32] {
        return None;
    }
    if low != sign {
        x = neg(&x);
    }
    Some([x, y, ONE, mul(&x, &y)])
}

/// A 64-byte little-endian number mod L, one bit at a time from the top.
fn reduce(h: &[u8]) -> [u8; 32] {
    let limbs = |b: &[u8; 32]| -> [u64; 4] {
        std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap()))
    };
    let l = limbs(&L);
    let mut r = [0u64; 4];
    for i in (0..h.len() * 8).rev() {
        // r < L < 2^253, so 2r + 1 fits.
        r = [
            r[0] << 1 | (h[i / 8] >> (i % 8) & 1) as u64,
            r[1] << 1 | r[0] >> 63,
            r[2] << 1 | r[1] >> 63,
            r[3] << 1 | r[2] >> 63,
        ];
        if !r.iter().rev().cmp(l.iter().rev()).is_lt() {
            let mut borrow = false;
            for (x, &y) in r.iter_mut().zip(&l) {
                let (d, b1) = x.overflowing_sub(y);
                let (d, b2) = d.overflowing_sub(borrow as u64);
                *x = d;
                borrow = b1 | b2;
            }
        }
    }
    let mut out = [0; 32];
    for (o, l) in out.chunks_mut(8).zip(r) {
        o.copy_from_slice(&l.to_le_bytes());
    }
    out
}
