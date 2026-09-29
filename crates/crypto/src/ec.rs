//! Short Weierstrass curves y^2 = x^3 - 3x + b over a prime field, shared by P-256 (N = 4) and
//! P-384 (N = 6).
//!
//! Numbers are N 64-bit limbs, least significant first. Field elements, mod p or mod n, are kept
//! fully reduced and in Montgomery form: x is stored as x·R mod m with R = 2^(64N), so
//! `mul(aR, bR) = abR`. All field arithmetic is constant time: carries and borrows are
//! computed, never branched on.
//!
//! Points are homogeneous projective (X : Y : Z) with x = X/Z, y = Y/Z; the point at infinity is
//! (0 : 1 : 0). Addition and doubling use the complete formulas for a = -3 of Renes, Costello and
//! Batina, "Complete addition formulas for prime order elliptic curves" (2016), algorithms 4
//! and 6. They are correct for every input, the identity and P + P included, so the scalar
//! multiplications need no special cases.

type Limbs<const N: usize> = [u64; N];

/// An odd modulus m > 2^(64N - 1), with its Montgomery constants.
pub(crate) struct Modulus<const N: usize> {
    m: Limbs<N>,
    /// -m^-1 mod 2^64.
    m0: u64,
    /// R^2 mod m, to move numbers into Montgomery form.
    rr: Limbs<N>,
}

/// Big-endian hex to limbs, at compile time.
pub(crate) const fn hex<const N: usize>(s: &str) -> Limbs<N> {
    let s = s.as_bytes();
    assert!(s.len() == 16 * N);
    let mut out = [0u64; N];
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        };
        let bit = 4 * (s.len() - 1 - i);
        out[bit / 64] |= (d as u64) << (bit % 64);
        i += 1;
    }
    out
}

impl<const N: usize> Modulus<N> {
    pub(crate) const fn new(m: Limbs<N>) -> Self {
        // Newton's iteration doubles the number of correct low bits each step: 1, 2, 4, ... 64.
        let mut inv = 1u64;
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
            i += 1;
        }
        // R mod m = R - m, since m > R/2. Doubling it 64N times mod m gives R^2 mod m.
        let mut r = [0u64; N];
        let mut borrow = 0;
        i = 0;
        while i < N {
            let (d, b1) = 0u64.overflowing_sub(m[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            r[i] = d;
            borrow = (b1 | b2) as u64;
            i += 1;
        }
        let mut k = 0;
        while k < 64 * N {
            // r = 2r mod m: shift, then subtract m when the result is at least m.
            let top = r[N - 1] >> 63;
            let mut j = N - 1;
            while j > 0 {
                r[j] = r[j] << 1 | r[j - 1] >> 63;
                j -= 1;
            }
            r[0] <<= 1;
            let mut d = [0u64; N];
            let mut borrow = 0;
            j = 0;
            while j < N {
                let (x, b1) = r[j].overflowing_sub(m[j]);
                let (x, b2) = x.overflowing_sub(borrow);
                d[j] = x;
                borrow = (b1 | b2) as u64;
                j += 1;
            }
            if top == 1 || borrow == 0 {
                r = d;
            }
            k += 1;
        }
        Modulus { m, m0: inv.wrapping_neg(), rr: r }
    }

    /// Subtracts m from (hi : t) when that is at least m. Needs (hi : t) < 2m.
    fn reduce_once(&self, t: &Limbs<N>, hi: u64) -> Limbs<N> {
        let mut d = [0; N];
        let mut borrow = 0;
        for i in 0..N {
            (d[i], borrow) = sbb(t[i], self.m[i], borrow);
        }
        let (_, borrow) = sbb(hi, 0, borrow);
        // borrow = 1: (hi : t) < m, keep t.
        let keep = borrow.wrapping_neg();
        for i in 0..N {
            d[i] = (t[i] & keep) | (d[i] & !keep);
        }
        d
    }

    fn add(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        let mut s = [0; N];
        let mut carry = 0;
        for i in 0..N {
            (s[i], carry) = adc(a[i], b[i], carry);
        }
        self.reduce_once(&s, carry)
    }

    fn sub(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        let mut d = [0; N];
        let mut borrow = 0;
        for i in 0..N {
            (d[i], borrow) = sbb(a[i], b[i], borrow);
        }
        // On borrow, add m back.
        let mask = borrow.wrapping_neg();
        let mut carry = 0;
        for (x, m) in d.iter_mut().zip(&self.m) {
            (*x, carry) = adc(*x, m & mask, carry);
        }
        d
    }

    /// Montgomery multiplication, a·b/R mod m (CIOS). Needs a < R and b < m; returns < m.
    fn mul(&self, a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
        let mut t = [0u64; N];
        let mut hi = 0u64;
        for bi in b {
            let mut c = 0;
            for j in 0..N {
                (t[j], c) = mac(t[j], a[j], *bi, c);
            }
            let (tn, c1) = adc(hi, c, 0);
            // Add k·m, with k chosen so the low limb becomes zero, and shift down one limb.
            let k = t[0].wrapping_mul(self.m0);
            let (_, mut c) = mac(t[0], k, self.m[0], 0);
            for j in 1..N {
                (t[j - 1], c) = mac(t[j], k, self.m[j], c);
            }
            let c2;
            (t[N - 1], c2) = adc(tn, c, 0);
            hi = c1 + c2;
        }
        self.reduce_once(&t, hi)
    }

    fn sq(&self, a: &Limbs<N>) -> Limbs<N> {
        self.mul(a, a)
    }

    fn to_mont(&self, a: &Limbs<N>) -> Limbs<N> {
        self.mul(a, &self.rr)
    }

    fn out_of_mont(&self, a: &Limbs<N>) -> Limbs<N> {
        let mut one = [0; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// 1 in Montgomery form: R mod m.
    fn one(&self) -> Limbs<N> {
        let mut one = [0; N];
        one[0] = 1;
        self.to_mont(&one)
    }

    /// 1/a = a^(m-2) for prime m, in Montgomery form. The exponent is public, so branching on
    /// its bits leaks nothing about a.
    fn invert(&self, a: &Limbs<N>) -> Limbs<N> {
        let mut e = self.m;
        e[0] -= 2;
        let mut r = self.one();
        for i in (0..64 * N).rev() {
            r = self.sq(&r);
            if e[i / 64] >> (i % 64) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// Big-endian bytes (8N of them) to limbs, if the number is below m.
    fn decode(&self, b: &[u8]) -> Option<Limbs<N>> {
        let x = from_be(b);
        lt(&x, &self.m).then_some(x)
    }
}

fn from_be<const N: usize>(b: &[u8]) -> Limbs<N> {
    let mut x = [0; N];
    for (i, chunk) in b.rchunks(8).enumerate().take(N) {
        let mut w = [0; 8];
        w[8 - chunk.len()..].copy_from_slice(chunk);
        x[i] = u64::from_be_bytes(w);
    }
    x
}

fn to_be<const N: usize>(x: &Limbs<N>, out: &mut [u8]) {
    for (i, chunk) in out.rchunks_mut(8).enumerate() {
        chunk.copy_from_slice(&x[i].to_be_bytes());
    }
}

/// a < b, in constant time.
fn lt<const N: usize>(a: &Limbs<N>, b: &Limbs<N>) -> bool {
    let mut borrow = 0;
    for i in 0..N {
        (_, borrow) = sbb(a[i], b[i], borrow);
    }
    std::hint::black_box(borrow) == 1
}

fn is_zero<const N: usize>(a: &Limbs<N>) -> bool {
    std::hint::black_box(a.iter().fold(0, |acc, x| acc | x)) == 0
}

fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub(b as u128 + borrow as u128);
    (t as u64, (t >> 127) as u64)
}

fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = a as u128 + b as u128 * c as u128 + carry as u128;
    (t as u64, (t >> 64) as u64)
}

#[derive(Clone, Copy)]
struct Point<const N: usize> {
    x: Limbs<N>,
    y: Limbs<N>,
    z: Limbs<N>,
}

pub(crate) struct Curve<const N: usize> {
    pub(crate) p: Modulus<N>,
    pub(crate) n: Modulus<N>,
    /// b, gx, gy as plain numbers (not Montgomery form).
    pub(crate) b: Limbs<N>,
    pub(crate) gx: Limbs<N>,
    pub(crate) gy: Limbs<N>,
}

impl<const N: usize> Curve<N> {
    const LEN: usize = 8 * N;

    fn identity(&self) -> Point<N> {
        Point { x: [0; N], y: self.p.one(), z: [0; N] }
    }

    fn generator(&self) -> Point<N> {
        Point { x: self.p.to_mont(&self.gx), y: self.p.to_mont(&self.gy), z: self.p.one() }
    }

    /// Parses `04 || x || y`, checking both coordinates are below p and the point is on the
    /// curve. There is no uncompressed encoding of the point at infinity, so it never parses.
    fn parse_point(&self, b: &[u8]) -> Option<Point<N>> {
        if b.len() != 1 + 2 * Self::LEN || b[0] != 4 {
            return None;
        }
        let f = &self.p;
        let x = f.to_mont(&f.decode(&b[1..1 + Self::LEN])?);
        let y = f.to_mont(&f.decode(&b[1 + Self::LEN..])?);
        // y^2 = x^3 - 3x + b
        let x3 = f.mul(&f.sq(&x), &x);
        let three_x = f.add(&f.add(&x, &x), &x);
        let rhs = f.add(&f.sub(&x3, &three_x), &f.to_mont(&self.b));
        if f.sq(&y) != rhs {
            return None;
        }
        Some(Point { x, y, z: f.one() })
    }

    /// Algorithm 4 of Renes–Costello–Batina: complete addition for a = -3. 12M + 2 mul by b.
    fn add(&self, p: &Point<N>, q: &Point<N>, b: &Limbs<N>) -> Point<N> {
        let f = &self.p;
        let (x1, y1, z1, x2, y2, z2) = (&p.x, &p.y, &p.z, &q.x, &q.y, &q.z);
        let mut t0 = f.mul(x1, x2);
        let mut t1 = f.mul(y1, y2);
        let mut t2 = f.mul(z1, z2);
        let mut t3 = f.add(x1, y1);
        let mut t4 = f.add(x2, y2);
        t3 = f.mul(&t3, &t4);
        t4 = f.add(&t0, &t1);
        t3 = f.sub(&t3, &t4);
        t4 = f.add(y1, z1);
        let mut x3 = f.add(y2, z2);
        t4 = f.mul(&t4, &x3);
        x3 = f.add(&t1, &t2);
        t4 = f.sub(&t4, &x3);
        x3 = f.add(x1, z1);
        let mut y3 = f.add(x2, z2);
        x3 = f.mul(&x3, &y3);
        y3 = f.add(&t0, &t2);
        y3 = f.sub(&x3, &y3);
        let mut z3 = f.mul(b, &t2);
        x3 = f.sub(&y3, &z3);
        z3 = f.add(&x3, &x3);
        x3 = f.add(&x3, &z3);
        z3 = f.sub(&t1, &x3);
        x3 = f.add(&t1, &x3);
        y3 = f.mul(b, &y3);
        t1 = f.add(&t2, &t2);
        t2 = f.add(&t1, &t2);
        y3 = f.sub(&y3, &t2);
        y3 = f.sub(&y3, &t0);
        t1 = f.add(&y3, &y3);
        y3 = f.add(&t1, &y3);
        t1 = f.add(&t0, &t0);
        t0 = f.add(&t1, &t0);
        t0 = f.sub(&t0, &t2);
        t1 = f.mul(&t4, &y3);
        t2 = f.mul(&t0, &y3);
        y3 = f.mul(&x3, &z3);
        y3 = f.add(&y3, &t2);
        x3 = f.mul(&t3, &x3);
        x3 = f.sub(&x3, &t1);
        z3 = f.mul(&t4, &z3);
        t1 = f.mul(&t3, &t0);
        z3 = f.add(&z3, &t1);
        Point { x: x3, y: y3, z: z3 }
    }

    /// Algorithm 6 of Renes–Costello–Batina: doubling for a = -3. 8M + 3S + 2 mul by b.
    fn double(&self, p: &Point<N>, b: &Limbs<N>) -> Point<N> {
        let f = &self.p;
        let (x, y, z) = (&p.x, &p.y, &p.z);
        let mut t0 = f.sq(x);
        let t1 = f.sq(y);
        let mut t2 = f.sq(z);
        let mut t3 = f.mul(x, y);
        t3 = f.add(&t3, &t3);
        let mut z3 = f.mul(x, z);
        z3 = f.add(&z3, &z3);
        let mut y3 = f.mul(b, &t2);
        y3 = f.sub(&y3, &z3);
        let mut x3 = f.add(&y3, &y3);
        y3 = f.add(&x3, &y3);
        x3 = f.sub(&t1, &y3);
        y3 = f.add(&t1, &y3);
        y3 = f.mul(&x3, &y3);
        x3 = f.mul(&x3, &t3);
        t3 = f.add(&t2, &t2);
        t2 = f.add(&t2, &t3);
        z3 = f.mul(b, &z3);
        z3 = f.sub(&z3, &t2);
        z3 = f.sub(&z3, &t0);
        t3 = f.add(&z3, &z3);
        z3 = f.add(&z3, &t3);
        t3 = f.add(&t0, &t0);
        t0 = f.add(&t3, &t0);
        t0 = f.sub(&t0, &t2);
        t0 = f.mul(&t0, &z3);
        y3 = f.add(&y3, &t0);
        t0 = f.mul(y, z);
        t0 = f.add(&t0, &t0);
        z3 = f.mul(&t0, &z3);
        x3 = f.sub(&x3, &z3);
        z3 = f.mul(&t0, &t1);
        z3 = f.add(&z3, &z3);
        z3 = f.add(&z3, &z3);
        Point { x: x3, y: y3, z: z3 }
    }

    /// [0]P, [1]P, ... [15]P.
    fn table(&self, p: &Point<N>, b: &Limbs<N>) -> [Point<N>; 16] {
        let mut t = [self.identity(); 16];
        t[1] = *p;
        for i in 2..16 {
            t[i] = if i % 2 == 0 { self.double(&t[i / 2], b) } else { self.add(&t[i - 1], p, b) };
        }
        t
    }

    /// k·P in constant time, k < n: a fixed 4-bit window, most significant first, and every
    /// table entry read on every step.
    fn mul_ct(&self, k: &Limbs<N>, p: &Point<N>) -> Point<N> {
        let b = self.p.to_mont(&self.b);
        let table = self.table(p, &b);
        let mut acc = self.identity();
        for w in (0..16 * N).rev() {
            for _ in 0..4 {
                acc = self.double(&acc, &b);
            }
            let digit = k[w / 16] >> (w % 16 * 4) & 15;
            let mut sel = Point { x: [0; N], y: [0; N], z: [0; N] };
            for (i, e) in table.iter().enumerate() {
                // All ones when i == digit: (i ^ digit) - 1 borrows only from zero.
                let mask = std::hint::black_box(((i as u64 ^ digit).wrapping_sub(1) >> 63).wrapping_neg());
                for j in 0..N {
                    sel.x[j] |= e.x[j] & mask;
                    sel.y[j] |= e.y[j] & mask;
                    sel.z[j] |= e.z[j] & mask;
                }
            }
            acc = self.add(&acc, &sel, &b);
        }
        acc
    }

    /// The affine coordinates as big-endian bytes, or `None` for the point at infinity.
    fn to_affine(&self, p: &Point<N>, x_out: &mut [u8], y_out: Option<&mut [u8]>) -> Option<()> {
        let f = &self.p;
        if is_zero(&p.z) {
            return None;
        }
        let zi = f.invert(&p.z);
        to_be(&f.out_of_mont(&f.mul(&p.x, &zi)), x_out);
        if let Some(y_out) = y_out {
            to_be(&f.out_of_mont(&f.mul(&p.y, &zi)), y_out);
        }
        Some(())
    }

    /// The secret scalar, if 0 < k < n. The check is constant time; only its result shows.
    fn scalar(&self, secret: &[u8]) -> Option<Limbs<N>> {
        let k = from_be(secret);
        let ok = lt(&k, &self.n.m) & !is_zero(&k);
        ok.then_some(k)
    }

    pub(crate) fn public_key(&self, secret: &[u8], out: &mut [u8]) -> Option<()> {
        let k = self.scalar(secret)?;
        let q = self.mul_ct(&k, &self.generator());
        out[0] = 4;
        let (x, y) = out[1..].split_at_mut(Self::LEN);
        self.to_affine(&q, x, Some(y))
    }

    pub(crate) fn shared_secret(&self, secret: &[u8], peer: &[u8], out: &mut [u8]) -> Option<()> {
        let k = self.scalar(secret)?;
        let p = self.parse_point(peer)?;
        self.to_affine(&self.mul_ct(&k, &p), out, None)
    }

    /// ECDSA verification (FIPS 186-4 section 6.4.2). Everything here is public, so it may
    /// branch and skip work freely.
    pub(crate) fn verify(&self, public: &[u8], digest: &[u8], signature: &[u8]) -> bool {
        self.verify_inner(public, digest, signature).is_some()
    }

    fn verify_inner(&self, public: &[u8], digest: &[u8], signature: &[u8]) -> Option<()> {
        let (r, s) = parse_signature::<N>(signature)?;
        let n = &self.n;
        let in_range = |v: &Limbs<N>| !is_zero(v) && lt(v, &n.m);
        if !in_range(&r) || !in_range(&s) {
            return None;
        }
        let q = self.parse_point(public)?;
        // e is the leftmost bitlen(n) = 64N bits of the digest. It may be above n; the
        // Montgomery product below takes any e < R and reduces.
        let e = from_be::<N>(&digest[..digest.len().min(Self::LEN)]);
        // w = 1/s in Montgomery form, so mul(e, w) = e/s and mul(r, w) = r/s, plain.
        let w = n.invert(&n.to_mont(&s));
        let u1 = n.mul(&e, &w);
        let u2 = n.mul(&r, &w);

        // u1·G + u2·Q: one chain of doublings with 4-bit windows of both scalars (Shamir's
        // trick). Zero digits skip their addition.
        let b = self.p.to_mont(&self.b);
        let tg = self.table(&self.generator(), &b);
        let tq = self.table(&q, &b);
        let mut acc = self.identity();
        for w in (0..16 * N).rev() {
            for _ in 0..4 {
                acc = self.double(&acc, &b);
            }
            let shift = w % 16 * 4;
            let (d1, d2) = ((u1[w / 16] >> shift & 15) as usize, (u2[w / 16] >> shift & 15) as usize);
            if d1 != 0 {
                acc = self.add(&acc, &tg[d1], &b);
            }
            if d2 != 0 {
                acc = self.add(&acc, &tq[d2], &b);
            }
        }
        if is_zero(&acc.z) {
            return None;
        }
        // x(R) mod n == r without inverting Z: x(R) = X/Z is r or r + n (the only values below
        // p that are r mod n, since p < 2n), so check X == r·Z, then X == (r + n)·Z.
        let f = &self.p;
        if f.mul(&f.to_mont(&r), &acc.z) == acc.x {
            return Some(());
        }
        let mut rn = [0; N];
        let mut carry = 0;
        for i in 0..N {
            (rn[i], carry) = adc(r[i], n.m[i], carry);
        }
        if carry == 0 && lt(&rn, &f.m) && f.mul(&f.to_mont(&rn), &acc.z) == acc.x {
            return Some(());
        }
        None
    }
}

/// Parses DER `SEQUENCE { INTEGER r, INTEGER s }` strictly: short-form lengths only (every
/// valid signature here is under 128 bytes, so a long form would be non-minimal), minimal
/// positive integers of at most 8N bytes, and nothing after the sequence.
fn parse_signature<const N: usize>(sig: &[u8]) -> Option<(Limbs<N>, Limbs<N>)> {
    let body = match sig {
        [0x30, len, body @ ..] if *len < 0x80 && *len as usize == body.len() => body,
        _ => return None,
    };
    let (r, rest) = parse_integer::<N>(body)?;
    let (s, rest) = parse_integer::<N>(rest)?;
    rest.is_empty().then_some((r, s))
}

fn parse_integer<const N: usize>(b: &[u8]) -> Option<(Limbs<N>, &[u8])> {
    let (len, rest) = match b {
        [0x02, len, rest @ ..] if *len < 0x80 && *len as usize <= rest.len() => (*len as usize, rest),
        _ => return None,
    };
    let (v, rest) = rest.split_at(len);
    let v = match v {
        [] => return None,
        // Negative.
        [x, ..] if x & 0x80 != 0 => return None,
        // A zero byte is only allowed to keep the next byte's high bit from reading as a sign.
        [0, x, ..] if x & 0x80 == 0 => return None,
        [0, v @ ..] => v,
        v => v,
    };
    if v.len() > 8 * N {
        return None;
    }
    Some((from_be(v), rest))
}
