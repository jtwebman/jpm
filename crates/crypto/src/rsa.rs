//! RSA signature verification: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017). Public keys only,
//! so nothing here needs constant time. Moduli of 2048 to 8192 bits; odd exponents of 3 to 2^32-1.

use crate::hash::{self, Alg};

/// `n` and `e` big-endian as a key holds them (a leading zero byte allowed), `digest` the hash
/// of the message under `alg`, `signature` exactly as long as the modulus.
pub fn verify_pkcs1(n: &[u8], e: &[u8], alg: Alg, digest: &[u8], signature: &[u8]) -> bool {
    // The DER DigestInfo header for each hash (RFC 8017 section 9.2, note 1).
    let prefix: &[u8] = match alg {
        Alg::Sha1 => return false,
        Alg::Sha256 => &[48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32],
        Alg::Sha384 => &[48, 65, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 48],
        Alg::Sha512 => &[48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64],
    };
    if digest.len() != alg.len() {
        return false;
    }
    let Some(em) = public_op(n, e, signature) else { return false };
    // Build the one valid encoding, 00 01 FF..FF 00 DigestInfo digest, and compare it whole.
    // At 2048 bits and more the FF run is always far longer than the 8 bytes required.
    let mut want = vec![0xff; em.len()];
    let t = em.len() - prefix.len() - digest.len();
    want[0] = 0;
    want[1] = 1;
    want[t - 1] = 0;
    want[t..t + prefix.len()].copy_from_slice(prefix);
    want[t + prefix.len()..].copy_from_slice(digest);
    em == want
}

/// PSS with MGF1 over the same hash and a salt as long as the digest, as TLS 1.3 and the Web
/// PKI use it.
pub fn verify_pss(n: &[u8], e: &[u8], alg: Alg, digest: &[u8], signature: &[u8]) -> bool {
    // EMSA-PSS-VERIFY, RFC 8017 section 9.1.2.
    let h_len = alg.len();
    if alg == Alg::Sha1 || digest.len() != h_len {
        return false;
    }
    let Some(out) = public_op(n, e, signature) else { return false };
    // emBits = modBits - 1. When modBits - 1 is a multiple of 8 the encoding is one byte
    // shorter than the modulus and the first output byte must be zero.
    let n = strip(n);
    let em_bits = 8 * n.len() - n[0].leading_zeros() as usize - 1;
    let em = match out.len() - em_bits.div_ceil(8) {
        0 => &out[..],
        _ if out[0] == 0 => &out[1..],
        _ => return false,
    };
    // The top 8 * emLen - emBits bits of the encoding must be zero.
    let top_mask = 0xffu8 >> (8 * em.len() - em_bits);
    if em[em.len() - 1] != 0xbc || em[0] & !top_mask != 0 {
        return false;
    }
    let (masked_db, h) = em[..em.len() - 1].split_at(em.len() - 1 - h_len);
    // DB = maskedDB xor MGF1(H).
    let mut db = masked_db.to_vec();
    for (i, chunk) in db.chunks_mut(h_len).enumerate() {
        let mask = hash_parts(alg, &[h, &(i as u32).to_be_bytes()]);
        chunk.iter_mut().zip(mask.iter()).for_each(|(b, m)| *b ^= m);
    }
    db[0] &= top_mask;
    // DB = 00..00 01 salt, with the salt hLen bytes long.
    let (ps, salt) = db.split_at(db.len() - h_len);
    let Some((&one, zeros)) = ps.split_last() else { return false };
    if one != 1 || zeros.iter().any(|&b| b != 0) {
        return false;
    }
    *hash_parts(alg, &[&[0; 8], digest, salt]) == *h
}

fn hash_parts(alg: Alg, parts: &[&[u8]]) -> hash::Digest {
    let mut h = hash::Hasher::new(alg);
    parts.iter().for_each(|p| h.update(p));
    h.finish()
}

/// RSAVP1 (RFC 8017 section 5.2.2): signature^e mod n, big-endian and as long as the modulus.
/// `None` for keys outside the limits, a signature of the wrong length, or one not below n.
fn public_op(n: &[u8], e: &[u8], signature: &[u8]) -> Option<Vec<u8>> {
    let n = strip(n);
    let e = strip(e);
    let bits = 8 * n.len() - n.first()?.leading_zeros() as usize;
    if !(2048..=8192).contains(&bits) || n[n.len() - 1] & 1 == 0 || e.len() > 4 || signature.len() != n.len() {
        return None;
    }
    let e = e.iter().fold(0u32, |acc, &b| acc << 8 | b as u32);
    if e < 3 || e & 1 == 0 {
        return None;
    }
    let m = Mont::new(n, bits);
    let s = m.limbs(signature);
    if !less(&s, &m.n) {
        return None;
    }
    // Left-to-right square and multiply in Montgomery form. e is odd, so the last step
    // multiplies by plain s, which also takes the result out of Montgomery form.
    let s_mont = m.mul(&s, &m.rr);
    let mut x = s_mont.clone();
    for i in (0..31 - e.leading_zeros()).rev() {
        x = m.mul(&x, &x);
        if i == 0 {
            x = m.mul(&x, &s);
        } else if e >> i & 1 == 1 {
            x = m.mul(&x, &s_mont);
        }
    }
    Some((0..n.len()).rev().map(|i| (x[i / 8] >> (8 * (i % 8))) as u8).collect())
}

fn strip(b: &[u8]) -> &[u8] {
    &b[b.iter().take_while(|&&x| x == 0).count()..]
}

/// Arithmetic mod an odd n in Montgomery form, R = 2^(64k), on k little-endian u64 limbs.
struct Mont {
    n: Vec<u64>,
    /// -n^-1 mod 2^64.
    n0: u64,
    /// R^2 mod n.
    rr: Vec<u64>,
}

impl Mont {
    fn new(n: &[u8], bits: usize) -> Self {
        let k = n.len().div_ceil(8);
        let mut m = Mont { n: vec![0; k], n0: 0, rr: vec![0; k] };
        m.n = m.limbs(n);
        // Newton's iteration doubles the correct low bits each round; n * n = 1 mod 8 gives 3.
        let mut inv = m.n[0];
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m.n[0].wrapping_mul(inv)));
        }
        m.n0 = inv.wrapping_neg();
        // Doubling from 2^(bits-1) < n reaches 2^(64k+k) mod n. Each Montgomery squaring
        // then maps 2^(64k+a) to 2^(64k+2a), so six of them give 2^(64k+64k) = R^2.
        let mut x = vec![0u64; k];
        x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        for _ in bits - 1..65 * k {
            let carry = x.iter_mut().fold(0, |c, l| {
                let top = *l >> 63;
                *l = *l << 1 | c;
                top
            });
            if carry == 1 || !less(&x, &m.n) {
                sub(&mut x, &m.n);
            }
        }
        for _ in 0..6 {
            x = m.mul(&x, &x);
        }
        m.rr = x;
        m
    }

    /// Big-endian bytes, at most 8k of them, to limbs.
    fn limbs(&self, b: &[u8]) -> Vec<u64> {
        let mut l = vec![0; self.n.len()];
        for (l, c) in l.iter_mut().zip(b.rchunks(8)) {
            *l = c.iter().fold(0, |acc, &b| acc << 8 | b as u64);
        }
        l
    }

    /// a * b / R mod n, for a, b < n. Multiplication and reduction interleaved, one limb of a
    /// at a time (FIOS); t stays below 2n.
    fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = &self.n[..];
        let k = n.len();
        let (a, b) = (&a[..k], &b[..k]);
        let mut t = vec![0u64; k + 1];
        for &ai in a {
            let p = t[0] as u128 + ai as u128 * b[0] as u128;
            let m = (p as u64).wrapping_mul(self.n0);
            let q = (p as u64) as u128 + m as u128 * n[0] as u128;
            let (mut c1, mut c2) = ((p >> 64) as u64, (q >> 64) as u64);
            for j in 1..k {
                let p = t[j] as u128 + ai as u128 * b[j] as u128 + c1 as u128;
                let q = (p as u64) as u128 + m as u128 * n[j] as u128 + c2 as u128;
                t[j - 1] = q as u64;
                (c1, c2) = ((p >> 64) as u64, (q >> 64) as u64);
            }
            let s = t[k] as u128 + c1 as u128 + c2 as u128;
            t[k - 1] = s as u64;
            t[k] = (s >> 64) as u64;
        }
        if t[k] != 0 || !less(&t[..k], n) {
            sub(&mut t[..k], n);
        }
        t.truncate(k);
        t
    }
}

/// a < b, for equal lengths.
fn less(a: &[u64], b: &[u64]) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}

/// a -= b mod 2^(64k).
fn sub(a: &mut [u64], b: &[u64]) {
    let mut borrow = false;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d, b1) = x.overflowing_sub(y);
        let (d, b2) = d.overflowing_sub(borrow as u64);
        *x = d;
        borrow = b1 | b2;
    }
}
