//! Certificate parsing (RFC 5280 section 4.1) and the checks on one certificate: validity,
//! basic constraints, extended key usage, and its signature. Fields are kept as slices and
//! decoded only when a check needs them, as webpki does, so a malformed field in a certificate
//! that never lands on a path costs nothing and fails nothing.

use jpm_crypto::hash::{self, Alg};

use super::Code::{self, *};
use super::{PublicKey, Scheme};
use crate::der::Reader;

const SEQUENCE: u8 = 0x30;
const OID: u8 = 0x06;

/// One parsed certificate. Names, the validity and the SPKI are the contents of their
/// SEQUENCEs; extensions are the contents of their values.
pub(super) struct Cert<'a> {
    /// The whole TBSCertificate, header included: the bytes the signature covers.
    pub tbs: &'a [u8],
    pub alg: &'a [u8],
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub validity: &'a [u8],
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub basic_constraints: Option<&'a [u8]>,
    pub eku: Option<&'a [u8]>,
    pub name_constraints: Option<&'a [u8]>,
    pub san: Option<&'a [u8]>,
}

/// Parse a certificate. Only v3 certificates; the TBS signature algorithm must equal the outer
/// one byte for byte; an unknown extension marked critical, or a known one twice, refuses it.
pub(super) fn parse(der: &[u8]) -> Result<Cert<'_>, Code> {
    let mut outer = Reader::new(der);
    let body = outer.expect(SEQUENCE).ok_or(Encoding)?;
    // webpki reads no value of 64 KiB or more; nor do we.
    if !outer.is_empty() || body.len() >= 0xffff {
        return Err(Encoding);
    }
    let mut r = Reader::new(body);
    let tbs_contents = r.expect(SEQUENCE).ok_or(Encoding)?;
    let tbs = &body[..body.len() - r.rest().len()];
    let alg = r.expect(SEQUENCE).ok_or(Encoding)?;
    let signature = bit_string(&mut r)?;
    if !r.is_empty() {
        return Err(Encoding);
    }

    let mut t = Reader::new(tbs_contents);
    // version [0] EXPLICIT INTEGER, which must be 2 (v3). The DEFAULT v1 is not accepted.
    if t.expect(0xa0) != Some(&[2, 1, 2]) {
        return Err(Unsupported);
    }
    // The serial number is read leniently, as webpki does: any INTEGER.
    t.expect(0x02).ok_or(Encoding)?;
    if t.expect(SEQUENCE).ok_or(Encoding)? != alg {
        return Err(BadSignature);
    }
    let mut seq = || t.expect(SEQUENCE).ok_or(Encoding);
    let (issuer, validity, subject, spki) = (seq()?, seq()?, seq()?, seq()?);
    let mut cert = Cert {
        tbs,
        alg,
        signature,
        issuer,
        validity,
        subject,
        spki,
        basic_constraints: None,
        eku: None,
        name_constraints: None,
        san: None,
    };
    // Anything else must be extensions [3]; unique IDs [1] and [2] are refused, as webpki does.
    if !t.is_empty() {
        let mut wrap = Reader::new(t.expect(0xa3).ok_or(Encoding)?);
        let mut exts = Reader::new(wrap.expect(SEQUENCE).ok_or(Encoding)?);
        if !wrap.is_empty() || !t.is_empty() {
            return Err(Encoding);
        }
        // Key usage and CRL distribution points are not used, but still may appear only once.
        let (mut key_usage, mut crl_dp) = (None, None);
        while !exts.is_empty() {
            let mut ext = Reader::new(exts.expect(SEQUENCE).ok_or(Encoding)?);
            let id = ext.expect(OID).ok_or(Encoding)?;
            let critical = boolean(&mut ext)?;
            let value = ext.expect(0x04).ok_or(Encoding)?;
            if !ext.is_empty() {
                return Err(Encoding);
            }
            // id-ce, 2.5.29 (RFC 5280 section 4.2.1).
            let slot = match id {
                [0x55, 0x1d, 15] => &mut key_usage,
                [0x55, 0x1d, 17] => &mut cert.san,
                [0x55, 0x1d, 19] => &mut cert.basic_constraints,
                [0x55, 0x1d, 30] => &mut cert.name_constraints,
                [0x55, 0x1d, 31] => &mut crl_dp,
                [0x55, 0x1d, 37] => &mut cert.eku,
                _ if critical => return Err(Unsupported),
                _ => continue,
            };
            if slot.is_some() {
                return Err(Encoding);
            }
            *slot = Some(match id[2] {
                15 => value,
                _ => {
                    let mut v = Reader::new(value);
                    let inner = v.expect(SEQUENCE).ok_or(Encoding)?;
                    if !v.is_empty() {
                        return Err(Encoding);
                    }
                    inner
                }
            });
        }
    }
    Ok(cert)
}

/// A BIT STRING with no unused bits, without its leading count byte.
fn bit_string<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Code> {
    match r.expect(0x03) {
        Some([0, rest @ ..]) => Ok(rest),
        _ => Err(Encoding),
    }
}

/// An optional BOOLEAN, `false` when absent. 0x00 is accepted as webpki accepts it.
fn boolean(r: &mut Reader) -> Result<bool, Code> {
    if r.peek() != Some(0x01) {
        return Ok(false);
    }
    match r.expect(0x01) {
        Some([0xff]) => Ok(true),
        Some([0]) => Ok(false),
        _ => Err(Encoding),
    }
}

/// notBefore <= now <= notAfter, both ends inclusive (RFC 5280 section 4.1.2.5).
pub(super) fn check_validity(validity: &[u8], now: u64) -> Result<(), Code> {
    let mut r = Reader::new(validity);
    let not_before = time(&mut r)?;
    let not_after = time(&mut r)?;
    if !r.is_empty() {
        return Err(Encoding);
    }
    if not_before > not_after {
        Err(BadValidity)
    } else if now < not_before {
        Err(NotYetValid)
    } else if now > not_after {
        Err(Expired)
    } else {
        Ok(())
    }
}

/// UTCTime YYMMDDHHMMSSZ (years 50 to 99 are 19xx) or GeneralizedTime YYYYMMDDHHMMSSZ, as
/// seconds since the Unix epoch. No fractions, no offsets, no years before 1970.
fn time(r: &mut Reader) -> Result<u64, Code> {
    let utc = r.peek() == Some(0x17);
    let v = r.expect(if utc { 0x17 } else { 0x18 }).ok_or(Encoding)?;
    let digits = if utc { 12 } else { 14 };
    if v.len() != digits + 1 || v[digits] != b'Z' || !v[..digits].iter().all(u8::is_ascii_digit) {
        return Err(Encoding);
    }
    let two = |i: usize| (v[i] - b'0') as u64 * 10 + (v[i + 1] - b'0') as u64;
    let (year, i) = match utc {
        true if two(0) >= 50 => (1900 + two(0), 2),
        true => (2000 + two(0), 2),
        false => (two(0) * 100 + two(2), 4),
    };
    let (month, day, hour, minute, second) = (two(i), two(i + 2), two(i + 4), two(i + 6), two(i + 8));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return Err(Encoding);
    }
    let month_days = DAYS[month as usize - 1] + (leap && month == 2) as u64;
    if day < 1 || day > month_days {
        return Err(Encoding);
    }
    let y = year - 1;
    let days_before_year = y * 365 + y / 4 - y / 100 + y / 400 - 719_162;
    let days_before_month = DAYS[..month as usize - 1].iter().sum::<u64>() + (leap && month > 2) as u64;
    let days = days_before_year + days_before_month + day - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// basicConstraints (RFC 5280 section 4.2.1.9). A server certificate must not be a CA; an
/// issuer must be one, with at most `sub_ca` CAs (the leaf not counted) below it when it sets
/// pathLenConstraint.
pub(super) fn check_basic_constraints(bc: Option<&[u8]>, leaf: bool, sub_ca: usize) -> Result<(), Code> {
    let (ca, path_len) = match bc {
        None => (false, None),
        Some(v) => {
            let mut r = Reader::new(v);
            let ca = boolean(&mut r)?;
            let path_len = match r.is_empty() {
                true => None,
                false => Some(small_uint(&mut r)?),
            };
            if !r.is_empty() {
                return Err(Encoding);
            }
            (ca, path_len)
        }
    };
    match (leaf, ca, path_len) {
        (true, true, _) => Err(CaAsLeaf),
        (false, false, _) => Err(NotCa),
        (false, true, Some(n)) if sub_ca > n as usize => Err(PathLen),
        _ => Ok(()),
    }
}

/// A non-negative INTEGER that fits in one byte, minimally encoded.
fn small_uint(r: &mut Reader) -> Result<u8, Code> {
    match r.expect(0x02) {
        Some(&[b]) if b < 0x80 => Ok(b),
        Some(&[0, b]) if b >= 0x80 => Ok(b),
        _ => Err(Encoding),
    }
}

/// extKeyUsage (RFC 5280 section 4.2.1.12), when present, must list id-kp-serverAuth. webpki
/// applies this to every certificate on the path, not only the leaf, and so do we.
/// anyExtendedKeyUsage does not count.
pub(super) fn check_eku(eku: Option<&[u8]>) -> Result<(), Code> {
    let Some(v) = eku else { return Ok(()) };
    let mut r = Reader::new(v);
    while !r.is_empty() {
        if r.expect(OID).ok_or(Encoding)? == [0x2b, 6, 1, 5, 5, 7, 3, 1] {
            return Ok(());
        }
    }
    Err(Eku)
}

/// The key types a SubjectPublicKeyInfo may hold.
#[derive(Clone, Copy, PartialEq)]
enum KeyType {
    Rsa,
    P256,
    P384,
}

/// The key in a SubjectPublicKeyInfo (its SEQUENCE's contents), in two steps as webpki takes
/// them: an unknown algorithm is `Unsupported`, and a bad key under a known one is `None`.
fn spki(spki: &[u8]) -> Result<(KeyType, &[u8]), Code> {
    let mut r = Reader::new(spki);
    let alg = r.expect(SEQUENCE).ok_or(Encoding)?;
    let key = bit_string(&mut r)?;
    if !r.is_empty() {
        return Err(Encoding);
    }
    let ty = match alg {
        // rsaEncryption with NULL parameters (RFC 3279 section 2.3.1).
        [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1, 5, 0] => KeyType::Rsa,
        // id-ecPublicKey with a named curve, prime256v1 or secp384r1 (RFC 5480 section 2.1.1).
        [6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, 6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7] => KeyType::P256,
        [6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, 6, 5, 0x2b, 0x81, 4, 0, 0x22] => KeyType::P384,
        _ => return Err(Unsupported),
    };
    Ok((ty, key))
}

fn key(ty: KeyType, key: &[u8]) -> Option<PublicKey<'_>> {
    match ty {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 8017 A.1.1).
        KeyType::Rsa => {
            let mut outer = Reader::new(key);
            let mut r = Reader::new(outer.expect(SEQUENCE)?);
            let (n, e) = (positive(&mut r)?, positive(&mut r)?);
            (outer.is_empty() && r.is_empty()).then_some(PublicKey::Rsa { n, e })
        }
        // Uncompressed points only; the curve code checks the point is on the curve.
        KeyType::P256 => (key.len() == 65 && key[0] == 4).then_some(PublicKey::P256(key)),
        KeyType::P384 => (key.len() == 97 && key[0] == 4).then_some(PublicKey::P384(key)),
    }
}

/// A positive, minimally encoded INTEGER without its sign byte.
fn positive<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    match r.expect(0x02)? {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => Some(rest),
        v @ [b, ..] if b & 0x80 == 0 && *b != 0 => Some(v),
        _ => None,
    }
}

/// The server's key, for the handshake to check its signature with.
pub(super) fn leaf_key(spki_contents: &[u8]) -> Result<PublicKey<'_>, Code> {
    let (ty, k) = spki(spki_contents)?;
    key(ty, k).ok_or(Unsupported)
}

/// The signature algorithms a certificate may be signed with, by the exact encodings of their
/// AlgorithmIdentifier contents that webpki accepts. SHA-1 is not among them.
fn scheme(alg: &[u8]) -> Option<Scheme> {
    const PKCS1: [u8; 10] = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1];
    const ECDSA: [u8; 9] = [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3];
    Some(match alg {
        // sha{256,384,512}WithRSAEncryption, parameters NULL or absent (RFC 4055 section 5).
        [a @ .., 11] | [a @ .., 11, 5, 0] if a == PKCS1 => Scheme::RsaPkcs1Sha256,
        [a @ .., 12] | [a @ .., 12, 5, 0] if a == PKCS1 => Scheme::RsaPkcs1Sha384,
        [a @ .., 13] | [a @ .., 13, 5, 0] if a == PKCS1 => Scheme::RsaPkcs1Sha512,
        // ecdsa-with-SHA{256,384,512}, parameters absent (RFC 5758 section 3.2).
        [a @ .., 2] if a == ECDSA => Scheme::EcdsaSha256,
        [a @ .., 3] if a == ECDSA => Scheme::EcdsaSha384,
        [a @ .., 4] if a == ECDSA => Scheme::EcdsaSha512,
        _ => return pss(alg),
    })
}

/// RSASSA-PSS with SHA-256, 384 or 512, MGF1 over the same hash, and a salt as long as the
/// hash, in the one DER encoding RFC 4055 section 3.1 gives (hash parameters NULL, the trailer
/// field left at its default).
fn pss(alg: &[u8]) -> Option<Scheme> {
    #[rustfmt::skip]
    const PSS: [u8; 65] = [
        6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10,
        0x30, 0x34,
        0xa0, 0x0f, 0x30, 0x0d, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 0xff, 5, 0,
        0xa1, 0x1c, 0x30, 0x1a, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8,
        0x30, 0x0d, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 0xff, 5, 0,
        0xa2, 3, 2, 1, 0xff,
    ];
    // The bytes marked 0xff: the hash's OID arc twice, then its length.
    let (hash, salt, scheme) = match alg.get(27) {
        Some(1) => (1, 32, Scheme::RsaPssSha256),
        Some(2) => (2, 48, Scheme::RsaPssSha384),
        Some(3) => (3, 64, Scheme::RsaPssSha512),
        _ => return None,
    };
    let mut want = PSS;
    (want[27], want[57], want[64]) = (hash, hash, salt);
    (alg == want).then_some(scheme)
}

/// Check `cert`'s signature against the issuer's SubjectPublicKeyInfo contents.
pub(super) fn check_signature(issuer_spki: &[u8], cert: &Cert) -> Result<(), Code> {
    let scheme = scheme(cert.alg).ok_or(Unsupported)?;
    let (ty, k) = spki(issuer_spki)?;
    let rsa = matches!(
        scheme,
        Scheme::RsaPkcs1Sha256
            | Scheme::RsaPkcs1Sha384
            | Scheme::RsaPkcs1Sha512
            | Scheme::RsaPssSha256
            | Scheme::RsaPssSha384
            | Scheme::RsaPssSha512
    );
    if rsa != (ty == KeyType::Rsa) {
        return Err(Unsupported);
    }
    let ok = key(ty, k).is_some_and(|k| super::verify_signature(&k, scheme, cert.tbs, cert.signature));
    if ok { Ok(()) } else { Err(BadSignature) }
}

/// Hash `message` and check `signature` with `key`.
pub(super) fn verify(key: &PublicKey, scheme: Scheme, message: &[u8], signature: &[u8]) -> bool {
    use Scheme::*;
    let alg = match scheme {
        RsaPkcs1Sha256 | RsaPssSha256 | EcdsaSha256 => Alg::Sha256,
        RsaPkcs1Sha384 | RsaPssSha384 | EcdsaSha384 => Alg::Sha384,
        RsaPkcs1Sha512 | RsaPssSha512 | EcdsaSha512 => Alg::Sha512,
    };
    let digest = hash::digest(alg, message);
    let ecdsa = matches!(scheme, EcdsaSha256 | EcdsaSha384 | EcdsaSha512);
    let pss = matches!(scheme, RsaPssSha256 | RsaPssSha384 | RsaPssSha512);
    match *key {
        PublicKey::Rsa { n, e } if pss => jpm_pk::rsa::verify_pss(n, e, alg, &digest, signature),
        PublicKey::Rsa { n, e } if !ecdsa => jpm_pk::rsa::verify_pkcs1(n, e, alg, &digest, signature),
        PublicKey::P256(q) if ecdsa => jpm_pk::p256::verify(q, &digest, signature),
        PublicKey::P384(q) if ecdsa => jpm_pk::p384::verify(q, &digest, signature),
        _ => false,
    }
}
