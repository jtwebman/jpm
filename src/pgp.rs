//! OpenPGP (RFC 9580), only as far as checking a Node.js release's signature needs: a detached
//! v4 signature over `SHASUMS256.txt`, made by one of Node's release keys or by a subkey the
//! key has bound for signing, with RSA or Ed25519 over SHA-256, SHA-384 or SHA-512.
//!
//! jpm keeps only the keys' fingerprints. The keys themselves come from nodejs/release-keys, and
//! a key is used only when it hashes to the fingerprint the signature's issuer maps to here.
//!
//! Strict: a packet with a partial or indeterminate length, a length past the end of the data,
//! a version other than 4, an unknown critical subpacket, a hash other than SHA-2, or armor
//! whose checksum is wrong is refused. Revocations and key expiry are not read: Node's keys are
//! re-certified over time and old releases stay signed by the keys of their day, which is how
//! pnpm reads them too. A revoked subkey is simply left out of the list below.

use jpm_crypto::hash::{Alg, Digest, Hasher};

pub type Fpr = [u8; 20];

/// Node's release keys, from nodejs/release-keys (keys.list and README.md, 2026-09): current
/// releasers first, then retired ones, whose keys signed older releases.
const RELEASE_KEYS: [Fpr; 29] = [
    fpr("5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"), // Antoine du Hamel
    fpr("DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7"), // Juan José Arboleda
    fpr("CC68F5A3106FF448322E48ED27F5E38D5B0A215F"), // Marco Ippolito
    fpr("890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4"), // Rafael Gonzaga
    fpr("C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C"), // Richard Lau
    fpr("108F52B48DB57BB0CC439B2997B01419BD92F80A"), // Ruy Adorno
    fpr("655F3B5C1FB3FA8D1A0CA6BDE4A7D232B936D2FD"), // Stewart X Addison
    fpr("A363A499291CBBC940DD62E41F10027AF002F8B0"), // Ulises Gascón
    fpr("C0D6248439F1D5604AAFFB4021D900FFDB233756"), // Antoine du Hamel
    fpr("4ED778F539E3634C779C87C6D7062848A1AB005C"), // Beth Griggs
    fpr("141F07595B7B3FFE74309A937405533BE57C7D57"), // Bryan English
    fpr("9554F04D7259F04124DE6B476D5A82AC7E37093B"), // Chris Dickinson
    fpr("94AE36675C464D64BAFA68DD7434390BDBE9B9C5"), // Colin Ihrig
    fpr("1C050899334244A8AF75E53792EF661D867B9DFA"), // Danielle Adams
    fpr("74F12602B6F1C4E913FAA37AD3A89613643B6201"), // Danielle Adams
    fpr("B9AE9905FFD7803F25714661B63B535A4C206CA9"), // Evan Lucas
    fpr("77984A986EBC2AA786BC0F66B01FBB92821C587A"), // Gibson Fahnestock
    fpr("93C7E9E91B49E432C2F75674B0A78B0A6C481CF6"), // Isaac Z. Schlueter
    fpr("56730D5401028683275BD23C23EFEFE93C4CFFFE"), // Italo A. Casas
    fpr("71DCFD284A79C3B38668286BC97EC7A07EDE3FC1"), // James M Snell
    fpr("FD3A5288F042B6850C66B31F09FE44734EB7990E"), // Jeremiah Senkpiel
    fpr("61FC681DFB92A079F1685E77973F295594EC4689"), // Juan José Arboleda
    fpr("114F43EE0176B71C7BC219DD50A3051F888C628D"), // Julien Gilli
    fpr("8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600"), // Michaël Zasso
    fpr("C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8"), // Myles Borins
    fpr("DD8F2338BAE7501E3DD5AC78C273792F7D83545D"), // Rod Vagg
    fpr("A48C2BEE680E841632CD4E44F07496B3EB3C1762"), // Ruben Bridgewater
    fpr("B9E2F5981AA6E0CD28160D9FF13993A75599653C"), // Shelley Vohr
    fpr("7937DFD2AB06298B2293C3187D33FF9D0246406D"), // Timothy J Fontaine
];

/// The subkeys of those that sign releases, each with its key. Myles Borins' revoked subkey
/// 2B2B9F0D620463DB3DE74C50DEA16371974031A5 is left out.
const SUBKEYS: [(Fpr, Fpr); 6] = [
    (fpr("C2B25D9B4272DB29565BA87F3C7824F39A895758"), RELEASE_KEYS[7]),
    (fpr("A6023530FC53461FEC91F99C04CD3F2FDE079578"), RELEASE_KEYS[7]),
    (fpr("26FFD37528D0DE0E6D4D1C1A7341B15C070877AC"), RELEASE_KEYS[19]),
    (fpr("50CBD045680704B1B723693545F5EEBD813DAE8E"), RELEASE_KEYS[20]),
    (fpr("86C8D74642E67846F8E120284DAA80D1E737BC9F"), RELEASE_KEYS[23]),
    (fpr("0EFFE1BCEFD9C84E3D098152933B01F40B5CA946"), RELEASE_KEYS[24]),
];

const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

const fn fpr(s: &str) -> Fpr {
    const fn digit(c: u8) -> u8 {
        if c <= b'9' { c - b'0' } else { c - b'A' + 10 }
    }
    let s = s.as_bytes();
    let mut out = [0; 20];
    let mut i = 0;
    while i < 40 {
        out[i / 2] = digit(s[i]) << 4 | digit(s[i + 1]);
        i += 2;
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02X}")).collect()
}

/// Why a signature is refused.
type Why = &'static str;

const MALFORMED: Why = "a malformed packet, or one with a partial or indeterminate length";

/// A fingerprint is the issuer a signature names: the whole of it, or its last 8 bytes (the key
/// ID older signatures carry).
fn is(fpr: &Fpr, issuer: &[u8]) -> bool {
    !issuer.is_empty() && fpr.ends_with(issuer)
}

/// The release key whose key or subkey made `sig` (a `.sig` file's bytes).
pub fn signer(sig: &[u8]) -> Result<Fpr, String> {
    let sig = detached(sig)?;
    let sub = || SUBKEYS.iter().find(|(s, _)| is(s, sig.issuer)).map(|(_, key)| key);
    let found = RELEASE_KEYS.iter().find(|k| is(k, sig.issuer)).or_else(sub);
    found.copied().ok_or_else(|| format!("it was made by key {}, not a Node.js release key", hex(sig.issuer)))
}

/// Whether `sig` is a signature over `document` by `key` (an armored public key block), which
/// must be the release key `primary`.
pub fn verify(document: &[u8], sig: &[u8], primary: &Fpr, key: &[u8]) -> Result<(), Why> {
    let sig = detached(sig)?;
    let key = dearmor(key)?;
    let signer = signing_key(&packets(&key).ok_or(MALFORMED)?, primary, sig.issuer)?;
    let text;
    let document = match sig.kind {
        0 => document,
        // A text signature is over the text with CR LF line ends.
        1 => {
            text = crlf(document);
            &text
        }
        _ => return Err("a signature that is not over a document"),
    };
    check(signer, &sig, &digest(&sig, &[document]))
}

fn crlf(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + text.len() / 32);
    for (i, &b) in text.iter().enumerate() {
        if b == b'\n' && (i == 0 || text[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// A `.sig` file: one signature packet.
fn detached(bytes: &[u8]) -> Result<Signature<'_>, Why> {
    match packets(bytes).ok_or(MALFORMED)?[..] {
        [(2, body)] => signature(body),
        _ => Err("the signature file is not one signature packet"),
    }
}

/// Reads a packet body front to back; running past its end is `None`, never a panic.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn be(&mut self, n: usize) -> Option<usize> {
        Some(self.take(n)?.iter().fold(0, |acc, &b| acc << 8 | b as usize))
    }

    /// A multiprecision integer: a bit count, then the bytes that hold that many bits.
    fn mpi(&mut self) -> Option<&'a [u8]> {
        let bits = self.be(2)?;
        self.take(bits.div_ceil(8))
    }

    /// A subpacket (RFC 9580 section 5.2.3.7): its type byte, critical bit included, and data.
    fn subpacket(&mut self) -> Option<(u8, &'a [u8])> {
        let len = match self.u8()? as usize {
            a @ 0..192 => a,
            a @ 192..255 => ((a - 192) << 8) + self.u8()? as usize + 192,
            _ => self.be(4)?,
        };
        let (&kind, data) = self.take(len)?.split_first()?;
        Some((kind, data))
    }
}

/// Each packet's tag and body. Partial and indeterminate lengths are `None`.
fn packets(mut data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let mut r = Reader(data);
        let ctb = r.u8()?;
        let (tag, len) = match ctb {
            0..0x80 => return None,
            // The new format: a 6-bit tag, then a 1, 2 or 5 byte length.
            0xc0.. => {
                let len = match r.u8()? as usize {
                    a @ 0..192 => a,
                    a @ 192..224 => ((a - 192) << 8) + r.u8()? as usize + 192,
                    255 => r.be(4)?,
                    _ => return None,
                };
                (ctb & 0x3f, len)
            }
            // The old format: a 4-bit tag and the length's size in the low bits.
            _ if ctb & 3 == 3 => return None,
            _ => (ctb >> 2 & 0xf, r.be(1 << (ctb & 3))?),
        };
        out.push((tag, r.take(len)?));
        data = r.0;
    }
    Some(out)
}

/// A v4 signature packet, as far as checking it needs.
struct Signature<'a> {
    kind: u8,
    algo: u8,
    hash: Alg,
    /// From the version to the end of the hashed subpackets: what the hash covers after the data.
    hashed: &'a [u8],
    left16: &'a [u8],
    mpis: &'a [u8],
    /// The issuer's fingerprint, else its key ID.
    issuer: &'a [u8],
    /// The key flags a binding signature grants, when it says.
    flags: Option<u8>,
}

fn signature(body: &[u8]) -> Result<Signature<'_>, Why> {
    let Some((&[version, kind, algo, hash], rest)) = body.split_first_chunk() else { return Err(MALFORMED) };
    let mut r = Reader(rest);
    if version != 4 {
        return Err("a signature of a version other than 4");
    }
    let hash = match hash {
        8 => Alg::Sha256,
        9 => Alg::Sha384,
        10 => Alg::Sha512,
        _ => return Err("a signature over a hash other than SHA-2"),
    };
    let mut area = || r.be(2).and_then(|n| r.take(n));
    let (Some(hashed_area), Some(unhashed_area)) = (area(), area()) else { return Err(MALFORMED) };
    let mut sig = Signature {
        kind,
        algo,
        hash,
        hashed: &body[..6 + hashed_area.len()],
        left16: r.take(2).ok_or(MALFORMED)?,
        mpis: r.0,
        issuer: &[],
        flags: None,
    };
    let (mut id, mut created, mut expires) = (None, 0, 0);
    for (area, hashed) in [(hashed_area, true), (unhashed_area, false)] {
        let mut r = Reader(area);
        while !r.0.is_empty() {
            let (kind, data) = r.subpacket().ok_or(MALFORMED)?;
            let time = || Reader(data).be(4).unwrap_or(0) as u64;
            match (kind & 0x7f, data.len()) {
                (33, 21) if data[0] == 4 => sig.issuer = &data[1..],
                (16, 8) => id = Some(data),
                (2, 4) if hashed => created = time(),
                (3, 4) if hashed => expires = time(),
                (27, 1..) if hashed => sig.flags = Some(data[0]),
                // Key expiry, preferences and the like, and the primary key's back signature:
                // known, and nothing this check needs.
                (9 | 11 | 21 | 22 | 23 | 25 | 30 | 32 | 34, _) => {}
                _ if hashed && kind & 0x80 != 0 => return Err("a signature with an unknown critical subpacket"),
                _ => {}
            }
        }
    }
    if sig.issuer.is_empty() {
        sig.issuer = id.ok_or("a signature that names no issuer")?;
    }
    if expires != 0 && (created + expires) as i64 <= crate::util::now_ms() / 1000 {
        return Err("an expired signature");
    }
    Ok(sig)
}

/// The hash a signature covers: `parts`, then its own hashed fields and the v4 trailer.
fn digest(sig: &Signature, parts: &[&[u8]]) -> Digest {
    let mut h = Hasher::new(sig.hash);
    parts.iter().for_each(|p| h.update(p));
    h.update(sig.hashed);
    h.update(&[4, 0xff]);
    h.update(&(sig.hashed.len() as u32).to_be_bytes());
    h.finish()
}

/// What goes before a key packet's body where it is hashed. `fingerprint` checks it fits.
fn head(key: &[u8]) -> [u8; 3] {
    [0x99, (key.len() >> 8) as u8, key.len() as u8]
}

/// A v4 key's fingerprint, or `None` for another version or a packet too long to have one.
fn fingerprint(key: &[u8]) -> Option<Fpr> {
    if key.first() != Some(&4) || key.len() > 0xffff {
        return None;
    }
    let mut h = Hasher::new(Alg::Sha1);
    h.update(&head(key));
    h.update(key);
    h.finish().as_ref().try_into().ok()
}

/// The key in `packets` that made a signature by `issuer`: the primary key, which must be
/// `primary`, or one of its subkeys, bound to it by a signature the primary key made that does
/// not deny it signing.
fn signing_key<'a>(packets: &[(u8, &'a [u8])], primary: &Fpr, issuer: &[u8]) -> Result<&'a [u8], Why> {
    let Some(&(6, main)) = packets.first() else { return Err("the key file holds no public key") };
    if fingerprint(main) != Some(*primary) {
        return Err("the key file holds another key than the one it is named for");
    }
    if is(primary, issuer) {
        return Ok(main);
    }
    for (i, &(tag, sub)) in packets.iter().enumerate() {
        if tag != 14 || !fingerprint(sub).is_some_and(|f| is(&f, issuer)) {
            continue;
        }
        let bound = packets[i + 1..].iter().take_while(|(t, _)| *t == 2).any(|(_, body)| {
            signature(body).is_ok_and(|b| {
                b.kind == 0x18
                    && b.flags.is_none_or(|f| f & 2 != 0)
                    && check(main, &b, &digest(&b, &[&head(main), main, &head(sub), sub])).is_ok()
            })
        });
        if bound {
            return Ok(sub);
        }
    }
    Err("the release key has no subkey bound to it for signing that made the signature")
}

/// The signature's check itself, with `key` a v4 public key packet's body.
fn check(key: &[u8], sig: &Signature, digest: &[u8]) -> Result<(), Why> {
    if digest[..2] != *sig.left16 {
        return Err("the document is not the one signed");
    }
    if !matches!(sig.algo, 1 | 3 | 22) {
        return Err("a public-key algorithm other than RSA and Ed25519");
    }
    if key.get(5) == Some(&sig.algo) && valid(key, sig, digest) == Some(true) {
        return Ok(());
    }
    Err("the signature does not match")
}

fn valid(key: &[u8], sig: &Signature, digest: &[u8]) -> Option<bool> {
    let (mut k, mut s) = (Reader(key.get(6..)?), Reader(sig.mpis));
    let ok = if sig.algo == 22 {
        // EdDSA with Ed25519, over the digest: the key is 0x40 then the point, the signature R
        // and S as integers, which may have lost leading zero bytes.
        let oid_len = k.u8()? as usize;
        let (oid, point, r, big_s) = (k.take(oid_len)?, k.mpi()?, s.mpi()?, s.mpi()?);
        let (0x40, point) = point.split_first()? else { return None };
        let mut rs = [0; 64];
        let (lo, hi) = rs.split_at_mut(32);
        lo.get_mut(32usize.checked_sub(r.len())?..)?.copy_from_slice(r);
        hi.get_mut(32usize.checked_sub(big_s.len())?..)?.copy_from_slice(big_s);
        oid == ED25519_OID && jpm_pk::ed25519::verify(point, digest, &rs)
    } else {
        // RSA, and RSA sign-only. PKCS#1 v1.5: the signature is as long as the modulus.
        let (n, e, value) = (k.mpi()?, k.mpi()?, s.mpi()?);
        let n = &n[n.iter().take_while(|b| **b == 0).count()..];
        let mut padded = vec![0; n.len().saturating_sub(value.len())];
        padded.extend_from_slice(value);
        jpm_pk::rsa::verify_pkcs1(n, e, sig.hash, digest, &padded)
    };
    Some(ok && s.0.is_empty())
}

/// The packets of an ASCII-armored public key block.
fn dearmor(text: &[u8]) -> Result<Vec<u8>, Why> {
    const ARMOR: Why = "the key file's armor is malformed";
    let text = std::str::from_utf8(text).map_err(|_| ARMOR)?;
    let mut lines = text.lines().map(str::trim_end);
    lines.find(|l| *l == "-----BEGIN PGP PUBLIC KEY BLOCK-----").ok_or("the key file holds no public key block")?;
    // Headers, then a blank line.
    if !lines.by_ref().take_while(|l| !l.is_empty()).all(|l| l.contains(": ")) {
        return Err(ARMOR);
    }
    let base64 = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    let (mut body, mut crc) = (String::new(), None);
    for line in lines {
        if line == "-----END PGP PUBLIC KEY BLOCK-----" {
            let data = body.trim_end_matches('=');
            if body.len() % 4 != 0 || body.len() - data.len() > 2 || !base64(data) {
                return Err(ARMOR);
            }
            let data = crate::util::from_base64(&body);
            // The checksum is optional (RFC 9580 section 6.1); when there, it must match.
            if crc.is_some_and(|c: Vec<u8>| c != crc24(&data).to_be_bytes()[1..]) {
                return Err("the key file's armor checksum does not match");
            }
            return Ok(data);
        }
        match line.strip_prefix('=') {
            Some(c) if crc.is_none() && c.len() == 4 && base64(c) => crc = Some(crate::util::from_base64(c)),
            None if crc.is_none() => body.push_str(line),
            _ => break,
        }
    }
    Err(ARMOR)
}

/// RFC 9580 section 6.1.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc = 0xb704ce;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4cfb;
            }
        }
    }
    crc & 0xff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/node");

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}/{name}")).unwrap()
    }

    /// (version, the key that signed it): Ed25519, an Ed25519 subkey of an RSA key, and RSA.
    const RELEASES: [(&str, &str); 3] = [
        ("24.21.0", "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"),
        ("24.12.0", "8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600"),
        ("26.5.1", "890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4"),
    ];

    /// Where a one-packet file's body starts, after its 2 or 3 byte header.
    fn body_at(sig: &[u8]) -> usize {
        sig.len() - packets(sig).unwrap()[0].1.len()
    }

    fn release(i: usize) -> (Vec<u8>, Vec<u8>, Fpr, Vec<u8>) {
        let (v, key) = RELEASES[i];
        let doc = read(&format!("v{v}-SHASUMS256.txt"));
        let sig = read(&format!("v{v}-SHASUMS256.txt.sig"));
        (doc, sig, fpr(key), read(&format!("{key}.asc")))
    }

    #[test]
    fn real_releases_verify() {
        for (i, (version, _)) in RELEASES.iter().enumerate() {
            let (doc, sig, key, armored) = release(i);
            assert_eq!(signer(&sig).unwrap(), key, "{version}");
            verify(&doc, &sig, &key, &armored).unwrap();
        }
    }

    #[test]
    fn every_embedded_fingerprint_is_distinct() {
        let mut all: Vec<Fpr> = RELEASE_KEYS.iter().copied().chain(SUBKEYS.iter().map(|(s, _)| *s)).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n);
        assert_eq!(hex(&fpr("0123456789ABCDEF0123456789ABCDEF01234567")), "0123456789ABCDEF0123456789ABCDEF01234567");
        // Each subkey's key, by name.
        assert_eq!(SUBKEYS[0].1, fpr("A363A499291CBBC940DD62E41F10027AF002F8B0"));
        assert_eq!(SUBKEYS[2].1, fpr("71DCFD284A79C3B38668286BC97EC7A07EDE3FC1"));
        assert_eq!(SUBKEYS[3].1, fpr("FD3A5288F042B6850C66B31F09FE44734EB7990E"));
        assert_eq!(SUBKEYS[4].1, fpr("8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600"));
        assert_eq!(SUBKEYS[5].1, fpr("C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8"));
    }

    #[test]
    fn refuses_a_changed_document_or_signature() {
        for (i, (version, _)) in RELEASES.iter().enumerate() {
            let (doc, sig, key, armored) = release(i);
            let mut changed = doc.clone();
            changed[100] ^= 1;
            assert_eq!(verify(&changed, &sig, &key, &armored).unwrap_err(), "the document is not the one signed");
            let mut longer = doc.clone();
            longer.push(b'\n');
            assert!(verify(&longer, &sig, &key, &armored).is_err());
            // Every byte of the signature matters, but for the unhashed subpackets (which name
            // the issuer, and are not signed: a wrong one just finds no key).
            let body = body_at(&sig);
            let hashed_end = body + 6 + u16::from_be_bytes([sig[body + 4], sig[body + 5]]) as usize;
            let unhashed_end = hashed_end + 2 + u16::from_be_bytes([sig[hashed_end], sig[hashed_end + 1]]) as usize;
            for at in (0..sig.len()).filter(|at| !(hashed_end + 2..unhashed_end).contains(at)) {
                let mut bad = sig.clone();
                bad[at] ^= 0x10;
                assert!(verify(&doc, &bad, &key, &armored).is_err(), "{version} byte {at}");
            }
        }
    }

    #[test]
    fn refuses_another_key() {
        let (doc, sig, key, _) = release(0);
        let (_, _, other, other_armored) = release(2);
        // The file holds a key other than the one the signature needs.
        let err = verify(&doc, &sig, &key, &other_armored).unwrap_err();
        assert!(err.contains("another key"), "{err}");
        // A real release key, asked to be a key it is not the signer of.
        let err = verify(&doc, &sig, &other, &other_armored).unwrap_err();
        assert!(err.contains("no subkey"), "{err}");
    }

    #[test]
    fn refuses_a_key_not_in_the_list() {
        let (_, mut sig, _, _) = release(0);
        // The issuer fingerprint subpacket's last byte: now no release key's.
        let at = sig.windows(20).position(|w| w == fpr(RELEASES[0].1)).unwrap() + 19;
        sig[at] ^= 1;
        assert!(signer(&sig).unwrap_err().contains("not a Node.js release key"));
    }

    #[test]
    fn a_subkey_must_be_bound() {
        let (_, sig, key, armored) = release(1);
        let raw = dearmor(&armored).unwrap();
        let mut owned: Vec<(u8, Vec<u8>)> = packets(&raw).unwrap().into_iter().map(|(t, b)| (t, b.to_vec())).collect();
        let issuer = detached(&sig).unwrap().issuer.to_vec();
        let find = |p: &[(u8, Vec<u8>)]| {
            let borrowed: Vec<(u8, &[u8])> = p.iter().map(|(t, b)| (*t, b.as_slice())).collect();
            signing_key(&borrowed, &key, &issuer).map(<[u8]>::to_vec)
        };
        find(&owned).unwrap();
        // With the binding signatures after the subkey broken, or gone, the subkey is not trusted.
        let at = owned.iter().position(|(t, b)| *t == 14 && fingerprint(b).is_some_and(|f| is(&f, &issuer))).unwrap();
        let mut broken = owned.clone();
        for (_, b) in broken[at + 1..].iter_mut().take_while(|(t, _)| *t == 2) {
            let n = b.len();
            b[n - 5] ^= 1;
        }
        assert!(find(&broken).unwrap_err().contains("no subkey"));
        owned.retain(|(t, _)| *t != 2);
        assert!(find(&owned).unwrap_err().contains("no subkey"));
    }

    #[test]
    fn armor_is_checked() {
        let (doc, sig, key, armored) = release(0);
        let text = String::from_utf8(armored.clone()).unwrap();
        let crc_line = text.lines().find(|l| l.starts_with('=')).unwrap();
        // A wrong checksum; no checksum at all is allowed.
        let wrong = text.replace(crc_line, if crc_line == "=AAAA" { "=AAAB" } else { "=AAAA" });
        assert!(verify(&doc, &sig, &key, wrong.as_bytes()).unwrap_err().contains("checksum"));
        let none = text.replace(&format!("{crc_line}\n"), "");
        verify(&doc, &sig, &key, none.as_bytes()).unwrap();
        // CR LF line ends read the same.
        verify(&doc, &sig, &key, text.replace('\n', "\r\n").as_bytes()).unwrap();
        // A changed character in the body fails the checksum (or the parse), never passes.
        let body_at = text.find("\n\n").unwrap() + 10;
        let mut changed = text.clone().into_bytes();
        changed[body_at] = if changed[body_at] == b'A' { b'B' } else { b'A' };
        assert!(verify(&doc, &sig, &key, &changed).is_err());
        for bad in [
            text.replace("-----END PGP PUBLIC KEY BLOCK-----", ""),
            text.replace("-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----BEGIN PGP MESSAGE-----"),
            text.replacen("\n\n", "\nnot a header\n\n", 1),
            text.replacen("\n\n", "\n\n!!!!\n", 1),
            text.replace(crc_line, &format!("{crc_line}\nmore")),
            String::new(),
        ] {
            assert!(verify(&doc, &sig, &key, bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(verify(&doc, &sig, &key, &[0xff, 0xfe]).is_err());
    }

    #[test]
    fn refuses_ed25519_values_too_long() {
        let (doc, sig, key, armored) = release(0);
        let body = &sig[body_at(&sig)..];
        // The signature ends with R and S, each a 2-byte bit count and 32 bytes.
        let (fields, rs) = body.split_at(body.len() - 68);
        assert_eq!((rs[0], rs[34]), (1, 0), "R's bit count is 256 or so");
        for (at, extra) in [(0, 1), (34, 1), (0, 20), (34, 200)] {
            let mut long = rs.to_vec();
            let bits = u16::from_be_bytes([long[at], long[at + 1]]) + 8 * extra as u16;
            long[at..at + 2].copy_from_slice(&bits.to_be_bytes());
            long.splice(at + 2..at + 2, std::iter::repeat_n(1, extra));
            let body = [fields, &long].concat();
            let framed = [&[0xc2, 0xff][..], &(body.len() as u32).to_be_bytes(), &body].concat();
            assert_eq!(verify(&doc, &framed, &key, &armored), Err("the signature does not match"));
        }
    }

    #[test]
    fn refuses_hostile_packets() {
        // Partial and indeterminate lengths, lengths past the end, and the largest lengths.
        for bad in [
            &[0xc2, 0xe0, 1, 2, 3][..],
            &[0x8b, 1, 2, 3],
            &[0xc2, 0xff, 0xff, 0xff, 0xff, 0xff, 4],
            &[0x8a, 0xff, 0xff, 0xff, 0xff, 4],
            &[0x89, 0xff, 0xff, 4],
            &[0xc2, 0xdf, 0xff, 4],
            &[0xc2],
            &[0x88],
            &[0x04, 0x00],
            &[],
        ] {
            assert!(signer(bad).is_err(), "{bad:02x?}");
        }
        // Two signature packets, or another packet.
        let (_, sig, _, _) = release(0);
        assert!(signer(&[sig.clone(), sig.clone()].concat()).is_err());
        let mut other = sig.clone();
        other[0] = 0xc0 | 11;
        assert!(signer(&other).is_err());
        // The same signature in either packet format reads the same.
        let body = &sig[body_at(&sig)..];
        for framed in [[&[0x88, body.len() as u8][..], body].concat(), [&[0xc2, body.len() as u8][..], body].concat()] {
            assert_eq!(signer(&framed).unwrap(), fpr(RELEASES[0].1));
        }
    }

    #[test]
    fn refuses_what_it_does_not_read() {
        let (doc, sig, key, armored) = release(2);
        // Offsets in the packet body: 0 version, 1 type, 3 hash algorithm.
        let body = body_at(&sig);
        for (at, value, why) in [
            (0, 5, "a version other than 4"),
            (3, 2, "a hash other than SHA-2"),
            (3, 11, "a hash other than SHA-2"),
            (1, 0x13, "not over a document"),
        ] {
            let mut bad = sig.clone();
            bad[body + at] = value;
            assert!(verify(&doc, &bad, &key, &armored).unwrap_err().contains(why), "{why}");
        }
        // A critical subpacket this does not know: the first hashed subpacket's type, made critical.
        let hashed_len = u16::from_be_bytes([sig[body + 4], sig[body + 5]]) as usize;
        assert!(hashed_len > 2);
        let mut bad = sig.clone();
        let first_type = body + 6 + 1;
        bad[first_type] = 0x80 | 100;
        assert!(verify(&doc, &bad, &key, &armored).unwrap_err().contains("unknown critical"));
        // A text signature is over CR LF lines: this document is not one, so it does not match.
        let mut text = sig.clone();
        text[body + 1] = 1;
        assert!(verify(&doc, &text, &key, &armored).is_err());
        assert_eq!(crlf(b"a\nb\r\nc\n"), b"a\r\nb\r\nc\r\n");
    }

    /// Random changes to every fixture, a bounded number of times: errors, never a panic.
    #[test]
    fn random_mutations_never_panic() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut mutate = |b: &[u8]| -> Vec<u8> {
            let (r, at, v) = (next(), next() as usize, next() as u8);
            let mut b = b.to_vec();
            match (r % 4, b.len()) {
                (0, n @ 1..) => b[at % n] ^= 1 << ((r >> 8) % 8),
                (1, n) => b.truncate(at % (n + 1)),
                (2, n @ 1..) => b[at % n] = v,
                (_, n) => b.insert(at % (n + 1), v),
            }
            b
        };
        for i in 0..RELEASES.len() {
            let (doc, sig, key, armored) = release(i);
            let raw = dearmor(&armored).unwrap();
            let issuer = detached(&sig).unwrap().issuer.to_vec();
            for _ in 0..300 {
                let bad_sig = mutate(&sig);
                let _ = signer(&bad_sig);
                let _ = verify(&doc, &bad_sig, &key, &armored);
                let _ = verify(&doc, &sig, &key, &mutate(&armored));
                // The key's packets changed under the armor, where the checksum is no guard.
                let bad_raw = mutate(&raw);
                if let Some(p) = packets(&bad_raw)
                    && let Ok(k) = signing_key(&p, &key, &issuer)
                {
                    let s = detached(&sig).unwrap();
                    let _ = check(k, &s, &digest(&s, &[&doc]));
                }
            }
        }
    }
}
