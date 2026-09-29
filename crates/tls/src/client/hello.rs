//! The first round trip, shared by both versions: ClientHello, an optional HelloRetryRequest
//! (RFC 8446 section 4.1.4), and ServerHello, which picks the version and the rest of the
//! handshake.

use std::io::{Read, Write};

use jpm_crypto::hash::{self, Hasher};
use jpm_crypto::{aead, rand};
use jpm_pk::{p256, x25519};

use super::record::{Conn, HANDSHAKE};
use super::{Config, Error, Result, alert, tls12, tls13};
use crate::x509::{PublicKey, Scheme};

pub(crate) const X25519: u16 = 0x001d;
pub(crate) const SECP256R1: u16 = 0x0017;
/// Listed in supported_groups but never used for key exchange: TLS 1.2 servers with a P-384
/// certificate may check the list for the certificate's curve (RFC 4492 section 5.1) and
/// refuse the handshake without it.
pub(crate) const SECP384R1: u16 = 0x0018;

const SERVER_HELLO: u8 = 2;
const MESSAGE_HASH: u8 = 254;

/// A cipher suite and what it implies.
pub(crate) struct Suite {
    pub(crate) id: u16,
    pub(crate) aead: aead::Alg,
    pub(crate) hash: hash::Alg,
    pub(crate) kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Tls13,
    /// TLS 1.2 ECDHE_ECDSA: an EC certificate key.
    Ecdsa,
    /// TLS 1.2 ECDHE_RSA: an RSA certificate key.
    Rsa,
}

const fn suite(id: u16, aead: aead::Alg, hash: hash::Alg, kind: Kind) -> Suite {
    Suite { id, aead, hash, kind }
}

use aead::Alg::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use hash::Alg::{Sha256, Sha384};

static SUITES: [Suite; 9] = [
    suite(0x1301, Aes128Gcm, Sha256, Kind::Tls13),
    suite(0x1302, Aes256Gcm, Sha384, Kind::Tls13),
    suite(0x1303, ChaCha20Poly1305, Sha256, Kind::Tls13),
    suite(0xc02b, Aes128Gcm, Sha256, Kind::Ecdsa),
    suite(0xc02f, Aes128Gcm, Sha256, Kind::Rsa),
    suite(0xc02c, Aes256Gcm, Sha384, Kind::Ecdsa),
    suite(0xc030, Aes256Gcm, Sha384, Kind::Rsa),
    suite(0xcca9, ChaCha20Poly1305, Sha256, Kind::Ecdsa),
    suite(0xcca8, ChaCha20Poly1305, Sha256, Kind::Rsa),
];

/// The order suites are offered in: AES first where the CPU runs it, ChaCha20 first elsewhere.
const AES_FIRST: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
const CHACHA_FIRST: [usize; 9] = [2, 0, 1, 7, 8, 3, 4, 5, 6];

/// ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pss_rsae_sha256/384/512 and
/// rsa_pkcs1_sha256/384/512 (the last three for TLS 1.2 and certificates only).
const SIGNATURE_SCHEMES: [u16; 8] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];

/// The x509 scheme for a TLS signature scheme, when we offered it and it fits `key`. TLS 1.3
/// binds an ECDSA scheme to its curve and leaves out PKCS#1 v1.5 (RFC 8446 section 4.2.3);
/// TLS 1.2 does neither.
pub(crate) fn scheme(code: u16, key: &PublicKey, tls13: bool) -> Option<Scheme> {
    use PublicKey::{P256, P384, Rsa};
    Some(match (code, key) {
        (0x0403, P256(_)) => Scheme::EcdsaSha256,
        (0x0503, P384(_)) => Scheme::EcdsaSha384,
        (0x0403, P384(_)) if !tls13 => Scheme::EcdsaSha256,
        (0x0503, P256(_)) if !tls13 => Scheme::EcdsaSha384,
        (0x0804, Rsa { .. }) => Scheme::RsaPssSha256,
        (0x0805, Rsa { .. }) => Scheme::RsaPssSha384,
        (0x0806, Rsa { .. }) => Scheme::RsaPssSha512,
        (0x0401, Rsa { .. }) if !tls13 => Scheme::RsaPkcs1Sha256,
        (0x0501, Rsa { .. }) if !tls13 => Scheme::RsaPkcs1Sha384,
        (0x0601, Rsa { .. }) if !tls13 => Scheme::RsaPkcs1Sha512,
        _ => return None,
    })
}

/// HelloRetryRequest's special random: SHA-256 of "HelloRetryRequest" (RFC 8446 section 4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The end of a TLS 1.3 server's random when it negotiates TLS 1.2 or below: seeing it means
/// someone removed TLS 1.3 from our ClientHello (RFC 8446 section 4.1.3).
const DOWNGRADE: [u8; 7] = *b"DOWNGRD";

// Extension types.
const SERVER_NAME: u16 = 0;
const SUPPORTED_GROUPS: u16 = 10;
const EC_POINT_FORMATS: u16 = 11;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const EXTENDED_MASTER_SECRET: u16 = 23;
const SUPPORTED_VERSIONS: u16 = 43;
const COOKIE: u16 = 44;
const KEY_SHARE: u16 = 51;
const RENEGOTIATION_INFO: u16 = 0xff01;

/// A cursor over a handshake message. Every read is `None` past the end.
pub(crate) struct Rd<'a>(pub(crate) &'a [u8]);

impl<'a> Rd<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn len(&mut self, n: usize) -> Option<usize> {
        Some(self.take(n)?.iter().fold(0, |a, &b| a << 8 | usize::from(b)))
    }

    /// A vector with an `n`-byte length.
    pub(crate) fn vec(&mut self, n: usize) -> Option<&'a [u8]> {
        let len = self.len(n)?;
        self.take(len)
    }

    pub(crate) fn done(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

pub(crate) fn decode_error(what: &'static str) -> Error {
    Error::Tls(alert::DECODE_ERROR, what)
}

pub(crate) fn illegal(what: &'static str) -> Error {
    Error::Tls(alert::ILLEGAL_PARAMETER, what)
}

/// A handshake message's body, when it is of type `typ`.
pub(crate) fn body<'a>(m: &'a [u8], typ: u8, what: &'static str) -> Result<&'a [u8]> {
    if m[0] != typ {
        return Err(Error::Tls(alert::UNEXPECTED_MESSAGE, what));
    }
    Ok(&m[4..])
}

/// Extensions as `(type, data)`, each type at most once (RFC 8446 section 4.2).
pub(crate) fn extensions(data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut r = Rd(data);
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while !r.0.is_empty() {
        let typ = r.u16()?;
        let data = r.vec(2)?;
        if out.iter().any(|&(t, _)| t == typ) {
            return None;
        }
        out.push((typ, data));
    }
    Some(out)
}

/// A handshake message: type, 24-bit length, body.
pub(crate) fn message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(typ);
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

/// What the client sent, as the rest of the handshake needs it.
pub(crate) struct Hello<'c> {
    pub(crate) random: [u8; 32],
    session_id: [u8; 32],
    pub(crate) host: &'c str,
    pub(crate) config: &'c Config,
    /// The group of the key share sent, and the secret for it.
    pub(crate) group: u16,
    secret: [u8; 32],
}

impl Hello<'_> {
    /// Our public key for `self.group`.
    pub(crate) fn public(&self) -> Vec<u8> {
        match self.group {
            X25519 => x25519::public_key(&self.secret).to_vec(),
            // The secret was drawn so that this is `Some`.
            _ => p256::public_key(&self.secret).map_or(Vec::new(), |p| p.to_vec()),
        }
    }

    /// Start over with a fresh key for `group`.
    pub(crate) fn new_key(&mut self, group: u16) {
        self.group = group;
        loop {
            rand::fill(&mut self.secret);
            if group == X25519 || p256::public_key(&self.secret).is_some() {
                return;
            }
        }
    }

    /// A copy with a fresh key for `group`, for TLS 1.2's ServerKeyExchange.
    pub(crate) fn fresh(&self, group: u16) -> Self {
        let mut k = Hello { ..*self };
        k.new_key(group);
        k
    }

    /// The shared secret with the server's public key for our group. Invalid points and the
    /// all-zero X25519 result are refused.
    pub(crate) fn shared(&self, peer: &[u8]) -> Result<[u8; 32]> {
        let bad = || illegal("tls: illegal parameter: bad key share");
        match self.group {
            X25519 => x25519::shared_secret(&self.secret, peer.try_into().map_err(|_| bad())?),
            _ => p256::shared_secret(&self.secret, peer),
        }
        .ok_or_else(bad)
    }

    /// The name for SNI: the host, unless it is an IP address (RFC 6066 section 3).
    pub(crate) fn sni(&self) -> Option<&str> {
        let name = self.host;
        (name.parse::<std::net::IpAddr>().is_err() && !name.is_empty() && name.len() < 256).then_some(name)
    }

    fn client_hello(&self, cookie: Option<&[u8]>) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        b.extend_from_slice(&[3, 3]);
        b.extend_from_slice(&self.random);
        b.push(32);
        b.extend_from_slice(&self.session_id);
        let order = if aead::aes_hardware() { AES_FIRST } else { CHACHA_FIRST };
        b.extend_from_slice(&(2 * order.len() as u16).to_be_bytes());
        for i in order {
            b.extend_from_slice(&SUITES[i].id.to_be_bytes());
        }
        b.extend_from_slice(&[1, 0]);

        let mut e = Vec::with_capacity(256);
        if let Some(name) = self.sni() {
            let n = name.len() as u16;
            let mut d = Vec::with_capacity(name.len() + 5);
            d.extend_from_slice(&(n + 3).to_be_bytes());
            d.push(0);
            d.extend_from_slice(&n.to_be_bytes());
            d.extend_from_slice(name.as_bytes());
            ext(&mut e, SERVER_NAME, &d);
        }
        ext(&mut e, SUPPORTED_GROUPS, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]);
        ext(&mut e, EC_POINT_FORMATS, &[1, 0]);
        let mut d = vec![0, 2 * SIGNATURE_SCHEMES.len() as u8];
        SIGNATURE_SCHEMES.iter().for_each(|s| d.extend_from_slice(&s.to_be_bytes()));
        ext(&mut e, SIGNATURE_ALGORITHMS, &d);
        if let Some(d) = alpn_list(self.config) {
            ext(&mut e, ALPN, &d);
        }
        ext(&mut e, EXTENDED_MASTER_SECRET, &[]);
        ext(&mut e, RENEGOTIATION_INFO, &[0]);
        ext(&mut e, SUPPORTED_VERSIONS, &[4, 3, 4, 3, 3]);
        let public = self.public();
        let mut d = Vec::with_capacity(public.len() + 6);
        d.extend_from_slice(&(public.len() as u16 + 4).to_be_bytes());
        d.extend_from_slice(&self.group.to_be_bytes());
        d.extend_from_slice(&(public.len() as u16).to_be_bytes());
        d.extend_from_slice(&public);
        ext(&mut e, KEY_SHARE, &d);
        if let Some(c) = cookie {
            ext(&mut e, COOKIE, c);
        }
        b.extend_from_slice(&(e.len() as u16).to_be_bytes());
        b.extend_from_slice(&e);
        message(1, &b)
    }
}

fn ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// The ALPN extension's data, or `None` to leave it out. Names must be 1 to 255 bytes.
fn alpn_list(config: &Config) -> Option<Vec<u8>> {
    let mut d = vec![0, 0];
    for p in config.alpn.iter().filter(|p| (1..256).contains(&p.len())) {
        d.push(p.len() as u8);
        d.extend_from_slice(p);
    }
    let n = d.len() - 2;
    d[..2].copy_from_slice(&(n as u16).to_be_bytes());
    (n > 0).then_some(d)
}

/// The server's ALPN choice (RFC 7301 section 3.1): one protocol, one we offered.
pub(crate) fn alpn_choice(data: &[u8], config: &Config) -> Result<Vec<u8>> {
    let bad = || decode_error("tls: decode error: bad ALPN extension");
    let mut r = Rd(data);
    let mut list = Rd(r.vec(2).ok_or_else(bad)?);
    r.done().ok_or_else(bad)?;
    let p = list.vec(1).filter(|p| !p.is_empty()).ok_or_else(bad)?;
    list.done().ok_or_else(bad)?;
    if !config.alpn.iter().any(|a| a == p) {
        return Err(illegal("tls: illegal parameter: server chose an unoffered ALPN protocol"));
    }
    Ok(p.to_vec())
}

/// A ServerHello or HelloRetryRequest, checked against what we sent.
pub(crate) struct ServerHello<'a> {
    pub(crate) random: [u8; 32],
    pub(crate) suite: &'static Suite,
    pub(crate) tls13: bool,
    retry: bool,
    pub(crate) exts: Vec<(u16, &'a [u8])>,
}

impl ServerHello<'_> {
    pub(crate) fn ext(&self, typ: u16) -> Option<&[u8]> {
        self.exts.iter().find(|e| e.0 == typ).map(|e| e.1)
    }
}

fn server_hello<'a>(m: &'a [u8], h: &Hello) -> Result<ServerHello<'a>> {
    let body = body(m, SERVER_HELLO, "tls: unexpected message: expected ServerHello")?;
    let bad = || decode_error("tls: decode error: bad ServerHello");
    let mut r = Rd(body);
    if r.u16().ok_or_else(bad)? != 0x0303 {
        return Err(Error::Tls(
            alert::PROTOCOL_VERSION,
            "tls: protocol version: the server supports neither TLS 1.3 nor 1.2",
        ));
    }
    let random: [u8; 32] = r.take(32).ok_or_else(bad)?.try_into().unwrap();
    let session_id = r.vec(1).ok_or_else(bad)?;
    let id = r.u16().ok_or_else(bad)?;
    let compression = r.u8().ok_or_else(bad)?;
    let exts = if r.0.is_empty() { Vec::new() } else { extensions(r.vec(2).ok_or_else(bad)?).ok_or_else(bad)? };
    r.done().ok_or_else(bad)?;

    if compression != 0 {
        return Err(illegal("tls: illegal parameter: server chose compression"));
    }
    let retry = random == HRR_RANDOM;
    let tls13 = match exts.iter().find(|e| e.0 == SUPPORTED_VERSIONS) {
        None => false,
        Some((_, [3, 4])) => true,
        Some(_) => return Err(illegal("tls: illegal parameter: server chose an unoffered version")),
    };
    // TLS 1.3 echoes our session id (RFC 8446 section 4.1.3); a TLS 1.2 server sends its own.
    if tls13 && session_id != h.session_id {
        return Err(illegal("tls: illegal parameter: session id not echoed"));
    }
    if session_id.len() > 32 {
        return Err(decode_error("tls: decode error: bad ServerHello"));
    }
    if retry && !tls13 {
        return Err(illegal("tls: illegal parameter: HelloRetryRequest without TLS 1.3"));
    }
    let suite = SUITES
        .iter()
        .find(|s| s.id == id && (s.kind == Kind::Tls13) == tls13)
        .ok_or(illegal("tls: handshake failure: server chose an unoffered cipher suite"))?;
    // Only extensions we sent, and only those this message may carry (RFC 8446 section 4.2).
    for &(typ, data) in &exts {
        let ok = match typ {
            SUPPORTED_VERSIONS | KEY_SHARE => tls13,
            COOKIE => retry,
            SERVER_NAME => !tls13 && h.sni().is_some() && data.is_empty(),
            ALPN => !tls13 && alpn_list(h.config).is_some(),
            EC_POINT_FORMATS => !tls13,
            EXTENDED_MASTER_SECRET | RENEGOTIATION_INFO => !tls13,
            _ => false,
        };
        if !ok {
            return Err(Error::Tls(
                alert::UNSUPPORTED_EXTENSION,
                "tls: unsupported extension: server sent one not offered",
            ));
        }
    }
    if !tls13 {
        if random[24..31] == DOWNGRADE && random[31] <= 1 {
            return Err(illegal("tls: illegal parameter: downgrade from TLS 1.3 detected"));
        }
        let ems = exts.iter().find(|e| e.0 == EXTENDED_MASTER_SECRET);
        let reneg = exts.iter().find(|e| e.0 == RENEGOTIATION_INFO);
        let formats = exts.iter().find(|e| e.0 == EC_POINT_FORMATS);
        if ems.is_some_and(|e| !e.1.is_empty())
            || reneg.is_some_and(|e| e.1 != [0])
            || formats.is_some_and(|e| Rd(e.1).vec(1).is_none_or(|f| !f.contains(&0) || f.len() + 1 != e.1.len()))
        {
            return Err(illegal("tls: illegal parameter: bad ServerHello extension"));
        }
    }
    Ok(ServerHello { random, suite, tls13, retry, exts })
}

pub(crate) struct Done {
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) secrets: Option<tls13::Secrets>,
}

pub(crate) fn handshake<S: Read + Write>(conn: &mut Conn<S>, host: &str, config: &Config) -> Result<Done> {
    // "example.com." is "example.com": SNI carries no trailing dot (RFC 6066 section 3).
    let host = host.strip_suffix('.').unwrap_or(host);
    let mut h = Hello { random: [0; 32], session_id: [0; 32], host, config, group: X25519, secret: [0; 32] };
    rand::fill(&mut h.random);
    // A random legacy session id: middlebox compatibility mode (RFC 8446 appendix D.4).
    rand::fill(&mut h.session_id);
    h.new_key(X25519);
    let ch = h.client_hello(None);
    conn.send(HANDSHAKE, &ch)?;

    let mut m = conn.read_hs()?;
    let sh = server_hello(&m, &h)?;
    let mut t = Hasher::new(sh.suite.hash);
    if !sh.retry {
        t.update(&ch);
        t.update(&m);
        return finish(conn, &h, &sh, t);
    }

    // HelloRetryRequest (RFC 8446 section 4.1.4).
    conn.ccs_ok = true;
    let suite = sh.suite;
    let group = match sh.ext(KEY_SHARE) {
        Some(&[a, b]) => Some(u16::from_be_bytes([a, b])),
        Some(_) => return Err(decode_error("tls: decode error: bad HelloRetryRequest")),
        None => None,
    };
    let cookie = sh.ext(COOKIE).map(<[u8]>::to_vec);
    if cookie.as_deref().is_some_and(|c| Rd(c).vec(2).is_none_or(|v| v.is_empty() || v.len() + 2 != c.len())) {
        return Err(decode_error("tls: decode error: bad HelloRetryRequest cookie"));
    }
    match group {
        None if cookie.is_none() => return Err(illegal("tls: illegal parameter: HelloRetryRequest changes nothing")),
        Some(X25519) => return Err(illegal("tls: illegal parameter: HelloRetryRequest for the key share sent")),
        Some(SECP256R1) => h.new_key(SECP256R1),
        Some(SECP384R1) => return Err(no_p384()),
        Some(_) => return Err(illegal("tls: illegal parameter: HelloRetryRequest for an unoffered group")),
        None => {}
    }
    // The transcript starts with a hash of the first ClientHello in its place.
    let mut hash_msg = vec![MESSAGE_HASH, 0, 0, suite.hash.len() as u8];
    hash_msg.extend_from_slice(&hash::digest(suite.hash, &ch));
    t.update(&hash_msg);
    t.update(&m);
    let ch = h.client_hello(cookie.as_deref());
    conn.send(HANDSHAKE, &ch)?;
    t.update(&ch);

    m = conn.read_hs()?;
    let sh = server_hello(&m, &h)?;
    if sh.retry {
        return Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message: a second HelloRetryRequest"));
    }
    if !sh.tls13 || sh.suite.id != suite.id {
        return Err(illegal("tls: illegal parameter: ServerHello differs from HelloRetryRequest"));
    }
    t.update(&m);
    finish(conn, &h, &sh, t)
}

fn finish<S: Read + Write>(conn: &mut Conn<S>, h: &Hello, sh: &ServerHello, t: Hasher) -> Result<Done> {
    if sh.tls13 { tls13::finish(conn, h, sh, t) } else { tls12::finish(conn, h, sh, t) }
}

pub(crate) fn no_p384() -> Error {
    Error::Tls(
        alert::HANDSHAKE_FAILURE,
        "tls: handshake failure: server chose secp384r1 key exchange, which is not supported",
    )
}

/// Seconds since the Unix epoch, for certificate validity.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The server's certificate chain, checked, and the leaf's key.
pub(crate) fn verify_chain<'a>(h: &Hello, chain: &[&'a [u8]]) -> Result<PublicKey<'a>> {
    if chain.is_empty() {
        return Err(decode_error("tls: decode error: the server sent no certificate"));
    }
    crate::x509::verify_server(chain, h.host, now(), &h.config.roots).map_err(|e| Error::Cert(e.0))
}
