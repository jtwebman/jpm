//! TLS 1.3 after ServerHello (RFC 8446 section 4): the key schedule, the server's encrypted
//! flight, and the client's Finished.

use std::io::{Read, Write};

use jpm_crypto::hash::{self, Hasher, hkdf_expand, hkdf_extract, hmac};
use jpm_crypto::{aead, ct_eq};

use super::hello::{self, Hello, Rd, ServerHello, body, decode_error, illegal, message};
use super::record::{CHANGE_CIPHER_SPEC, Conn, HANDSHAKE, Keys};
use super::{Error, Result, alert};
use crate::x509;

const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;

/// A secret from the key schedule: as long as the suite's hash.
#[derive(Clone, Copy)]
pub(crate) struct Secret {
    bytes: [u8; 48],
    len: u8,
}

impl std::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The application traffic secrets, kept for KeyUpdate.
#[derive(Clone)]
pub(crate) struct Secrets {
    pub(crate) hash: hash::Alg,
    pub(crate) aead: aead::Alg,
    pub(crate) client: Secret,
    pub(crate) server: Secret,
}

/// HKDF-Expand-Label (RFC 8446 section 7.1).
pub(crate) fn expand_label(alg: hash::Alg, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    hkdf_expand(alg, secret, &[&len, &[6 + label.len() as u8], b"tls13 ", label, &[context.len() as u8], context], out);
}

fn secret(bytes: &[u8]) -> Secret {
    let mut s = Secret { bytes: [0; 48], len: bytes.len() as u8 };
    s.bytes[..bytes.len()].copy_from_slice(bytes);
    s
}

/// Derive-Secret with the transcript hash already taken.
pub(crate) fn derive(alg: hash::Alg, secret: &[u8], label: &[u8], transcript: &[u8]) -> Secret {
    let mut s = Secret { bytes: [0; 48], len: alg.len() as u8 };
    expand_label(alg, secret, label, transcript, &mut s.bytes[..alg.len()]);
    s
}

/// The handshake secret from the (EC)DHE shared secret, with no PSK.
pub(crate) fn handshake_secret(alg: hash::Alg, shared: &[u8]) -> Secret {
    let zeros = [0; 48];
    let early = hkdf_extract(alg, &zeros[..alg.len()], &zeros[..alg.len()]);
    let derived = derive(alg, &early, b"derived", &hash::digest(alg, b""));
    secret(&hkdf_extract(alg, &derived, shared))
}

pub(crate) fn master_secret(alg: hash::Alg, handshake: &[u8]) -> Secret {
    let zeros = [0; 48];
    let derived = derive(alg, handshake, b"derived", &hash::digest(alg, b""));
    secret(&hkdf_extract(alg, &derived, &zeros[..alg.len()]))
}

/// The record keys for a traffic secret.
pub(crate) fn keys(alg: hash::Alg, aead: aead::Alg, secret: &[u8]) -> Keys {
    let mut key = [0; 32];
    let mut iv = [0; 12];
    expand_label(alg, secret, b"key", b"", &mut key[..aead.key_len()]);
    expand_label(alg, secret, b"iv", b"", &mut iv);
    Keys::new(aead, &key[..aead.key_len()], &iv)
}

/// The next traffic secret after a KeyUpdate (RFC 8446 section 7.2).
pub(crate) fn next_secret(alg: hash::Alg, s: &[u8]) -> Secret {
    derive(alg, s, b"traffic upd", b"")
}

/// Finished's verify_data (RFC 8446 section 4.4.4).
pub(crate) fn finished(alg: hash::Alg, base: &[u8], transcript: &[u8]) -> hash::Digest {
    let key = derive(alg, base, b"finished", b"");
    hmac(alg, &key, &[transcript])
}

/// Read the next handshake message and add it to the transcript.
fn next<S: Read + Write>(conn: &mut Conn<S>, t: &mut Hasher) -> Result<Vec<u8>> {
    let m = conn.read_hs()?;
    t.update(&m);
    Ok(m)
}

pub(crate) fn finish<S: Read + Write>(
    conn: &mut Conn<S>,
    h: &Hello,
    sh: &ServerHello,
    mut t: Hasher,
) -> Result<hello::Done> {
    let alg = sh.suite.hash;
    let aead = sh.suite.aead;
    let share = sh.ext(51).ok_or(Error::Tls(alert::MISSING_EXTENSION, "tls: missing extension: no key share"))?;
    let bad = || decode_error("tls: decode error: bad key share");
    let mut r = Rd(share);
    let group = r.u16().ok_or_else(bad)?;
    let key = r.vec(2).ok_or_else(bad)?;
    r.done().ok_or_else(bad)?;
    if group != h.group {
        return Err(illegal("tls: illegal parameter: key share for another group"));
    }
    let hs = handshake_secret(alg, &h.shared(key)?);
    let th = t.clone().finish();
    let c_hs = derive(alg, &hs, b"c hs traffic", &th);
    let s_hs = derive(alg, &hs, b"s hs traffic", &th);
    if !conn.hs.is_empty() {
        return Err(super::record::across_key_change());
    }
    conn.tls13 = true;
    conn.ccs_ok = true;
    conn.read = Some(keys(alg, aead, &s_hs));
    conn.write = Some(keys(alg, aead, &c_hs));

    // EncryptedExtensions (RFC 8446 section 4.3.1).
    let m = next(conn, &mut t)?;
    let b = body(&m, ENCRYPTED_EXTENSIONS, "tls: unexpected message: expected EncryptedExtensions")?;
    let bad = || decode_error("tls: decode error: bad EncryptedExtensions");
    let mut r = Rd(b);
    let exts = hello::extensions(r.vec(2).ok_or_else(bad)?).ok_or_else(bad)?;
    r.done().ok_or_else(bad)?;
    let mut alpn = None;
    for (typ, data) in exts {
        match typ {
            0 if data.is_empty() && h.sni().is_some() => {}
            10 => {}
            16 if !h.config.alpn.is_empty() => alpn = Some(hello::alpn_choice(data, h.config)?),
            _ => {
                return Err(Error::Tls(
                    alert::UNSUPPORTED_EXTENSION,
                    "tls: unsupported extension: server sent one not offered",
                ));
            }
        }
    }

    // CertificateRequest (section 4.3.2): we have no certificate, and say so.
    let mut m = next(conn, &mut t)?;
    let mut request = None;
    if m[0] == CERTIFICATE_REQUEST {
        let bad = || decode_error("tls: decode error: bad CertificateRequest");
        let mut r = Rd(&m[4..]);
        request = Some(r.vec(1).ok_or_else(bad)?.to_vec());
        r.vec(2).ok_or_else(bad)?;
        r.done().ok_or_else(bad)?;
        m = next(conn, &mut t)?;
    }

    // Certificate (section 4.4.2).
    let b = body(&m, CERTIFICATE, "tls: unexpected message: expected Certificate")?;
    let bad = || decode_error("tls: decode error: bad Certificate");
    let mut r = Rd(b);
    if !r.vec(1).ok_or_else(bad)?.is_empty() {
        return Err(illegal("tls: illegal parameter: Certificate with a request context"));
    }
    let mut list = Rd(r.vec(3).ok_or_else(bad)?);
    r.done().ok_or_else(bad)?;
    let mut chain = Vec::new();
    while !list.0.is_empty() {
        let cert = list.vec(3).filter(|c| !c.is_empty()).ok_or_else(bad)?;
        // We asked for no certificate extensions (OCSP, SCT), so there must be none.
        if !list.vec(2).ok_or_else(bad)?.is_empty() {
            return Err(Error::Tls(alert::UNSUPPORTED_EXTENSION, "tls: unsupported extension: in Certificate"));
        }
        chain.push(cert);
    }
    let key = hello::verify_chain(h, &chain)?;

    // CertificateVerify (section 4.4.3), over the transcript through Certificate.
    let th = t.clone().finish();
    let m = next(conn, &mut t)?;
    let b = body(&m, CERTIFICATE_VERIFY, "tls: unexpected message: expected CertificateVerify")?;
    let bad = || decode_error("tls: decode error: bad CertificateVerify");
    let mut r = Rd(b);
    let code = r.u16().ok_or_else(bad)?;
    let sig = r.vec(2).ok_or_else(bad)?;
    r.done().ok_or_else(bad)?;
    let scheme = hello::scheme(code, &key, true)
        .ok_or(illegal("tls: illegal parameter: signature scheme not offered or not for this key"))?;
    let mut content = Vec::with_capacity(64 + 34 + th.len());
    content.extend_from_slice(&[0x20; 64]);
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(&th);
    if !x509::verify_signature(&key, scheme, &content, sig) {
        return Err(Error::Tls(alert::DECRYPT_ERROR, "tls: decrypt error: bad CertificateVerify signature"));
    }

    // Finished (section 4.4.4), over the transcript through CertificateVerify.
    let want = finished(alg, &s_hs, &t.clone().finish());
    let m = next(conn, &mut t)?;
    let b = body(&m, FINISHED, "tls: unexpected message: expected Finished")?;
    if !ct_eq(b, &want) {
        return Err(Error::Tls(alert::DECRYPT_ERROR, "tls: decrypt error: bad Finished"));
    }
    if !conn.hs.is_empty() {
        return Err(super::record::across_key_change());
    }
    conn.ccs_ok = false;
    let th = t.clone().finish();
    let master = master_secret(alg, &hs);
    let c_ap = derive(alg, &master, b"c ap traffic", &th);
    let s_ap = derive(alg, &master, b"s ap traffic", &th);

    // Our flight: the compatibility change_cipher_spec, an empty Certificate if asked, Finished.
    conn.push(CHANGE_CIPHER_SPEC, &[1])?;
    if let Some(context) = request {
        let mut b = vec![context.len() as u8];
        b.extend_from_slice(&context);
        b.extend_from_slice(&[0, 0, 0]);
        let m = message(CERTIFICATE, &b);
        t.update(&m);
        conn.push(HANDSHAKE, &m)?;
    }
    let m = message(FINISHED, &finished(alg, &c_hs, &t.finish()));
    conn.push(HANDSHAKE, &m)?;
    conn.flush_records()?;
    conn.read = Some(keys(alg, aead, &s_ap));
    conn.write = Some(keys(alg, aead, &c_ap));
    Ok(hello::Done { alpn, secrets: Some(Secrets { hash: alg, aead, client: c_ap, server: s_ap }) })
}
