//! TLS 1.2 after ServerHello, ECDHE and AEAD suites only (RFC 5246 section 7.3, RFC 8422,
//! RFC 7627 for the extended master secret).

use std::io::{Read, Write};

use jpm_crypto::hash::{Hasher, tls12_prf};
use jpm_crypto::{aead, ct_eq};

use super::hello::{
    self, Hello, Kind, Rd, SECP256R1, SECP384R1, ServerHello, X25519, body, decode_error, illegal, message,
};
use super::record::{CHANGE_CIPHER_SPEC, Conn, HANDSHAKE, Keys};
use super::{Error, Result, alert};
use crate::x509::{self, PublicKey};

const CERTIFICATE: u8 = 11;
const SERVER_KEY_EXCHANGE: u8 = 12;
const CERTIFICATE_REQUEST: u8 = 13;
const SERVER_HELLO_DONE: u8 = 14;
const CLIENT_KEY_EXCHANGE: u8 = 16;
const FINISHED: u8 = 20;

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
    let suite = sh.suite;
    let alg = suite.hash;
    let alpn = sh.ext(16).map(|d| hello::alpn_choice(d, h.config)).transpose()?;

    // Certificate (RFC 5246 section 7.4.2).
    let m = next(conn, &mut t)?;
    let b = body(&m, CERTIFICATE, "tls: unexpected message: expected Certificate")?;
    let bad = || decode_error("tls: decode error: bad Certificate");
    let mut r = Rd(b);
    let mut list = Rd(r.vec(3).ok_or_else(bad)?);
    r.done().ok_or_else(bad)?;
    let mut chain = Vec::new();
    while !list.0.is_empty() {
        chain.push(list.vec(3).filter(|c| !c.is_empty()).ok_or_else(bad)?);
    }
    let key = hello::verify_chain(h, &chain)?;
    let fits = match key {
        PublicKey::Rsa { .. } => suite.kind == Kind::Rsa,
        PublicKey::P256(_) | PublicKey::P384(_) => suite.kind == Kind::Ecdsa,
    };
    if !fits {
        return Err(Error::Tls(
            alert::UNSUPPORTED_CERTIFICATE,
            "tls: unsupported certificate: key does not fit the cipher suite",
        ));
    }

    // ServerKeyExchange (RFC 8422 section 5.4): named curve, point, signature.
    let m = next(conn, &mut t)?;
    let b = body(&m, SERVER_KEY_EXCHANGE, "tls: unexpected message: expected ServerKeyExchange")?;
    let bad = || decode_error("tls: decode error: bad ServerKeyExchange");
    let mut r = Rd(b);
    if r.u8().ok_or_else(bad)? != 3 {
        return Err(illegal("tls: illegal parameter: ServerKeyExchange without a named curve"));
    }
    let group = r.u16().ok_or_else(bad)?;
    let point = r.vec(1).ok_or_else(bad)?;
    let params = &b[..4 + point.len()];
    let code = r.u16().ok_or_else(bad)?;
    let sig = r.vec(2).ok_or_else(bad)?;
    r.done().ok_or_else(bad)?;
    match group {
        X25519 | SECP256R1 => {}
        SECP384R1 => return Err(hello::no_p384()),
        _ => return Err(illegal("tls: illegal parameter: server chose an unoffered group")),
    }
    let scheme = hello::scheme(code, &key, false)
        .ok_or(illegal("tls: illegal parameter: signature scheme not offered or not for this key"))?;
    let mut signed = Vec::with_capacity(64 + params.len());
    signed.extend_from_slice(&h.random);
    signed.extend_from_slice(&sh.random);
    signed.extend_from_slice(params);
    if !x509::verify_signature(&key, scheme, &signed, sig) {
        return Err(Error::Tls(alert::DECRYPT_ERROR, "tls: decrypt error: bad ServerKeyExchange signature"));
    }

    // CertificateRequest (section 7.4.4), then ServerHelloDone.
    let mut m = next(conn, &mut t)?;
    let requested = m[0] == CERTIFICATE_REQUEST;
    if requested {
        let bad = || decode_error("tls: decode error: bad CertificateRequest");
        let mut r = Rd(&m[4..]);
        r.vec(1).ok_or_else(bad)?;
        r.vec(2).ok_or_else(bad)?;
        r.vec(2).ok_or_else(bad)?;
        r.done().ok_or_else(bad)?;
        m = next(conn, &mut t)?;
    }
    if !body(&m, SERVER_HELLO_DONE, "tls: unexpected message: expected ServerHelloDone")?.is_empty() {
        return Err(decode_error("tls: decode error: bad ServerHelloDone"));
    }

    // Our key share and the premaster secret. X25519 reuses the key from our ClientHello.
    let (public, premaster) = match group {
        X25519 => (h.public(), h.shared(point)?),
        _ => {
            let k = h.fresh(SECP256R1);
            (k.public(), k.shared(point)?)
        }
    };

    // Our flight: an empty Certificate if asked, ClientKeyExchange, ChangeCipherSpec, Finished.
    if requested {
        let m = message(CERTIFICATE, &[0, 0, 0]);
        t.update(&m);
        conn.push(HANDSHAKE, &m)?;
    }
    let mut b = vec![public.len() as u8];
    b.extend_from_slice(&public);
    let m = message(CLIENT_KEY_EXCHANGE, &b);
    t.update(&m);
    conn.push(HANDSHAKE, &m)?;

    let mut master = [0; 48];
    if sh.ext(23).is_some() {
        let session_hash = t.clone().finish();
        tls12_prf(alg, &premaster, b"extended master secret", &[&session_hash], &mut master);
    } else {
        tls12_prf(alg, &premaster, b"master secret", &[&h.random, &sh.random], &mut master);
    }
    // RFC 5288 section 3 and RFC 7905 section 2: no MAC keys; a 4-byte salt for AES-GCM, a
    // 12-byte IV for ChaCha20-Poly1305.
    let klen = suite.aead.key_len();
    let ivlen = if suite.aead == aead::Alg::ChaCha20Poly1305 { 12 } else { 4 };
    let mut kb = [0; 2 * (32 + 12)];
    let kb = &mut kb[..2 * (klen + ivlen)];
    tls12_prf(alg, &master, b"key expansion", &[&sh.random, &h.random], kb);
    let (ck, rest) = kb.split_at(klen);
    let (sk, rest) = rest.split_at(klen);
    let (civ, siv) = rest.split_at(ivlen);

    conn.push(CHANGE_CIPHER_SPEC, &[1])?;
    conn.explicit_nonce = ivlen == 4;
    conn.write = Some(Keys::new(suite.aead, ck, civ));
    let mut verify = [0; 12];
    tls12_prf(alg, &master, b"client finished", &[&t.clone().finish()], &mut verify);
    let m = message(FINISHED, &verify);
    t.update(&m);
    conn.push(HANDSHAKE, &m)?;
    conn.flush_records()?;

    // The server's ChangeCipherSpec and Finished.
    conn.read_ccs()?;
    conn.read = Some(Keys::new(suite.aead, sk, siv));
    tls12_prf(alg, &master, b"server finished", &[&t.finish()], &mut verify);
    let m = conn.read_hs()?;
    let b = body(&m, FINISHED, "tls: unexpected message: expected Finished")?;
    if !ct_eq(b, &verify) {
        return Err(Error::Tls(alert::DECRYPT_ERROR, "tls: decrypt error: bad Finished"));
    }
    if !conn.hs.is_empty() {
        return Err(super::record::across_key_change());
    }
    Ok(hello::Done { alpn, secrets: None })
}
