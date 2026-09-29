//! Against the scripted server (tests/common/fake.rs): what the client sends, and every way a
//! server can get the handshake or the records wrong. Each bad case must end in a clean error
//! with a message saying what went wrong, the right alert to the server, and no panic or hang.

mod common;

use std::io::{ErrorKind, Read, Write};

use common::fake::{self, ALERT, APP, CCS, ClientHello, HANDSHAKE, Outcome, SECP256R1, Script, X25519};
use common::{KeyType, connect, err_msg, pki};

const UNEXPECTED_MESSAGE: u8 = 10;
const BAD_RECORD_MAC: u8 = 20;
const RECORD_OVERFLOW: u8 = 22;
const HANDSHAKE_FAILURE: u8 = 40;
const UNSUPPORTED_CERTIFICATE: u8 = 43;
const ILLEGAL_PARAMETER: u8 = 47;
const DECODE_ERROR: u8 = 50;
const DECRYPT_ERROR: u8 = 51;
const PROTOCOL_VERSION: u8 = 70;
const UNSUPPORTED_EXTENSION: u8 = 110;

/// Connect to `script` as "localhost" with ALPN `alpn`.
fn try_connect(script: Script, alpn: &[&[u8]]) -> (std::io::Result<jpm_tls::Stream<std::net::TcpStream>>, Outcome) {
    let key = script.key;
    let (tcp, h) = fake::run(script);
    let r = connect(tcp, "localhost", &pki(key).config(alpn));
    (r, h.join().unwrap())
}

/// The handshake must fail with `msg` in the error, and the server must get alert `alert`.
#[track_caller]
fn refused(script: Script, msg: &str, alert: Option<u8>) {
    refused_alpn(script, &[], msg, alert);
}

#[track_caller]
fn refused_alpn(script: Script, alpn: &[&[u8]], msg: &str, alert: Option<u8>) {
    let (r, out) = try_connect(watch_alert(script), alpn);
    let e = err_msg(r);
    assert!(e.contains(msg), "error {e:?}, wanted {msg:?}");
    assert_eq!(out.alert, alert, "alert for {e:?}");
}

/// The handshake works; then reading must fail with `msg`, and the server gets `alert`.
#[track_caller]
fn read_fails(script: Script, msg: &str, alert: Option<u8>) {
    let key = script.key;
    let (tcp, h) = fake::run(watch_alert(script));
    let mut s = connect(tcp, "localhost", &pki(key).config(&[])).unwrap();
    let mut buf = Vec::new();
    let e = err_msg(s.read_to_end(&mut buf));
    assert!(e.contains(msg), "error {e:?}, wanted {msg:?}");
    // Reads after a failure fail too.
    assert!(s.read(&mut [0; 10]).is_err());
    drop(s);
    let out = h.join().unwrap();
    assert!(out.finished, "the handshake was fine");
    assert_eq!(out.alert, alert, "alert for {e:?}");
}

/// After the script's end, wait for the client's alert.
fn watch_alert(mut script: Script) -> Script {
    let after = std::mem::replace(&mut script.after, Box::new(|_| Ok(())));
    script.after = Box::new(move |f| {
        after(f)?;
        f.seen_alert = f.recv_alert();
        Ok(())
    });
    script
}

/// Edit the extensions of a message whose extension block starts at `at` (its 2-byte
/// length), fixing the lengths after.
fn edit_exts(m: &mut Vec<u8>, at: usize, f: impl FnOnce(&mut Vec<(u16, Vec<u8>)>)) {
    let n = usize::from(u16::from_be_bytes([m[at], m[at + 1]]));
    let mut exts = Vec::new();
    let mut e = &m[at + 2..at + 2 + n];
    while !e.is_empty() {
        let len = usize::from(u16::from_be_bytes([e[2], e[3]]));
        exts.push((u16::from_be_bytes([e[0], e[1]]), e[4..4 + len].to_vec()));
        e = &e[4 + len..];
    }
    f(&mut exts);
    let mut block = Vec::new();
    for (t, d) in exts {
        block.extend_from_slice(&t.to_be_bytes());
        block.extend_from_slice(&(d.len() as u16).to_be_bytes());
        block.extend_from_slice(&d);
    }
    m.truncate(at);
    m.extend_from_slice(&(block.len() as u16).to_be_bytes());
    m.extend_from_slice(&block);
    fix_len(m);
}

/// Set the handshake header's length to the body's.
fn fix_len(m: &mut [u8]) {
    let n = (m.len() - 4) as u32;
    m[1..4].copy_from_slice(&n.to_be_bytes()[1..]);
}

/// Where a ServerHello's extensions start, with a 32-byte session id.
const SH_EXTS: usize = 4 + 2 + 32 + 1 + 32 + 2 + 1;
const SH_SUITE: usize = 4 + 2 + 32 + 1 + 32;

fn on(name: &'static str, f: impl Fn(&mut Vec<u8>) + Send + 'static) -> impl FnMut(&str, &mut Vec<u8>) + Send {
    move |n, m| {
        if n == name {
            f(m)
        }
    }
}

// --- what the client sends ------------------------------------------------------------------

#[test]
fn client_hello_contents() {
    let (r, out) = try_connect(Script::default(), &[b"h2", b"http/1.1"]);
    r.unwrap();
    let ch = ClientHello::parse(&out.client_hello);
    assert_eq!(&out.client_hello[4..6], [3, 3]);
    assert_eq!(ch.session_id.len(), 32, "middlebox compatibility mode");
    let mut want = vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8];
    if !jpm_crypto::aead::aes_hardware() {
        want = vec![0x1303, 0x1301, 0x1302, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030];
    }
    assert_eq!(ch.suites, want);
    assert_eq!(ch.ext(0).unwrap(), b"\x00\x0c\x00\x00\x09localhost");
    assert_eq!(ch.ext(10).unwrap(), [0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]);
    assert_eq!(ch.ext(11).unwrap(), [1, 0]);
    assert_eq!(ch.ext(13).unwrap(), [0, 16, 4, 3, 5, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1]);
    assert_eq!(ch.ext(16).unwrap(), b"\x00\x0c\x02h2\x08http/1.1");
    assert_eq!(ch.ext(23).unwrap(), []);
    assert_eq!(ch.ext(0xff01).unwrap(), [0]);
    assert_eq!(ch.ext(43).unwrap(), [4, 3, 4, 3, 3]);
    assert_eq!(ch.share(X25519).unwrap().len(), 32);
    assert!(ch.share(SECP256R1).is_none());
    // Nothing else: no PSK, early data, tickets, status request or heartbeat.
    let types: Vec<u16> = ch.exts.iter().map(|e| e.0).collect();
    assert_eq!(types, [0, 10, 11, 13, 16, 23, 0xff01, 43, 51]);
}

#[test]
fn no_sni_for_ip_addresses_and_no_trailing_dot() {
    for (host, sni) in [("127.0.0.1", None), ("::1", None), ("localhost.", Some(&b"\x00\x0c\x00\x00\x09localhost"[..]))]
    {
        let (tcp, h) = fake::run(Script::default());
        let r = connect(tcp, host, &pki(KeyType::P256).config(&[]));
        // The certificate has localhost and 127.0.0.1.
        assert_eq!(r.is_ok(), host != "::1", "{host}");
        let out = h.join().unwrap();
        assert_eq!(ClientHello::parse(&out.client_hello).ext(0), sni, "{host}");
    }
}

#[test]
fn randoms_differ() {
    let hello = || {
        let (r, out) = try_connect(Script::default(), &[]);
        r.unwrap();
        ClientHello::parse(&out.client_hello)
    };
    let (a, b) = (hello(), hello());
    assert_ne!(a.random, b.random);
    assert_ne!(a.session_id, b.session_id);
    assert_ne!(a.share(X25519), b.share(X25519));
}

// --- handshakes that work -------------------------------------------------------------------

/// A full exchange: the handshake, data both ways, close_notify.
fn exchange(script: Script) -> Outcome {
    let script = script.after(|f| {
        let got = f.recv_data()?;
        f.send(APP, &got)?;
        f.close_notify()
    });
    let (r, out) = try_connect_then(script, |s| {
        s.write_all(b"ping").unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"ping");
    });
    r.unwrap();
    assert!(out.done, "{out:?}");
    out
}

fn try_connect_then(
    script: Script,
    f: impl FnOnce(&mut jpm_tls::Stream<std::net::TcpStream>),
) -> (std::io::Result<()>, Outcome) {
    let key = script.key;
    let (tcp, h) = fake::run(script);
    let r = connect(tcp, "localhost", &pki(key).config(&[])).map(|mut s| f(&mut s));
    (r, h.join().unwrap())
}

#[test]
fn works_tls13() {
    for suite in [0x1301, 0x1302, 0x1303] {
        for key in common::KEY_TYPES {
            exchange(Script { suite, key, ..Script::default() });
        }
    }
    exchange(Script { ccs: false, ..Script::default() });
    exchange(Script { split: true, ..Script::default() });
}

#[test]
fn works_tls12() {
    for (suite, key) in [
        (0xc02b, KeyType::P256),
        (0xc02c, KeyType::P384),
        (0xcca9, KeyType::P256),
        (0xc02f, KeyType::Rsa2048),
        (0xc030, KeyType::Rsa4096),
        (0xcca8, KeyType::Rsa2048),
    ] {
        for group12 in [X25519, SECP256R1] {
            for ems in [true, false] {
                exchange(Script { suite, key, group12, ems, ..Script::tls12() });
            }
        }
    }
    // PKCS#1 v1.5 is fine in TLS 1.2 ServerKeyExchange.
    for scheme in [0x0401, 0x0501, 0x0601, 0x0805, 0x0806] {
        exchange(Script { key: KeyType::Rsa2048, scheme, ..Script::tls12() });
    }
}

#[test]
fn works_with_one_byte_records() {
    exchange(Script { fragment: 1, ..Script::default() });
    exchange(Script { fragment: 1, ..Script::tls12() });
    exchange(Script { fragment: 1, hrr: Some(SECP256R1), ..Script::default() });
}

#[test]
fn hello_retry_request() {
    let out = exchange(Script { hrr: Some(SECP256R1), ..Script::default() });
    let (a, b) = (ClientHello::parse(&out.client_hello), ClientHello::parse(out.client_hello2.as_ref().unwrap()));
    assert_eq!(a.random, b.random);
    assert_eq!(a.session_id, b.session_id);
    assert!(b.share(X25519).is_none());
    assert_eq!(b.share(SECP256R1).unwrap().len(), 65);
    assert!(b.ext(44).is_none());

    let out = exchange(Script { hrr: Some(SECP256R1), cookie: true, suite: 0x1302, ..Script::default() });
    let b = ClientHello::parse(out.client_hello2.as_ref().unwrap());
    assert_eq!(b.ext(44).unwrap(), b"\x00\x18a cookie from the server");

    // A cookie alone, with the same group again.
    let script = Script { hrr: Some(SECP256R1), cookie: true, ..Script::default() };
    let out = exchange(script.edit(on("HRR", |m| edit_exts(m, SH_EXTS, |e| e.retain(|x| x.0 != 51)))));
    let b = ClientHello::parse(out.client_hello2.as_ref().unwrap());
    assert_eq!(b.share(X25519).unwrap().len(), 32);
}

#[test]
fn certificate_request() {
    let out = exchange(Script { cert_request: true, ..Script::default() });
    assert_eq!(out.client_cert.unwrap(), [11, 0, 0, 7, 3, b'c', b't', b'x', 0, 0, 0]);
    let out = exchange(Script { cert_request: true, ..Script::tls12() });
    assert_eq!(out.client_cert.unwrap(), [11, 0, 0, 3, 0, 0, 0]);
}

#[test]
fn alpn_accepted() {
    for script in [Script::default(), Script::tls12()] {
        let script = Script { alpn: Some(b"http/1.1".to_vec()), ..script };
        let (r, _) = try_connect(script, &[b"h2", b"http/1.1"]);
        assert_eq!(r.unwrap().alpn(), Some(&b"http/1.1"[..]));
    }
}

// --- ServerHello and HelloRetryRequest ------------------------------------------------------

#[test]
fn bad_server_hello() {
    let sh = |f: fn(&mut Vec<u8>)| Script::default().edit(on("SH", f));
    let sh12 = |f: fn(&mut Vec<u8>)| Script::tls12().edit(on("SH", f));
    refused(sh(|m| m[4..6].copy_from_slice(&[3, 2])), "tls: protocol version", Some(PROTOCOL_VERSION));
    refused(sh12(|m| m[4..6].copy_from_slice(&[3, 1])), "tls: protocol version", Some(PROTOCOL_VERSION));
    refused(sh(|m| m[40] ^= 1), "session id not echoed", Some(ILLEGAL_PARAMETER));
    refused(
        sh(|m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0x13, 0x04])),
        "tls: handshake failure: server chose an unoffered cipher suite",
        Some(ILLEGAL_PARAMETER),
    );
    // A TLS 1.2 suite in a TLS 1.3 ServerHello, and the other way round.
    refused(
        sh(|m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0xc0, 0x2b])),
        "unoffered cipher suite",
        Some(ILLEGAL_PARAMETER),
    );
    refused(
        sh12(|m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0x13, 0x01])),
        "unoffered cipher suite",
        Some(ILLEGAL_PARAMETER),
    );
    refused(
        sh12(|m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0x00, 0x9c])),
        "unoffered cipher suite",
        Some(ILLEGAL_PARAMETER),
    );
    refused(sh(|m| m[SH_SUITE + 2] = 1), "compression", Some(ILLEGAL_PARAMETER));
    refused(
        sh(|m| {
            m.push(0);
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
    // A byte after the ServerHello, in its record: the start of a message before the keys
    // change.
    refused(sh(|m| m.push(0)), "handshake data across a key change", Some(UNEXPECTED_MESSAGE));
    // Cut short: the next record interrupts it.
    refused(sh(|m| m.truncate(40)), "inside a handshake message", Some(UNEXPECTED_MESSAGE));
    refused(
        sh(|m| {
            m.truncate(10);
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
    // supported_versions: another version, TLS 1.2 in it, or junk.
    for v in [&[3u8, 5][..], &[3, 3], &[3, 4, 3, 3], &[]] {
        let v = v.to_vec();
        let script = Script::default().edit(move |n, m| {
            if n == "SH" {
                edit_exts(m, SH_EXTS, |e| e.iter_mut().filter(|x| x.0 == 43).for_each(|x| x.1 = v.clone()))
            }
        });
        refused(script, "unoffered version", Some(ILLEGAL_PARAMETER));
    }
    // A TLS 1.3 ServerHello without a key share.
    refused(sh(|m| edit_exts(m, SH_EXTS, |e| e.retain(|x| x.0 != 51))), "no key share", Some(109));
    // A key share for a group other than the one sent.
    refused(
        sh(|m| edit_exts(m, SH_EXTS, |e| e.iter_mut().filter(|x| x.0 == 51).for_each(|x| x.1[1] = 0x17))),
        "key share for another group",
        Some(ILLEGAL_PARAMETER),
    );
    // Bad points: all zeros gives an all-zero X25519 shared secret; a P-256 point off the
    // curve, or not uncompressed, or of the wrong length.
    refused(Script::default().edit(on("Point", |p| p.fill(0))), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(Script::default().edit(on("Point", |p| p.truncate(31))), "bad key share", Some(ILLEGAL_PARAMETER));
    let p256 = |f: fn(&mut Vec<u8>)| Script { hrr: Some(SECP256R1), ..Script::default() }.edit(on("Point", f));
    refused(p256(|p| p[40] ^= 1), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(p256(|p| p[0] = 2), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(p256(|p| p.truncate(33)), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(p256(|p| p.fill(0)), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(
        sh(|m| edit_exts(m, SH_EXTS, |e| e.iter_mut().filter(|x| x.0 == 51).for_each(|x| x.1.truncate(20)))),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
    // A duplicate extension.
    refused(sh(|m| edit_exts(m, SH_EXTS, |e| e.push(e[0].clone()))), "tls: decode error", Some(DECODE_ERROR));
    // Extensions not offered, or not allowed in a TLS 1.3 ServerHello.
    for typ in [0u16, 16, 23, 0xff01, 0x1234, 44, 41] {
        let script = Script::default().edit(move |n, m| {
            if n == "SH" {
                edit_exts(m, SH_EXTS, |e| e.push((typ, Vec::new())))
            }
        });
        refused(script, "tls: unsupported extension", Some(UNSUPPORTED_EXTENSION));
    }
    for typ in [43u16, 51, 44, 0x1234, 10, 13] {
        let script = Script::tls12().edit(move |n, m| {
            if n == "SH" {
                edit_exts(m, SH_EXTS, |e| e.push((typ, Vec::new())))
            }
        });
        let alert = if typ == 43 { ILLEGAL_PARAMETER } else { UNSUPPORTED_EXTENSION };
        refused(script, "tls: ", Some(alert));
    }
}

#[test]
fn downgrade_sentinel() {
    for last in [0u8, 1] {
        let script = Script::tls12().edit(move |n, m| {
            if n == "SH" {
                m[30..38].copy_from_slice(b"DOWNGRD\0");
                m[37] = last;
            }
        });
        refused(script, "tls: illegal parameter: downgrade from TLS 1.3 detected", Some(ILLEGAL_PARAMETER));
    }
    // Any other value there is fine.
    let script = Script::tls12().edit(on("SH", |m| m[30..38].copy_from_slice(b"DOWNGRD\x02")));
    exchange(script);
}

#[test]
fn tls12_server_hello_extensions() {
    let sh12 = |f: fn(&mut Vec<u8>)| Script::tls12().edit(on("SH", f));
    let bad = |t: u16, d: &'static [u8]| {
        Script::tls12().edit(move |n, m| {
            if n == "SH" {
                edit_exts(m, SH_EXTS, |e| e.iter_mut().filter(|x| x.0 == t).for_each(|x| x.1 = d.to_vec()))
            }
        })
    };
    refused(bad(0xff01, &[1, 0]), "bad ServerHello extension", Some(ILLEGAL_PARAMETER));
    refused(bad(23, &[0]), "bad ServerHello extension", Some(ILLEGAL_PARAMETER));
    refused(bad(11, &[1, 1]), "bad ServerHello extension", Some(ILLEGAL_PARAMETER));
    refused(bad(11, &[2, 0]), "bad ServerHello extension", Some(ILLEGAL_PARAMETER));
    // Without renegotiation_info or point formats is fine (RFC 5746 section 3.4, RFC 8422).
    exchange(sh12(|m| edit_exts(m, SH_EXTS, |e| e.retain(|x| x.0 != 0xff01 && x.0 != 11))));
    // A server session id of any length up to 32, or none.
    exchange(sh12(|m| {
        m.drain(39..71);
        m[38] = 0;
        fix_len(m)
    }));
    refused(
        sh12(|m| {
            m[38] = 33;
            m.insert(39, 0);
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
}

#[test]
fn hello_retry_request_errors() {
    refused(
        Script { hrr: Some(SECP256R1), hrr_twice: true, ..Script::default() },
        "tls: unexpected message: a second HelloRetryRequest",
        Some(UNEXPECTED_MESSAGE),
    );
    refused(
        Script { hrr: Some(SECP256R1), hrr_twice: true, cookie: true, ..Script::default() },
        "a second HelloRetryRequest",
        Some(UNEXPECTED_MESSAGE),
    );
    refused(Script { hrr: Some(X25519), ..Script::default() }, "for the key share sent", Some(ILLEGAL_PARAMETER));
    refused(Script { hrr: Some(0x001e), ..Script::default() }, "for an unoffered group", Some(ILLEGAL_PARAMETER));
    refused(Script { hrr: Some(0x0018), ..Script::default() }, "secp384r1", Some(HANDSHAKE_FAILURE));
    let hrr = |f: fn(&mut Vec<u8>)| Script { hrr: Some(SECP256R1), ..Script::default() }.edit(on("HRR", f));
    refused(hrr(|m| edit_exts(m, SH_EXTS, |e| e.retain(|x| x.0 != 51))), "changes nothing", Some(ILLEGAL_PARAMETER));
    refused(
        hrr(|m| edit_exts(m, SH_EXTS, |e| e.retain(|x| x.0 != 43))),
        "HelloRetryRequest without TLS 1.3",
        Some(ILLEGAL_PARAMETER),
    );
    refused(
        hrr(|m| edit_exts(m, SH_EXTS, |e| e.push((0x1234, Vec::new())))),
        "unsupported extension",
        Some(UNSUPPORTED_EXTENSION),
    );
    refused(hrr(|m| edit_exts(m, SH_EXTS, |e| e.push((44, vec![0, 0])))), "cookie", Some(DECODE_ERROR));
    refused(
        hrr(|m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0x13, 0x07])),
        "unoffered cipher suite",
        Some(ILLEGAL_PARAMETER),
    );
    // The ServerHello after it must agree with it.
    let script = Script { hrr: Some(SECP256R1), ..Script::default() };
    refused(
        script.edit(on("SH", |m| m[SH_SUITE..SH_SUITE + 2].copy_from_slice(&[0x13, 0x03]))),
        "ServerHello differs from HelloRetryRequest",
        Some(ILLEGAL_PARAMETER),
    );
}

// --- the encrypted flight -------------------------------------------------------------------

#[test]
fn bad_encrypted_extensions() {
    let ee = |f: fn(&mut Vec<u8>)| Script::default().edit(on("EE", f));
    for typ in [43u16, 51, 0x1234, 23, 0xff01, 11, 13, 16] {
        let script = Script::default().edit(move |n, m| {
            if n == "EE" {
                edit_exts(m, 4, |e| e.push((typ, Vec::new())))
            }
        });
        refused(script, "tls: unsupported extension", Some(UNSUPPORTED_EXTENSION));
    }
    // Duplicates, and trailing bytes.
    refused(
        ee(|m| edit_exts(m, 4, |e| e.extend([(10, vec![]), (10, vec![])]))),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
    refused(
        ee(|m| {
            m.push(0);
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
    // supported_groups and an empty server_name are fine.
    exchange(
        Script::default().edit(on("EE", |m| edit_exts(m, 4, |e| e.extend([(10, vec![0, 2, 0, 0x1d]), (0, vec![])])))),
    );
}

#[test]
fn alpn_errors() {
    for base in [Script::default, Script::tls12] {
        // Chosen but not offered at all.
        let script = Script { alpn: Some(b"h2".to_vec()), ..base() };
        refused_alpn(script, &[], "tls: unsupported extension", Some(UNSUPPORTED_EXTENSION));
        // Chosen from outside our list.
        let script = Script { alpn: Some(b"h2".to_vec()), ..base() };
        refused_alpn(script, &[b"http/1.1"], "unoffered ALPN protocol", Some(ILLEGAL_PARAMETER));
        // Two protocols, or an empty one.
        for d in [&b"\x00\x0a\x03abc\x05http1"[..], b"\x00\x01\x00", b"\x00\x00", b""] {
            let name = if base().tls12 { "SH" } else { "EE" };
            let at = if base().tls12 { SH_EXTS } else { 4 };
            let script = Script { alpn: Some(b"abc".to_vec()), ..base() }.edit(move |n, m| {
                if n == name {
                    edit_exts(m, at, |e| e.iter_mut().filter(|x| x.0 == 16).for_each(|x| x.1 = d.to_vec()))
                }
            });
            refused_alpn(script, &[b"abc", b"http1"], "tls: decode error", Some(DECODE_ERROR));
        }
    }
}

#[test]
fn bad_certificate_message() {
    let cert = |f: fn(&mut Vec<u8>)| Script::default().edit(on("Cert", f));
    // No certificates.
    refused(cert(|m| *m = vec![11, 0, 0, 4, 0, 0, 0, 0]), "no certificate", Some(DECODE_ERROR));
    refused(
        Script::tls12().edit(on("Cert", |m| *m = vec![11, 0, 0, 3, 0, 0, 0])),
        "no certificate",
        Some(DECODE_ERROR),
    );
    // A request context we never asked for.
    refused(
        cert(|m| {
            m[4] = 1;
            m.insert(5, 7);
            fix_len(m)
        }),
        "request context",
        Some(ILLEGAL_PARAMETER),
    );
    // An extension on a certificate entry (none were asked for).
    refused(
        cert(|m| {
            let leaf = &pki(KeyType::P256).chain[0];
            let mut entry = (leaf.len() as u32).to_be_bytes()[1..].to_vec();
            entry.extend_from_slice(leaf);
            entry.extend_from_slice(&[0, 4, 0, 5, 0, 0]);
            let mut body = vec![0];
            body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..]);
            body.extend_from_slice(&entry);
            *m = fake::message(11, &body);
        }),
        "tls: unsupported extension",
        Some(UNSUPPORTED_EXTENSION),
    );
    // Lengths that do not add up.
    refused(cert(|m| m[7] ^= 1), "tls: decode error", Some(DECODE_ERROR));
    refused(Script::tls12().edit(on("Cert", |m| m[6] ^= 1)), "tls: decode error", Some(DECODE_ERROR));
    // Garbage for a certificate: the checks refuse it.
    refused(
        cert(|m| {
            let at = 11;
            m[at..at + 20].fill(0x41);
        }),
        "tls: bad certificate",
        Some(42),
    );
}

#[test]
fn bad_certificate_verify() {
    let cv = |f: fn(&mut Vec<u8>)| Script::default().edit(on("CV", f));
    refused(
        cv(|m| *m.last_mut().unwrap() ^= 1),
        "tls: decrypt error: bad CertificateVerify signature",
        Some(DECRYPT_ERROR),
    );
    refused(cv(|m| m[20] ^= 0x10), "tls: decrypt error", Some(DECRYPT_ERROR));
    // Schemes not offered, not allowed in TLS 1.3, or not for the key.
    for scheme in [0x0503u16, 0x0804, 0x0401, 0x0807, 0x0203, 0x0603] {
        let script = Script::default().edit(move |n, m| {
            if n == "CV" {
                m[4..6].copy_from_slice(&scheme.to_be_bytes())
            }
        });
        refused(script, "signature scheme not offered", Some(ILLEGAL_PARAMETER));
    }
    for scheme in [0x0401u16, 0x0501, 0x0601, 0x0403] {
        let script = Script { key: KeyType::Rsa2048, ..Script::default() }.edit(move |n, m| {
            if n == "CV" {
                m[4..6].copy_from_slice(&scheme.to_be_bytes())
            }
        });
        refused(script, "signature scheme not offered", Some(ILLEGAL_PARAMETER));
    }
    // The P-384 scheme with a P-256 key (TLS 1.3 binds the curve).
    let script =
        Script { key: KeyType::P384, ..Script::default() }.edit(on("CV", |m| m[4..6].copy_from_slice(&[4, 3])));
    refused(script, "signature scheme not offered", Some(ILLEGAL_PARAMETER));
    refused(
        cv(|m| {
            m.pop();
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
}

#[test]
fn bad_finished() {
    refused(
        Script::default().edit(on("Fin", |m| *m.last_mut().unwrap() ^= 1)),
        "tls: decrypt error: bad Finished",
        Some(DECRYPT_ERROR),
    );
    refused(
        Script::default().edit(on("Fin", |m| {
            m.pop();
            fix_len(m)
        })),
        "bad Finished",
        Some(DECRYPT_ERROR),
    );
    // TLS 1.2: the server's Finished comes after ours, encrypted.
    refused(Script::tls12().edit(on("Fin", |m| m[4] ^= 0x80)), "tls: decrypt error: bad Finished", Some(DECRYPT_ERROR));
}

#[test]
fn messages_out_of_order() {
    let named = |name: &'static str, f: fn(&mut Vec<u8>)| Script::default().edit(on(name, f));
    // A message of the wrong type where each one is expected, empty or not.
    for name in ["EE", "Cert", "CV", "Fin"] {
        for typ in [0u8, 1, 2, 4, 5, 8, 11, 13, 15, 20, 24, 254] {
            let script = Script::default().edit(move |n, m| {
                if n == name {
                    *m = vec![typ, 0, 0, 0];
                }
            });
            let (r, out) = try_connect(script, &[]);
            let e = err_msg(r);
            assert!(e.starts_with("tls: "), "{name} {typ}: {e}");
            assert!(out.alert.is_some(), "{name} {typ}: {e}");
        }
    }
    refused(named("SH", |m| m[0] = 4), "expected ServerHello", Some(UNEXPECTED_MESSAGE));
    for name in ["SKE", "SHD", "Cert"] {
        let script = Script::tls12().edit(move |n, m| {
            if n == name {
                m[0] = 99;
            }
        });
        refused(script, "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    }
    refused(Script::tls12().edit(on("SHD", |m| *m = vec![14, 0, 0, 1, 0])), "ServerHelloDone", Some(DECODE_ERROR));
}

#[test]
fn bad_server_key_exchange() {
    let ske = |f: fn(&mut Vec<u8>)| Script::tls12().edit(on("SKE", f));
    refused(
        ske(|m| *m.last_mut().unwrap() ^= 1),
        "tls: decrypt error: bad ServerKeyExchange signature",
        Some(DECRYPT_ERROR),
    );
    // The signature covers the point.
    refused(ske(|m| m[10] ^= 1), "tls: decrypt error", Some(DECRYPT_ERROR));
    refused(ske(|m| m[4] = 1), "named curve", Some(ILLEGAL_PARAMETER));
    refused(Script { group12: 0x0018, ..Script::tls12() }, "secp384r1", Some(HANDSHAKE_FAILURE));
    refused(ske(|m| m[5..7].copy_from_slice(&[0, 0x1e])), "unoffered group", Some(ILLEGAL_PARAMETER));
    // Scheme not offered, or not for the key.
    for s in [[8u8, 7], [2, 3], [8, 4], [4, 1]] {
        let script = Script::tls12().edit(move |n, m| {
            if n == "SKE" {
                let at = 4 + 4 + usize::from(m[7]);
                m[at..at + 2].copy_from_slice(&s);
            }
        });
        refused(script, "signature scheme not offered", Some(ILLEGAL_PARAMETER));
    }
    // Invalid points, correctly signed.
    let script = Script { group12: SECP256R1, ..Script::tls12() };
    refused(script.edit(on("Point", |p| p[9] ^= 1)), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(Script::tls12().edit(on("Point", |p| p.fill(0))), "bad key share", Some(ILLEGAL_PARAMETER));
    refused(Script::tls12().edit(on("Point", |p| p.push(0))), "bad key share", Some(ILLEGAL_PARAMETER));
    // The ECDSA suite with an RSA certificate, and the other way round.
    refused(
        Script { key: KeyType::Rsa2048, suite: 0xc02b, ..Script::tls12() },
        "key does not fit the cipher suite",
        Some(UNSUPPORTED_CERTIFICATE),
    );
    refused(
        Script { key: KeyType::P256, suite: 0xc02f, ..Script::tls12() },
        "key does not fit the cipher suite",
        Some(UNSUPPORTED_CERTIFICATE),
    );
    refused(
        ske(|m| {
            m.push(0);
            fix_len(m)
        }),
        "tls: decode error",
        Some(DECODE_ERROR),
    );
}

// --- records --------------------------------------------------------------------------------

#[test]
fn not_a_tls_server() {
    let raw = |b: &[u8]| Script { raw: Some(b.to_vec()), ..Script::default() };
    refused(raw(b"HTTP/1.1 400 Bad Request\r\n\r\n"), "not a TLS record", Some(UNEXPECTED_MESSAGE));
    refused(raw(&[21, 3, 3, 0, 2, 2, 40]), "tls: received alert handshake_failure", None);
    refused(raw(&[21, 3, 3, 0, 2, 2, 70]), "tls: received alert protocol_version", None);
    refused(raw(&[21, 3, 3, 0, 2, 2, 199]), "tls: received an unknown alert", None);
    refused(raw(&[21, 3, 3, 0, 3, 2, 40, 0]), "bad alert", Some(DECODE_ERROR));
    // A close_notify during the handshake is still an early end.
    let (r, _) = try_connect(raw(&[21, 3, 3, 0, 2, 1, 0]), &[]);
    assert_eq!(r.err().unwrap().kind(), ErrorKind::UnexpectedEof);
    // Records too long before any keys: 2^14 plaintext at most.
    let mut big = vec![22, 3, 3, 0x40, 0x01];
    big.resize(5 + 0x4001, 0);
    refused(raw(&big), "tls: record overflow", Some(RECORD_OVERFLOW));
    // Empty handshake records, and application data before the handshake.
    refused(raw(&[22, 3, 3, 0, 0]), "empty handshake record", Some(DECODE_ERROR));
    refused(raw(&[23, 3, 3, 0, 1, 0]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    // A change_cipher_spec before any ServerHello.
    refused(raw(&[20, 3, 3, 0, 1, 1]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    // A handshake message longer than 64 KiB.
    refused(raw(&[22, 3, 3, 0, 4, 2, 1, 0, 1]), "handshake message too long", Some(DECODE_ERROR));
    // A ServerHello interrupted by another record.
    refused(raw(&[22, 3, 3, 0, 2, 2, 0, 23, 3, 3, 0, 1, 0]), "inside a handshake message", Some(UNEXPECTED_MESSAGE));
    // Or by an alert, even a warning.
    refused(
        raw(&[22, 3, 3, 0, 2, 2, 0, 21, 3, 3, 0, 2, 1, 112]),
        "inside a handshake message",
        Some(UNEXPECTED_MESSAGE),
    );
    // Warnings before the ServerHello are ignored, but only so many.
    let warnings = [21, 3, 3, 0, 2, 1, 112].repeat(33);
    refused(raw(&warnings), "too many ignored records", Some(UNEXPECTED_MESSAGE));
    // An early end, between records and inside one.
    for b in [&[][..], &[22, 3, 3], &[22, 3, 3, 0, 10, 2, 0]] {
        let (r, _) = try_connect(raw(b), &[]);
        assert_eq!(r.err().unwrap().kind(), ErrorKind::UnexpectedEof);
    }
}

#[test]
fn records_between_messages() {
    let inject = |b: &[u8]| Script { inject: b.to_vec(), ..Script::default() };
    // TLS 1.3: change_cipher_spec is ignored during the handshake; only [1], and only 32 in a
    // row (with the script's own).
    exchange(inject(&[20, 3, 3, 0, 1, 1]));
    exchange(inject(&[20, 3, 3, 0, 1, 1].repeat(31)));
    refused(inject(&[20, 3, 3, 0, 1, 1].repeat(32)), "too many ignored records", Some(UNEXPECTED_MESSAGE));
    refused(inject(&[20, 3, 3, 0, 1, 2]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    refused(inject(&[20, 3, 3, 0, 2, 1, 1]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    refused(inject(&[20, 3, 3, 0, 0]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    // Plaintext once the handshake keys are in: handshake, application data.
    refused(inject(&[22, 3, 3, 0, 4, 8, 0, 0, 0]), "unprotected record", Some(UNEXPECTED_MESSAGE));
    refused(inject(&[23, 3, 3, 0, 1, 0]), "tls: bad record mac", Some(BAD_RECORD_MAC));
    // A plaintext alert is still an alert.
    refused(inject(&[21, 3, 3, 0, 2, 2, 40]), "unprotected record", Some(UNEXPECTED_MESSAGE));
    // TLS 1.2: a change_cipher_spec before the client's Finished, or a stray record.
    let inject12 = |b: &[u8]| Script { inject: b.to_vec(), ..Script::tls12() };
    // An early change_cipher_spec is taken where it belongs, after our flight; the real one
    // then comes protected and fails.
    refused(inject12(&[20, 3, 3, 0, 1, 1]), "tls: bad record mac", Some(BAD_RECORD_MAC));
    refused(inject12(&[20, 3, 3, 0, 1, 2]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    refused(inject12(&[23, 3, 3, 0, 1, 1]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    refused(inject12(&[22, 3, 3, 0, 4, 0, 0, 0, 0]), "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    refused(inject12(&[21, 3, 3, 0, 2, 2, 40]), "tls: received alert handshake_failure", None);
    // A warning is ignored in TLS 1.2, up to 32 in a row.
    exchange(inject12(&[21, 3, 3, 0, 2, 1, 112]));
    exchange(inject12(&[21, 3, 3, 0, 2, 1, 112].repeat(32)));
    refused(inject12(&[21, 3, 3, 0, 2, 1, 112].repeat(33)), "too many ignored records", Some(UNEXPECTED_MESSAGE));
}

#[test]
fn stray_change_cipher_spec() {
    // After the handshake, a change_cipher_spec is out of place in both versions.
    let script = Script::tls12().after(|f| f.send(CCS, &[1]));
    read_fails(script, "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
    let script = Script::default().after(|f| f.send(CCS, &[1]));
    read_fails(script, "tls: unexpected message", Some(UNEXPECTED_MESSAGE));
}

#[test]
fn application_data_records() {
    // Padding, empty records, and records of every size up to the limit.
    let script = Script::default().after(|f| {
        f.send_padded(APP, b"padded", 100)?;
        f.send(APP, b"")?;
        f.send_padded(APP, b"", 1000)?;
        f.send_padded(APP, &[7; 1 << 14], 0)?;
        f.send_padded(APP, b"", 1 << 14)?;
        f.close_notify()
    });
    let (r, _) = try_connect_then(script, |s| {
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(&got[..6], b"padded");
        assert_eq!(got.len(), 6 + (1 << 14));
    });
    r.unwrap();
    // The inner plaintext, content type and padding included, is 2^14 + 1 bytes at most (RFC 8446
    // section 5.4), though the ciphertext has room for more.
    let script = Script::default().after(|f| f.send_padded(APP, &[7; 1 << 14], 1));
    read_fails(script, "tls: record overflow", Some(RECORD_OVERFLOW));
    let script = Script::default().after(|f| f.send_padded(APP, b"", (1 << 14) + 1));
    read_fails(script, "tls: record overflow", Some(RECORD_OVERFLOW));
}

#[test]
fn bad_records_after_handshake() {
    // Plaintext too long inside an allowed ciphertext.
    read_fails(
        Script::default().after(|f| f.send(APP, &[0; (1 << 14) + 1])),
        "tls: record overflow",
        Some(RECORD_OVERFLOW),
    );
    read_fails(
        Script::tls12().after(|f| f.send(APP, &[0; (1 << 14) + 1])),
        "tls: record overflow",
        Some(RECORD_OVERFLOW),
    );
    // Ciphertext over the limit: 2^14 + 256 in TLS 1.3, 2^14 + 2048 in TLS 1.2.
    for (script, n) in [(Script::default(), (1 << 14) + 257), (Script::tls12(), (1 << 14) + 2049)] {
        let script = script.after(move |f| {
            let mut rec = vec![23, 3, 3];
            rec.extend_from_slice(&(n as u16).to_be_bytes());
            rec.resize(5 + n, 0);
            f.send_raw(&rec)
        });
        read_fails(script, "tls: record overflow", Some(RECORD_OVERFLOW));
    }
    // A flipped bit anywhere in a protected record: header (version, length) or body.
    for (tls12, suite) in [(false, 0x1301), (false, 0x1303), (true, 0xc02b), (true, 0xcca9)] {
        for at in [2, 4, 5, 12, 20, 30, 40] {
            let script = Script { tls12, suite, ..Script::default() }.after(move |f| {
                let mut rec = f.seal(APP, b"some application data", 0);
                rec[at] ^= 1;
                f.send_raw(&rec)?;
                f.tcp.shutdown(std::net::Shutdown::Write)
            });
            // A longer length waits for bytes that never come; a shorter one fails the tag.
            let long = at == 4 && !tls12;
            let (want, alert) = match long {
                true => ("tls: connection closed in the middle of a record", None),
                false => ("tls: bad record mac", Some(BAD_RECORD_MAC)),
            };
            read_fails(script, want, alert);
        }
    }
    // Too short for a tag.
    let short = |b: &'static [u8]| Script::default().after(move |f| f.send_raw(b));
    read_fails(short(&[23, 3, 3, 0, 5, 1, 2, 3, 4, 5]), "tls: bad record mac", Some(BAD_RECORD_MAC));
    read_fails(short(&[23, 3, 3, 0, 0]), "tls: bad record mac", Some(BAD_RECORD_MAC));
    let short12 = |b: &'static [u8]| Script::tls12().after(move |f| f.send_raw(b));
    read_fails(
        short12(&[23, 3, 3, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        "bad record mac",
        Some(BAD_RECORD_MAC),
    );
    // All-zero inner plaintext: no content type.
    read_fails(
        Script::default().after(|f| f.send_padded(0, &[], 5)),
        "without a content type",
        Some(UNEXPECTED_MESSAGE),
    );
    read_fails(
        Script::default().after(|f| f.send_padded(0, &[], 0)),
        "without a content type",
        Some(UNEXPECTED_MESSAGE),
    );
    // Inner content types that are not allowed: change_cipher_spec, unknown.
    let inner = |t: u8| {
        Script::default().after(move |f| {
            let rec = f.seal(t, &[1], 0);
            f.send_raw(&rec)
        })
    };
    read_fails(inner(CCS), "bad inner content type", Some(UNEXPECTED_MESSAGE));
    read_fails(inner(99), "bad inner content type", Some(UNEXPECTED_MESSAGE));
    read_fails(inner(24), "bad inner content type", Some(UNEXPECTED_MESSAGE));
    // A plaintext record once keys are in use.
    read_fails(short(&[22, 3, 3, 0, 1, 0]), "unprotected record", Some(UNEXPECTED_MESSAGE));
    // An unknown outer type, or a version that is not 3.x.
    read_fails(short(&[24, 3, 3, 0, 1, 0]), "not a TLS record", Some(UNEXPECTED_MESSAGE));
    read_fails(short(&[23, 2, 3, 0, 1, 0]), "not a TLS record", Some(UNEXPECTED_MESSAGE));
    // An empty handshake record.
    read_fails(Script::default().after(|f| f.send(HANDSHAKE, &[])), "empty handshake record", Some(DECODE_ERROR));
    // Application data inside a handshake message.
    read_fails(
        Script::default().after(|f| f.send(HANDSHAKE, &[4, 0, 0, 10, 0]).and_then(|_| f.send(APP, b"x"))),
        "inside a handshake message",
        Some(UNEXPECTED_MESSAGE),
    );
}

#[test]
fn truncation() {
    for base in [Script::default, Script::tls12] {
        // Data, then a TCP close without close_notify: the data, then an error.
        let script = base().after(|f| f.send(APP, b"all of it"));
        let (r, _) = try_connect_then(script, |s| {
            let mut buf = [0; 100];
            assert_eq!(s.read(&mut buf).unwrap(), 9);
            let e = s.read(&mut buf).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::UnexpectedEof);
            assert!(e.to_string().contains("without close_notify"), "{e}");
            // It stays an error.
            assert_eq!(s.read(&mut buf).unwrap_err().kind(), ErrorKind::UnexpectedEof);
        });
        r.unwrap();
        // Half a record, then a close.
        let script = base().after(|f| {
            let rec = f.seal(APP, b"all of it", 0);
            f.send_raw(&rec[..rec.len() - 3])
        });
        let (r, _) = try_connect_then(script, |s| {
            let e = s.read(&mut [0; 100]).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::UnexpectedEof);
            assert!(e.to_string().contains("middle of a record"), "{e}");
        });
        r.unwrap();
        // Mid-handshake.
        let script = base().edit(on("SH", |m| m.clear()));
        let (r, _) = try_connect(script, &[]);
        assert!(r.is_err());
    }
}

#[test]
fn alerts_after_handshake() {
    for base in [Script::default, Script::tls12] {
        read_fails(base().after(|f| f.send(ALERT, &[2, 80])), "tls: received alert internal_error", None);
        read_fails(base().after(|f| f.send(ALERT, &[1])), "bad alert", Some(DECODE_ERROR));
        read_fails(base().after(|f| f.send(ALERT, &[2, 40, 0])), "bad alert", Some(DECODE_ERROR));
        // user_canceled is not an end; close_notify after it is.
        let script = base().after(|f| {
            f.send(ALERT, &[1, 90])?;
            f.send(APP, b"more")?;
            f.close_notify()
        });
        let (r, _) = try_connect_then(script, |s| {
            let mut got = Vec::new();
            s.read_to_end(&mut got).unwrap();
            assert_eq!(got, b"more");
        });
        r.unwrap();
    }
    // Warnings are ignored in TLS 1.2 and fatal in TLS 1.3.
    let script = Script::tls12().after(|f| {
        f.send(ALERT, &[1, 112])?;
        f.send(APP, b"more")?;
        f.close_notify()
    });
    let (r, _) = try_connect_then(script, |s| {
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"more");
    });
    r.unwrap();
    read_fails(Script::default().after(|f| f.send(ALERT, &[1, 112])), "unrecognized_name", None);
}

// --- after the handshake --------------------------------------------------------------------

#[test]
fn key_update_from_the_server() {
    for suite in [0x1301, 0x1302, 0x1303] {
        for request in [false, true] {
            let script = Script { suite, ..Script::default() }.after(move |f| {
                f.send(APP, b"one")?;
                f.key_update(request)?;
                f.send(APP, b"two")?;
                f.key_update(request)?;
                f.send(APP, b"three")?;
                // Our data comes under the client's next key when it was asked to update.
                assert_eq!(f.recv_data()?, b"reply");
                f.close_notify()
            });
            let (r, out) = try_connect_then(script, |s| {
                let mut buf = [0; 11];
                s.read_exact(&mut buf).unwrap();
                assert_eq!(&buf, b"onetwothree");
                s.write_all(b"reply").unwrap();
                assert_eq!(s.read(&mut buf).unwrap(), 0);
            });
            r.unwrap();
            assert!(out.done, "{out:?}");
        }
    }
}

#[test]
fn bad_post_handshake_messages() {
    let hs = |m: &'static [u8]| Script::default().after(move |f| f.send(HANDSHAKE, m));
    read_fails(hs(&[24, 0, 0, 1, 2]), "bad KeyUpdate", Some(DECODE_ERROR));
    read_fails(hs(&[24, 0, 0, 0]), "bad KeyUpdate", Some(DECODE_ERROR));
    read_fails(hs(&[24, 0, 0, 2, 0, 0]), "bad KeyUpdate", Some(DECODE_ERROR));
    // A KeyUpdate with more handshake data after it in the same record.
    read_fails(hs(&[24, 0, 0, 1, 0, 4, 0]), "handshake data across a key change", Some(UNEXPECTED_MESSAGE));
    // Post-handshake authentication was not offered; nor renegotiation in TLS 1.3.
    read_fails(hs(&[13, 0, 0, 4, 0, 0, 0, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
    read_fails(hs(&[0, 0, 0, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
    read_fails(hs(&[20, 0, 0, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
    // TLS 1.2 has neither tickets (not offered) nor KeyUpdate.
    let hs12 = |m: &'static [u8]| Script::tls12().after(move |f| f.send(HANDSHAKE, m));
    read_fails(hs12(&[4, 0, 0, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
    read_fails(hs12(&[24, 0, 0, 1, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
    read_fails(hs12(&[0, 0, 0, 1, 0]), "unexpected handshake message", Some(UNEXPECTED_MESSAGE));
}

#[test]
fn session_tickets_are_ignored() {
    let script = Script::default().after(|f| {
        // Split across records, and two in one record.
        let ticket = [4, 0, 0, 14, 0, 0, 0, 60, 1, 2, 3, 4, 0, 0, 1, 9, 0, 0];
        f.send(HANDSHAKE, &ticket[..3])?;
        f.send(HANDSHAKE, &ticket[3..])?;
        f.send(HANDSHAKE, &[ticket, ticket].concat())?;
        f.send(APP, b"data")?;
        f.close_notify()
    });
    let (r, _) = try_connect_then(script, |s| {
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"data");
    });
    r.unwrap();
}

#[test]
fn hello_request_is_refused_politely() {
    let script = Script::tls12().after(|f| {
        f.send(HANDSHAKE, &[0, 0, 0, 0])?;
        f.send(APP, b"data")?;
        // The client answers with a no_renegotiation warning and goes on.
        match f.recv()? {
            (ALERT, a) => assert_eq!(a, [1, 100]),
            other => panic!("{other:?}"),
        }
        assert_eq!(f.recv_data()?, b"after");
        f.close_notify()
    });
    let (r, out) = try_connect_then(script, |s| {
        let mut buf = [0; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"data");
        s.write_all(b"after").unwrap();
        assert_eq!(s.read(&mut buf).unwrap(), 0);
    });
    r.unwrap();
    assert!(out.done, "{out:?}");
}

#[test]
fn writes_in_records_of_at_most_16k() {
    let script = Script::default().after(|f| {
        let mut total = 0;
        while total < 100_000 {
            let (typ, d) = f.recv()?;
            assert_eq!(typ, APP);
            assert!(d.len() <= 1 << 14 && !d.is_empty());
            total += d.len();
        }
        assert_eq!(total, 100_000);
        f.close_notify()
    });
    let (r, _) = try_connect_then(script, |s| {
        s.write_all(&[5; 100_000]).unwrap();
        s.flush().unwrap();
        assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    });
    r.unwrap();
}
