//! The key schedule and record protection against RFC 8448 section 3, the simple 1-RTT
//! handshake: every secret, key and IV, both Finished messages, and every protected record,
//! byte for byte. The trace's certificate has a 1024-bit RSA key, which the certificate checks
//! refuse, so the handshake itself is tested elsewhere against real servers.

use std::io::{self, Cursor, Read, Write};

use jpm_crypto::hash::{self, Alg::Sha256, Hasher};
use jpm_crypto::{aead::Alg::Aes128Gcm, x25519};

use super::Error;
use super::record::{ALERT, APPLICATION_DATA, Conn, HANDSHAKE};
use super::tls13::{derive, expand_label, finished, handshake_secret, keys, master_secret};

const TRACE: &str = include_str!("../../tests/data/rfc8448-section3.txt");

/// Every value in the trace as `(step, label, bytes)`: the step is the `{client}` or `{server}`
/// line it belongs to, the label what comes before "(N octets)".
fn values() -> Vec<(String, String, Vec<u8>)> {
    let mut out: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut step = String::new();
    let mut in_value = false;
    let mut lens = Vec::new();
    for line in TRACE.lines() {
        let t = line.trim();
        if t.starts_with('{') {
            step = t.to_string();
            in_value = false;
        } else if let Some((label, rest)) = t.split_once(" octets):") {
            let (label, n) = label.rsplit_once(" (").unwrap();
            out.push((step.clone(), label.to_string(), Vec::new()));
            lens.push(n.parse::<usize>().unwrap());
            in_value = true;
            hex_into(&mut out.last_mut().unwrap().2, rest);
        } else if t.is_empty() {
            // Page breaks leave blank lines inside values.
        } else if in_value && t.split(' ').all(|w| w.len() == 2) {
            hex_into(&mut out.last_mut().unwrap().2, t);
        } else {
            in_value = false;
        }
    }
    // Each value as long as the trace says, except the one "0 (all zero octets)" salt.
    for ((step, label, v), n) in out.iter().zip(lens) {
        assert!(v.len() == n || label == "salt", "{step} {label}");
    }
    out
}

fn hex_into(out: &mut Vec<u8>, s: &str) {
    for w in s.split_whitespace() {
        if w.len() == 2
            && let Ok(b) = u8::from_str_radix(w, 16)
        {
            out.push(b);
        }
    }
}

struct Trace(Vec<(String, String, Vec<u8>)>);

impl Trace {
    /// The `n`th value (from 0) under a step starting with `step` and labelled `label`.
    fn nth(&self, step: &str, label: &str, n: usize) -> &[u8] {
        let found = self.0.iter().filter(|(s, l, _)| s.starts_with(step) && l == label).nth(n);
        &found.unwrap_or_else(|| panic!("no {step} / {label} #{n}")).2
    }

    fn get(&self, step: &str, label: &str) -> &[u8] {
        self.nth(step, label, 0)
    }
}

fn transcript(parts: &[&[u8]]) -> hash::Digest {
    let mut h = Hasher::new(Sha256);
    parts.iter().for_each(|p| h.update(p));
    h.finish()
}

#[test]
fn key_schedule() {
    let tr = Trace(values());
    let client_private: [u8; 32] = tr.get("{client}  create an ephemeral x25519", "private key").try_into().unwrap();
    let server_public: [u8; 32] = tr.get("{server}  create an ephemeral x25519", "public key").try_into().unwrap();
    let shared = x25519::shared_secret(&client_private, &server_public).unwrap();
    assert_eq!(shared, tr.get("{server}  extract secret \"handshake\"", "IKM"));

    let ch = tr.get("{client}  construct a ClientHello", "ClientHello");
    let sh = tr.get("{server}  construct a ServerHello", "ServerHello");
    let ee = tr.get("{server}  construct an EncryptedExtensions", "EncryptedExtensions");
    let cert = tr.get("{server}  construct a Certificate", "Certificate");
    let cv = tr.get("{server}  construct a CertificateVerify", "CertificateVerify");
    let sfin = tr.get("{server}  construct a Finished", "Finished");

    let th = transcript(&[ch, sh]);
    assert_eq!(&th[..], tr.get("{server}  derive secret \"tls13 c hs traffic\"", "hash"));
    let hs = handshake_secret(Sha256, &shared);
    assert_eq!(&hs[..], tr.get("{server}  extract secret \"handshake\"", "secret"));
    let c_hs = derive(Sha256, &hs, b"c hs traffic", &th);
    let s_hs = derive(Sha256, &hs, b"s hs traffic", &th);
    assert_eq!(&c_hs[..], tr.get("{server}  derive secret \"tls13 c hs traffic\"", "expanded"));
    assert_eq!(&s_hs[..], tr.get("{server}  derive secret \"tls13 s hs traffic\"", "expanded"));

    let master = master_secret(Sha256, &hs);
    assert_eq!(&master[..], tr.get("{server}  extract secret \"master\"", "secret"));

    // Handshake traffic keys, both ways.
    let mut key = [0; 16];
    let mut iv = [0; 12];
    expand_label(Sha256, &s_hs, b"key", b"", &mut key);
    expand_label(Sha256, &s_hs, b"iv", b"", &mut iv);
    assert_eq!(key, tr.get("{server}  derive write traffic keys for handshake", "key expanded"));
    assert_eq!(iv, tr.get("{server}  derive write traffic keys for handshake", "iv expanded"));
    expand_label(Sha256, &c_hs, b"key", b"", &mut key);
    expand_label(Sha256, &c_hs, b"iv", b"", &mut iv);
    assert_eq!(key, tr.get("{server}  derive read traffic keys for handshake", "key expanded"));
    assert_eq!(iv, tr.get("{server}  derive read traffic keys for handshake", "iv expanded"));

    // The server's Finished, over ClientHello through CertificateVerify.
    let server_finished = finished(Sha256, &s_hs, &transcript(&[ch, sh, ee, cert, cv]));
    assert_eq!(&server_finished[..], tr.get("{server}  calculate finished", "finished"));
    assert_eq!(&server_finished[..], &sfin[4..]);

    // Application secrets, over ClientHello through the server's Finished.
    let th = transcript(&[ch, sh, ee, cert, cv, sfin]);
    assert_eq!(&th[..], tr.get("{server}  derive secret \"tls13 c ap traffic\"", "hash"));
    let c_ap = derive(Sha256, &master, b"c ap traffic", &th);
    let s_ap = derive(Sha256, &master, b"s ap traffic", &th);
    assert_eq!(&c_ap[..], tr.get("{server}  derive secret \"tls13 c ap traffic\"", "expanded"));
    assert_eq!(&s_ap[..], tr.get("{server}  derive secret \"tls13 s ap traffic\"", "expanded"));
    expand_label(Sha256, &s_ap, b"key", b"", &mut key);
    expand_label(Sha256, &s_ap, b"iv", b"", &mut iv);
    assert_eq!(key, tr.get("{server}  derive write traffic keys for application", "key expanded"));
    assert_eq!(iv, tr.get("{server}  derive write traffic keys for application", "iv expanded"));
    expand_label(Sha256, &c_ap, b"key", b"", &mut key);
    expand_label(Sha256, &c_ap, b"iv", b"", &mut iv);
    assert_eq!(key, tr.get("{client}  derive write traffic keys for application", "key expanded"));
    assert_eq!(iv, tr.get("{client}  derive write traffic keys for application", "iv expanded"));

    // The client's Finished, over ClientHello through the server's Finished.
    let client_finished = finished(Sha256, &c_hs, &th);
    assert_eq!(&client_finished[..], tr.get("{client}  calculate finished", "finished"));
}

/// Reads come from a fixed input; writes are kept.
struct Pipe {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The secrets the record tests need, from the trace.
fn traffic(tr: &Trace) -> [Vec<u8>; 4] {
    let get = |s: &str| tr.get(&format!("{{server}}  derive secret \"tls13 {s}\""), "expanded").to_vec();
    [get("c hs traffic"), get("s hs traffic"), get("c ap traffic"), get("s ap traffic")]
}

#[test]
fn server_records() {
    let tr = Trace(values());
    let [_, s_hs, _, s_ap] = traffic(&tr);
    let rec = |n| tr.nth("{server}  send handshake record", "complete record", n).to_vec();
    let payload = |n| tr.nth("{server}  send handshake record", "payload", n).to_vec();
    let mut input = Vec::new();
    for r in [
        rec(0),
        rec(1),
        rec(2),
        tr.get("{server}  send application_data record", "complete record").to_vec(),
        tr.get("{server}  send alert record", "complete record").to_vec(),
    ] {
        input.extend_from_slice(&r);
    }
    let mut conn = Conn::new(Pipe { input: Cursor::new(input), output: Vec::new() });

    assert_eq!(conn.next_record().ok(), Some(HANDSHAKE));
    assert_eq!(conn.plaintext(), payload(0));
    conn.tls13 = true;
    conn.read = Some(keys(Sha256, Aes128Gcm, &s_hs));
    assert_eq!(conn.next_record().ok(), Some(HANDSHAKE));
    assert_eq!(conn.plaintext(), payload(1));
    conn.read = Some(keys(Sha256, Aes128Gcm, &s_ap));
    assert_eq!(conn.next_record().ok(), Some(HANDSHAKE));
    assert_eq!(conn.plaintext(), payload(2));
    assert_eq!(conn.next_record().ok(), Some(APPLICATION_DATA));
    assert_eq!(conn.plaintext(), tr.get("{server}  send application_data record", "payload"));
    assert_eq!(conn.next_record().ok(), Some(ALERT));
    assert_eq!(conn.plaintext(), [1, 0]);
    assert!(matches!(conn.alert(), Err(Error::Closed)));
    // Then the end of the input, with no more records: truncation.
    assert!(matches!(conn.next_record(), Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof));
}

#[test]
fn client_records() {
    let tr = Trace(values());
    let [c_hs, _, c_ap, _] = traffic(&tr);
    let mut conn = Conn::new(Pipe { input: Cursor::new(Vec::new()), output: Vec::new() });
    conn.tls13 = true;
    conn.write = Some(keys(Sha256, Aes128Gcm, &c_hs));
    // The second client handshake record: the first is the ClientHello.
    conn.send(HANDSHAKE, tr.nth("{client}  send handshake record", "payload", 1)).ok().unwrap();
    assert_eq!(conn.io.output, tr.nth("{client}  send handshake record", "complete record", 1));

    conn.io.output.clear();
    conn.write = Some(keys(Sha256, Aes128Gcm, &c_ap));
    conn.send(APPLICATION_DATA, tr.get("{client}  send application_data record", "payload")).ok().unwrap();
    conn.send(ALERT, &[1, 0]).ok().unwrap();
    let mut want = tr.get("{client}  send application_data record", "complete record").to_vec();
    want.extend_from_slice(tr.get("{client}  send alert record", "complete record"));
    assert_eq!(conn.io.output, want);
}

/// Every single-bit change to the protected flight fails the tag, or the header checks when it
/// hits the header, and never panics.
#[test]
fn tampered_records() {
    let tr = Trace(values());
    let [_, s_hs, _, _] = traffic(&tr);
    let rec = tr.nth("{server}  send handshake record", "complete record", 1).to_vec();
    for bit in 0..rec.len() * 8 {
        let mut bad = rec.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        let mut conn = Conn::new(Pipe { input: Cursor::new(bad), output: Vec::new() });
        conn.tls13 = true;
        conn.read = Some(keys(Sha256, Aes128Gcm, &s_hs));
        assert!(conn.next_record().is_err(), "bit {bit}");
    }
}
