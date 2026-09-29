//! A scripted TLS server for the tests that need a server to misbehave in exact ways. It runs
//! real TLS 1.3 and 1.2 handshakes on jpm-crypto's primitives (and rustls's signers), and lets a
//! test edit each handshake message before it is sent. Edits happen before the message enters
//! the transcript, so the checks a test does not aim at still pass: an edited
//! EncryptedExtensions is still covered by a valid CertificateVerify and Finished, and the client
//! must refuse it for what it is.
//!
//! Its key schedule is written again here from RFC 8446 and RFC 5246 rather than shared with the
//! client, and rustls interop keeps both honest.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use jpm_crypto::aead::{self, Alg as Aead};
use jpm_crypto::hash::{self, Alg as Hash, hkdf_expand, hkdf_extract, hmac, tls12_prf};
use jpm_crypto::rand;
use jpm_pk::{p256, x25519};

use super::{KeyType, pair, pki};

pub const X25519: u16 = 0x001d;
pub const SECP256R1: u16 = 0x0017;

pub const CCS: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APP: u8 = 23;

type Edit = Box<dyn FnMut(&str, &mut Vec<u8>) + Send>;
type After = Box<dyn FnOnce(&mut Fake) -> io::Result<()> + Send>;

/// What the server does. `Script::default()` is a correct TLS 1.3 server.
pub struct Script {
    pub tls12: bool,
    /// The cipher suite; 0 for TLS_AES_128_GCM_SHA256, or ECDHE with AES-128-GCM in TLS 1.2.
    pub suite: u16,
    pub key: KeyType,
    /// Send a HelloRetryRequest for this group (TLS 1.3).
    pub hrr: Option<u16>,
    /// And a cookie in it.
    pub cookie: bool,
    /// Answer the second ClientHello with another HelloRetryRequest.
    pub hrr_twice: bool,
    /// The ECDHE group in TLS 1.2.
    pub group12: u16,
    /// The signature scheme; 0 for the key's usual one.
    pub scheme: u16,
    /// The protocol to pick by ALPN.
    pub alpn: Option<Vec<u8>>,
    pub cert_request: bool,
    /// One record per handshake message, rather than as few records as fit.
    pub split: bool,
    /// The largest handshake record.
    pub fragment: usize,
    /// TLS 1.3: a change_cipher_spec after ServerHello.
    pub ccs: bool,
    /// TLS 1.2: agree to the extended master secret.
    pub ems: bool,
    /// Edit a message before it is sent: "HRR", "SH", "EE", "CR", "Cert", "CV", "SKE", "SHD", "Fin";
    /// or the server's key share before it is used and signed: "Point".
    pub edit: Edit,
    /// Instead of a handshake: send these bytes after the ClientHello, then read the answer.
    pub raw: Option<Vec<u8>>,
    /// Bytes to send as they are right after the ServerHello (TLS 1.3) or the first flight
    /// (TLS 1.2).
    pub inject: Vec<u8>,
    /// What to do once the handshake is done.
    pub after: After,
    /// Close the connection after the server's first flight (the HelloRetryRequest, if there
    /// is one): for fuzzing, where a mutated length can leave the client waiting for bytes
    /// that never come.
    pub close_after_flight: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            tls12: false,
            suite: 0,
            key: KeyType::P256,
            hrr: None,
            cookie: false,
            hrr_twice: false,
            group12: X25519,
            scheme: 0,
            alpn: None,
            cert_request: false,
            split: false,
            fragment: 1 << 14,
            ccs: true,
            ems: true,
            edit: Box::new(|_, _| {}),
            raw: None,
            inject: Vec::new(),
            after: Box::new(|_| Ok(())),
            close_after_flight: false,
        }
    }
}

impl Script {
    pub fn tls12() -> Self {
        Self { tls12: true, ..Self::default() }
    }

    pub fn edit(mut self, f: impl FnMut(&str, &mut Vec<u8>) + Send + 'static) -> Self {
        self.edit = Box::new(f);
        self
    }

    pub fn after(mut self, f: impl FnOnce(&mut Fake) -> io::Result<()> + Send + 'static) -> Self {
        self.after = Box::new(f);
        self
    }
}

/// What the server saw.
#[derive(Default, Debug)]
pub struct Outcome {
    pub client_hello: Vec<u8>,
    pub client_hello2: Option<Vec<u8>>,
    /// The alert the client sent, if it sent one.
    pub alert: Option<u8>,
    /// The client's Certificate message, if it sent one.
    pub client_cert: Option<Vec<u8>>,
    /// The client's Finished checked out.
    pub finished: bool,
    /// The script ran to its end.
    pub done: bool,
}

/// One direction's record protection.
struct Dir {
    key: aead::Key,
    iv: [u8; 12],
    seq: u64,
}

impl Dir {
    fn new(alg: Aead, key: &[u8], iv: &[u8]) -> Self {
        let mut full = [0; 12];
        full[..iv.len()].copy_from_slice(iv);
        Self { key: aead::Key::new(alg, key).unwrap(), iv: full, seq: 0 }
    }

    fn nonce(&self, n: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (b, x) in nonce[4..].iter_mut().zip(n.to_be_bytes()) {
            *b ^= x;
        }
        nonce
    }
}

/// The server's connection, for scripts to drive after the handshake.
pub struct Fake {
    pub tcp: TcpStream,
    pub tls13: bool,
    read: Option<Dir>,
    write: Option<Dir>,
    explicit_nonce: bool,
    /// Handshake bytes received and not yet taken as messages.
    hs: Vec<u8>,
    /// TLS 1.3 application secrets, for KeyUpdate.
    hash: Hash,
    aead: Aead,
    pub client_secret: Vec<u8>,
    pub server_secret: Vec<u8>,
    /// An alert the script saw from the client, for the outcome.
    pub seen_alert: Option<u8>,
}

impl Fake {
    /// One record of type `typ`; protected once there are keys, except a TLS 1.3
    /// change_cipher_spec.
    pub fn send(&mut self, typ: u8, data: &[u8]) -> io::Result<()> {
        if self.tls13 && typ == CCS {
            return self.send_raw(&[CCS, 3, 3, 0, data.len() as u8, data[0]]);
        }
        self.send_padded(typ, data, 0)
    }

    /// TLS 1.3: a record with `pad` zeros after the content type.
    pub fn send_padded(&mut self, typ: u8, data: &[u8], pad: usize) -> io::Result<()> {
        let rec = self.seal(typ, data, pad);
        self.send_raw(&rec)
    }

    pub fn seal(&mut self, typ: u8, data: &[u8], pad: usize) -> Vec<u8> {
        let Some(d) = self.write.as_mut() else {
            let mut rec = vec![typ, 3, 3];
            rec.extend_from_slice(&(data.len() as u16).to_be_bytes());
            rec.extend_from_slice(data);
            return rec;
        };
        let seq = d.seq;
        d.seq += 1;
        let explicit = if self.explicit_nonce { 8 } else { 0 };
        let inner = if self.tls13 { 1 + pad } else { 0 };
        let len = explicit + data.len() + inner + 16;
        let outer = if self.tls13 { APP } else { typ };
        let hdr = [outer, 3, 3, (len >> 8) as u8, len as u8];
        let mut rec = hdr.to_vec();
        if explicit > 0 {
            rec.extend_from_slice(&seq.to_be_bytes());
        }
        let at = rec.len();
        rec.extend_from_slice(data);
        let aad = if self.tls13 {
            rec.push(typ);
            rec.resize(rec.len() + pad, 0);
            hdr.to_vec()
        } else {
            let mut a = seq.to_be_bytes().to_vec();
            a.extend_from_slice(&[typ, 3, 3]);
            a.extend_from_slice(&(data.len() as u16).to_be_bytes());
            a
        };
        let tag = d.key.seal(&d.nonce(seq), &aad, &mut rec[at..]);
        rec.extend_from_slice(&tag);
        rec
    }

    /// Write errors are dropped: a client that gave up may have closed its end while the
    /// server still writes, and what matters is the alert it sent, read next.
    pub fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        let _ = self.tcp.write_all(bytes);
        Ok(())
    }

    /// The next record, unprotected: `(type, plaintext)`.
    pub fn recv(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let mut hdr = [0; 5];
        self.tcp.read_exact(&mut hdr)?;
        let mut body = vec![0; usize::from(u16::from_be_bytes([hdr[3], hdr[4]]))];
        self.tcp.read_exact(&mut body)?;
        let protected = if self.tls13 { hdr[0] == APP } else { hdr[0] != CCS };
        let Some(d) = self.read.as_mut().filter(|_| protected) else { return Ok((hdr[0], body)) };
        let seq = d.seq;
        d.seq += 1;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "fake: bad record from the client");
        let (n, ct_start) = if self.explicit_nonce {
            (u64::from_be_bytes(body.get(..8).ok_or_else(bad)?.try_into().unwrap()), 8)
        } else {
            (seq, 0)
        };
        if body.len() < ct_start + 16 {
            return Err(bad());
        }
        let tag: [u8; 16] = body[body.len() - 16..].try_into().unwrap();
        let mut pt = body[ct_start..body.len() - 16].to_vec();
        let aad = if self.tls13 {
            hdr.to_vec()
        } else {
            let mut a = seq.to_be_bytes().to_vec();
            a.extend_from_slice(&hdr[..3]);
            a.extend_from_slice(&(pt.len() as u16).to_be_bytes());
            a
        };
        if !d.key.open(&d.nonce(n), &aad, &mut pt, &tag) {
            return Err(bad());
        }
        if !self.tls13 {
            return Ok((hdr[0], pt));
        }
        let i = pt.iter().rposition(|&b| b != 0).ok_or_else(bad)?;
        let typ = pt[i];
        pt.truncate(i);
        Ok((typ, pt))
    }

    /// The next handshake message, skipping change_cipher_spec records. An alert is an error
    /// carrying its description.
    pub fn recv_handshake(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if self.hs.len() >= 4 {
                let n = 4 + (usize::from(self.hs[1]) << 16 | usize::from(self.hs[2]) << 8 | usize::from(self.hs[3]));
                if self.hs.len() >= n {
                    let rest = self.hs.split_off(n);
                    return Ok(std::mem::replace(&mut self.hs, rest));
                }
            }
            match self.recv()? {
                (HANDSHAKE, data) => self.hs.extend_from_slice(&data),
                (CCS, _) => {}
                (ALERT, a) => return Err(alert_error(&a)),
                (t, _) => return Err(io::Error::other(format!("fake: unexpected record type {t}"))),
            }
        }
    }

    /// Records until the client's application data; returns it.
    pub fn recv_data(&mut self) -> io::Result<Vec<u8>> {
        loop {
            match self.recv()? {
                (APP, data) => return Ok(data),
                (ALERT, a) => return Err(alert_error(&a)),
                (HANDSHAKE, m) if m.first() == Some(&24) => self.update_read_key(),
                (t, _) => return Err(io::Error::other(format!("fake: unexpected record type {t}"))),
            }
        }
    }

    /// Records until an alert; its description. `None` if the connection ends first.
    pub fn recv_alert(&mut self) -> Option<u8> {
        loop {
            match self.recv() {
                Ok((ALERT, a)) if a.len() == 2 => return Some(a[1]),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    /// TLS 1.3 KeyUpdate: send it, then move to the next write key.
    pub fn key_update(&mut self, request: bool) -> io::Result<()> {
        self.send(HANDSHAKE, &[24, 0, 0, 1, u8::from(request)])?;
        self.server_secret = expand_label(self.hash, &self.server_secret, b"traffic upd", b"", self.hash.len());
        self.write = Some(keys13(self.hash, self.aead, &self.server_secret));
        Ok(())
    }

    /// The client sent KeyUpdate: move to its next key.
    pub fn update_read_key(&mut self) {
        self.client_secret = expand_label(self.hash, &self.client_secret, b"traffic upd", b"", self.hash.len());
        self.read = Some(keys13(self.hash, self.aead, &self.client_secret));
    }

    pub fn close_notify(&mut self) -> io::Result<()> {
        self.send(ALERT, &[1, 0])
    }
}

fn alert_error(a: &[u8]) -> io::Error {
    io::Error::other(format!("fake: alert {}", a.get(1).copied().unwrap_or(255)))
}

/// Run `script` on a fresh loopback connection; the client's socket and the server thread.
pub fn run(script: Script) -> (TcpStream, thread::JoinHandle<Outcome>) {
    let (client, server) = pair();
    let h = thread::spawn(move || {
        let mut f = Fake {
            tcp: server,
            tls13: false,
            read: None,
            write: None,
            explicit_nonce: false,
            hs: Vec::new(),
            hash: Hash::Sha256,
            aead: Aead::Aes128Gcm,
            client_secret: Vec::new(),
            server_secret: Vec::new(),
            seen_alert: None,
        };
        let mut out = Outcome::default();
        let r = if script.tls12 { server12(&mut f, script, &mut out) } else { server13(&mut f, script, &mut out) };
        match r {
            Ok(()) => {
                out.done = true;
                out.alert = out.alert.or(f.seen_alert);
            }
            Err(e) => {
                if let Some(a) = e.to_string().strip_prefix("fake: alert ") {
                    out.alert = a.parse().ok();
                }
            }
        }
        out
    });
    (client, h)
}

/// A parsed ClientHello: random, session id, and extensions.
pub struct ClientHello {
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub suites: Vec<u16>,
    pub exts: Vec<(u16, Vec<u8>)>,
}

impl ClientHello {
    pub fn parse(m: &[u8]) -> Self {
        let mut r = &m[4..];
        let mut take = |n: usize| {
            let (a, b) = r.split_at(n);
            r = b;
            a.to_vec()
        };
        take(2);
        let random = take(32);
        let n = take(1)[0] as usize;
        let session_id = take(n);
        let n = u16::from_be_bytes(take(2).try_into().unwrap()) as usize;
        let suites = take(n).chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        let n = take(1)[0] as usize;
        take(n);
        let n = u16::from_be_bytes(take(2).try_into().unwrap()) as usize;
        let mut e = &take(n)[..];
        let mut exts = Vec::new();
        while !e.is_empty() {
            let typ = u16::from_be_bytes([e[0], e[1]]);
            let len = u16::from_be_bytes([e[2], e[3]]) as usize;
            exts.push((typ, e[4..4 + len].to_vec()));
            e = &e[4 + len..];
        }
        Self { random, session_id, suites, exts }
    }

    pub fn ext(&self, typ: u16) -> Option<&[u8]> {
        self.exts.iter().find(|e| e.0 == typ).map(|e| &e.1[..])
    }

    /// The key share for `group`, if the client sent one.
    pub fn share(&self, group: u16) -> Option<Vec<u8>> {
        let d = self.ext(51)?;
        let mut e = &d[2..];
        while !e.is_empty() {
            let g = u16::from_be_bytes([e[0], e[1]]);
            let len = u16::from_be_bytes([e[2], e[3]]) as usize;
            if g == group {
                return Some(e[4..4 + len].to_vec());
            }
            e = &e[4 + len..];
        }
        None
    }
}

pub fn message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![typ];
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    m.extend_from_slice(body);
    m
}

fn ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn vec16(data: &[u8]) -> Vec<u8> {
    let mut v = (data.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

fn expand_label(alg: Hash, secret: &[u8], label: &[u8], ctx: &[u8], n: usize) -> Vec<u8> {
    let mut info = (n as u16).to_be_bytes().to_vec();
    info.push(6 + label.len() as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    let mut out = vec![0; n];
    hkdf_expand(alg, secret, &[&info], &mut out);
    out
}

fn keys13(alg: Hash, aead: Aead, secret: &[u8]) -> Dir {
    Dir::new(aead, &expand_label(alg, secret, b"key", b"", aead.key_len()), &expand_label(alg, secret, b"iv", b"", 12))
}

fn suite_algs(suite: u16) -> (Hash, Aead) {
    match suite {
        0x1301 | 0xc02b | 0xc02f => (Hash::Sha256, Aead::Aes128Gcm),
        0x1302 | 0xc02c | 0xc030 => (Hash::Sha384, Aead::Aes256Gcm),
        _ => (Hash::Sha256, Aead::ChaCha20Poly1305),
    }
}

/// A server key share: `(public, secret)`.
fn key_share(group: u16) -> (Vec<u8>, [u8; 32]) {
    let mut secret = [0; 32];
    loop {
        rand::fill(&mut secret);
        match group {
            SECP256R1 => {
                if let Some(p) = p256::public_key(&secret) {
                    return (p.to_vec(), secret);
                }
            }
            _ => return (x25519::public_key(&secret).to_vec(), secret),
        }
    }
}

fn shared(group: u16, secret: &[u8; 32], peer: &[u8]) -> io::Result<Vec<u8>> {
    let s = match group {
        SECP256R1 => p256::shared_secret(secret, peer),
        _ => peer.try_into().ok().and_then(|p| x25519::shared_secret(secret, p)),
    };
    s.map(|s| s.to_vec()).ok_or_else(|| io::Error::other("fake: bad client key share"))
}

fn sign(key: KeyType, scheme: u16, msg: &[u8]) -> Vec<u8> {
    let signing = rustls::crypto::ring::sign::any_supported_type(&pki(key).rustls_key()).unwrap();
    let signer = signing.choose_scheme(&[rustls::SignatureScheme::from(scheme)]).expect("scheme for the key");
    signer.sign(msg).unwrap()
}

fn default_scheme(key: KeyType) -> u16 {
    match key {
        KeyType::P256 => 0x0403,
        KeyType::P384 => 0x0503,
        _ => 0x0804,
    }
}

/// Send handshake messages as records of at most `fragment` bytes, one message per record
/// when `split`.
fn send_flight(f: &mut Fake, msgs: &[Vec<u8>], split: bool, fragment: usize) -> io::Result<()> {
    let mut out = Vec::new();
    let groups: Vec<Vec<u8>> = if split { msgs.to_vec() } else { vec![msgs.concat()] };
    for g in groups {
        for chunk in g.chunks(fragment) {
            out.extend(f.seal(HANDSHAKE, chunk, 0));
        }
    }
    f.send_raw(&out)
}

fn close_and_watch(f: &mut Fake, out: &mut Outcome) -> io::Result<()> {
    f.tcp.shutdown(std::net::Shutdown::Write)?;
    out.alert = f.recv_alert();
    Ok(())
}

fn read_client_hello(f: &mut Fake) -> io::Result<Vec<u8>> {
    f.recv_handshake()
}

fn server13(f: &mut Fake, mut s: Script, out: &mut Outcome) -> io::Result<()> {
    let ch = read_client_hello(f)?;
    out.client_hello = ch.clone();
    if let Some(raw) = s.raw.take() {
        f.send_raw(&raw)?;
        f.tcp.shutdown(std::net::Shutdown::Write)?;
        out.alert = f.recv_alert();
        return Ok(());
    }
    let mut hello = ClientHello::parse(&ch);
    let suite = if s.suite == 0 { 0x1301 } else { s.suite };
    let (alg, aead) = suite_algs(suite);
    let mut transcript: Vec<u8> = ch.clone();
    let mut group = X25519;

    let sh_body = |random: &[u8], sid: &[u8], exts: &[u8]| {
        let mut b = vec![3, 3];
        b.extend_from_slice(random);
        b.push(sid.len() as u8);
        b.extend_from_slice(sid);
        b.extend_from_slice(&suite.to_be_bytes());
        b.push(0);
        b.extend_from_slice(&vec16(exts));
        message(2, &b)
    };
    const HRR_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2,
        0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    ];

    if let Some(g) = s.hrr {
        let mut exts = Vec::new();
        ext(&mut exts, 43, &[3, 4]);
        ext(&mut exts, 51, &g.to_be_bytes());
        if s.cookie {
            ext(&mut exts, 44, &vec16(b"a cookie from the server"));
        }
        let mut hrr = sh_body(&HRR_RANDOM, &hello.session_id, &exts);
        (s.edit)("HRR", &mut hrr);
        send_flight(f, std::slice::from_ref(&hrr), false, s.fragment)?;
        if s.ccs {
            f.send(CCS, &[1])?;
        }
        if s.close_after_flight {
            return close_and_watch(f, out);
        }
        let mut t = vec![254, 0, 0, alg.len() as u8];
        t.extend_from_slice(&hash::digest(alg, &ch));
        t.extend_from_slice(&hrr);
        let ch2 = f.recv_handshake()?;
        out.client_hello2 = Some(ch2.clone());
        if s.hrr_twice {
            (s.edit)("HRR2", &mut hrr);
            send_flight(f, &[hrr], false, s.fragment)?;
            out.alert = f.recv_alert();
            return Ok(());
        }
        t.extend_from_slice(&ch2);
        transcript = t;
        hello = ClientHello::parse(&ch2);
        // The group the HelloRetryRequest asked for, as edited; the same one without it.
        let _ = g;
        let exts = &hrr[4 + 2 + 32 + 1 + hrr[4 + 2 + 32] as usize + 3..];
        if let Some(i) = (0..exts.len().saturating_sub(5)).find(|&i| exts[i..i + 4] == [0, 51, 0, 2]) {
            group = u16::from_be_bytes([exts[i + 4], exts[i + 5]]);
        }
    }

    let peer = hello.share(group).ok_or_else(|| io::Error::other("fake: no key share for the group"))?;
    let (mut public, secret) = key_share(group);
    (s.edit)("Point", &mut public);
    let shared = shared(group, &secret, &peer)?;
    let mut random = [0; 32];
    rand::fill(&mut random);
    let mut exts = Vec::new();
    ext(&mut exts, 43, &[3, 4]);
    let mut ks = group.to_be_bytes().to_vec();
    ks.extend_from_slice(&vec16(&public));
    ext(&mut exts, 51, &ks);
    let mut sh = sh_body(&random, &hello.session_id, &exts);
    (s.edit)("SH", &mut sh);
    send_flight(f, std::slice::from_ref(&sh), false, s.fragment)?;
    transcript.extend_from_slice(&sh);
    f.send_raw(&s.inject)?;
    if s.ccs {
        f.send(CCS, &[1])?;
    }

    // RFC 8446 section 7.1.
    let zeros = vec![0; alg.len()];
    let early = hkdf_extract(alg, &zeros, &zeros);
    let empty = hash::digest(alg, b"");
    let derived = expand_label(alg, &early, b"derived", &empty, alg.len());
    let hs = hkdf_extract(alg, &derived, &shared);
    let th = hash::digest(alg, &transcript);
    let c_hs = expand_label(alg, &hs, b"c hs traffic", &th, alg.len());
    let s_hs = expand_label(alg, &hs, b"s hs traffic", &th, alg.len());
    f.tls13 = true;
    f.hash = alg;
    f.aead = aead;
    f.write = Some(keys13(alg, aead, &s_hs));
    f.read = Some(keys13(alg, aead, &c_hs));

    let mut flight = Vec::new();
    let mut exts = Vec::new();
    if let Some(p) = &s.alpn {
        let mut l = vec![p.len() as u8];
        l.extend_from_slice(p);
        ext(&mut exts, 16, &vec16(&l));
    }
    let mut ee = message(8, &vec16(&exts));
    (s.edit)("EE", &mut ee);
    transcript.extend_from_slice(&ee);
    flight.push(ee);
    if s.cert_request {
        let mut sa = Vec::new();
        ext(&mut sa, 13, &vec16(&[4, 3, 8, 4]));
        let mut b = vec![3, b'c', b't', b'x'];
        b.extend_from_slice(&vec16(&sa));
        let mut cr = message(13, &b);
        (s.edit)("CR", &mut cr);
        transcript.extend_from_slice(&cr);
        flight.push(cr);
    }
    let mut list = Vec::new();
    for c in &pki(s.key).chain {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
        list.extend_from_slice(&[0, 0]);
    }
    let mut b = vec![0];
    b.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    b.extend_from_slice(&list);
    let mut cert = message(11, &b);
    (s.edit)("Cert", &mut cert);
    transcript.extend_from_slice(&cert);
    flight.push(cert);

    let scheme = if s.scheme == 0 { default_scheme(s.key) } else { s.scheme };
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(&hash::digest(alg, &transcript));
    let mut b = scheme.to_be_bytes().to_vec();
    b.extend_from_slice(&vec16(&sign(s.key, scheme, &content)));
    let mut cv = message(15, &b);
    (s.edit)("CV", &mut cv);
    transcript.extend_from_slice(&cv);
    flight.push(cv);

    let fk = expand_label(alg, &s_hs, b"finished", b"", alg.len());
    let mut fin = message(20, &hmac(alg, &fk, &[&hash::digest(alg, &transcript)]));
    (s.edit)("Fin", &mut fin);
    transcript.extend_from_slice(&fin);
    flight.push(fin);
    send_flight(f, &flight, s.split, s.fragment)?;
    if s.close_after_flight {
        return close_and_watch(f, out);
    }

    let th = hash::digest(alg, &transcript);
    let derived = expand_label(alg, &hs, b"derived", &empty, alg.len());
    let master = hkdf_extract(alg, &derived, &zeros);
    let c_ap = expand_label(alg, &master, b"c ap traffic", &th, alg.len());
    let s_ap = expand_label(alg, &master, b"s ap traffic", &th, alg.len());

    // The client's flight.
    let mut m = f.recv_handshake()?;
    if s.cert_request {
        out.client_cert = Some(m.clone());
        transcript.extend_from_slice(&m);
        m = f.recv_handshake()?;
    }
    let fk = expand_label(alg, &c_hs, b"finished", b"", alg.len());
    let want = message(20, &hmac(alg, &fk, &[&hash::digest(alg, &transcript)]));
    out.finished = m == want;
    if !out.finished {
        return Err(io::Error::other("fake: bad client Finished"));
    }
    f.write = Some(keys13(alg, aead, &s_ap));
    f.read = Some(keys13(alg, aead, &c_ap));
    f.client_secret = c_ap;
    f.server_secret = s_ap;
    (s.after)(f)
}

fn server12(f: &mut Fake, mut s: Script, out: &mut Outcome) -> io::Result<()> {
    let ch = read_client_hello(f)?;
    out.client_hello = ch.clone();
    if let Some(raw) = s.raw.take() {
        f.send_raw(&raw)?;
        f.tcp.shutdown(std::net::Shutdown::Write)?;
        out.alert = f.recv_alert();
        return Ok(());
    }
    let hello = ClientHello::parse(&ch);
    let rsa = matches!(s.key, KeyType::Rsa2048 | KeyType::Rsa4096);
    let suite = match s.suite {
        0 if rsa => 0xc02f,
        0 => 0xc02b,
        n => n,
    };
    let (alg, aead) = suite_algs(suite);
    let mut transcript = ch.clone();

    let mut random = [0; 32];
    rand::fill(&mut random);
    let mut sid = [0; 32];
    rand::fill(&mut sid);
    let ems = s.ems && hello.ext(23).is_some();
    let mut exts = Vec::new();
    if hello.ext(0xff01).is_some() {
        ext(&mut exts, 0xff01, &[0]);
    }
    if ems {
        ext(&mut exts, 23, &[]);
    }
    ext(&mut exts, 11, &[1, 0]);
    if let Some(p) = &s.alpn {
        let mut l = vec![p.len() as u8];
        l.extend_from_slice(p);
        ext(&mut exts, 16, &vec16(&l));
    }
    let mut b = vec![3, 3];
    b.extend_from_slice(&random);
    b.push(32);
    b.extend_from_slice(&sid);
    b.extend_from_slice(&suite.to_be_bytes());
    b.push(0);
    b.extend_from_slice(&vec16(&exts));
    let mut sh = message(2, &b);
    (s.edit)("SH", &mut sh);
    // The random as sent, edits included, is what both sides sign and derive keys from.
    let random: [u8; 32] = sh.get(6..38).and_then(|r| r.try_into().ok()).unwrap_or(random);
    transcript.extend_from_slice(&sh);
    let mut flight = vec![sh];

    let mut list = Vec::new();
    for c in &pki(s.key).chain {
        list.extend_from_slice(&(c.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(c);
    }
    let mut b = (list.len() as u32).to_be_bytes()[1..].to_vec();
    b.extend_from_slice(&list);
    let mut cert = message(11, &b);
    (s.edit)("Cert", &mut cert);
    transcript.extend_from_slice(&cert);
    flight.push(cert);

    let group = s.group12;
    let (mut public, secret) = key_share(group);
    (s.edit)("Point", &mut public);
    let mut params = vec![3];
    params.extend_from_slice(&group.to_be_bytes());
    params.push(public.len() as u8);
    params.extend_from_slice(&public);
    let scheme = if s.scheme == 0 { default_scheme(s.key) } else { s.scheme };
    let mut signed = hello.random.clone();
    signed.extend_from_slice(&random);
    signed.extend_from_slice(&params);
    let mut b = params.clone();
    b.extend_from_slice(&scheme.to_be_bytes());
    b.extend_from_slice(&vec16(&sign(s.key, scheme, &signed)));
    let mut ske = message(12, &b);
    (s.edit)("SKE", &mut ske);
    transcript.extend_from_slice(&ske);
    flight.push(ske);

    if s.cert_request {
        let mut cr = message(13, &[1, 64, 0, 4, 4, 3, 8, 4, 0, 0]);
        (s.edit)("CR", &mut cr);
        transcript.extend_from_slice(&cr);
        flight.push(cr);
    }
    let mut shd = message(14, &[]);
    (s.edit)("SHD", &mut shd);
    transcript.extend_from_slice(&shd);
    flight.push(shd);
    send_flight(f, &flight, s.split, s.fragment)?;
    f.send_raw(&s.inject)?;
    if s.close_after_flight {
        return close_and_watch(f, out);
    }

    // The client's flight: [Certificate], ClientKeyExchange, ChangeCipherSpec, Finished.
    let mut m = f.recv_handshake()?;
    if s.cert_request {
        out.client_cert = Some(m.clone());
        transcript.extend_from_slice(&m);
        m = f.recv_handshake()?;
    }
    if m[0] != 16 || m.len() < 5 || usize::from(m[4]) + 5 != m.len() {
        return Err(io::Error::other("fake: bad ClientKeyExchange"));
    }
    let pms = shared(group, &secret, &m[5..])?;
    transcript.extend_from_slice(&m);
    let mut master = [0; 48];
    if ems {
        tls12_prf(alg, &pms, b"extended master secret", &[&hash::digest(alg, &transcript)], &mut master);
    } else {
        tls12_prf(alg, &pms, b"master secret", &[&hello.random, &random], &mut master);
    }
    let klen = aead.key_len();
    let ivlen = if aead == Aead::ChaCha20Poly1305 { 12 } else { 4 };
    let mut kb = vec![0; 2 * (klen + ivlen)];
    tls12_prf(alg, &master, b"key expansion", &[&random, &hello.random], &mut kb);
    let (ck, rest) = kb.split_at(klen);
    let (sk, rest) = rest.split_at(klen);
    let (civ, siv) = rest.split_at(ivlen);
    f.explicit_nonce = ivlen == 4;

    match f.recv()? {
        (CCS, d) if d == [1] => {}
        (ALERT, a) => return Err(alert_error(&a)),
        _ => return Err(io::Error::other("fake: expected ChangeCipherSpec")),
    }
    f.read = Some(Dir::new(aead, ck, civ));
    let mut want = [0; 12];
    tls12_prf(alg, &master, b"client finished", &[&hash::digest(alg, &transcript)], &mut want);
    let m = f.recv_handshake()?;
    out.finished = m == message(20, &want);
    if !out.finished {
        return Err(io::Error::other("fake: bad client Finished"));
    }
    transcript.extend_from_slice(&m);

    f.send(CCS, &[1])?;
    f.write = Some(Dir::new(aead, sk, siv));
    let mut verify = [0; 12];
    tls12_prf(alg, &master, b"server finished", &[&hash::digest(alg, &transcript)], &mut verify);
    let mut fin = message(20, &verify);
    (s.edit)("Fin", &mut fin);
    f.send(HANDSHAKE, &fin)?;
    (s.after)(f)
}
