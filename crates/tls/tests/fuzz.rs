//! Robustness: random bytes and mutated messages at every stage of the handshake and after it.
//! Nothing may panic or hang, and whatever is refused is refused with a "tls: " error.
//!
//! The mutations go into the scripted server's messages before they are encrypted and hashed,
//! so they reach the parsers behind the record protection, as a hostile server's would. Set
//! JPM_TLS_FUZZ=n to run n times as many cases.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::fake::{self, APP, HANDSHAKE, SECP256R1, Script};
use common::{KeyType, ServerOpts, connect, pki, proxy, rustls_server, rustls_server_config};

/// xorshift64*: deterministic, so a failing case can be run again.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545f4914f6cdd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn scale() -> usize {
    std::env::var("JPM_TLS_FUZZ").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

/// One mutation of a handshake message: flipped bits, bytes set, cut short, grown, a length
/// field changed, or bytes spliced in.
fn mutate(rng: &mut Rng, m: &mut Vec<u8>) {
    if m.is_empty() {
        m.extend(rng.bytes(4));
        return;
    }
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(m.len());
        match rng.below(8) {
            0 | 1 => m[at] ^= 1 << rng.below(8),
            2 => m[at] = rng.next() as u8,
            3 => m.truncate(at),
            4 => {
                let n = 1 + rng.below(40);
                let extra = rng.bytes(n);
                m.splice(at..at, extra);
            }
            5 => m[at] = [0, 1, 0x7f, 0x80, 0xff][rng.below(5)],
            6 => {
                let n = rng.below(m.len() - at + 1);
                m.drain(at..at + n);
            }
            _ => {
                // Keep the header's length right, so the change reaches the message's parser.
                m[at] ^= 1 << rng.below(8);
                if m.len() >= 4 {
                    let n = (m.len() - 4) as u32;
                    m[1..4].copy_from_slice(&n.to_be_bytes()[1..]);
                }
            }
        }
        if m.is_empty() {
            return;
        }
    }
}

/// Run `script` against our client with a short timeout; the client's result.
fn attempt(script: Script) -> Result<(), String> {
    let key = script.key;
    let (tcp, h) = fake::run(script);
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let r = connect(tcp, "localhost", &pki(key).config(&[b"http/1.1"])).map(|mut s| {
        let mut buf = [0; 64];
        let _ = s.read(&mut buf);
        let _ = s.write(b"x");
    });
    let _ = h.join();
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => Err(format!("hang: {e}")),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.starts_with("tls: "), "not a TLS error: {msg}");
            Err(msg)
        }
    }
}

/// Mutate the message `name` in `cases` handshakes of `base`. Messages whose every byte is
/// covered by a signature or a MAC the client checks (`strict`) must never be accepted
/// changed.
fn fuzz_message(base: fn() -> Script, name: &'static str, cases: usize, seed: u64) {
    let strict = matches!(name, "CV" | "Fin" | "Cert" | "SKE" | "SHD" | "HRR");
    let mut accepted = 0;
    for case in 0..cases * scale() {
        let seed = seed ^ (case as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15);
        let mut rng = Rng(seed);
        let changed = Arc::new(AtomicBool::new(false));
        let c2 = changed.clone();
        let script = Script { close_after_flight: true, ..base() }.edit(move |n, m| {
            if n == name {
                let before = m.clone();
                mutate(&mut rng, m);
                c2.store(*m != before, Ordering::Relaxed);
            }
        });
        match attempt(script) {
            Ok(()) if changed.load(Ordering::Relaxed) => {
                accepted += 1;
                assert!(!strict, "{name} seed {seed:#x}: a changed message was accepted");
            }
            Ok(()) => {}
            Err(e) => assert!(!e.starts_with("hang"), "{name} seed {seed:#x}: {e}"),
        }
    }
    eprintln!("{name}: {accepted} of {} changed messages accepted", cases * scale());
}

#[test]
fn mutated_tls13_server_hello() {
    fuzz_message(Script::default, "SH", 400, 1);
}

#[test]
fn mutated_tls13_encrypted_extensions() {
    fn base() -> Script {
        Script { alpn: Some(b"http/1.1".to_vec()), ..Script::default() }
    }
    fuzz_message(base, "EE", 300, 2);
}

#[test]
fn mutated_tls13_certificate() {
    fuzz_message(Script::default, "Cert", 400, 3);
}

#[test]
fn mutated_tls13_certificate_verify() {
    fuzz_message(Script::default, "CV", 200, 4);
    fn rsa() -> Script {
        Script { key: KeyType::Rsa2048, ..Script::default() }
    }
    fuzz_message(rsa, "CV", 100, 5);
}

#[test]
fn mutated_tls13_finished_and_request() {
    fuzz_message(Script::default, "Fin", 150, 6);
    fn cr() -> Script {
        Script { cert_request: true, ..Script::default() }
    }
    fuzz_message(cr, "CR", 150, 7);
}

#[test]
fn mutated_hello_retry_request() {
    fn hrr() -> Script {
        Script { hrr: Some(SECP256R1), cookie: true, ..Script::default() }
    }
    fuzz_message(hrr, "HRR", 300, 8);
}

#[test]
fn mutated_tls12_messages() {
    for (i, name) in ["SH", "Cert", "SKE", "SHD"].into_iter().enumerate() {
        fuzz_message(Script::tls12, name, 200, 9 + i as u64);
    }
    fn cr() -> Script {
        Script { cert_request: true, ..Script::tls12() }
    }
    fuzz_message(cr, "CR", 100, 13);
    fn p256() -> Script {
        Script { group12: SECP256R1, ..Script::tls12() }
    }
    fuzz_message(p256, "Point", 100, 14);
    fuzz_message(Script::default, "Point", 100, 15);
}

/// Random bytes where the ServerHello should be: raw, and inside records.
#[test]
fn random_bytes_for_a_server_hello() {
    let mut rng = Rng(16);
    for case in 0..1500 * scale() {
        let n = rng.below(300);
        let body = rng.bytes(n);
        let raw = match case % 3 {
            0 => body,
            1 => [&[22, 3, 3, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat(),
            _ => {
                // A handshake header of a random type in a record.
                let mut m = vec![rng.next() as u8 % 25, 0, (body.len() >> 8) as u8, body.len() as u8];
                if case % 2 == 0 {
                    m[0] = 2;
                }
                m.extend_from_slice(&body);
                [&[22, 3, 3, (m.len() >> 8) as u8, m.len() as u8][..], &m].concat()
            }
        };
        let script = Script { raw: Some(raw), tls12: case % 2 == 1, ..Script::default() };
        let r = attempt(script);
        assert!(r.is_err(), "case {case}: accepted random bytes");
        assert!(!r.unwrap_err().starts_with("hang"), "case {case}");
    }
}

/// Random records after the handshake: types, contents, padding, alerts, handshake messages.
#[test]
fn random_records_after_the_handshake() {
    let mut seeds = Rng(17);
    for case in 0..600 * scale() {
        let seed = seeds.next();
        let tls12 = case % 3 == 2;
        let script = Script { tls12, ..Script::default() }.after(move |f| {
            let mut rng = Rng(seed);
            // An alert of description 0 is a real close_notify, after which a clean end is
            // right: every alert here is some other one.
            let not_close = |typ: u8, mut data: Vec<u8>| {
                if typ == 21 && data.get(1) == Some(&0) {
                    data[1] = 10;
                }
                data
            };
            for _ in 0..1 + rng.below(4) {
                let n = rng.below(60);
                match rng.below(6) {
                    0 => f.send(APP, &rng.bytes(n))?,
                    1 => {
                        let n = rng.below(4);
                        f.send(21, &not_close(21, rng.bytes(n)))?
                    }
                    2 => {
                        // A handshake message of a random type and length, maybe split.
                        let mut m = vec![[4, 24, 0, 13, 20, 1][rng.below(6)], 0, 0, n as u8];
                        m.extend(rng.bytes(n));
                        mutate(&mut rng, &mut m);
                        let cut = rng.below(m.len() + 1);
                        f.send(HANDSHAKE, &m[..cut])?;
                        f.send(HANDSHAKE, &m[cut..])?;
                    }
                    3 => {
                        let (typ, data, pad) = (rng.next() as u8, rng.bytes(n), rng.below(3));
                        let rec = f.seal(typ, &not_close(typ, data), pad);
                        f.send_raw(&rec)?;
                    }
                    4 => {
                        let mut rec = f.seal(APP, &rng.bytes(n), 0);
                        let at = rng.below(rec.len());
                        rec[at] ^= 1 << rng.below(8);
                        f.send_raw(&rec)?;
                    }
                    _ => f.send_raw(&rng.bytes(n))?,
                }
            }
            f.tcp.shutdown(std::net::Shutdown::Write)
        });
        let (tcp, h) = fake::run(script);
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut s = connect(tcp, "localhost", &pki(KeyType::P256).config(&[])).unwrap();
        let mut buf = Vec::new();
        // The script always ends without close_notify, so reading must end in an error.
        let e = s.read_to_end(&mut buf).unwrap_err();
        assert!(e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut, "case {case}: hang");
        assert!(e.to_string().starts_with("tls: "), "case {case}: {e}");
        drop(s);
        let _ = h.join();
    }
}

/// A real rustls handshake with one bit flipped in what the server sent, at offsets through
/// its whole first flight. Only the legacy record version (ignored, RFC 8446 section 5.1) may
/// change without the handshake failing.
#[test]
fn bit_flips_in_a_rustls_flight() {
    for tls13 in [true, false] {
        let mut rng = Rng(18 + u64::from(tls13));
        let mut accepted = Vec::new();
        let mut offset = 0;
        while offset < 3000 {
            let flipped = Arc::new(Mutex::new(None));
            let (at, bit) = (offset, rng.below(8));
            let f2 = flipped.clone();
            let config = rustls_server_config(pki(KeyType::P256), &ServerOpts { tls13, ..ServerOpts::default() });
            let (server, h) = rustls_server(config, |s| {
                s.sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
                let mut buf = [0; 16];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"hello");
                let _ = s.flush();
            });
            let tcp = proxy(server, move |start, chunk| {
                if (start..start + chunk.len()).contains(&at) {
                    chunk[at - start] ^= 1 << bit;
                    *f2.lock().unwrap() = Some(chunk[at - start]);
                }
                true
            });
            tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let r = connect(tcp, "localhost", &pki(KeyType::P256).config(&[])).and_then(|mut s| {
                s.write_all(b"x")?;
                let mut buf = [0; 5];
                s.read_exact(&mut buf)?;
                assert_eq!(&buf, b"hello");
                Ok(())
            });
            let _ = h.join();
            if flipped.lock().unwrap().is_none() {
                break; // Past the end of what the server sent.
            }
            match r {
                Ok(()) => accepted.push(at),
                Err(e) => {
                    let msg = e.to_string();
                    let timeout = matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut);
                    // A longer length leaves the client waiting for the rest: it times out.
                    assert!(msg.starts_with("tls: ") || timeout, "offset {at}: {msg}");
                }
            }
            offset += 1 + rng.below(3);
        }
        // Minor version bytes of plaintext record headers only: at most a few.
        assert!(accepted.len() <= 4, "tls13 {tls13}: flips accepted at {accepted:?}");
        eprintln!("tls13 {tls13}: stopped at {offset}; accepted at {accepted:?}");
    }
}
