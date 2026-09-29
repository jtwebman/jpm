//! The record layer (RFC 8446 section 5, RFC 5246 section 6.2): framing, AEAD protection both
//! ways, and handshake messages reassembled across records. One implementation serves both
//! versions; `tls13` and `explicit_nonce` pick the record format.
//!
//! Records are read into one fixed buffer and decrypted in place; records are sealed into one
//! reused buffer. Neither allocates once the connection is up.

use std::io::{self, Read, Write};

use jpm_crypto::aead::{self, TAG_LEN};

use super::{Error, Result, alert};

pub(crate) const CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const ALERT: u8 = 21;
pub(crate) const HANDSHAKE: u8 = 22;
pub(crate) const APPLICATION_DATA: u8 = 23;

/// The largest plaintext a record may carry.
pub(crate) const MAX_PLAIN: usize = 1 << 14;
/// The largest ciphertext: 2^14 + 256 in TLS 1.3, 2^14 + 2048 in TLS 1.2.
const MAX_CIPHER_13: usize = MAX_PLAIN + 256;
const MAX_CIPHER_12: usize = MAX_PLAIN + 2048;
/// Room for one whole record and most of the next, so one read from the socket often brings
/// in more than one record.
const BUF_LEN: usize = 5 + MAX_CIPHER_12 + MAX_PLAIN;
/// The longest handshake message accepted. Certificate chains are the longest in practice and
/// stay far below this.
const MAX_HANDSHAKE: usize = 1 << 16;

/// One direction's key: the AEAD key, the IV and the sequence number.
pub(crate) struct Keys {
    key: aead::Key,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    /// `iv` is 12 bytes, or 4 for TLS 1.2 AES-GCM (the salt; the rest of the nonce is the
    /// explicit part each record carries).
    pub(crate) fn new(alg: aead::Alg, key: &[u8], iv: &[u8]) -> Self {
        let mut full = [0; 12];
        full[..iv.len()].copy_from_slice(iv);
        // Keys come from the key schedule at the right length, so this never fails.
        let key = aead::Key::new(alg, key).expect("key length");
        Self { key, iv: full, seq: 0 }
    }

    /// The IV with `n` XORed into its last eight bytes (RFC 8446 section 5.3; RFC 7905
    /// section 2). For TLS 1.2 AES-GCM the last eight IV bytes are zero, so this is the salt
    /// followed by `n`, the explicit nonce (RFC 5288 section 3).
    fn nonce(&self, n: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (b, x) in nonce[4..].iter_mut().zip(n.to_be_bytes()) {
            *b ^= x;
        }
        nonce
    }

    /// The sequence number for the next record. RFC 8446 section 5.3: it must not wrap.
    fn next_seq(&mut self) -> Result<u64> {
        let seq = self.seq;
        self.seq = seq.checked_add(1).ok_or(Error::Tls(alert::INTERNAL_ERROR, "tls: sequence number overflow"))?;
        Ok(seq)
    }
}

pub(crate) struct Conn<S> {
    pub(crate) io: S,
    buf: Box<[u8]>,
    /// The current record starts at `start`; bytes read from `io` end at `end`.
    start: usize,
    end: usize,
    /// The end of the current record, and its unconsumed plaintext.
    rec_end: usize,
    pt_start: usize,
    pt_end: usize,
    pub(crate) read: Option<Keys>,
    pub(crate) write: Option<Keys>,
    /// The TLS 1.3 record format: an inner content type, and outer type application_data.
    pub(crate) tls13: bool,
    /// TLS 1.2 AES-GCM: records carry an explicit 8-byte nonce.
    pub(crate) explicit_nonce: bool,
    /// TLS 1.3 middlebox compatibility: a plaintext change_cipher_spec is ignored during the
    /// handshake (RFC 8446 section 5).
    pub(crate) ccs_ok: bool,
    /// Handshake bytes waiting to become whole messages.
    pub(crate) hs: Vec<u8>,
    wbuf: Vec<u8>,
}

impl<S: Read + Write> Conn<S> {
    pub(crate) fn new(io: S) -> Self {
        Self {
            io,
            buf: vec![0; BUF_LEN].into_boxed_slice(),
            start: 0,
            end: 0,
            rec_end: 0,
            pt_start: 0,
            pt_end: 0,
            read: None,
            write: None,
            tls13: false,
            explicit_nonce: false,
            ccs_ok: false,
            hs: Vec::new(),
            wbuf: Vec::new(),
        }
    }

    /// The current record's plaintext not yet consumed.
    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.buf[self.pt_start..self.pt_end]
    }

    pub(crate) fn consume(&mut self, n: usize) {
        self.pt_start += n;
    }

    /// Drop the current record and read, check and decrypt the next. Returns its content type;
    /// the plaintext is in `plaintext()`. An error from `io` leaves the connection as it was,
    /// so a read that timed out can be tried again.
    pub(crate) fn next_record(&mut self) -> Result<u8> {
        self.start = self.rec_end;
        self.pt_start = self.rec_end;
        self.pt_end = self.rec_end;
        let len = loop {
            let have = self.end - self.start;
            let mut need = 5;
            if have >= 5 {
                let h = &self.buf[self.start..self.start + 5];
                if !(CHANGE_CIPHER_SPEC..=APPLICATION_DATA).contains(&h[0]) || h[1] != 3 {
                    return Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message: not a TLS record"));
                }
                let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
                let max = match self.read {
                    None => MAX_PLAIN,
                    Some(_) if self.tls13 => MAX_CIPHER_13,
                    Some(_) => MAX_CIPHER_12,
                };
                if len > max {
                    return Err(Error::Tls(alert::RECORD_OVERFLOW, "tls: record overflow"));
                }
                if have >= 5 + len {
                    break len;
                }
                need += len;
            }
            if self.start + need > self.buf.len() {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.rec_end = 0;
                self.start = 0;
                self.pt_start = 0;
                self.pt_end = 0;
            }
            let n = match self.io.read(&mut self.buf[self.end..]) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                let msg = if have == 0 {
                    "tls: connection closed without close_notify"
                } else {
                    "tls: connection closed in the middle of a record"
                };
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, msg).into());
            }
            self.end += n;
        };

        let hdr: [u8; 5] = self.buf[self.start..self.start + 5].try_into().unwrap();
        let body = self.start + 5;
        self.rec_end = body + len;
        let mut typ = hdr[0];
        let (mut a, mut b) = (body, self.rec_end);
        match &mut self.read {
            // A TLS 1.3 change_cipher_spec is never protected.
            Some(_) if self.tls13 && typ == CHANGE_CIPHER_SPEC => {}
            None => {}
            Some(k) => {
                if self.tls13 && typ != APPLICATION_DATA {
                    return Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message: unprotected record"));
                }
                let explicit = if self.explicit_nonce { 8 } else { 0 };
                if len < explicit + TAG_LEN {
                    return Err(Error::Tls(alert::BAD_RECORD_MAC, "tls: bad record mac"));
                }
                let seq = k.next_seq()?;
                let n = match explicit {
                    0 => seq,
                    _ => u64::from_be_bytes(self.buf[body..body + 8].try_into().unwrap()),
                };
                a = body + explicit;
                b = self.rec_end - TAG_LEN;
                let tag: [u8; TAG_LEN] = self.buf[b..self.rec_end].try_into().unwrap();
                // RFC 8446 section 5.2: the record header; RFC 5246 section 6.2.3.3: sequence
                // number, type, version and plaintext length.
                let mut aad = [0; 13];
                let aad: &[u8] = if self.tls13 {
                    &hdr
                } else {
                    aad[..8].copy_from_slice(&seq.to_be_bytes());
                    aad[8..11].copy_from_slice(&hdr[..3]);
                    aad[11..].copy_from_slice(&((b - a) as u16).to_be_bytes());
                    &aad
                };
                if !k.key.open(&k.nonce(n), aad, &mut self.buf[a..b], &tag) {
                    return Err(Error::Tls(alert::BAD_RECORD_MAC, "tls: bad record mac"));
                }
                if self.tls13 {
                    // The content type is the last non-zero byte; zeros after it are padding.
                    let Some(i) = self.buf[a..b].iter().rposition(|&x| x != 0) else {
                        return Err(Error::Tls(
                            alert::UNEXPECTED_MESSAGE,
                            "tls: unexpected message: record without a content type",
                        ));
                    };
                    typ = self.buf[a + i];
                    b = a + i;
                    if !(ALERT..=APPLICATION_DATA).contains(&typ) {
                        return Err(Error::Tls(
                            alert::UNEXPECTED_MESSAGE,
                            "tls: unexpected message: bad inner content type",
                        ));
                    }
                }
                if b - a > MAX_PLAIN {
                    return Err(Error::Tls(alert::RECORD_OVERFLOW, "tls: record overflow"));
                }
            }
        }
        self.pt_start = a;
        self.pt_end = b;
        Ok(typ)
    }

    /// The current record as an alert. Warnings in TLS 1.2 (and before the version is known) and
    /// user_canceled are ignored; close_notify is `Error::Closed`; anything else is fatal.
    pub(crate) fn alert(&mut self) -> Result<()> {
        let &[level, desc] = self.plaintext() else {
            return Err(Error::Tls(alert::DECODE_ERROR, "tls: decode error: bad alert"));
        };
        self.consume(2);
        match desc {
            alert::CLOSE_NOTIFY => Err(Error::Closed),
            alert::USER_CANCELED => Ok(()),
            _ if level == 1 && !self.tls13 => Ok(()),
            _ => Err(Error::Tls(alert::NONE, alert::received(desc))),
        }
    }

    /// The next whole handshake message, header included.
    pub(crate) fn read_hs(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(m) = self.hs_message()? {
                return Ok(m);
            }
            let typ = self.next_record()?;
            match typ {
                HANDSHAKE if self.plaintext().is_empty() => {
                    return Err(Error::Tls(alert::DECODE_ERROR, "tls: decode error: empty handshake record"));
                }
                HANDSHAKE => self.take_hs(),
                ALERT => match self.alert() {
                    Err(Error::Closed) => {
                        let e =
                            io::Error::new(io::ErrorKind::UnexpectedEof, "tls: connection closed during the handshake");
                        return Err(e.into());
                    }
                    r => r?,
                },
                _ if !self.hs.is_empty() => return Err(interleaved()),
                CHANGE_CIPHER_SPEC if self.ccs_ok && self.plaintext() == [1] => {}
                _ => return Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message during the handshake")),
            }
        }
    }

    /// Move the current record's plaintext to the handshake bytes waiting.
    pub(crate) fn take_hs(&mut self) {
        self.hs.extend_from_slice(&self.buf[self.pt_start..self.pt_end]);
        self.pt_start = self.pt_end;
    }

    /// A whole handshake message from the bytes waiting, if there is one.
    pub(crate) fn hs_message(&mut self) -> Result<Option<Vec<u8>>> {
        let &[_, a, b, c, ..] = &self.hs[..] else { return Ok(None) };
        let n = 4 + (usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c));
        if n > MAX_HANDSHAKE {
            return Err(Error::Tls(alert::DECODE_ERROR, "tls: decode error: handshake message too long"));
        }
        if self.hs.len() < n {
            return Ok(None);
        }
        let rest = self.hs.split_off(n);
        Ok(Some(std::mem::replace(&mut self.hs, rest)))
    }

    /// TLS 1.2: the server's change_cipher_spec, alone in its record and between messages.
    pub(crate) fn read_ccs(&mut self) -> Result<()> {
        loop {
            match self.next_record()? {
                ALERT => self.alert()?,
                CHANGE_CIPHER_SPEC if self.hs.is_empty() && self.plaintext() == [1] => return Ok(()),
                _ => {
                    return Err(Error::Tls(
                        alert::UNEXPECTED_MESSAGE,
                        "tls: unexpected message: expected ChangeCipherSpec",
                    ));
                }
            }
        }
    }

    /// Seal `data` as records of type `typ` into the write buffer. `flush_records` sends them.
    pub(crate) fn push(&mut self, typ: u8, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(MAX_PLAIN) {
            let w = &mut self.wbuf;
            let Some(k) = self.write.as_mut().filter(|_| !(self.tls13 && typ == CHANGE_CIPHER_SPEC)) else {
                w.extend_from_slice(&[typ, 3, 3]);
                w.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                w.extend_from_slice(chunk);
                continue;
            };
            let seq = k.next_seq()?;
            let explicit = if self.explicit_nonce { 8 } else { 0 };
            let len = explicit + chunk.len() + usize::from(self.tls13) + TAG_LEN;
            let outer = if self.tls13 { APPLICATION_DATA } else { typ };
            let hdr = [outer, 3, 3, (len >> 8) as u8, len as u8];
            w.extend_from_slice(&hdr);
            if explicit > 0 {
                w.extend_from_slice(&seq.to_be_bytes());
            }
            let at = w.len();
            w.extend_from_slice(chunk);
            let mut aad = [0; 13];
            let aad: &[u8] = if self.tls13 {
                w.push(typ);
                &hdr
            } else {
                aad[..8].copy_from_slice(&seq.to_be_bytes());
                aad[8..11].copy_from_slice(&hdr[..3]);
                aad[11..].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
                &aad
            };
            let tag = k.key.seal(&k.nonce(seq), aad, &mut w[at..]);
            w.extend_from_slice(&tag);
        }
        Ok(())
    }

    /// Write the sealed records to `io`.
    pub(crate) fn flush_records(&mut self) -> Result<()> {
        let r = self.io.write_all(&self.wbuf);
        self.wbuf.clear();
        Ok(r?)
    }

    pub(crate) fn send(&mut self, typ: u8, data: &[u8]) -> Result<()> {
        self.push(typ, data)?;
        self.flush_records()
    }

    /// Tell the peer why the connection failed, when there is an alert for it, and turn the
    /// error into what the caller sees.
    pub(crate) fn fail(&mut self, e: Error) -> io::Error {
        let desc = match e {
            Error::Tls(desc, _) => desc,
            Error::Cert(_) => alert::BAD_CERTIFICATE,
            Error::Io(_) | Error::Closed => alert::NONE,
        };
        if desc != alert::NONE {
            self.wbuf.clear();
            let _ = self.send(ALERT, &[2, desc]);
        }
        e.into()
    }
}

/// RFC 8446 section 5.1: handshake messages must not span a key change.
pub(crate) fn across_key_change() -> Error {
    Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message: handshake data across a key change")
}

pub(crate) fn interleaved() -> Error {
    Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message: record inside a handshake message")
}
