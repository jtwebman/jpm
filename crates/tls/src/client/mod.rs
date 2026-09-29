//! The client: a handshake on `connect`, then records both ways through `Read` and `Write`.

mod hello;
mod record;
#[cfg(test)]
mod rfc8448;
mod tls12;
mod tls13;

use std::io::{self, Read, Write};

use crate::x509::Anchor;
use record::{ALERT, APPLICATION_DATA, Conn, HANDSHAKE, MAX_PLAIN};

/// What every connection shares: the roots it trusts and the protocols it asks for by ALPN.
pub struct Config {
    pub roots: Vec<Anchor<'static>>,
    pub alpn: Vec<Vec<u8>>,
}

/// A TLS connection over `S`, usually a `TcpStream`.
pub struct Stream<S> {
    conn: Conn<S>,
    alpn: Option<Vec<u8>>,
    /// TLS 1.3 traffic secrets, for KeyUpdate. `None` in TLS 1.2.
    secrets: Option<tls13::Secrets>,
    /// The server sent close_notify: reads return 0 from now on.
    closed: bool,
    /// A fatal error has happened: the connection is unusable.
    failed: bool,
}

impl<S: Read + Write> Stream<S> {
    /// Handshake with `host` (the name to check the certificate against and send by SNI; an IP
    /// literal sends no SNI) over `io`. Errors are `InvalidData` for the peer's mistakes, with a
    /// message saying which.
    pub fn connect(io: S, host: &str, config: &Config) -> io::Result<Self> {
        let mut conn = Conn::new(io);
        match hello::handshake(&mut conn, host, config) {
            Ok(done) => Ok(Self { conn, alpn: done.alpn, secrets: done.secrets, closed: false, failed: false }),
            Err(e) => Err(conn.fail(e)),
        }
    }

    /// The protocol the server picked by ALPN, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn get_ref(&self) -> &S {
        &self.conn.io
    }

    fn fail(&mut self, e: Error) -> io::Error {
        if !matches!(&e, Error::Io(_)) {
            self.failed = true;
        }
        self.conn.fail(e)
    }

    /// Read one record and act on it. Application data waits in `conn.plaintext()`.
    fn next(&mut self) -> Result<()> {
        let typ = self.conn.next_record()?;
        if !self.conn.hs.is_empty() && typ != HANDSHAKE {
            return Err(record::interleaved());
        }
        match typ {
            APPLICATION_DATA => Ok(()),
            ALERT => match self.conn.alert() {
                Err(Error::Closed) => {
                    self.closed = true;
                    Ok(())
                }
                r => r,
            },
            HANDSHAKE => {
                if self.conn.plaintext().is_empty() {
                    return Err(Error::Tls(alert::DECODE_ERROR, "tls: decode error: empty handshake record"));
                }
                self.conn.take_hs();
                while let Some(m) = self.conn.hs_message()? {
                    // Any error here is fatal, even from `io`: the read key has moved on, or a
                    // reply may be half sent.
                    if let Err(e) = self.post_handshake(&m) {
                        self.failed = true;
                        return Err(e);
                    }
                }
                Ok(())
            }
            _ => Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected message after the handshake")),
        }
    }

    /// Handshake messages after the handshake: RFC 8446 section 4.6, RFC 5246 section 7.4.1.1.
    fn post_handshake(&mut self, m: &[u8]) -> Result<()> {
        const HELLO_REQUEST: u8 = 0;
        const NEW_SESSION_TICKET: u8 = 4;
        const KEY_UPDATE: u8 = 24;
        let (typ, body) = (m[0], &m[4..]);
        match (&mut self.secrets, typ) {
            // No resumption: tickets are dropped.
            (Some(_), NEW_SESSION_TICKET) => Ok(()),
            (Some(s), KEY_UPDATE) => {
                let requested = match body {
                    [0] => false,
                    [1] => true,
                    _ => return Err(Error::Tls(alert::DECODE_ERROR, "tls: decode error: bad KeyUpdate")),
                };
                if !self.conn.hs.is_empty() {
                    return Err(record::across_key_change());
                }
                s.server = tls13::next_secret(s.hash, &s.server);
                self.conn.read = Some(tls13::keys(s.hash, s.aead, &s.server));
                if requested {
                    self.conn.send(HANDSHAKE, &[KEY_UPDATE, 0, 0, 1, 0])?;
                    s.client = tls13::next_secret(s.hash, &s.client);
                    self.conn.write = Some(tls13::keys(s.hash, s.aead, &s.client));
                }
                Ok(())
            }
            // No renegotiation (RFC 5746 section 4.2): say so with a warning and go on.
            (None, HELLO_REQUEST) if body.is_empty() => self.conn.send(ALERT, &[1, alert::NO_RENEGOTIATION]),
            _ => Err(Error::Tls(alert::UNEXPECTED_MESSAGE, "tls: unexpected handshake message after the handshake")),
        }
    }
}

impl<S: Read + Write> Read for Stream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // After a failure, what is left of the record that caused it is not data.
            if self.failed {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "tls: connection failed earlier"));
            }
            let pt = self.conn.plaintext();
            if !pt.is_empty() {
                let n = pt.len().min(buf.len());
                buf[..n].copy_from_slice(&pt[..n]);
                self.conn.consume(n);
                return Ok(n);
            }
            if self.closed {
                return Ok(0);
            }
            if let Err(e) = self.next() {
                return Err(self.fail(e));
            }
        }
    }
}

impl<S: Read + Write> Write for Stream<S> {
    /// Up to four full records at a time, sealed and written in one go.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tls: connection failed earlier"));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(4 * MAX_PLAIN);
        if let Err(e) = self.conn.send(APPLICATION_DATA, &buf[..n]) {
            // Part of a record may have gone out: nothing more can be sent after it.
            self.failed = true;
            return Err(self.conn.fail(e));
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.io.flush()
    }
}

/// Why a connection failed.
pub(crate) enum Error {
    Io(io::Error),
    /// A protocol error: the alert to send the peer (`alert::NONE` for none) and the message.
    Tls(u8, &'static str),
    /// The certificate chain was refused, for this reason.
    Cert(&'static str),
    /// The peer sent close_notify.
    Closed,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Tls(_, msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::Cert(why) => {
                let mut msg = String::from("tls: bad certificate: ");
                msg.push_str(why);
                io::Error::new(io::ErrorKind::InvalidData, msg)
            }
            Error::Closed => io::Error::new(io::ErrorKind::UnexpectedEof, "tls: connection closed"),
        }
    }
}

/// Alert descriptions (RFC 8446 section 6).
pub(crate) mod alert {
    pub(crate) const CLOSE_NOTIFY: u8 = 0;
    pub(crate) const UNEXPECTED_MESSAGE: u8 = 10;
    pub(crate) const BAD_RECORD_MAC: u8 = 20;
    pub(crate) const RECORD_OVERFLOW: u8 = 22;
    pub(crate) const HANDSHAKE_FAILURE: u8 = 40;
    pub(crate) const BAD_CERTIFICATE: u8 = 42;
    pub(crate) const UNSUPPORTED_CERTIFICATE: u8 = 43;
    pub(crate) const ILLEGAL_PARAMETER: u8 = 47;
    pub(crate) const DECODE_ERROR: u8 = 50;
    pub(crate) const DECRYPT_ERROR: u8 = 51;
    pub(crate) const PROTOCOL_VERSION: u8 = 70;
    pub(crate) const INTERNAL_ERROR: u8 = 80;
    pub(crate) const USER_CANCELED: u8 = 90;
    pub(crate) const NO_RENEGOTIATION: u8 = 100;
    pub(crate) const MISSING_EXTENSION: u8 = 109;
    pub(crate) const UNSUPPORTED_EXTENSION: u8 = 110;
    /// Not an alert: nothing is sent.
    pub(crate) const NONE: u8 = 255;

    /// The message for an alert received from the peer.
    pub(crate) fn received(desc: u8) -> &'static str {
        match desc {
            10 => "tls: received alert unexpected_message",
            20 => "tls: received alert bad_record_mac",
            22 => "tls: received alert record_overflow",
            40 => "tls: received alert handshake_failure",
            42 => "tls: received alert bad_certificate",
            43 => "tls: received alert unsupported_certificate",
            44 => "tls: received alert certificate_revoked",
            45 => "tls: received alert certificate_expired",
            46 => "tls: received alert certificate_unknown",
            47 => "tls: received alert illegal_parameter",
            48 => "tls: received alert unknown_ca",
            49 => "tls: received alert access_denied",
            50 => "tls: received alert decode_error",
            51 => "tls: received alert decrypt_error",
            70 => "tls: received alert protocol_version",
            71 => "tls: received alert insufficient_security",
            80 => "tls: received alert internal_error",
            86 => "tls: received alert inappropriate_fallback",
            100 => "tls: received alert no_renegotiation",
            109 => "tls: received alert missing_extension",
            110 => "tls: received alert unsupported_extension",
            112 => "tls: received alert unrecognized_name",
            113 => "tls: received alert bad_certificate_status_response",
            115 => "tls: received alert unknown_psk_identity",
            116 => "tls: received alert certificate_required",
            120 => "tls: received alert no_application_protocol",
            _ => "tls: received an unknown alert",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};

    use jpm_crypto::aead::Alg::Aes128Gcm;
    use jpm_crypto::hash::Alg::Sha256;

    use super::Stream;
    use super::record::{Conn, HANDSHAKE};
    use super::tls13::{Secret, Secrets, derive, keys};

    /// Reads from `input`; writes fail while `fail_writes` is set.
    struct Pipe {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        fail_writes: bool,
    }

    impl Read for Pipe {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.fail_writes {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out"));
            }
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn conn(input: Vec<u8>, read: &Secret, write: &Secret) -> Conn<Pipe> {
        let mut c = Conn::new(Pipe { input: Cursor::new(input), output: Vec::new(), fail_writes: false });
        c.tls13 = true;
        c.read = Some(keys(Sha256, Aes128Gcm, read));
        c.write = Some(keys(Sha256, Aes128Gcm, write));
        c
    }

    /// When the answer to a KeyUpdate(update_requested) cannot be sent, the connection has
    /// failed: nothing more may go out under the old key.
    #[test]
    fn key_update_reply_fails() {
        let server = derive(Sha256, &[1; 32], b"s", b"");
        let client = derive(Sha256, &[2; 32], b"c", b"");
        let mut peer = conn(Vec::new(), &client, &server);
        peer.send(HANDSHAKE, &[24, 0, 0, 1, 1]).ok().unwrap();

        let mut c = conn(peer.io.output, &server, &client);
        c.io.fail_writes = true;
        let secrets = Secrets { hash: Sha256, aead: Aes128Gcm, client, server };
        let mut s = Stream { conn: c, alpn: None, secrets: Some(secrets), closed: false, failed: false };
        assert_eq!(s.read(&mut [0; 16]).unwrap_err().kind(), io::ErrorKind::TimedOut);
        s.conn.io.fail_writes = false;
        assert!(s.write(b"GET").is_err());
        assert!(s.conn.io.output.is_empty());
    }
}
