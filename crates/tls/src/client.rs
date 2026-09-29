//! The client: a handshake on `connect`, then records both ways through `Read` and `Write`.

use std::io::{self, Read, Write};

use crate::x509::Anchor;

/// What every connection shares: the roots it trusts and the protocols it asks for by ALPN.
pub struct Config {
    pub roots: Vec<Anchor<'static>>,
    pub alpn: Vec<Vec<u8>>,
}

/// A TLS connection over `S`, usually a `TcpStream`.
pub struct Stream<S> {
    io: S,
}

impl<S: Read + Write> Stream<S> {
    /// Handshake with `host` (the name to check the certificate against and send by SNI; an IP
    /// literal sends no SNI) over `io`. Errors are `InvalidData` for the peer's mistakes, with a
    /// message saying which.
    pub fn connect(io: S, host: &str, config: &Config) -> io::Result<Self> {
        todo!("{host} {} {}", config.roots.len(), std::mem::size_of_val(&io))
    }

    /// The protocol the server picked by ALPN, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        todo!()
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Read + Write> Read for Stream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!("{}", buf.len())
    }
}

impl<S: Read + Write> Write for Stream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!("{}", buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}
