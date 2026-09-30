//! The HTTP client jpm fetches registries with. For now, HTTP/2 (RFC 9113) over jpm-tls, made
//! for one use: GET requests for registry documents and tarballs, each response's body read as
//! it arrives. A few connections per host carry many streams each; ALPN picks HTTP/2, and a
//! server that picks HTTP/1.1 gets its connection handed back for the caller's own client.
//!
//! What it leaves out: server push, priorities, request bodies, trailers (read and dropped),
//! and HTTP/2 without TLS.

pub mod frame;
mod h2;
pub mod hpack;

use std::fmt;
use std::io;
use std::sync::Arc;

pub use h2::{Body, Conn, Got, Link, Pool, Request, Response, tls_link};

/// Why a request failed.
#[derive(Debug, Clone)]
pub struct Error {
    /// `TimedOut` for a silent server, `InvalidData` for one that broke the protocol (and for
    /// TLS refusals, whose messages start "tls: "), and what the socket said otherwise.
    pub kind: io::ErrorKind,
    pub message: Arc<str>,
    /// The server never acted on the request: it can go again at once, on another connection.
    pub unprocessed: bool,
}

impl Error {
    pub(crate) fn new(kind: io::ErrorKind, message: impl Into<Arc<str>>) -> Self {
        Self { kind, message: message.into(), unprocessed: false }
    }

    pub(crate) fn unprocessed(message: impl Into<Arc<str>>) -> Self {
        Self { unprocessed: true, ..Self::new(io::ErrorKind::ConnectionAborted, message) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::new(e.kind(), e.to_string())
    }
}

impl From<frame::Violation> for Error {
    fn from(v: frame::Violation) -> Self {
        Self::new(io::ErrorKind::InvalidData, v.why)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(e.kind, e.message.to_string())
    }
}
