//! A TLS client for jpm: TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246, ECDHE and AEAD suites only),
//! with server certificates checked against the Web PKI the way browsers and webpki do.
//!
//! What it offers: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; X25519 and P-256 key
//! exchange; RSA (PKCS#1 v1.5 and PSS) and ECDSA (P-256, P-384) signatures. What it leaves out:
//! client certificates, session resumption, 0-RTT, renegotiation, compression, CBC and RSA key
//! exchange, and anything below TLS 1.2.

mod client;
pub mod der;
pub mod x509;

pub use client::{Config, Stream, Verified, Writer};
pub use x509::Anchor;
