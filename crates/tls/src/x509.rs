//! Server certificate checks (RFC 5280 path validation as the Web PKI uses it): a chain from the
//! server's certificate to a trust anchor, each link signed by the next, all valid now, CA
//! constraints and name constraints held, and the name matching the host by subjectAltName.
//! No revocation checks, as browsers and rustls do by default.

/// A trusted root, as `webpki-roots` lists them: the DER of its subject name, its
/// SubjectPublicKeyInfo, and any name constraints.
#[derive(Clone, Copy, Debug)]
pub struct Anchor<'a> {
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub name_constraints: Option<&'a [u8]>,
}

/// A public key a signature is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// Modulus and exponent, big-endian.
    Rsa { n: &'a [u8], e: &'a [u8] },
    /// An uncompressed point.
    P256(&'a [u8]),
    /// An uncompressed point.
    P384(&'a [u8]),
}

/// A signature algorithm, as a certificate names it by OID and TLS by code point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
}

/// Why a chain was refused. The message is what a user sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Check `chain` (DER certificates, the server's first, then whatever intermediates it sent in
/// any order) for `host` (a DNS name or an IP address literal) at `now` (seconds since the Unix
/// epoch). The server certificate's public key on success.
pub fn verify_server<'a>(chain: &[&'a [u8]], host: &str, now: u64, anchors: &[Anchor]) -> Result<PublicKey<'a>, Error> {
    todo!("{} {host} {now} {}", chain.len(), anchors.len())
}

/// Whether `signature` over `message` is `key`'s under `scheme`. A key and scheme that do not
/// go together (an EC key with an RSA scheme) are `false`.
pub fn verify_signature(key: &PublicKey, scheme: Scheme, message: &[u8], signature: &[u8]) -> bool {
    todo!("{key:?} {scheme:?} {} {}", message.len(), signature.len())
}
