//! Server certificate checks (RFC 5280 path validation as the Web PKI uses it): a chain from the
//! server's certificate to a trust anchor, each link signed by the next, all valid now, CA
//! constraints and name constraints held, and the name matching the host by subjectAltName.
//! No revocation checks, as browsers and rustls do by default.
//!
//! The rules are webpki's (rustls-webpki 0.103), which the tests hold this code to case by
//! case. Where the two differ on purpose, the tests say so.

mod cert;
mod name;

use cert::Cert;
use name::Host;

/// A trusted root, as `webpki-roots` lists them: the DER of its subject name, its
/// SubjectPublicKeyInfo, and any name constraints.
///
/// Each is the contents of its SEQUENCE, without the tag and length, as in webpki's
/// `TrustAnchor`.
#[derive(Clone, Copy, Debug)]
pub struct Anchor<'a> {
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub name_constraints: Option<&'a [u8]>,
}

impl<'a> Anchor<'a> {
    /// The anchor a CA certificate (DER) makes: its subject, key and name constraints, as
    /// webpki's `anchor_from_trusted_cert` takes them. Nothing else in it is checked: a root is
    /// trusted because it was configured, not for what it says about itself.
    pub fn from_cert(der: &'a [u8]) -> Result<Self, Error> {
        let c = cert::parse(der)?;
        Ok(Self { subject: c.subject, spki: c.spki, name_constraints: c.name_constraints })
    }
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

/// Why a certificate or a path failed, least telling first. When several paths fail, the most
/// telling reason is reported, as webpki ranks its errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Code {
    UnknownIssuer,
    Encoding,
    PathTooLong,
    Unsupported,
    BadMask,
    BadValidity,
    CaAsLeaf,
    NotCa,
    PathLen,
    NameConstraints,
    Eku,
    BadSignature,
    WrongHost,
    NotYetValid,
    Expired,
    /// A budget ran out. This ends the search at once.
    TooComplex,
}

impl From<Code> for Error {
    fn from(code: Code) -> Self {
        Error(match code {
            Code::UnknownIssuer => "unknown issuer",
            Code::Encoding => "invalid certificate encoding",
            Code::PathTooLong => "path too long",
            Code::Unsupported => "unsupported certificate",
            Code::BadMask => "invalid name constraint",
            Code::BadValidity => "invalid certificate validity",
            Code::CaAsLeaf => "CA certificate used as a server certificate",
            Code::NotCa => "issuer is not a CA",
            Code::PathLen => "path length constraint violated",
            Code::NameConstraints => "certificate not allowed by name constraints",
            Code::Eku => "certificate is not for server authentication",
            Code::BadSignature => "bad signature",
            Code::WrongHost => "certificate is not valid for this host",
            Code::NotYetValid => "certificate not yet valid",
            Code::Expired => "certificate expired",
            Code::TooComplex => "certificate path too complex",
        })
    }
}

/// At most this many intermediates on a path.
const MAX_INTERMEDIATES: usize = 6;
/// At most this many certificates in a chain. Each search step scans them all, so a long chain
/// of junk would make the step budget slow to spend. webpki has no such limit.
const MAX_CHAIN: usize = 64;

/// Check `chain` (DER certificates, the server's first, then whatever intermediates it sent in
/// any order) for `host` (a DNS name or an IP address literal) at `now` (seconds since the Unix
/// epoch). The server certificate's public key on success.
pub fn verify_server<'a>(chain: &[&'a [u8]], host: &str, now: u64, anchors: &[Anchor]) -> Result<PublicKey<'a>, Error> {
    verify_server_within(chain, host, now, anchors).map(|(key, _)| key)
}

/// `verify_server`, and the times (seconds since the Unix epoch) between which the path it found
/// holds: the latest notBefore and the earliest notAfter on it. Anchors carry no validity.
pub fn verify_server_within<'a>(
    chain: &[&'a [u8]],
    host: &str,
    now: u64,
    anchors: &[Anchor],
) -> Result<(PublicKey<'a>, (u64, u64)), Error> {
    let (&leaf_der, rest) = chain.split_first().ok_or(Error::from(Code::Encoding))?;
    if chain.len() > MAX_CHAIN {
        return Err(Code::TooComplex.into());
    }
    let leaf = cert::parse(leaf_der)?;
    let mut search = Search {
        certs: rest.iter().map(|der| cert::parse(der)).collect(),
        leaf: &leaf,
        anchors,
        now,
        path: [0; MAX_INTERMEDIATES],
        top: 0,
        signatures: 100,
        steps: 200_000,
        comparisons: 250_000,
    };
    search.build(0)?;
    name::check_host(leaf.san, &Host::new(host))?;
    let mut within = (0, u64::MAX);
    for i in 0..=search.top {
        let (from, until) = cert::check_validity(search.at(i).validity, now)?;
        within = (within.0.max(from), within.1.min(until));
    }
    Ok((cert::leaf_key(leaf.spki)?, within))
}

/// The server certificate's key, with nothing checked but that the certificate reads: for
/// `Config::insecure_skip_verify`.
pub fn leaf_key(der: &[u8]) -> Result<PublicKey<'_>, Error> {
    Ok(cert::leaf_key(cert::parse(der)?.spki)?)
}

/// Whether `signature` over `message` is `key`'s under `scheme`. A key and scheme that do not
/// go together (an EC key with an RSA scheme) are `false`.
pub fn verify_signature(key: &PublicKey, scheme: Scheme, message: &[u8], signature: &[u8]) -> bool {
    cert::verify(key, scheme, message, signature)
}

/// A depth-first search for a path from the leaf to an anchor. The budgets (signature checks,
/// search steps, name constraint comparisons) are webpki's; they bound the work a hostile
/// chain can cause.
struct Search<'s, 'a> {
    /// The intermediates offered, each parsed once.
    certs: Vec<Result<Cert<'a>, Code>>,
    leaf: &'s Cert<'a>,
    anchors: &'s [Anchor<'s>],
    now: u64,
    /// Indexes into `certs` of the intermediates on the path, leaf side first.
    path: [usize; MAX_INTERMEDIATES],
    /// The certificate on the path found that an anchor signed: 0 the leaf.
    top: usize,
    signatures: usize,
    steps: usize,
    comparisons: usize,
}

impl<'a> Search<'_, 'a> {
    /// The `i`th certificate on the path: 0 the leaf, then the intermediates.
    fn at(&self, i: usize) -> &Cert<'a> {
        match i {
            0 => self.leaf,
            _ => self.certs[self.path[i - 1]].as_ref().unwrap_or_else(|_| unreachable!()),
        }
    }

    /// Extend the path whose top is certificate `depth` (0 the leaf) to an anchor. The error is
    /// the most telling of those met on the way.
    fn build(&mut self, depth: usize) -> Result<(), Code> {
        let head = self.at(depth);
        // Each certificate on the path is checked on its own first (RFC 5280 section 6.1.3).
        // pathLenConstraint counts the intermediates below, the leaf not included.
        cert::check_validity(head.validity, self.now)?;
        cert::check_basic_constraints(head.basic_constraints, depth == 0, depth.saturating_sub(1))?;
        cert::check_eku(head.eku)?;
        let issuer = head.issuer;

        let mut err = Code::UnknownIssuer;

        // Anchors first: the shortest path wins.
        for anchor in self.anchors {
            if anchor.subject != issuer {
                continue;
            }
            match self.check_path(depth, anchor) {
                Ok(()) => {
                    self.top = depth;
                    return Ok(());
                }
                Err(e) => note(&mut err, e)?,
            }
        }

        for i in 0..self.certs.len() {
            let candidate = match &self.certs[i] {
                Ok(c) => c,
                Err(e) => {
                    note(&mut err, *e)?;
                    continue;
                }
            };
            // Issuer and subject names are compared byte for byte, as webpki does.
            if candidate.subject != issuer {
                continue;
            }
            // No certificate (by subject and key) twice on a path.
            if (0..=depth).any(|j| {
                let c = self.at(j);
                c.spki == candidate.spki && c.subject == candidate.subject
            }) {
                continue;
            }
            self.steps = self.steps.checked_sub(1).ok_or(Code::TooComplex)?;
            if depth == MAX_INTERMEDIATES {
                note(&mut err, Code::PathTooLong)?;
                continue;
            }
            self.path[depth] = i;
            match self.build(depth + 1) {
                Ok(()) => return Ok(()),
                Err(e) => note(&mut err, e)?,
            }
        }
        Err(err)
    }

    /// Check a complete path, certificates 0 to `top` then `anchor`: each signature, from the
    /// anchor down, then each issuer's name constraints over everything below it.
    fn check_path(&mut self, top: usize, anchor: &Anchor) -> Result<(), Code> {
        let mut spki = anchor.spki;
        for i in (0..=top).rev() {
            self.signatures = self.signatures.checked_sub(1).ok_or(Code::TooComplex)?;
            let c = self.at(i);
            cert::check_signature(spki, c)?;
            spki = c.spki;
        }
        let mut nc = anchor.name_constraints;
        let mut budget = self.comparisons;
        for i in (0..=top).rev() {
            if let Some(nc) = nc {
                let below = (0..=i).map(|j| self.at(j).san);
                let result = name::check_constraints(nc, below, &mut budget);
                self.comparisons = budget;
                result?;
            }
            nc = self.at(i).name_constraints;
        }
        Ok(())
    }
}

/// Keep the more telling of two errors; a spent budget ends the search.
fn note(err: &mut Code, e: Code) -> Result<(), Code> {
    if e == Code::TooComplex {
        return Err(e);
    }
    *err = (*err).max(e);
    Ok(())
}
