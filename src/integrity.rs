//! Subresource-integrity strings (`sha512-<base64>`): parse, hash and verify.

use jpm_crypto::hash::{Alg, Hasher};

use crate::error::{Error, Result};
use crate::util::{from_base64, from_hex, to_base64};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub algorithm: &'static str,
    /// Raw digest bytes.
    pub digest: Vec<u8>,
}

/// Strongest first: a packument may offer several and only the best is checked.
const ALGORITHMS: [(&str, usize); 4] = [("sha512", 64), ("sha384", 48), ("sha256", 32), ("sha1", 20)];

impl Integrity {
    pub fn parse(value: &str) -> Result<Self> {
        let mut best: Option<(usize, Self)> = None;
        for entry in value.split_whitespace() {
            let entry = entry.split('?').next().unwrap_or(entry);
            let Some((algo, b64)) = entry.split_once('-') else { continue };
            let Some(rank) = ALGORITHMS.iter().position(|(a, _)| *a == algo) else { continue };
            if !b64.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
                continue;
            }
            let raw = from_base64(b64);
            if raw.len() != ALGORITHMS[rank].1 {
                continue;
            }
            if best.as_ref().is_none_or(|(r, _)| rank < *r) {
                best = Some((rank, Self { algorithm: ALGORITHMS[rank].0, digest: raw }));
            }
        }
        best.map(|(_, i)| i).ok_or_else(|| {
            Error::new("EINTEGRITY", format!("Invalid integrity: no supported algorithm in \"{value}\""))
        })
    }

    /// Canonical text: one algorithm, padded base64.
    pub fn text(&self) -> String {
        format!("{}-{}", self.algorithm, to_base64(&self.digest))
    }

    pub fn hasher(&self) -> Hasher {
        Hasher::new(algorithm(self.algorithm))
    }

    /// Check a finished hash against this integrity.
    pub fn check(&self, actual: &[u8]) -> Result<()> {
        if actual == self.digest.as_slice() {
            return Ok(());
        }
        Err(Error::new(
            "EINTEGRITY",
            format!("Integrity check failed: expected {}, got {}-{}", self.text(), self.algorithm, to_base64(actual)),
        ))
    }
}

fn algorithm(name: &str) -> Alg {
    match name {
        "sha512" => Alg::Sha512,
        "sha384" => Alg::Sha384,
        "sha256" => Alg::Sha256,
        _ => Alg::Sha1,
    }
}

/// A legacy hex `dist.shasum` as `sha1-<base64>`.
pub fn from_shasum(shasum: &str) -> Result<String> {
    let hex = shasum.trim();
    match from_hex(hex) {
        Some(raw) if raw.len() == 20 => Ok(format!("sha1-{}", to_base64(&raw))),
        _ => Err(Error::new("EINTEGRITY", format!("Invalid shasum: expected 40 hex characters, got \"{shasum}\""))),
    }
}

/// `sha512-<base64>` of some bytes.
#[cfg(test)]
pub fn sha512(data: &[u8]) -> String {
    format!("sha512-{}", to_base64(&jpm_crypto::hash::digest(Alg::Sha512, data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_strongest() {
        let a = sha512(b"x");
        let both = format!("sha1-{} {a}", to_base64(&[0; 20]));
        assert_eq!(Integrity::parse(&both).unwrap().algorithm, "sha512");
        assert!(Integrity::parse("md5-abc").is_err());
        assert!(Integrity::parse("sha512-short").is_err());
    }

    #[test]
    fn verifies() {
        let i = Integrity::parse(&sha512(b"hello")).unwrap();
        let mut h = i.hasher();
        h.update(b"hel");
        h.update(b"lo");
        assert!(i.check(h.finish().as_ref()).is_ok());
        assert_eq!(i.check(&[0; 64]).unwrap_err().code, "EINTEGRITY");
    }

    #[test]
    fn converts_shasum() {
        let s = from_shasum("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert!(s.starts_with("sha1-"));
        assert!(from_shasum("xyz").is_err());
    }
}
