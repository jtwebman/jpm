//! Shared by the certificate tests: webpki as the reference, certificate generation with
//! rcgen, a DER writer for hand-made certificates, and a small random generator.
#![allow(dead_code)]

use std::time::Duration;

use jpm_tls::der::Reader;
use jpm_tls::x509::{self, Anchor};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SigningKey,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};

/// 2030-01-01T00:00:00Z, inside every generated certificate's validity.
pub const NOW: u64 = 1_893_456_000;

/// What rustls with the ring provider accepts, less Ed25519, which jpm-tls does not support.
pub static ALGS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
];

pub fn anchor<'a>(ta: &'a TrustAnchor) -> Anchor<'a> {
    Anchor {
        subject: ta.subject.as_ref(),
        spki: ta.subject_public_key_info.as_ref(),
        name_constraints: ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
    }
}

/// A trust anchor from a root certificate, as webpki makes one.
pub fn trust(root: &[u8]) -> TrustAnchor<'static> {
    webpki::anchor_from_trusted_cert(&CertificateDer::from(root)).unwrap().to_owned()
}

pub fn ours(chain: &[&[u8]], host: &str, now: u64, anchors: &[TrustAnchor]) -> Result<(), &'static str> {
    let anchors: Vec<_> = anchors.iter().map(anchor).collect();
    x509::verify_server(chain, host, now, &anchors).map(|_| ()).map_err(|e| e.0)
}

/// What rustls's WebPkiServerVerifier would decide: the path, then the name.
pub fn theirs(chain: &[&[u8]], host: &str, now: u64, anchors: &[TrustAnchor]) -> Result<(), webpki::Error> {
    let first = chain.first().ok_or(webpki::Error::BadDer)?;
    let leaf_der = CertificateDer::from(*first);
    let leaf = EndEntityCert::try_from(&leaf_der)?;
    let rest: Vec<_> = chain[1..].iter().map(|c| CertificateDer::from(*c)).collect();
    let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
    leaf.verify_for_usage(ALGS, anchors, &rest, time, KeyUsage::server_auth(), None, None)?;
    // webpki takes IPv6 without brackets.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    let host = bare.filter(|h| h.parse::<std::net::Ipv6Addr>().is_ok()).unwrap_or(host);
    let name = ServerName::try_from(host).map_err(|_| webpki::Error::UnsupportedNameType)?;
    leaf.verify_is_valid_for_subject_name(&name)
}

/// Why the two may disagree on one input, when they do.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Allowed {
    /// Nothing: they must agree.
    None,
    /// The leaf's own key was changed: webpki never reads it while checking the path, but
    /// verify_server returns it and so refuses one it cannot use.
    LeafKey,
}

/// Run both and compare. Returns ours. Every difference is either one of the intentional ones
/// (see `difference`) or a failure.
pub fn check(chain: &[&[u8]], host: &str, now: u64, anchors: &[TrustAnchor]) -> Result<(), &'static str> {
    check_allowing(chain, host, now, anchors, Allowed::None)
}

pub fn check_allowing(
    chain: &[&[u8]],
    host: &str,
    now: u64,
    anchors: &[TrustAnchor],
    allowed: Allowed,
) -> Result<(), &'static str> {
    let a = ours(chain, host, now, anchors);
    let b = theirs(chain, host, now, anchors);
    if a.is_ok() != b.is_ok() {
        let why = difference(chain, a, &b, allowed);
        assert!(
            why.is_some(),
            "jpm-tls {a:?} but webpki {b:?} for host {host} at {now}\nchain: {}",
            chain.iter().map(|c| hex(c)).collect::<Vec<_>>().join(" ")
        );
    }
    a
}

/// The intentional differences from webpki, each with its reason. `None` when a difference is
/// not one of these.
pub fn difference(
    chain: &[&[u8]],
    ours: Result<(), &'static str>,
    theirs: &Result<(), webpki::Error>,
    allowed: Allowed,
) -> Option<&'static str> {
    match (ours, theirs) {
        // 1. verify_server returns the leaf's key for the handshake, so a leaf whose key type is
        //    not supported (Ed25519, P-521, RSA-PSS keys, a malformed key) is refused at once.
        //    webpki leaves that to the handshake signature, which then fails the same way.
        (Err("unsupported certificate"), Ok(())) if !leaf_key_supported(chain[0]) => Some("leaf key type"),
        (Err("unsupported certificate" | "invalid certificate encoding"), Ok(())) if allowed == Allowed::LeafKey => {
            Some("leaf key")
        }
        // 2. ecdsa-with-SHA512 is accepted (webpki's aws-lc-rs backend accepts it too; its
        //    ring backend, the reference here, does not).
        (Ok(()), Err(e))
            if format!("{e:?}").starts_with("UnsupportedSignatureAlgorithm") && uses_ecdsa_sha512(chain) =>
        {
            Some("ecdsa-with-SHA512")
        }
        // 3. A chain of more than 64 certificates is refused before any search, so junk
        //    cannot make the search slow. webpki has no such limit.
        (Err("certificate path too complex"), Ok(())) if chain.len() > 64 => Some("chain length"),
        _ => None,
    }
}

fn uses_ecdsa_sha512(chain: &[&[u8]]) -> bool {
    let oid = [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 4];
    chain.iter().any(|c| c.windows(oid.len()).any(|w| w == oid))
}

/// Whether the certificate's SubjectPublicKeyInfo names an algorithm jpm-tls supports.
pub fn leaf_key_supported(cert: &[u8]) -> bool {
    let Some(spki) = spki(cert) else { return true };
    let mut r = Reader::new(spki);
    let alg = r.expect(0x30).unwrap_or_default();
    [
        &hex_bytes("06092a864886f70d0101010500")[..],
        &hex_bytes("06072a8648ce3d020106082a8648ce3d030107"),
        &hex_bytes("06072a8648ce3d020106052b81040022"),
    ]
    .contains(&alg)
}

/// The contents of a certificate's SubjectPublicKeyInfo SEQUENCE, if it gets that far.
pub fn spki(cert: &[u8]) -> Option<&[u8]> {
    let fields = tbs_fields(cert)?;
    fields.get(6).map(|f| f.1)
}

/// A TLV as (tag, contents, whole encoding).
pub type Field<'a> = (u8, &'a [u8], &'a [u8]);

/// The TBSCertificate's fields.
pub fn tbs_fields(cert: &[u8]) -> Option<Vec<Field<'_>>> {
    let mut r = Reader::new(Reader::new(cert).expect(0x30)?);
    let mut t = Reader::new(r.expect(0x30)?);
    let mut out = Vec::new();
    while !t.is_empty() {
        let before = t.rest();
        let (tag, v) = t.read()?;
        out.push((tag, v, &before[..before.len() - t.rest().len()]));
    }
    Some(out)
}

/// The byte range of `inner` within `outer`.
pub fn range_of(outer: &[u8], inner: &[u8]) -> std::ops::Range<usize> {
    let start = inner.as_ptr() as usize - outer.as_ptr() as usize;
    start..start + inner.len()
}

// DER writing.

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend(&bytes[skip..]);
    }
    out.extend(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A certificate with its TBS fields rewritten by `edit` (over each field's whole encoding)
/// and signed again with `signer`, keeping the signature algorithm.
pub fn resign(cert: &[u8], signer: &KeyPair, edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
    let mut fields: Vec<Vec<u8>> = tbs_fields(cert).unwrap().iter().map(|f| f.2.to_vec()).collect();
    edit(&mut fields);
    let alg = fields[2].clone();
    let tbs = tlv(0x30, &fields.concat());
    let sig = signer.sign(&tbs).unwrap();
    seq(&[&tbs, &alg, &tlv(3, &[&[0][..], &sig].concat())])
}

/// Like `resign`, but with any signature algorithm (its AlgorithmIdentifier's whole encoding)
/// and signing function.
pub fn resign_with(cert: &[u8], alg: &[u8], sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut fields: Vec<Vec<u8>> = tbs_fields(cert).unwrap().iter().map(|f| f.2.to_vec()).collect();
    fields[2] = alg.to_vec();
    let tbs = tlv(0x30, &fields.concat());
    let sig = sign(&tbs);
    seq(&[&tbs, alg, &tlv(3, &[&[0][..], &sig].concat())])
}

/// Replace the extensions ([3]) with these whole Extension encodings.
pub fn set_extensions(fields: &mut Vec<Vec<u8>>, exts: &[Vec<u8>]) {
    fields.retain(|f| f[0] != 0xa3);
    fields.push(tlv(0xa3, &seq(&exts.iter().map(|e| &e[..]).collect::<Vec<_>>())));
}

/// A certificate's extensions, whole encodings.
pub fn extensions(cert: &[u8]) -> Vec<Vec<u8>> {
    let fields = tbs_fields(cert).unwrap();
    let Some(f) = fields.iter().find(|f| f.0 == 0xa3) else { return vec![] };
    let mut r = Reader::new(Reader::new(f.1).expect(0x30).unwrap());
    let mut out = Vec::new();
    while !r.is_empty() {
        let before = r.rest();
        r.read().unwrap();
        out.push(before[..before.len() - r.rest().len()].to_vec());
    }
    out
}

pub fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { tlv(1, &[0xff]) } else { vec![] };
    seq(&[&tlv(6, oid), &crit, &tlv(4, value)])
}

// Keys and certificates.

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    P256,
    P384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed25519,
}

pub const KINDS: [Kind; 5] = [Kind::P256, Kind::P384, Kind::Rsa2048, Kind::Rsa3072, Kind::Rsa4096];

/// The RSA test keys of jpm-crypto, as PKCS#8.
pub fn rsa_pkcs8(bits: u32) -> Vec<u8> {
    let path = format!("{}/../pk/tests/data/rsa{bits}.der", env!("CARGO_MANIFEST_DIR"));
    let rsa = std::fs::read(path).unwrap();
    let alg = hex_bytes("300d06092a864886f70d0101010500");
    seq(&[&[2, 1, 0], &alg, &tlv(4, &rsa)])
}

pub fn key(kind: Kind) -> KeyPair {
    let rsa = |bits| {
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rsa_pkcs8(bits)));
        KeyPair::from_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA256).unwrap()
    };
    match kind {
        Kind::P256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        Kind::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap(),
        Kind::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
        Kind::Rsa2048 => rsa(2048),
        Kind::Rsa3072 => rsa(3072),
        Kind::Rsa4096 => rsa(4096),
    }
}

/// 2020-01-01 to 2040-01-01.
pub fn validity(params: &mut CertificateParams) {
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);
}

pub fn ca_params(name: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut p);
    p
}

pub fn leaf_params(names: &[&str]) -> CertificateParams {
    let mut p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name = DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, "leaf");
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    validity(&mut p);
    p
}

/// A certificate and what it takes to sign with it.
pub struct Node {
    pub params: CertificateParams,
    pub key: KeyPair,
    pub der: Vec<u8>,
}

impl Node {
    pub fn root(params: CertificateParams, kind: Kind) -> Node {
        let key = key(kind);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        Node { params, key, der }
    }

    /// A certificate for `params` and a new key of `kind`, signed by `self`.
    pub fn sign(&self, params: CertificateParams, kind: Kind) -> Node {
        self.sign_key(params, key(kind))
    }

    pub fn sign_key(&self, params: CertificateParams, key: KeyPair) -> Node {
        let issuer = Issuer::from_params(&self.params, &self.key);
        let der = params.signed_by(&key, &issuer).unwrap().der().to_vec();
        Node { params, key, der }
    }

    pub fn anchor(&self) -> TrustAnchor<'static> {
        trust(&self.der)
    }
}

/// A root, `n` intermediates and a leaf for `names`, keys of the kinds given in turn.
pub struct Chain {
    pub root: Node,
    pub inters: Vec<Node>,
    pub leaf: Node,
}

impl Chain {
    pub fn new(n: usize, names: &[&str], kinds: &[Kind]) -> Chain {
        Chain::custom(n, names, kinds, |_, _| {})
    }

    /// Like `new`, with `edit` changing each certificate's parameters first: level 0 is the
    /// root, 1 to `n` the intermediates from the root down, `n + 1` the leaf.
    pub fn custom(n: usize, names: &[&str], kinds: &[Kind], edit: impl Fn(usize, &mut CertificateParams)) -> Chain {
        let kind = |i: usize| kinds[i % kinds.len()];
        let mut params = ca_params("root");
        edit(0, &mut params);
        let root = Node::root(params, kind(0));
        let mut inters: Vec<Node> = Vec::new();
        for i in 0..n {
            let issuer = inters.last().unwrap_or(&root);
            let mut params = ca_params(&format!("intermediate {i}"));
            edit(i + 1, &mut params);
            let node = issuer.sign(params, kind(i + 1));
            inters.push(node);
        }
        let mut params = leaf_params(names);
        edit(n + 1, &mut params);
        let leaf = inters.last().unwrap_or(&root).sign(params, kind(n + 1));
        Chain { root, inters, leaf }
    }

    /// Leaf first, then the intermediates from the leaf up.
    pub fn ders(&self) -> Vec<&[u8]> {
        let mut v = vec![&self.leaf.der[..]];
        v.extend(self.inters.iter().rev().map(|n| &n.der[..]));
        v
    }

    pub fn anchors(&self) -> Vec<TrustAnchor<'static>> {
        vec![self.root.anchor()]
    }
}

/// xorshift64*, for reproducible randomized tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i + 1));
        }
    }
}

/// PEM certificates, in order.
pub fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes()).map(|c| c.unwrap().to_vec()).collect()
}
