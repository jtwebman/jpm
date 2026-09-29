//! What the interop and negative tests share: test certificates, a rustls server, a byte
//! proxy, and connect helpers with timeouts so that no test can hang.
#![allow(dead_code)]

pub mod fake;

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use jpm_tls::{Anchor, Config, Stream};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub const TIMEOUT: Duration = Duration::from_secs(20);

/// The leaf key types the tests run with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    P256,
    P384,
    Rsa2048,
    Rsa4096,
}

pub const KEY_TYPES: [KeyType; 4] = [KeyType::P256, KeyType::P384, KeyType::Rsa2048, KeyType::Rsa4096];

/// A root, an intermediate and a leaf for "localhost" and 127.0.0.1.
pub struct Pki {
    pub root: Vec<u8>,
    /// Leaf first, then the intermediate: what a server sends.
    pub chain: Vec<Vec<u8>>,
    /// The leaf's key as PKCS#8.
    pub key: Vec<u8>,
    pub key_type: KeyType,
}

impl Pki {
    pub fn anchor(&self) -> Anchor<'static> {
        anchor_of(Box::leak(self.root.clone().into_boxed_slice()))
    }

    pub fn config(&self, alpn: &[&[u8]]) -> Config {
        Config { roots: vec![self.anchor()], alpn: alpn.iter().map(|p| p.to_vec()).collect() }
    }

    pub fn rustls_chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.iter().map(|c| CertificateDer::from(c.clone())).collect()
    }

    pub fn rustls_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }
}

/// The certificates for a key type, made once per test binary.
pub fn pki(key_type: KeyType) -> &'static Pki {
    static CACHE: [OnceLock<Pki>; 4] = [const { OnceLock::new() }; 4];
    let i = KEY_TYPES.iter().position(|&k| k == key_type).unwrap();
    CACHE[i].get_or_init(|| make_pki(key_type, |_| {}))
}

/// A fresh set of certificates, the leaf's parameters adjusted by `leaf`.
pub fn make_pki(key_type: KeyType, leaf: impl FnOnce(&mut CertificateParams)) -> Pki {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "jpm-tls test root");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = CertifiedIssuer::self_signed(p, KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()).unwrap();

    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "jpm-tls test intermediate");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let inter_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let inter = CertifiedIssuer::signed_by(p, inter_key, &root).unwrap();

    let key = match key_type {
        KeyType::P256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        KeyType::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap(),
        KeyType::Rsa2048 => rsa_key("rsa2048.der"),
        KeyType::Rsa4096 => rsa_key("rsa4096.der"),
    };
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    p.distinguished_name.push(DnType::CommonName, "localhost");
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf(&mut p);
    let cert = p.signed_by(&key, &inter).unwrap();
    Pki {
        root: root.der().to_vec(),
        chain: vec![cert.der().to_vec(), inter.der().to_vec()],
        key: key.serialize_der(),
        key_type,
    }
}

/// An RSA key from jpm-crypto's test data (PKCS#1 RSAPrivateKey), wrapped as PKCS#8.
fn rsa_key(name: &str) -> KeyPair {
    let path = format!("{}/../pk/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    let pkcs1 = std::fs::read(path).unwrap();
    // PrivateKeyInfo { version 0, AlgorithmIdentifier { rsaEncryption, NULL }, OCTET STRING }
    let alg = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(&alg);
    body.extend(der_tlv(0x04, &pkcs1));
    let pkcs8 = der_tlv(0x30, &body);
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &rcgen::PKCS_RSA_SHA256).unwrap()
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = value.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(value);
    out
}

/// One DER value: `(tag, contents, rest)`.
fn der_read(d: &[u8]) -> (u8, &[u8], &[u8]) {
    let (len, hdr) = match d[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let k = usize::from(n & 0x7f);
            (d[2..2 + k].iter().fold(0, |a, &b| a << 8 | usize::from(b)), 2 + k)
        }
    };
    (d[0], &d[hdr..hdr + len], &d[hdr + len..])
}

/// A trust anchor from a root certificate, the way webpki-roots lists them: the contents of
/// the subject Name and of the SubjectPublicKeyInfo, without their outer tags.
pub fn anchor_of(cert: &'static [u8]) -> Anchor<'static> {
    let (_, cert, _) = der_read(cert);
    let (_, tbs, _) = der_read(cert);
    let mut rest = tbs;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (tag, value, r) = der_read(rest);
        fields.push((tag, value));
        rest = r;
    }
    // [0] version, serial, signature, issuer, validity, subject, subjectPublicKeyInfo.
    let skip = usize::from(fields[0].0 == 0xa0);
    Anchor { subject: fields[skip + 4].1, spki: fields[skip + 5].1, name_constraints: None }
}

/// A connected pair of loopback sockets, both with timeouts.
///
/// One listener serves every pair: a listener per pair would take a port each, held for a
/// minute in TIME_WAIT, and the fuzz tests make thousands. Connecting sockets can reuse ports
/// in TIME_WAIT on loopback (Linux's default tcp_tw_reuse = 2).
pub fn pair() -> (TcpStream, TcpStream) {
    static LISTENER: OnceLock<std::sync::Mutex<TcpListener>> = OnceLock::new();
    let l = LISTENER.get_or_init(|| std::sync::Mutex::new(TcpListener::bind("127.0.0.1:0").unwrap()));
    let l = l.lock().unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    drop(l);
    for s in [&a, &b] {
        s.set_read_timeout(Some(TIMEOUT)).unwrap();
        s.set_write_timeout(Some(TIMEOUT)).unwrap();
        s.set_nodelay(true).unwrap();
    }
    (a, b)
}

/// A server thread on one end of a fresh pair; the client end is returned.
pub fn serve<T: Send + 'static>(f: impl FnOnce(TcpStream) -> T + Send + 'static) -> (TcpStream, thread::JoinHandle<T>) {
    let (client, server) = pair();
    (client, thread::spawn(move || f(server)))
}

/// rustls's server settings for one version, AEAD and group.
#[derive(Clone, Debug)]
pub struct ServerOpts {
    pub tls13: bool,
    /// 0 AES-128-GCM, 1 AES-256-GCM, 2 ChaCha20-Poly1305.
    pub aead: usize,
    pub groups: Vec<&'static str>,
    pub alpn: Vec<Vec<u8>>,
    pub max_fragment: Option<usize>,
}

impl Default for ServerOpts {
    fn default() -> Self {
        Self { tls13: true, aead: 0, groups: vec!["x25519"], alpn: Vec::new(), max_fragment: None }
    }
}

pub fn rustls_server_config(pki: &Pki, o: &ServerOpts) -> Arc<rustls::ServerConfig> {
    use rustls::crypto::ring::{cipher_suite as cs, default_provider, kx_group};
    let suites = match (o.tls13, o.aead) {
        (true, 0) => vec![cs::TLS13_AES_128_GCM_SHA256],
        (true, 1) => vec![cs::TLS13_AES_256_GCM_SHA384],
        (true, _) => vec![cs::TLS13_CHACHA20_POLY1305_SHA256],
        (false, 0) => vec![cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        (false, 1) => vec![cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
        (false, _) => {
            vec![cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
        }
    };
    let kx_groups = o
        .groups
        .iter()
        .map(|g| match *g {
            "x25519" => kx_group::X25519,
            "secp256r1" => kx_group::SECP256R1,
            "secp384r1" => kx_group::SECP384R1,
            _ => panic!("{g}"),
        })
        .collect();
    let provider = rustls::crypto::CryptoProvider { cipher_suites: suites, kx_groups, ..default_provider() };
    let version = if o.tls13 { &rustls::version::TLS13 } else { &rustls::version::TLS12 };
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.rustls_chain(), pki.rustls_key())
        .unwrap();
    c.alpn_protocols = o.alpn.clone();
    c.max_fragment_size = o.max_fragment;
    Arc::new(c)
}

pub type RustlsStream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// A rustls server on the other end of the returned socket, running `f` once connected.
pub fn rustls_server<T: Send + 'static>(
    config: Arc<rustls::ServerConfig>,
    f: impl FnOnce(&mut RustlsStream) -> T + Send + 'static,
) -> (TcpStream, thread::JoinHandle<T>) {
    serve(move |tcp| {
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut s = rustls::StreamOwned::new(conn, tcp);
        f(&mut s)
    })
}

/// Our client over `tcp`.
pub fn connect(tcp: TcpStream, host: &str, config: &Config) -> io::Result<Stream<TcpStream>> {
    Stream::connect(tcp, host, config)
}

/// Deterministic test data.
pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).rotate_right(13) as u8 ^ seed).collect()
}

/// A proxy between our client and a server: bytes from the server pass through `edit` (given
/// the stream offset of each chunk) on their way to the client. Returns the client's socket.
pub fn proxy(server: TcpStream, mut edit: impl FnMut(usize, &mut Vec<u8>) -> bool + Send + 'static) -> TcpStream {
    let (client, mine) = pair();
    let (mut up_in, mut up_out) = (mine.try_clone().unwrap(), server.try_clone().unwrap());
    thread::spawn(move || {
        let _ = io::copy(&mut up_in, &mut up_out);
        let _ = up_out.shutdown(std::net::Shutdown::Write);
    });
    let (mut down_in, mut down_out) = (server, mine);
    thread::spawn(move || {
        let mut at = 0;
        let mut buf = vec![0; 65536];
        loop {
            let n = match down_in.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut chunk = buf[..n].to_vec();
            let go_on = edit(at, &mut chunk);
            at += n;
            if down_out.write_all(&chunk).is_err() || !go_on {
                break;
            }
        }
        let _ = down_out.shutdown(std::net::Shutdown::Both);
    });
    client
}

/// The error's message, or a panic if there was none.
pub fn err_msg<T>(r: io::Result<T>) -> String {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}
