//! End to end over TLS: a registry whose certificate a private CA signed, as behind a
//! TLS-inspecting proxy or on an internal network, trusted through NODE_EXTRA_CA_CERTS or
//! .npmrc's `cafile` and `ca`; `strict-ssl=false`; and .npmrc's proxy settings. All of these are
//! the user's to set: a project's own .npmrc cannot, so a cloned repository cannot weaken them.
//! And HTTP/2, which the registry offers by ALPN, when `JPM_HTTP2` asks for it.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};

use common::{Env, Registry, pkg};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::json;

/// A CA certificate, as PEM, and the issuer to sign with.
fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap()
}

/// A registry over TLS for 127.0.0.1, its certificate signed by a private CA; and the CA's PEM.
fn tls_registry() -> (Registry, String) {
    let corp = ca("jpm test corp CA");
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = p.signed_by(&key, &corp).unwrap();
    let pkgs = vec![pkg("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })), pkg("b", "1.0.0", json!({}))];
    (common::start_tls(pkgs, vec![leaf.der().to_vec()], key.serialize_der()), corp.pem())
}

/// A scratch project that depends on `a`, with the CA's PEM in `corp.pem` beside it.
fn project(r: &Registry, corp: &str) -> (Env, PathBuf) {
    let env = Env::new(r);
    env.manifest(json!({ "name": "app", "dependencies": { "a": "1.0.0" } }));
    let pem = env.root.join("corp.pem");
    std::fs::write(&pem, corp).unwrap();
    (env, pem)
}

/// `jpm install`, with none of the user's own TLS, proxy or HTTP/2 settings.
fn install(env: &Env, vars: &[(&str, &str)]) -> Output {
    let mut c: Command = env.command(&["install"]);
    for v in [
        "NODE_EXTRA_CA_CERTS",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
        "JPM_HTTP2",
        "JPM_HTTP2_STREAMS",
    ] {
        c.env_remove(v);
    }
    c.envs(vars.iter().copied());
    c.output().unwrap()
}

#[track_caller]
fn installed(env: &Env, out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{err}");
    assert!(env.read("node_modules/a/index.js").contains("a@1.0.0"));
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.0.0"));
    err
}

#[track_caller]
fn failed(out: &Output, want: &str) -> String {
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "{err}");
    assert!(err.contains(want), "wanted {want:?} in:\n{err}");
    err
}

#[test]
fn trusts_a_private_ca() {
    let (r, corp) = tls_registry();

    // Mozilla's roots alone: refused, and not retried.
    let (env, pem) = project(&r, &corp);
    failed(&install(&env, &[]), "unknown issuer");
    assert_eq!(r.hits.lock().unwrap().len(), 0);

    // NODE_EXTRA_CA_CERTS adds the CA to Mozilla's roots.
    let extra = pem.to_str().unwrap();
    installed(&env, &install(&env, &[("NODE_EXTRA_CA_CERTS", extra)]));
    // So do the system's, read at the first connection: on Linux, SSL_CERT_FILE names them.
    if cfg!(target_os = "linux") {
        let (env, _) = project(&r, &corp);
        installed(&env, &install(&env, &[("SSL_CERT_FILE", extra)]));
    }

    // cafile in ~/.npmrc, by a full path, by a ~/ path, and relative to jpm's cwd.
    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\n", pem.display()));
    installed(&env, &install(&env, &[]));
    let (env, _) = project(&r, &corp);
    std::fs::write(env.root.join("home/corp.pem"), &corp).unwrap();
    std::fs::write(env.root.join("home/.npmrc"), "cafile=~/corp.pem\n").unwrap();
    installed(&env, &install(&env, &[]));
    let (env, _) = project(&r, &corp);
    env.write("certs/corp.pem", &corp);
    env.user_npmrc("cafile=certs/corp.pem\n");
    installed(&env, &install(&env, &[]));

    // ca in .npmrc, as npm writes it: one line, `\n` for the line breaks.
    let (env, _) = project(&r, &corp);
    let inline = corp.trim_end().replace("\r\n", "\n").replace('\n', "\\n");
    env.user_npmrc(&format!("ca=\"{inline}\"\n"));
    installed(&env, &install(&env, &[]));
    // In a list, with another CA.
    let (env, _) = project(&r, &corp);
    let other = ca("another CA").pem().trim_end().replace("\r\n", "\n").replace('\n', "\\n");
    env.user_npmrc(&format!("ca[]=\"{other}\"\nca[]=\"{inline}\"\n"));
    installed(&env, &install(&env, &[]));
}

/// `ca` and `cafile` replace the default roots, NODE_EXTRA_CA_CERTS's too, as they do in npm.
#[test]
fn ca_settings_replace_the_default_roots() {
    let (r, corp) = tls_registry();
    let (env, pem) = project(&r, &corp);
    std::fs::write(env.root.join("other.pem"), ca("another CA").pem()).unwrap();
    env.user_npmrc(&format!("cafile={}\n", env.root.join("other.pem").display()));
    failed(&install(&env, &[("NODE_EXTRA_CA_CERTS", pem.to_str().unwrap())]), "unknown issuer");
    // cafile wins over ca, as npm reads it last.
    let (env, _) = project(&r, &corp);
    let inline = corp.trim_end().replace('\n', "\\n");
    env.user_npmrc(&format!("ca=\"{inline}\"\ncafile={}\n", env.root.join("nothing.pem").display()));
    failed(&install(&env, &[]), "nothing.pem");
}

#[test]
fn names_a_bad_ca_file() {
    let (r, corp) = tls_registry();
    let (env, _) = project(&r, &corp);
    let missing = env.root.join("missing.pem");
    let err = failed(&install(&env, &[("NODE_EXTRA_CA_CERTS", missing.to_str().unwrap())]), "ECONFIG");
    assert!(err.contains(&format!("cannot read CA certificates from {}", missing.display())), "{err}");

    let junk = env.root.join("junk.pem");
    std::fs::write(&junk, "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n").unwrap();
    env.user_npmrc(&format!("cafile={}\n", junk.display()));
    failed(&install(&env, &[]), &format!("{}: certificate 1 is not base64", junk.display()));

    let cut = corp.replace("-----END CERTIFICATE-----", "");
    std::fs::write(&junk, cut).unwrap();
    failed(&install(&env, &[]), &format!("{}: certificate 1 has no END line", junk.display()));

    env.user_npmrc("ca=\"not a certificate\"\n");
    failed(&install(&env, &[]), "the ca setting: no PEM certificates");
    assert_eq!(r.hits.lock().unwrap().len(), 0, "nothing is fetched under a bad setting");
}

#[test]
fn strict_ssl_false_takes_any_certificate_and_says_so() {
    let (r, corp) = tls_registry();
    let (env, _) = project(&r, &corp);
    env.user_npmrc("strict-ssl=false\n");
    let err = installed(&env, &install(&env, &[]));
    assert!(err.contains("strict-ssl=false: certificates are not checked"), "{err}");
    // Every run says so, even one with nothing to fetch.
    let out = install(&env, &[]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("strict-ssl=false"));
    // A later layer turns the checks back on.
    let (env, _) = project(&r, &corp);
    env.user_npmrc("strict-ssl=false\n");
    failed(&install(&env, &[("npm_config_strict_ssl", "true")]), "unknown issuer");
    // The project's own .npmrc cannot turn them off, and says it was ignored.
    let (env, _) = project(&r, &corp);
    env.write(".npmrc", "strict-ssl=false\n");
    let err = failed(&install(&env, &[]), "unknown issuer");
    assert!(err.contains(".npmrc sets strict-ssl, which only ~/.npmrc"), "{err}");
}

/// An HTTP proxy on localhost that tunnels CONNECT requests; it records each target and the
/// credentials it was given.
fn connect_proxy() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(client.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut auth = String::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("proxy-authorization:") {
                        auth = format!(" {}", v.trim());
                    }
                }
                let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{target}{auth}"));
                let mut upstream = TcpStream::connect(&target).unwrap();
                (&client).write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
                let (mut down, mut back) = (upstream.try_clone().unwrap(), client.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut down, &mut back);
                    let _ = back.shutdown(std::net::Shutdown::Both);
                });
                let _ = std::io::copy(&mut reader, &mut upstream);
                let _ = upstream.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    (url, seen)
}

#[test]
fn npmrc_proxy_settings_win_over_the_environment() {
    let (r, corp) = tls_registry();
    let (proxy, seen) = connect_proxy();
    let target = r.url.trim_start_matches("https://").to_string();
    // A proxy nothing listens on: using it would fail.
    let dead = [("HTTPS_PROXY", "http://127.0.0.1:1"), ("NO_PROXY", "")];

    // https-proxy, with credentials in its url, over HTTPS_PROXY.
    let (env, pem) = project(&r, &corp);
    let with_user = proxy.replace("http://", "http://me%40corp:s3cret@");
    env.user_npmrc(&format!("cafile={}\nhttps-proxy={with_user}\n", pem.display()));
    installed(&env, &install(&env, &dead));
    let log = seen.lock().unwrap().clone();
    let basic = format!("basic {}", common::b64(b"me@corp:s3cret").to_ascii_lowercase());
    assert!(!log.is_empty() && log.iter().all(|l| *l == format!("{target} {basic}")), "{log:?}");

    // proxy alone serves https too, as in npm.
    seen.lock().unwrap().clear();
    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\nproxy={proxy}\n", pem.display()));
    installed(&env, &install(&env, &dead));
    assert!(seen.lock().unwrap().iter().all(|l| *l == target), "{:?}", seen.lock().unwrap());
    assert!(!seen.lock().unwrap().is_empty());

    // noproxy over NO_PROXY: straight to the registry, around a proxy from either place.
    seen.lock().unwrap().clear();
    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\nhttps-proxy=http://127.0.0.1:1\nnoproxy=127.0.0.1\n", pem.display()));
    installed(&env, &install(&env, &dead));
    assert!(seen.lock().unwrap().is_empty());

    // The environment's proxy when .npmrc names none.
    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\n", pem.display()));
    installed(&env, &install(&env, &[("HTTPS_PROXY", &proxy)]));
    assert!(!seen.lock().unwrap().is_empty());
}

/// HTTP/2 when `JPM_HTTP2` asks for it and the registry offers it: every request goes over it,
/// the registry's token with each, straight and through a proxy's tunnel. The certificate is
/// checked as over HTTP/1.1. Unset or `0`, nothing is HTTP/2.
#[test]
fn installs_over_http2_when_asked() {
    let (r, corp) = tls_registry();
    let host = r.url.trim_start_matches("https://").to_string();
    // Counts of requests, and of those over HTTP/2, since `from`.
    let since = |from: (usize, usize)| (r.requests.load(Relaxed) - from.0, r.h2.load(Relaxed) - from.1);
    let now = || (r.requests.load(Relaxed), r.h2.load(Relaxed));

    for vars in [&[][..], &[("JPM_HTTP2", "0")]] {
        let (env, pem) = project(&r, &corp);
        env.user_npmrc(&format!("cafile={}\n", pem.display()));
        installed(&env, &install(&env, vars));
    }
    assert_eq!(r.h2.load(Relaxed), 0);

    // An unknown CA is refused over HTTP/2 as over HTTP/1.1.
    let (env, _) = project(&r, &corp);
    let at = now();
    failed(&install(&env, &[("JPM_HTTP2", "1")]), "unknown issuer");
    assert_eq!(since(at), (0, 0));

    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\n//{host}/:_authToken=h2-token\n", pem.display()));
    r.hits.lock().unwrap().clear();
    let at = now();
    installed(&env, &install(&env, &[("JPM_HTTP2", "1")]));
    let (all, h2) = since(at);
    assert!(all >= 4 && h2 == all, "{h2} of {all} requests over HTTP/2");
    let hits = r.hits.lock().unwrap().clone();
    assert!(hits.iter().all(|h| h.ends_with(" authorization: Bearer h2-token")), "{hits:?}");

    // Through a proxy's CONNECT tunnel, on two connections.
    let (proxy, seen) = connect_proxy();
    let (env, pem) = project(&r, &corp);
    env.user_npmrc(&format!("cafile={}\nhttps-proxy={proxy}\n", pem.display()));
    let at = now();
    installed(&env, &install(&env, &[("JPM_HTTP2", "2"), ("JPM_HTTP2_STREAMS", "3")]));
    let (all, h2) = since(at);
    assert!(all >= 4 && h2 == all, "{h2} of {all} requests over HTTP/2");
    let tunnels = seen.lock().unwrap().clone();
    assert!(!tunnels.is_empty() && tunnels.len() <= 2 && tunnels.iter().all(|t| *t == host), "{tunnels:?}");
}

/// A proxy that terminates the TLS it is asked to tunnel, with a certificate `issuer` signed:
/// it records each request line and the credential sent with it.
fn intercepting_proxy(issuer: &CertifiedIssuer<'static, KeyPair>) -> (String, Arc<Mutex<Vec<String>>>) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let leaf = p.signed_by(&key, issuer).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let (log, config) = (log.clone(), config.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(client.try_clone().unwrap());
                let mut h = String::new();
                while reader.read_line(&mut h).unwrap_or(0) > 0 && h != "\r\n" {
                    h.clear();
                }
                (&client).write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
                let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), client);
                let mut r = BufReader::new(tls);
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let mut auth = String::new();
                let mut h = String::new();
                while r.read_line(&mut h).unwrap_or(0) > 0 && h != "\r\n" {
                    if h.to_ascii_lowercase().starts_with("authorization:") {
                        auth = h.trim_end().to_string();
                    }
                    h.clear();
                }
                log.lock().unwrap().push(format!("{} {auth}", line.trim_end()));
                let _ =
                    r.get_mut().write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            });
        }
    });
    (url, seen)
}

/// A cloned repository's .npmrc names a proxy that poses as the registry, trusted by
/// `strict-ssl=false` or by its own `ca`: ignored, so the user's token never reaches it.
#[test]
fn a_project_npmrc_cannot_route_the_users_token_to_its_proxy() {
    let (r, corp) = tls_registry();
    let attacker = ca("attacker CA");
    let (proxy, seen) = intercepting_proxy(&attacker);
    let pem = attacker.pem().trim_end().replace("\r\n", "\n").replace('\n', "\\n");
    for rc in [format!("strict-ssl=false\nhttps-proxy={proxy}\n"), format!("ca=\"{pem}\"\nproxy={proxy}\n")] {
        let (env, pem) = project(&r, &corp);
        let host = r.url.trim_start_matches("https://");
        env.user_npmrc(&format!("cafile={}\n//{host}/:_authToken=USER-SECRET\n", pem.display()));
        env.write(".npmrc", &rc);
        let err = installed(&env, &install(&env, &[]));
        assert!(err.contains("which only ~/.npmrc"), "{err}");
        assert!(seen.lock().unwrap().is_empty(), "{:?}", seen.lock().unwrap());
        assert!(r.hits.lock().unwrap().iter().any(|h| h.ends_with("Bearer USER-SECRET")));
    }
}

/// An https:// proxy is refused before anything is sent: jpm reaches proxies over http only,
/// and would otherwise send the proxy's credentials in plain text.
#[test]
fn refuses_an_https_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://me:secret@{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let (r, corp) = tls_registry();
    let (env, _) = project(&r, &corp);
    env.user_npmrc(&format!("https-proxy={url}\n"));
    failed(&install(&env, &[]), "https://, and jpm reaches a proxy over http:// only");
    assert!(listener.accept().is_err(), "nothing connected to the proxy");
    let (env, _) = project(&r, &corp);
    failed(&install(&env, &[("HTTPS_PROXY", &url)]), "jpm reaches a proxy over http:// only");
}
