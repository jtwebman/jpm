//! End to end over TLS: a registry whose certificate a private CA signed, as behind a
//! TLS-inspecting proxy or on an internal network, trusted through NODE_EXTRA_CA_CERTS or
//! .npmrc's `cafile` and `ca`; `strict-ssl=false`; and .npmrc's proxy settings.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
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

/// `jpm install`, with none of the user's own TLS or proxy settings.
fn install(env: &Env, vars: &[(&str, &str)]) -> Output {
    let mut c: Command = env.command(&["install"]);
    for v in ["NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"] {
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

    // cafile in .npmrc, from the project, from ~/.npmrc by a ~/ path, and relative to jpm's cwd.
    let (env, pem) = project(&r, &corp);
    env.write(".npmrc", &format!("cafile={}\n", pem.display()));
    installed(&env, &install(&env, &[]));
    let (env, _) = project(&r, &corp);
    std::fs::write(env.root.join("home/corp.pem"), &corp).unwrap();
    std::fs::write(env.root.join("home/.npmrc"), "cafile=~/corp.pem\n").unwrap();
    installed(&env, &install(&env, &[]));
    let (env, _) = project(&r, &corp);
    env.write("certs/corp.pem", &corp);
    env.write(".npmrc", "cafile=certs/corp.pem\n");
    installed(&env, &install(&env, &[]));

    // ca in .npmrc, as npm writes it: one line, `\n` for the line breaks.
    let (env, _) = project(&r, &corp);
    let inline = corp.trim_end().replace("\r\n", "\n").replace('\n', "\\n");
    env.write(".npmrc", &format!("ca=\"{inline}\"\n"));
    installed(&env, &install(&env, &[]));
    // In a list, with another CA.
    let (env, _) = project(&r, &corp);
    let other = ca("another CA").pem().trim_end().replace("\r\n", "\n").replace('\n', "\\n");
    env.write(".npmrc", &format!("ca[]=\"{other}\"\nca[]=\"{inline}\"\n"));
    installed(&env, &install(&env, &[]));
}

/// `ca` and `cafile` replace the default roots, NODE_EXTRA_CA_CERTS's too, as they do in npm.
#[test]
fn ca_settings_replace_the_default_roots() {
    let (r, corp) = tls_registry();
    let (env, pem) = project(&r, &corp);
    std::fs::write(env.root.join("other.pem"), ca("another CA").pem()).unwrap();
    env.write(".npmrc", &format!("cafile={}\n", env.root.join("other.pem").display()));
    failed(&install(&env, &[("NODE_EXTRA_CA_CERTS", pem.to_str().unwrap())]), "unknown issuer");
    // cafile wins over ca, as npm reads it last.
    let (env, _) = project(&r, &corp);
    let inline = corp.trim_end().replace('\n', "\\n");
    env.write(".npmrc", &format!("ca=\"{inline}\"\ncafile={}\n", env.root.join("nothing.pem").display()));
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
    env.write(".npmrc", &format!("cafile={}\n", junk.display()));
    failed(&install(&env, &[]), &format!("{}: certificate 1 is not base64", junk.display()));

    let cut = corp.replace("-----END CERTIFICATE-----", "");
    std::fs::write(&junk, cut).unwrap();
    failed(&install(&env, &[]), &format!("{}: certificate 1 has no END line", junk.display()));

    env.write(".npmrc", "ca=\"not a certificate\"\n");
    failed(&install(&env, &[]), "the ca setting: no PEM certificates");
    assert_eq!(r.hits.lock().unwrap().len(), 0, "nothing is fetched under a bad setting");
}

#[test]
fn strict_ssl_false_takes_any_certificate_and_says_so() {
    let (r, corp) = tls_registry();
    let (env, _) = project(&r, &corp);
    env.write(".npmrc", "strict-ssl=false\n");
    let err = installed(&env, &install(&env, &[]));
    assert!(err.contains("strict-ssl=false: certificates are not checked"), "{err}");
    // Every run says so, even one with nothing to fetch.
    let out = install(&env, &[]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("strict-ssl=false"));
    // A later layer turns the checks back on.
    let (env, _) = project(&r, &corp);
    env.write(".npmrc", "strict-ssl=false\n");
    failed(&install(&env, &[("npm_config_strict_ssl", "true")]), "unknown issuer");
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
    env.write(".npmrc", &format!("cafile={}\nhttps-proxy={with_user}\n", pem.display()));
    installed(&env, &install(&env, &dead));
    let log = seen.lock().unwrap().clone();
    let basic = format!("basic {}", common::b64(b"me@corp:s3cret").to_ascii_lowercase());
    assert!(!log.is_empty() && log.iter().all(|l| *l == format!("{target} {basic}")), "{log:?}");

    // proxy alone serves https too, as in npm.
    seen.lock().unwrap().clear();
    let (env, pem) = project(&r, &corp);
    env.write(".npmrc", &format!("cafile={}\nproxy={proxy}\n", pem.display()));
    installed(&env, &install(&env, &dead));
    assert!(seen.lock().unwrap().iter().all(|l| *l == target), "{:?}", seen.lock().unwrap());
    assert!(!seen.lock().unwrap().is_empty());

    // noproxy over NO_PROXY: straight to the registry, around a proxy from either place.
    seen.lock().unwrap().clear();
    let (env, pem) = project(&r, &corp);
    env.write(".npmrc", &format!("cafile={}\nhttps-proxy=http://127.0.0.1:1\nnoproxy=127.0.0.1\n", pem.display()));
    installed(&env, &install(&env, &dead));
    assert!(seen.lock().unwrap().is_empty());

    // The environment's proxy when .npmrc names none.
    let (env, pem) = project(&r, &corp);
    env.write(".npmrc", &format!("cafile={}\n", pem.display()));
    installed(&env, &install(&env, &[("HTTPS_PROXY", &proxy)]));
    assert!(!seen.lock().unwrap().is_empty());
}
