//! A registry on localhost for end-to-end tests: packuments, per-version manifests and
//! tarballs made in memory, served over HTTP/1.1 with keep-alive (and over TLS, HTTP/2 when the
//! client asks for it by ALPN), plus helpers to run jpm against it with a private store and home.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

/// One version of a package on the fake registry.
#[derive(Clone)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    /// Extra manifest fields: dependencies, bin, os, peerDependencies…
    pub manifest: Value,
    /// Files besides package.json, as (path, mode, content).
    pub files: Vec<(String, u32, Vec<u8>)>,
}

pub fn pkg(name: &str, version: &str, manifest: Value) -> Pkg {
    Pkg {
        name: name.into(),
        version: version.into(),
        manifest,
        files: vec![("index.js".into(), 0o644, format!("module.exports = '{name}@{version}'").into_bytes())],
    }
}

impl Pkg {
    pub fn file(mut self, path: &str, mode: u32, content: &str) -> Self {
        self.files.push((path.into(), mode, content.as_bytes().to_vec()));
        self
    }

    fn package_json(&self) -> Value {
        let mut m = self.manifest.clone();
        m["name"] = json!(self.name);
        m["version"] = json!(self.version);
        m
    }

    pub fn tarball(&self) -> Vec<u8> {
        let mut entries: Vec<(String, u32, Vec<u8>)> =
            vec![("package/package.json".into(), 0o644, serde_json::to_vec(&self.package_json()).unwrap())];
        for (p, m, c) in &self.files {
            entries.push((format!("package/{p}"), *m, c.clone()));
        }
        gzip(&tar(&entries))
    }
}

/// A ustar header for a regular file of `size` bytes.
pub fn tar_header(path: &str, mode: u32, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..path.len()].copy_from_slice(path.as_bytes());
    h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
    h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    h
}

pub fn tar(entries: &[(String, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, mode, data) in entries {
        out.extend_from_slice(&tar_header(path, *mode, data.len()));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0; 1024]);
    out
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn sha512(data: &[u8]) -> String {
    let d = jpm_crypto::hash::digest(jpm_crypto::hash::Alg::Sha512, data);
    format!("sha512-{}", b64(d.as_ref()))
}

pub fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct Registry {
    pub url: String,
    pkgs: Arc<Mutex<Vec<Pkg>>>,
    /// Other paths it answers, such as a git host's archives: path -> body.
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    /// Requests served, by path.
    pub hits: Arc<Mutex<Vec<String>>>,
    pub requests: Arc<AtomicUsize>,
    /// Milliseconds each tarball takes to start.
    delay: Arc<AtomicUsize>,
    /// Milliseconds a package's documents take to start, by name.
    slow: Arc<Mutex<BTreeMap<String, u64>>>,
    /// Tarball requests: how many to answer 503 still, as a registry asking for fewer at a time
    /// does, and how many are answered at once (see `Flight`).
    busy: Arc<AtomicUsize>,
    flight: Arc<Flight>,
    /// Requests served over HTTP/2.
    pub h2: Arc<AtomicUsize>,
}

/// Tarball requests in flight at once, counting only those from the `from`th on (0 is the first):
/// how many there are now, and the most there were.
#[derive(Default)]
pub struct Flight {
    seen: AtomicUsize,
    from: AtomicUsize,
    now: AtomicUsize,
    most: AtomicUsize,
}

impl Registry {
    pub fn start(pkgs: Vec<Pkg>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let pkgs = Arc::new(Mutex::new(pkgs));
        let files = Arc::new(Mutex::new(BTreeMap::new()));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(AtomicUsize::new(0));
        let delay = Arc::new(AtomicUsize::new(0));
        let slow = Arc::new(Mutex::new(BTreeMap::new()));
        let (busy, flight) = (Arc::new(AtomicUsize::new(0)), Arc::new(Flight::default()));
        let server = Server {
            pkgs: pkgs.clone(),
            files: files.clone(),
            hits: hits.clone(),
            requests: requests.clone(),
            base: url.clone(),
            delay: delay.clone(),
            slow: slow.clone(),
            busy: busy.clone(),
            flight: flight.clone(),
        };
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let server = server.clone();
                std::thread::spawn(move || serve(stream, &server));
            }
        });
        Self { url, pkgs, files, hits, requests, delay, slow, busy, flight, h2: Arc::default() }
    }

    /// The next `n` tarball requests are answered 503 at once.
    pub fn busy_tarballs(&self, n: usize) {
        self.busy.store(n, Ordering::Relaxed);
    }

    /// From now on, counts the tarball requests in flight at once from the `from`th on.
    pub fn count_flight(&self, from: usize) {
        let f = &self.flight;
        for n in [&f.seen, &f.now, &f.most] {
            n.store(0, Ordering::Relaxed);
        }
        f.from.store(from, Ordering::Relaxed);
    }

    /// The most tarball requests counted that were in flight at once.
    pub fn most_in_flight(&self) -> usize {
        self.flight.most.load(Ordering::Relaxed)
    }

    /// Every tarball from now on starts `ms` late: downloads outlast the plan.
    pub fn slow_tarballs(&self, ms: usize) {
        self.delay.store(ms, Ordering::Relaxed);
    }

    /// From now on each of these packages' documents starts `ms` late, and every other one
    /// on time: the walk sees them arrive in the order the test picks.
    pub fn slow_documents(&self, names: &[&str], ms: u64) {
        let mut slow = self.slow.lock().unwrap();
        slow.clear();
        slow.extend(names.iter().map(|n| (format!("/{}", n.replace('/', "%2f")), ms)));
    }

    /// Answers `path` with `body` from now on.
    pub fn serve(&self, path: &str, body: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_string(), body);
    }

    /// Adds a version, or replaces one already published.
    pub fn publish(&self, p: Pkg) {
        let mut pkgs = self.pkgs.lock().unwrap();
        pkgs.retain(|old| (&old.name, &old.version) != (&p.name, &p.version));
        pkgs.push(p);
    }
}

/// A registry over TLS on 127.0.0.1, with the certificate chain (leaf first) and PKCS#8 key.
pub fn start_tls(pkgs: Vec<Pkg>, chain: Vec<Vec<u8>>, key: Vec<u8>) -> Registry {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            chain.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let server = Server {
        pkgs: Arc::new(Mutex::new(pkgs)),
        files: Arc::default(),
        hits: Arc::default(),
        requests: Arc::default(),
        base: url.clone(),
        delay: Arc::default(),
        slow: Arc::default(),
        busy: Arc::default(),
        flight: Arc::default(),
    };
    let h2 = Arc::new(AtomicUsize::new(0));
    let registry = Registry {
        url,
        pkgs: server.pkgs.clone(),
        files: server.files.clone(),
        hits: server.hits.clone(),
        requests: server.requests.clone(),
        delay: server.delay.clone(),
        slow: server.slow.clone(),
        busy: server.busy.clone(),
        flight: server.flight.clone(),
        h2: h2.clone(),
    };
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (server, config, h2) = (server.clone(), config.clone(), h2.clone());
            std::thread::spawn(move || {
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), stream);
                while tls.conn.is_handshaking() {
                    if tls.conn.complete_io(&mut tls.sock).is_err() {
                        return;
                    }
                }
                if tls.conn.alpn_protocol() == Some(b"h2") { serve_h2(tls, &server, &h2) } else { serve(tls, &server) }
            });
        }
    });
    registry
}

/// What a registry answers from, shared by its connections.
#[derive(Clone)]
struct Server {
    pkgs: Arc<Mutex<Vec<Pkg>>>,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    hits: Arc<Mutex<Vec<String>>>,
    requests: Arc<AtomicUsize>,
    base: String,
    delay: Arc<AtomicUsize>,
    slow: Arc<Mutex<BTreeMap<String, u64>>>,
    busy: Arc<AtomicUsize>,
    flight: Arc<Flight>,
}

impl Server {
    /// The status line and body for a GET of `path`, sent with the credential `auth` (as
    /// " authorization: ..." or empty), and whether it is a tarball `Flight` counts: then
    /// `sent` is called once it has gone.
    fn reply(&self, path: &str, auth: &str) -> (&'static str, Vec<u8>, bool) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        // The path, then any credential it came with, for tests that check where tokens go.
        self.hits.lock().unwrap().push(format!("{path}{auth}"));
        let tarball = path.contains("/-/");
        // A busy registry says so at once.
        let busy =
            tarball && self.busy.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1)).is_ok();
        let flight = &self.flight;
        let counted = tarball && flight.seen.fetch_add(1, Ordering::Relaxed) >= flight.from.load(Ordering::Relaxed);
        if counted {
            let now = flight.now.fetch_add(1, Ordering::Relaxed) + 1;
            flight.most.fetch_max(now, Ordering::Relaxed);
        }
        let ms = self.delay.load(Ordering::Relaxed);
        if ms > 0 && tarball && !busy {
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
        }
        let late = self.slow.lock().unwrap().get(path.split('?').next().unwrap_or(path)).copied();
        if let Some(ms) = late {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        let file = self.files.lock().unwrap().get(path).cloned();
        let (status, bytes) = match file {
            _ if busy => ("503 Service Unavailable", b"{}".to_vec()),
            Some(body) => ("200 OK", body),
            None => answer(&path.replace("%2f", "/").replace("%2F", "/"), &self.pkgs.lock().unwrap(), &self.base),
        };
        (status, bytes, counted)
    }

    /// A tarball `reply` counted has been sent.
    fn sent(&self, counted: bool) {
        if counted {
            self.flight.now.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn serve(stream: impl Read + Write, server: &Server) {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        let mut length = 0;
        let mut auth = String::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                break;
            }
            if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap_or(0);
            }
            if h.to_ascii_lowercase().starts_with("authorization:") {
                auth = format!(" {}", h.trim_end());
            }
        }
        let mut body = vec![0; length];
        let _ = reader.read_exact(&mut body);
        let (status, bytes, counted) = server.reply(&path, &auth);
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n",
            bytes.len()
        );
        let writer = reader.get_mut();
        let sent =
            writer.write_all(head.as_bytes()).and_then(|()| writer.write_all(&bytes)).and_then(|()| writer.flush());
        server.sent(counted);
        if sent.is_err() {
            return;
        }
    }
}

/// HTTP/2, one request at a time, built on jpm-http's frames and HPACK. It keeps no windows:
/// the client's (2 MiB a stream, 8 MiB the connection) hold every body a test serves.
fn serve_h2(mut s: impl Read + Write, server: &Server, served: &AtomicUsize) {
    use jpm_http::{frame, hpack};
    let mut preface = [0; 24];
    if s.read_exact(&mut preface).is_err() || preface[..] != *frame::PREFACE {
        return;
    }
    let mut out = Vec::new();
    frame::put(&mut out, frame::SETTINGS, 0, 0, &[]);
    let (mut decoder, mut block, mut buf) = (hpack::Decoder::default(), Vec::new(), Vec::new());
    loop {
        if s.write_all(&out).and_then(|()| s.flush()).is_err() {
            return;
        }
        out.clear();
        let Ok(Some(Ok(h))) = frame::read(&mut s, 1 << 24, &mut buf) else { return };
        match h.typ {
            frame::SETTINGS if h.flags & frame::ACK == 0 => frame::put(&mut out, frame::SETTINGS, frame::ACK, 0, &[]),
            frame::PING if h.flags & frame::ACK == 0 => frame::put(&mut out, frame::PING, frame::ACK, 0, &buf),
            frame::HEADERS | frame::CONTINUATION => {
                if h.typ == frame::HEADERS {
                    block.clear();
                }
                block.extend_from_slice(&buf);
                if h.flags & frame::END_HEADERS == 0 {
                    continue;
                }
                let Ok(fields) = decoder.decode(&block, 1 << 20) else { return };
                let field = |name: &[u8]| {
                    fields.iter().find(|(n, _)| n == name).map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                };
                let path = field(b":path").unwrap_or_default();
                let auth = field(b"authorization").map(|a| format!(" authorization: {a}")).unwrap_or_default();
                served.fetch_add(1, Ordering::Relaxed);
                let (status, bytes, counted) = server.reply(&path, &auth);
                let mut head = Vec::new();
                hpack::encode(&mut head, ":status", &status[..3], false);
                hpack::encode(&mut head, "content-length", &bytes.len().to_string(), false);
                hpack::encode(&mut head, "content-type", "application/json", false);
                let end = if bytes.is_empty() { frame::END_STREAM } else { 0 };
                frame::put(&mut out, frame::HEADERS, frame::END_HEADERS | end, h.stream, &head);
                let chunks: Vec<&[u8]> = bytes.chunks(frame::DEFAULT_MAX_FRAME).collect();
                for (i, chunk) in chunks.iter().enumerate() {
                    let end = if i + 1 == chunks.len() { frame::END_STREAM } else { 0 };
                    frame::put(&mut out, frame::DATA, end, h.stream, chunk);
                }
                server.sent(counted);
            }
            _ => {}
        }
    }
}

fn answer(path: &str, pkgs: &[Pkg], base: &str) -> (&'static str, Vec<u8>) {
    let not_found = ("404 Not Found", b"{\"error\":\"not found\"}".to_vec());
    let path = path.trim_start_matches('/');
    if let Some((name, file)) = path.split_once("/-/") {
        return pkgs
            .iter()
            .find(|p| p.name == name && file == format!("{}-{}.tgz", name.rsplit('/').next().unwrap(), p.version))
            .map_or(not_found, |p| ("200 OK", p.tarball()));
    }
    let versions: Vec<&Pkg> = pkgs.iter().filter(|p| p.name == path).collect();
    if !versions.is_empty() {
        let mut doc = BTreeMap::new();
        // A version's publish date is its manifest's `_published`, else long ago.
        let mut time = BTreeMap::new();
        for p in &versions {
            doc.insert(p.version.clone(), manifest(p, base));
            let at = p.manifest.get("_published").and_then(Value::as_str).unwrap_or("2000-01-01T00:00:00.000Z");
            time.insert(p.version.clone(), at.to_string());
        }
        let latest = versions.iter().map(|p| p.version.clone()).max_by(|a, b| cmp(a, b)).unwrap();
        // A manifest's own `dist-tags`, as berry's fixtures carry them, win over the newest.
        let mut tags = json!({ "latest": latest });
        for p in &versions {
            if let Some(Value::Object(own)) = p.manifest.get("dist-tags") {
                for (tag, v) in own {
                    tags[tag] = v.clone();
                }
            }
        }
        let modified = time.values().max().cloned().unwrap();
        let body = json!({ "name": path, "dist-tags": tags, "versions": doc, "time": time, "modified": modified });
        return ("200 OK", serde_json::to_vec(&body).unwrap());
    }
    // A version's own route: `name/version`.
    if let Some((name, version)) = path.rsplit_once('/')
        && let Some(p) = pkgs.iter().find(|p| p.name == name && p.version == version)
    {
        return ("200 OK", serde_json::to_vec(&manifest(p, base)).unwrap());
    }
    not_found
}

fn cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| v.split(['.', '-']).map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parts(a).cmp(&parts(b))
}

fn manifest(p: &Pkg, base: &str) -> Value {
    let mut m = p.package_json();
    let short = p.name.rsplit('/').next().unwrap();
    // A manifest may name its tarball's path, served with `Registry::serve`.
    let tarball = match p.manifest.pointer("/dist/tarball").and_then(Value::as_str) {
        Some(path) => format!("{base}{path}"),
        None => format!("{base}/{}/-/{short}-{}.tgz", p.name, p.version),
    };
    m["dist"] = json!({ "tarball": tarball, "integrity": sha512(&p.tarball()) });
    m
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// A scratch directory with a home and a store of its own.
pub struct Env {
    pub root: PathBuf,
    pub registry: String,
}

impl Env {
    pub fn new(registry: &Registry) -> Self {
        let root = std::env::temp_dir().join(format!(
            "jpm-e2e-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("project")).unwrap();
        // jpm prints and passes on real paths: macOS's temp directory is under a /var link.
        #[cfg(unix)]
        let root = std::fs::canonicalize(&root).unwrap();
        Self { root, registry: registry.url.clone() }
    }

    pub fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    pub fn store(&self) -> PathBuf {
        self.root.join("store")
    }

    pub fn write(&self, rel: &str, text: &str) {
        let file = self.project().join(rel);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    /// The user's own `~/.npmrc`, where settings a project's .npmrc may not make go.
    pub fn user_npmrc(&self, text: &str) {
        std::fs::write(self.root.join("home/.npmrc"), text).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap_or_default()
    }

    /// `rel` under the project, a `..` leaving a link's target as it would on unix (Windows
    /// takes `a/..` off by the letters, whatever `a` is).
    pub fn path(&self, rel: &str) -> PathBuf {
        let mut at = self.project();
        for part in rel.split('/') {
            if part == ".." {
                at = std::fs::canonicalize(&at).unwrap_or(at);
                at.pop();
            } else {
                at.push(part);
            }
        }
        at
    }

    pub fn manifest(&self, value: Value) {
        self.write("package.json", &serde_json::to_string_pretty(&value).unwrap());
    }

    pub fn command(&self, args: &[&str]) -> Command {
        self.command_in(&self.project(), args)
    }

    pub fn command_in(&self, dir: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_jpm"));
        c.args(args)
            .current_dir(dir)
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("JPM_STORE", self.store())
            .env("npm_config_registry", &self.registry)
            .env("npm_config_min_release_age", "0")
            .env("NO_COLOR", "1")
            .env("JPM_NODE_VERSION", "22.0.0")
            .env_remove("JPM_GLOBAL_STORE")
            .env_remove("npm_config_userconfig");
        c
    }

    pub fn jpm(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// Runs jpm and fails the test with its output when it does not exit 0.
    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.jpm(args);
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "jpm {args:?} failed:\n{text}");
        text
    }

    pub fn exists(&self, rel: &str) -> bool {
        std::fs::symlink_metadata(self.path(rel)).is_ok()
    }

    /// The lockfile as JSON, through `jpm lock --json` (the file itself is jpm's text format).
    pub fn lock(&self) -> Value {
        let out = self.jpm(&["lock", "--json"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // The store is read-only by design: lift that so the scratch directory can go.
        let _ = Command::new("chmod").args(["-R", "u+w"]).arg(&self.root).output();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
