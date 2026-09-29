//! A registry on localhost for end-to-end tests: packuments, per-version manifests and
//! tarballs made in memory, served over HTTP/1.1 with keep-alive, plus helpers to run jpm
//! against it with a private store and home.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
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

pub fn tar(entries: &[(String, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, mode, data) in entries {
        let mut h = [0u8; 512];
        h[..path.len()].copy_from_slice(path.as_bytes());
        h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
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

fn b64(bytes: &[u8]) -> String {
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
    /// Requests served, by path.
    pub hits: Arc<Mutex<Vec<String>>>,
    pub requests: Arc<AtomicUsize>,
}

impl Registry {
    pub fn start(pkgs: Vec<Pkg>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let pkgs = Arc::new(Mutex::new(pkgs));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(AtomicUsize::new(0));
        let (p, h, r, u) = (pkgs.clone(), hits.clone(), requests.clone(), url.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (p, h, r, u) = (p.clone(), h.clone(), r.clone(), u.clone());
                std::thread::spawn(move || serve(stream, &p, &h, &r, &u));
            }
        });
        Self { url, pkgs, hits, requests }
    }

    /// Adds a version, or replaces one already published.
    pub fn publish(&self, p: Pkg) {
        let mut pkgs = self.pkgs.lock().unwrap();
        pkgs.retain(|old| (&old.name, &old.version) != (&p.name, &p.version));
        pkgs.push(p);
    }
}

fn serve(stream: TcpStream, pkgs: &Mutex<Vec<Pkg>>, hits: &Mutex<Vec<String>>, requests: &AtomicUsize, base: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
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
        requests.fetch_add(1, Ordering::Relaxed);
        // The path, then any credential it came with, for tests that check where tokens go.
        hits.lock().unwrap().push(format!("{path}{auth}"));
        let (status, bytes) = answer(&path.replace("%2f", "/").replace("%2F", "/"), &pkgs.lock().unwrap(), base);
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n",
            bytes.len()
        );
        if writer.write_all(head.as_bytes()).and_then(|()| writer.write_all(&bytes)).is_err() {
            return;
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
        let modified = time.values().max().cloned().unwrap();
        let body = json!({ "name": path, "dist-tags": { "latest": latest }, "versions": doc, "time": time, "modified": modified });
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
    m["dist"] = json!({ "tarball": format!("{base}/{}/-/{short}-{}.tgz", p.name, p.version), "integrity": sha512(&p.tarball()) });
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

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.project().join(rel)).unwrap_or_default()
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
        std::fs::symlink_metadata(self.project().join(rel)).is_ok()
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
