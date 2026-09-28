//! Read-only npm registry client: packuments and single manifests, memoized per run, with
//! documents kept on disk between runs and revalidated by ETag.
//!
//! Every method blocks; the resolver calls them from many threads at once, and each document is
//! fetched once however many threads ask for it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::http;
use crate::manifest::{Manifest, Map, Packument, parse_date};
use crate::semver::{self, Version};
use crate::spec::{Kind, Spec, escape_name};
use crate::util::{now_ms, sha256_hex};

/// The abbreviated ("corgi") document first: the resolver's fields, 10-100x smaller.
const CORGI: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";
const FULL: &str = "application/json";
const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// When a kept document answers without asking the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// While the registry's `max-age` lasts, or while it was read after the release cutoff.
    Revalidate,
    /// Whenever there is one.
    Prefer,
    /// Whenever there is one, and nothing is ever asked.
    Only,
}

/// Where a registry lives, trailing slashes off.
pub fn registry_base(registry: Option<&str>) -> String {
    registry.filter(|r| !r.is_empty()).unwrap_or(DEFAULT_REGISTRY).trim_end_matches('/').to_string()
}

/// Where a registry serves a package's tarball, by the convention every registry follows.
pub fn tarball_url(base: &str, name: &str, version: &str) -> String {
    let basename = if name.starts_with('@') { name.split_once('/').map_or(name, |(_, b)| b) } else { name };
    format!("{base}/{name}/-/{basename}-{version}.tgz")
}

/// The registry a name is read from: its scope's when `.npmrc` sends the scope elsewhere.
pub fn base_for<'a>(base: &'a str, scopes: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    if name.starts_with('@')
        && let Some(scope) = name.split_once('/').map(|(s, _)| s)
        && let Some(b) = scopes.get(scope)
    {
        return b;
    }
    base
}

/// The header a url gets from the credentials: the longest `//host/path/` prefix, walking up one
/// segment or slash at a time as npm does.
pub fn auth_for(auth: &BTreeMap<String, String>, url: &str) -> Option<String> {
    if auth.is_empty() {
        return None;
    }
    let rest = url.split_once("://")?.1;
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let mut dart = format!("//{}", &rest[..path_end]);
    if !dart[2..].contains('/') {
        dart.push('/');
    }
    while dart.len() > 2 {
        if let Some(found) = auth.get(&dart) {
            return Some(found.clone());
        }
        if dart.ends_with('/') {
            dart.pop();
        } else {
            let cut = dart.rfind('/').map_or(0, |i| i + 1);
            dart.truncate(cut);
        }
    }
    None
}

/// A value computed once however many threads ask; the map lock is never held while computing.
type Memo<V> = Mutex<HashMap<String, Arc<OnceLock<Result<V>>>>>;

fn memo<V: Clone>(map: &Memo<V>, key: &str, load: impl FnOnce() -> Result<V>) -> Result<V> {
    let cell = {
        let mut m = map.lock().map_err(|_| poisoned())?;
        m.entry(key.to_string()).or_default().clone()
    };
    cell.get_or_init(load).clone()
}

fn poisoned() -> Error {
    Error::new("EINTERNAL", "a lock was poisoned by a crashed thread")
}

pub struct Registry {
    pub base: String,
    pub scopes: BTreeMap<String, String>,
    auth: BTreeMap<String, String>,
    before: Option<i64>,
    exclude: Vec<String>,
    cache: Option<DocCache>,
    corgis: Memo<Arc<Packument>>,
    fulls: Memo<Arc<Packument>>,
    routes: Memo<Option<Arc<Manifest>>>,
    /// Names a kept document answered without asking; and names asked about again since.
    unasked: Mutex<HashSet<String>>,
    rechecked: Mutex<HashSet<String>>,
}

impl Registry {
    pub fn new(config: &Config, metadata: Option<&Path>) -> Self {
        let mode = if config.offline {
            CacheMode::Only
        } else if config.prefer_offline {
            CacheMode::Prefer
        } else {
            CacheMode::Revalidate
        };
        Self {
            base: config.registry.clone(),
            scopes: config.scopes.clone(),
            auth: config.auth.clone(),
            before: config.before,
            exclude: config.release_age_exclude.clone(),
            cache: metadata.map(|dir| DocCache { dir: dir.to_path_buf(), mode }),
            corgis: Mutex::default(),
            fulls: Mutex::default(),
            routes: Mutex::default(),
            unasked: Mutex::default(),
            rechecked: Mutex::default(),
        }
    }

    pub fn base_for(&self, name: &str) -> &str {
        base_for(&self.base, &self.scopes, name)
    }

    fn path(&self, name: &str) -> Result<String> {
        Ok(format!("{}/{}", self.base_for(name), escape_name(name)?))
    }

    fn excluded(&self, name: &str) -> bool {
        self.exclude.iter().any(|p| wildcard(p.as_bytes(), name.as_bytes()))
    }

    fn mode(&self) -> Option<CacheMode> {
        self.cache.as_ref().map(|c| c.mode)
    }

    /// A document's bytes: kept, revalidated or fetched, as the cache mode says.
    fn document(&self, name: &str, url: &str, accept: &str, ask: bool) -> Result<Vec<u8>> {
        let key = format!("{} {url}", if accept == CORGI { "corgi" } else { "full" });
        let rechecked = self.rechecked.lock().map_err(|_| poisoned())?.contains(name);
        let kept = self.cache.as_ref().and_then(|c| c.get(&key));
        if let (Some(doc), Some(cache)) = (&kept, &self.cache) {
            let current = match cache.mode {
                CacheMode::Revalidate => {
                    doc.max_age.is_some_and(|age| now_ms() - doc.at < age * 1000)
                        || self.before.is_some_and(|b| doc.at >= b && !self.excluded(name))
                }
                _ => true,
            };
            if current && !ask && !rechecked {
                self.unasked.lock().map_err(|_| poisoned())?.insert(name.to_string());
                return Ok(doc.body.clone());
            }
        }
        if self.mode() == Some(CacheMode::Only) {
            return Err(Error::new("EOFFLINE", format!("offline: cannot ask the registry for {name}")));
        }
        let mut headers = vec![("accept", accept)];
        let etag = kept.as_ref().and_then(|d| d.etag.clone());
        if let Some(e) = &etag {
            headers.push(("if-none-match", e));
        }
        let response = http::get(url, &headers, &self.auth)?;
        let at = now_ms() - response.age.unwrap_or(0) as i64 * 1000;
        match response.status {
            304 if kept.is_some() => {
                if let Some(c) = &self.cache {
                    c.touch(&key, at);
                }
                Ok(kept.map(|d| d.body).unwrap_or_default())
            }
            200..=299 => {
                let control = response.cache_control.unwrap_or_default().to_ascii_lowercase();
                if let Some(c) = self.cache.as_ref().filter(|_| !control.contains("no-store")) {
                    let max_age =
                        control.split(',').find_map(|d| d.trim().strip_prefix("max-age=").and_then(|v| v.parse().ok()));
                    c.set(&key, &response.body, at, response.etag.as_deref(), max_age);
                }
                Ok(response.body)
            }
            404 => Err(Error::new("E404", format!("Package \"{name}\" not found in registry"))),
            status => Err(Error::new("EREGISTRY", format!("Registry returned {status} for {url}"))),
        }
    }

    fn load_corgi(&self, name: &str) -> Result<Arc<Packument>> {
        let url = self.path(name)?;
        let bytes = match self.document(name, &url, CORGI, false) {
            // A registry that chokes on the abbreviated media type gets asked for the full one.
            Err(e)
                if e.code == "EREGISTRY"
                    && ["400", "406", "415"].iter().any(|s| e.message.contains(&format!("returned {s} "))) =>
            {
                self.document(name, &url, FULL, false)?
            }
            other => other?,
        };
        let doc = Packument::parse(&bytes).map_err(|e| e.context(&url))?;
        let Some(before) = self.before.filter(|_| !self.excluded(name)) else { return Ok(Arc::new(doc)) };
        // Nothing in a document untouched since the cutoff is newer than it.
        if doc.modified.as_deref().and_then(parse_date).is_some_and(|m| m <= before) {
            return Ok(Arc::new(doc));
        }
        let times = self.times(name, &doc)?;
        Ok(Arc::new(doc.until(&times, before)))
    }

    /// Publish dates for every version, from the full document.
    fn times(&self, name: &str, corgi: &Packument) -> Result<Map> {
        let full = self.full(name)?;
        if corgi.versions().all(|v| full.time.contains_key(v)) || self.mode() == Some(CacheMode::Only) {
            let mut times = full.time.clone();
            // Offline, a version without a date is taken as too new: it was published since.
            let now = crate::manifest::iso_date(now_ms());
            for v in corgi.versions() {
                times.entry(v.to_string()).or_insert_with(|| now.clone());
            }
            return Ok(times);
        }
        // A kept full document older than the abbreviated one lacks the newest dates: ask again.
        let bytes = self.document(name, &self.path(name)?, FULL, true)?;
        let fresh = Packument::parse(&bytes)?;
        let times = fresh.time.clone();
        if let Ok(mut m) = self.fulls.lock() {
            let cell = OnceLock::new();
            let _ = cell.set(Ok(Arc::new(fresh)));
            m.insert(name.to_string(), Arc::new(cell));
        }
        Ok(times)
    }

    fn full(&self, name: &str) -> Result<Arc<Packument>> {
        memo(&self.fulls, name, || {
            let url = self.path(name)?;
            let bytes = self.document(name, &url, FULL, false)?;
            Ok(Arc::new(Packument::parse(&bytes).map_err(|e| e.context(&url))?))
        })
    }

    /// The abbreviated packument, as of the release cutoff.
    pub fn packument(&self, name: &str) -> Result<Arc<Packument>> {
        memo(&self.corgis, name, || self.load_corgi(name))
    }

    /// One version's full manifest by its own route, or `None` where nothing serves it.
    fn route(&self, name: &str, version: &str) -> Result<Option<Arc<Manifest>>> {
        memo(&self.routes, &format!("{name}@{version}"), || {
            let url = format!("{}/{version}", self.path(name)?);
            match self.document(name, &url, FULL, false) {
                Ok(bytes) => {
                    let mut m = Manifest::from_json(&String::from_utf8_lossy(&bytes)).map_err(|e| e.context(&url))?;
                    m.full = true;
                    Ok(Some(Arc::new(m)))
                }
                Err(e) if matches!(e.code, "E404" | "EOFFLINE" | "EREGISTRY") => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    /// One full manifest: `libc` lives only there. The per-version route for an unscoped name
    /// (a CDN hit on npmjs), the full packument for a scoped one (whose route is not cached).
    pub fn manifest(&self, name: &str, version: &str) -> Result<Arc<Manifest>> {
        let missing = || Error::new("E404", format!("Registry has no manifest for {name}@{version}"));
        if !name.starts_with('@')
            && let Some(m) = self.route(name, version)?
        {
            return Ok(m);
        }
        if let Some(m) = self.full(name).ok().and_then(|doc| doc.version(version)) {
            let mut m = (*m).clone();
            m.full = true;
            return Ok(Arc::new(m));
        }
        self.route(name, version)?.ok_or_else(missing)
    }

    /// One pinned version, or `None` when nothing serves it.
    fn pinned(&self, name: &str, version: &str) -> Result<Option<Arc<Manifest>>> {
        let known = self.corgis.lock().map_err(|_| poisoned())?.get(name).and_then(|c| c.get().cloned());
        if let Some(Ok(doc)) = known
            && let Some(m) = doc.version(version)
        {
            return Ok(Some(m));
        }
        if !name.starts_with('@')
            && let Some(m) = self.route(name, version)?
        {
            return Ok(Some(m));
        }
        Ok(self.packument(name).ok().and_then(|doc| doc.version(version)))
    }

    /// The walk's pick: `pinned` first when there is a version to try, then the usual pick.
    pub fn pick(&self, spec: &Spec, pinned: Option<&str>) -> Result<Arc<Manifest>> {
        let name = &spec.fetch_name;
        if let Some(v) = pinned
            && let Some(m) = self.pinned(name, v)?
        {
            return Ok(m);
        }
        // A tag written out, `foo@latest`, is what it points at now: revalidated.
        if spec.kind == Kind::Tag && self.mode() == Some(CacheMode::Revalidate) {
            self.recheck(name)?;
        }
        match pick_manifest(&*self.packument(name)?, spec) {
            Err(e) if matches!(e.code, "ETARGET" | "ENOVERSIONS") => {
                // A document kept from an earlier run may predate what is asked for: ask once.
                let unasked = self.unasked.lock().map_err(|_| poisoned())?.contains(name.as_str());
                let rechecked = self.rechecked.lock().map_err(|_| poisoned())?.contains(name.as_str());
                if !unasked || rechecked || self.mode() == Some(CacheMode::Only) {
                    return Err(e);
                }
                self.recheck(name)?;
                pick_manifest(&*self.packument(name)?, spec)
            }
            other => other,
        }
    }

    fn recheck(&self, name: &str) -> Result<()> {
        if !self.rechecked.lock().map_err(|_| poisoned())?.insert(name.to_string()) {
            return Ok(());
        }
        if self.unasked.lock().map_err(|_| poisoned())?.contains(name) {
            self.corgis.lock().map_err(|_| poisoned())?.remove(name);
            self.fulls.lock().map_err(|_| poisoned())?.remove(name);
        }
        Ok(())
    }
}

/// `*` within a segment, `**` across them, `?` one character.
fn wildcard(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => (0..=s.len()).any(|i| wildcard(&p[2..], &s[i..])),
        Some(b'*') => (0..=s.len()).take_while(|&i| i == 0 || s[i - 1] != b'/').any(|i| wildcard(&p[1..], &s[i..])),
        Some(b'?') => s.first().is_some_and(|c| *c != b'/') && wildcard(&p[1..], &s[1..]),
        Some(c) => s.first() == Some(c) && wildcard(&p[1..], &s[1..]),
    }
}

// --- picking a version ------------------------------------------------------------------------

/// The node this tree will run on, for `engines.node`: `JPM_NODE_VERSION`, else `node --version`.
/// Asked once, and only when a pick has to rank versions. No node means every engine passes.
fn node_version() -> Option<&'static Version> {
    static NODE: OnceLock<Option<Version>> = OnceLock::new();
    NODE.get_or_init(|| {
        let text = std::env::var("JPM_NODE_VERSION").ok().or_else(|| {
            let out = std::process::Command::new(crate::run::which("node")?).arg("--version").output().ok()?;
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        })?;
        semver::parse(&text)
    })
    .as_ref()
}

fn engine_ok(m: &Manifest) -> bool {
    let Some(range) = m.engines.get("node") else { return true };
    node_version().is_none_or(|v| semver::satisfies_version(v, range, true))
}

/// `npm-pick-manifest`: a packument and a spec in, one manifest out.
pub fn pick_manifest(doc: &Packument, spec: &Spec) -> Result<Arc<Manifest>> {
    let fail = || {
        if let Some(before) = &doc.before {
            return Error::new(
                "ETARGET",
                format!(
                    "No version of {} published before {before} (min-release-age; see min-release-age-exclude)",
                    spec.raw
                ),
            );
        }
        if doc.is_empty() {
            Error::new("ENOVERSIONS", format!("No versions available for {}", doc.name))
        } else {
            Error::new("ETARGET", format!("No matching version found for {}", spec.raw))
        }
    };
    if matches!(spec.kind, Kind::Tag | Kind::Version) {
        let wanted = if spec.kind == Kind::Tag {
            doc.tags.get(&spec.fetch_spec).cloned()
        } else {
            Some(spec.fetch_spec.clone())
        };
        // `=1.2.3` and `v1.2.3` are valid specs but never packument keys.
        let key = wanted.and_then(|w| semver::parse(&w)).map(|v| v.text);
        return key.and_then(|k| doc.version(&k)).ok_or_else(fail);
    }
    let range = &spec.fetch_spec;
    // The default tag usually wins, and skips parsing and sorting the list.
    if let Some(tagged) = doc.tags.get("latest")
        && (range == "*" || semver::satisfies(tagged, range))
        && let Some(m) = doc.version(tagged).filter(|m| !m.deprecated && engine_ok(m))
    {
        return Ok(m);
    }
    // Otherwise rank every match: usable first, newest as the tiebreaker.
    type Ranked = ((bool, bool, bool), Version, Arc<Manifest>);
    let mut best: Option<Ranked> = None;
    for raw in doc.versions() {
        let Some(v) = semver::parse(raw) else { continue };
        if !semver::satisfies_version(&v, range, false) {
            continue;
        }
        let Some(m) = doc.version(raw) else { continue };
        let (ok, fresh) = (engine_ok(&m), !m.deprecated);
        let rank = (fresh && ok, ok, fresh);
        let better = best.as_ref().is_none_or(|(r, bv, _)| rank > *r || (rank == *r && v > *bv));
        if better {
            best = Some((rank, v, m));
        }
    }
    best.map(|(_, _, m)| m).ok_or_else(fail)
}

// --- documents kept on disk -----------------------------------------------------------------

struct Kept {
    body: Vec<u8>,
    etag: Option<String>,
    /// When the registry's copy was current, in epoch ms.
    at: i64,
    max_age: Option<i64>,
}

/// One file per url and media type: a JSON head line, then the body as the registry sent it.
struct DocCache {
    dir: PathBuf,
    mode: CacheMode,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Head {
    at: i64,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(rename = "maxAge", skip_serializing_if = "Option::is_none")]
    max_age: Option<i64>,
}

impl DocCache {
    /// `corgi https://host:8080/base/@scope%2fname` -> `host+8080/base/@scope/name/_corgi`, or a
    /// hash for a url with a segment that is not plainly a name.
    fn file(&self, key: &str) -> PathBuf {
        let (kind, url) = key.split_once(' ').unwrap_or(("full", key));
        let rest = url.split_once("://").map_or("", |(_, r)| r);
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = path.replace("%2f", "/").replace("%2F", "/");
        let mut segments = vec![host.replace(':', "+")];
        segments.extend(path.split('/').filter(|s| !s.is_empty()).map(str::to_string));
        let plain = |s: &String| {
            s != "."
                && s != ".."
                && !s.is_empty()
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.@+~-".contains(&b))
        };
        if !segments.iter().all(plain) || host.is_empty() {
            let hash = sha256_hex(key);
            segments = vec!["_".into(), hash[..2].to_string(), hash];
        }
        let mut file = self.dir.clone();
        file.extend(segments);
        file.join(format!("_{kind}"))
    }

    fn get(&self, key: &str) -> Option<Kept> {
        let bytes = std::fs::read(self.file(key)).ok()?;
        let end = bytes.iter().position(|b| *b == b'\n')?;
        let head: Head = serde_json::from_slice(&bytes[..end]).ok()?;
        if head.key != key {
            return None;
        }
        Some(Kept { body: bytes[end + 1..].to_vec(), etag: head.etag, at: head.at, max_age: head.max_age })
    }

    fn set(&self, key: &str, body: &[u8], at: i64, etag: Option<&str>, max_age: Option<i64>) {
        // A captive portal's page, say, is never kept.
        let trimmed = body.trim_ascii();
        if !(trimmed.starts_with(b"{") && trimmed.ends_with(b"}")) {
            return;
        }
        let file = self.file(key);
        let head = Head { at, key: key.to_string(), etag: etag.map(str::to_string), max_age };
        let mut data = serde_json::to_vec(&head).unwrap_or_default();
        data.push(b'\n');
        data.extend_from_slice(body);
        if let Some(parent) = file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // A cache that cannot be written only costs the next run a request.
        let _ = crate::util::write_atomic(&file, &data);
    }

    /// The registry said it has not changed: current as of `at`.
    fn touch(&self, key: &str, at: i64) {
        if let Some(kept) = self.get(key) {
            self.set(key, &kept.body, at, kept.etag.as_deref(), kept.max_age);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::parse_dep;

    #[test]
    fn builds_tarball_urls() {
        assert_eq!(tarball_url("https://r.test", "@s/a", "1.0.0"), "https://r.test/@s/a/-/a-1.0.0.tgz");
        assert_eq!(tarball_url("https://r.test", "a", "1.0.0"), "https://r.test/a/-/a-1.0.0.tgz");
    }

    #[test]
    fn finds_credentials() {
        let auth: BTreeMap<String, String> = [("//r.test/npm/".to_string(), "x".to_string())].into();
        assert_eq!(auth_for(&auth, "https://r.test/npm/a/-/a.tgz").as_deref(), Some("x"));
        assert_eq!(auth_for(&auth, "https://r.test/other/a"), None);
        assert_eq!(auth_for(&auth, "https://evil.test/npm/a"), None);
    }

    #[test]
    fn matches_globs() {
        assert!(wildcard(b"@s/*", b"@s/a"));
        assert!(!wildcard(b"*", b"@s/a"));
        assert!(wildcard(b"**", b"@s/a"));
        assert!(wildcard(b"a?c", b"abc"));
    }

    fn doc() -> Packument {
        Packument::parse(
            br#"{"name":"a","dist-tags":{"latest":"1.1.0","next":"2.0.0-rc.1"},"versions":{
            "1.0.0":{"name":"a","version":"1.0.0"},
            "1.1.0":{"name":"a","version":"1.1.0"},
            "1.2.0":{"name":"a","version":"1.2.0","deprecated":"no"},
            "2.0.0-rc.1":{"name":"a","version":"2.0.0-rc.1"}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn picks_like_npm() {
        let pick = |range: &str| pick_manifest(&doc(), &parse_dep("a", range).unwrap()).map(|m| m.version.clone());
        assert_eq!(pick("^1").unwrap(), "1.1.0"); // latest wins over a newer match
        assert_eq!(pick("^1.2").unwrap(), "1.2.0"); // deprecated, but the only match
        assert_eq!(pick("next").unwrap(), "2.0.0-rc.1");
        assert_eq!(pick("=1.0.0").unwrap(), "1.0.0");
        assert_eq!(pick("^3").unwrap_err().code, "ETARGET");
        assert_eq!(pick("nope").unwrap_err().code, "ETARGET");
    }
}
