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
    use crate::spec::encode_segment as enc;
    let (path, basename) = match name.strip_prefix('@').and_then(|n| n.split_once('/')) {
        Some((scope, pkg)) => (format!("@{}/{}", enc(scope), enc(pkg)), enc(pkg)),
        None => (enc(name), enc(name)),
    };
    format!("{base}/{path}/-/{basename}-{version}.tgz")
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

/// Marks, in the credentials map, a host whose registry is configured over plain http.
pub const INSECURE: &str = "http:";

/// The header a url gets from the credentials: the longest `//host/path/` prefix, walking up one
/// segment or slash at a time as npm does. Nothing over plain http unless that host's registry is
/// http itself, and nothing for a path with dot segments, which the server would resolve to a
/// path the prefix does not cover.
pub fn auth_for(auth: &BTreeMap<String, String>, url: &str) -> Option<String> {
    if auth.is_empty() {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let host = rest[..path_end].split('/').next()?;
    if !scheme.eq_ignore_ascii_case("https") && !auth.contains_key(&format!("{INSECURE}//{host}/")) {
        return None;
    }
    // Some servers read `\` as `/`: a dot segment spelled either way is refused. Tomcat drops a
    // `;param` from a segment, so `..;` and `.;` are dot segments too; any `..`-led one is refused.
    let path = rest[host.len()..path_end].replace('\\', "/");
    let lower = path.to_ascii_lowercase();
    let dots = |s: &str| s.starts_with("..") || s.split(';').next() == Some(".");
    if path.split('/').any(dots) || lower.contains("%2e") || lower.contains("%5c") {
        return None;
    }
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

    /// Where kept documents go, when they are kept.
    pub fn metadata_dir(&self) -> Option<&Path> {
        self.cache.as_ref().map(|c| c.dir.as_path())
    }

    pub fn offline(&self) -> bool {
        self.mode() == Some(CacheMode::Only)
    }

    /// The credentials, each for the urls under its own prefix.
    pub fn auth(&self) -> &BTreeMap<String, String> {
        &self.auth
    }

    /// A document's bytes: kept, revalidated or fetched, as the cache mode says.
    fn document(&self, name: &str, url: &str, accept: &str, ask: bool) -> Result<Vec<u8>> {
        let key = format!("{} {url}", if accept == CORGI { "corgi" } else { "full" });
        let rechecked = self.rechecked.lock().map_err(|_| poisoned())?.contains(name);
        let kept = self.cache.as_ref().and_then(|c| c.get(&key));
        if let Some(doc) = &kept
            && self.current(name, doc)
            && !ask
            && !rechecked
        {
            self.unasked.lock().map_err(|_| poisoned())?.insert(name.to_string());
            return Ok(doc.body.clone());
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
                    c.set(&key, &response.body, response.gzipped.as_deref(), at, response.etag.as_deref(), max_age);
                }
                Ok(response.body)
            }
            404 => Err(Error::new("E404", format!("Package \"{name}\" not found in registry"))),
            status => Err(Error::new("EREGISTRY", format!("Registry returned {status} for {url}"))),
        }
    }

    /// Whether a kept document answers without asking the registry, as the cache mode says.
    fn current(&self, name: &str, doc: &Kept) -> bool {
        match self.mode() {
            Some(CacheMode::Revalidate) => {
                doc.max_age.is_some_and(|age| now_ms() - doc.at < age * 1000)
                    || self.before.is_some_and(|b| doc.at >= b && !self.excluded(name))
            }
            _ => true,
        }
    }

    /// Whether `key`'s kept document would answer without asking.
    fn answers(&self, name: &str, key: &str) -> bool {
        let rechecked = || self.rechecked.lock().is_ok_and(|r| r.contains(name));
        self.cache.as_ref().and_then(|c| c.get(key)).is_some_and(|doc| self.current(name, &doc)) && !rechecked()
    }

    fn load_corgi(&self, name: &str) -> Result<Arc<Packument>> {
        // A scoped package named for linux is nearly always a linux build: its libc is only in
        // the full document, as are the publish dates the release cutoff reads, so the walk
        // would ask for that next. Asked for first, it is one request instead of two. The name
        // only decides which document is asked for; what the package is, and where it runs,
        // is read from the document. Without one (offline, say), the abbreviated one serves.
        if name.starts_with('@')
            && name.contains("linux")
            && let Ok(full) = self.full(name)
        {
            return Ok(self.cut(name, full));
        }
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
        let doc = Packument::parse(bytes).map_err(|e| e.context(&url))?;
        let Some(before) = self.before.filter(|_| !self.excluded(name)) else { return Ok(Arc::new(doc)) };
        // Nothing in a document untouched since the cutoff is newer than it.
        if doc.modified.as_deref().and_then(parse_date).is_some_and(|m| m <= before) {
            return Ok(Arc::new(doc));
        }
        let times = self.times(name, &doc)?;
        Ok(Arc::new(doc.until(&times, before)))
    }

    /// A full document as the registry stood at the release cutoff, by its own dates.
    fn cut(&self, name: &str, full: Arc<Packument>) -> Arc<Packument> {
        let Some(before) = self.before.filter(|_| !self.excluded(name)) else { return full };
        let modified = full.time.get("modified").or(full.modified.as_ref());
        if modified.and_then(|m| parse_date(m)).is_some_and(|m| m <= before) {
            return full;
        }
        Arc::new(full.copy().until(&full.time, before))
    }

    /// Publish dates for every version, from the full document.
    fn times(&self, name: &str, corgi: &Packument) -> Result<Map> {
        let kept = self.kept_times(name)?;
        if corgi.versions().all(|v| kept.contains_key(v)) || self.mode() == Some(CacheMode::Only) {
            let mut times = kept;
            // Offline, a version without a date is taken as too new: it was published since.
            let now = crate::manifest::iso_date(now_ms());
            for v in corgi.versions() {
                times.entry(v.to_string()).or_insert_with(|| now.clone());
            }
            return Ok(times);
        }
        // A kept full document older than the abbreviated one lacks the newest dates: ask again.
        let bytes = self.document(name, &self.path(name)?, FULL, true)?;
        let fresh = Packument::parse(bytes)?;
        let times = fresh.time.clone();
        if let Ok(mut m) = self.fulls.lock() {
            let cell = OnceLock::new();
            let _ = cell.set(Ok(Arc::new(fresh)));
            m.insert(name.to_string(), Arc::new(cell));
        }
        Ok(times)
    }

    /// The full document's `time`. It is kept beside the document too, stamped with the file it
    /// was read from: kilobytes read instead of megabytes (typescript's is 16 MB) for every name
    /// the release cutoff has to date.
    fn kept_times(&self, name: &str) -> Result<Map> {
        let Some(cache) = &self.cache else { return Ok(self.full(name)?.time.clone()) };
        let file = cache.file(&format!("full {}", self.path(name)?));
        let side = file.with_file_name("_full.times");
        let stamp = || crate::state::stamp_of(&file).map(|s| s.join(" "));
        if let (Some(now), Ok(text)) = (crate::state::stamp_of(&file), std::fs::read_to_string(&side))
            && crate::state::settled(crate::state::mtime_of(&now), &side)
            && let Some((kept, body)) = text.split_once('\n')
            && kept == now.join(" ")
            && let Ok(doc) = Packument::parse(body.as_bytes().to_vec())
            && !doc.time.is_empty()
        {
            return Ok(doc.time);
        }
        let full = self.full(name)?;
        if let Some(now) = stamp() {
            let body = crate::json::to_string(&crate::json::obj([("time", crate::json::str_map(&full.time))]));
            let _ = crate::util::write_atomic(&side, format!("{now}\n{body}").as_bytes());
        }
        Ok(full.time.clone())
    }

    fn full(&self, name: &str) -> Result<Arc<Packument>> {
        memo(&self.fulls, name, || {
            let url = self.path(name)?;
            let bytes = self.document(name, &url, FULL, false)?;
            Ok(Arc::new(Packument::parse(bytes).map_err(|e| e.context(&url))?))
        })
    }

    /// The abbreviated packument, as of the release cutoff.
    pub fn packument(&self, name: &str) -> Result<Arc<Packument>> {
        memo(&self.corgis, name, || self.load_corgi(name))
    }

    /// Whether a thread is reading the document `packument` answers for `name` right now.
    pub fn reading(&self, name: &str) -> bool {
        self.corgis.lock().is_ok_and(|m| m.get(name).is_some_and(|cell| cell.get().is_none()))
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

    /// One pinned version, or `None` when nothing serves it. `exempt` looks past the release
    /// cutoff.
    fn pinned(&self, name: &str, version: &str, exempt: bool) -> Result<Option<Arc<Manifest>>> {
        let known = self.corgis.lock().map_err(|_| poisoned())?.get(name).and_then(|c| c.get().cloned());
        if let Some(Ok(doc)) = known
            && let Some(m) = doc.version(version)
        {
            return Ok(Some(m));
        }
        // An unscoped pin is asked for by its own route, past the release cutoff. When the
        // route was never kept, a kept packument that answers without asking goes first.
        let unscoped = !name.starts_with('@');
        let url = self.path(name)?;
        let route_kept = self.cache.as_ref().is_some_and(|c| c.file(&format!("full {url}/{version}")).is_file());
        if unscoped
            && (route_kept || !self.answers(name, &format!("corgi {url}")))
            && let Some(m) = self.route(name, version)?
        {
            return Ok(Some(m));
        }
        let cut = self.packument(name).ok().and_then(|doc| doc.version(version));
        if cut.is_none()
            && unscoped
            && let Some(m) = self.route(name, version)?
        {
            return Ok(Some(m));
        }
        Ok(if cut.is_none() && exempt { self.manifest(name, version).ok() } else { cut })
    }

    /// The walk's pick: `pinned` first when there is a version to try, then the usual pick.
    pub fn pick(&self, spec: &Spec, pinned: Option<&str>, exempt: bool) -> Result<Arc<Manifest>> {
        let name = &spec.fetch_name;
        if let Some(v) = pinned
            && let Some(m) = self.pinned(name, v, exempt)?
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

/// `*` within a segment, `**` across them, `?` one character. A table over (pattern, name)
/// positions, filled from the ends: time is pattern length times name length, and no recursion.
/// A pattern past `MAX_PATTERN` bytes matches nothing.
fn wildcard(p: &[u8], s: &[u8]) -> bool {
    const MAX_PATTERN: usize = 1024;
    if p.len() > MAX_PATTERN {
        return false;
    }
    // `next[j]`: whether the pattern after the current token matches `s[j..]`.
    let mut next = vec![false; s.len() + 1];
    next[s.len()] = true;
    let mut end = p.len();
    while end > 0 {
        let across = end >= 2 && p[end - 2..end] == *b"**";
        let start = if across { end - 2 } else { end - 1 };
        let mut cur = vec![false; s.len() + 1];
        for j in (0..=s.len()).rev() {
            let c = s.get(j);
            cur[j] = match p[start] {
                b'*' => next[j] || (c.is_some_and(|c| across || *c != b'/') && cur[j + 1]),
                b'?' => c.is_some_and(|c| *c != b'/') && next[j + 1],
                lit => c == Some(&lit) && next[j + 1],
            };
        }
        next = cur;
        end = start;
    }
    next[0]
}

// --- picking a version ------------------------------------------------------------------------

/// The node this tree will run on, for `engines.node`: `JPM_NODE_VERSION`, else `node --version`.
/// Asked once, and only when a pick has to rank versions. No node means every engine passes.
pub fn node_version() -> Option<&'static Version> {
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
    // The default tag usually wins, and skips parsing and sorting the list. `*` takes a
    // prerelease there only when there is no release, as pnpm picks (npm takes it anyway).
    let latest = doc.tags.get("latest");
    if let Some(tagged) = latest
        && semver::satisfies(tagged, range)
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
    best.map(|(_, _, m)| m).or_else(|| latest.filter(|_| range == "*").and_then(|t| doc.version(t))).ok_or_else(fail)
}

// --- documents kept on disk -----------------------------------------------------------------

struct Kept {
    body: Vec<u8>,
    /// The bytes after the head line as the file holds them: the body, or the body gzipped.
    stored: Vec<u8>,
    etag: Option<String>,
    /// When the registry's copy was current, in epoch ms.
    at: i64,
    max_age: Option<i64>,
}

/// One file per url and media type: a JSON head line, then the body as the registry sent it,
/// gzipped when it came gzipped (a third of the size or less, and nothing spent compressing).
struct DocCache {
    dir: PathBuf,
    mode: CacheMode,
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
        let mut bytes = std::fs::read(self.file(key)).ok()?;
        let end = bytes.iter().position(|b| *b == b'\n')?;
        let head = crate::json::parse(std::str::from_utf8(&bytes[..end]).ok()?).ok()?;
        if head.get("key")?.as_str()? != key {
            return None;
        }
        let number = |k: &str| {
            head.get(k).and_then(|v| if let crate::json::Value::Number(n) = v { n.parse().ok() } else { None })
        };
        let stored = bytes.split_off(end + 1);
        // A JSON body starts with `{`, never with gzip's magic bytes.
        let body = if stored.starts_with(&[0x1f, 0x8b]) {
            http::gunzip(&stored, http::MAX_DOCUMENT).ok()?
        } else {
            stored.clone()
        };
        Some(Kept {
            body,
            stored,
            etag: head.get("etag").and_then(crate::json::Value::as_str).map(str::to_string),
            at: number("at")?,
            max_age: number("maxAge"),
        })
    }

    /// Keep `body`, as `gzipped` when the registry sent it so.
    fn set(&self, key: &str, body: &[u8], gzipped: Option<&[u8]>, at: i64, etag: Option<&str>, max_age: Option<i64>) {
        // A captive portal's page, say, is never kept.
        let trimmed = body.trim_ascii();
        if !(trimmed.starts_with(b"{") && trimmed.ends_with(b"}")) {
            return;
        }
        self.write(key, gzipped.unwrap_or(body), at, etag, max_age);
    }

    fn write(&self, key: &str, stored: &[u8], at: i64, etag: Option<&str>, max_age: Option<i64>) {
        let file = self.file(key);
        let mut head = crate::json::Object::new();
        head.insert("at", at.into());
        head.insert("key", key.into());
        if let Some(e) = etag {
            head.insert("etag", e.into());
        }
        if let Some(m) = max_age {
            head.insert("maxAge", m.into());
        }
        let mut data = crate::json::to_string(&head.into()).into_bytes();
        data.push(b'\n');
        data.extend_from_slice(stored);
        if let Some(parent) = file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // A cache that cannot be written only costs the next run a request.
        let _ = crate::util::write_atomic(&file, &data);
    }

    /// The registry said it has not changed: current as of `at`.
    fn touch(&self, key: &str, at: i64) {
        if let Some(kept) = self.get(key) {
            self.write(key, &kept.stored, at, kept.etag.as_deref(), kept.max_age);
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
        // Not over plain http, unless that host's registry is http.
        assert_eq!(auth_for(&auth, "http://r.test/npm/a/-/a.tgz"), None);
        let mut local = auth.clone();
        local.insert(format!("{INSECURE}//r.test/"), String::new());
        assert_eq!(auth_for(&local, "http://r.test/npm/a/-/a.tgz").as_deref(), Some("x"));
        // Not for a path the server would resolve outside the prefix.
        for url in [
            "https://r.test/npm/../other",
            "https://r.test/npm/%2e%2e/other",
            "https://r.test/npm/./a",
            "https://r.test/npm/\\..\\other",
            "https://r.test/npm/%5c..%5cother",
            "https://r.test/npm/..;/other",
            "HTTPS://r.test/npm/..;",
            "https://r.test/npm/..;x/other",
            "https://r.test/npm/.;/a",
            "https://r.test/npm/.;x=1/a",
        ] {
            assert_eq!(auth_for(&auth, url), None, "{url}");
        }
    }

    #[test]
    fn matches_globs() {
        assert!(wildcard(b"@s/*", b"@s/a"));
        assert!(!wildcard(b"*", b"@s/a"));
        assert!(wildcard(b"**", b"@s/a"));
        assert!(wildcard(b"a?c", b"abc"));
        assert!(!wildcard(b"a?c", b"a/c"));
        assert!(wildcard(b"@s/a*-*", b"@s/ab-c-d"));
        assert!(!wildcard(b"@*a", b"@s/a"));
        assert!(wildcard(b"@**a", b"@s/a"));
        assert!(wildcard(b"***", b"@s/a"));
        assert!(!wildcard(b"a", b"ab") && !wildcard(b"ab", b"a") && wildcard(b"", b""));
    }

    #[test]
    fn globs_in_bounded_time() {
        // Exponential backtracking on `**`, and a recursion per pattern byte, were a hang and a
        // stack overflow. Run in a thread so a regression fails here instead of hanging.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let stars = format!("{}x", "**".repeat(80));
            let r = wildcard(stars.as_bytes(), "a".repeat(200).as_bytes());
            let long = "*".repeat(100_000);
            tx.send((r, wildcard(long.as_bytes(), b"a"), wildcard(&[b'*'; 1024], b"a"))).unwrap();
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("wildcard hung");
        assert_eq!(got, (false, false, true));
    }

    #[test]
    fn keeps_documents_as_the_registry_sent_them() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("jpm-docs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = DocCache { dir: dir.clone(), mode: CacheMode::Only };
        let body = br#"{"name":"a","versions":{}}"#;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(body).unwrap();
        let gz = gz.finish().unwrap();
        let key = "corgi https://r.test/a";
        let on_disk = || {
            let bytes = std::fs::read(cache.file(key)).unwrap();
            bytes[bytes.iter().position(|b| *b == b'\n').unwrap() + 1..].to_vec()
        };
        // Gzipped as it came, read back unpacked.
        cache.set(key, body, Some(&gz), 1, Some("\"e\""), None);
        assert_eq!(on_disk(), gz);
        let kept = cache.get(key).unwrap();
        assert_eq!((kept.body.as_slice(), kept.at, kept.etag.as_deref()), (&body[..], 1, Some("\"e\"")));
        // Touched: the same bytes, a new time.
        cache.touch(key, 2);
        assert_eq!(on_disk(), gz);
        assert_eq!(cache.get(key).unwrap().at, 2);
        // A body that came plain is kept plain, as every document was before.
        cache.set(key, body, None, 3, None, None);
        assert_eq!(on_disk(), body);
        assert_eq!(cache.get(key).unwrap().body, body);
        // A page that is not a document is never kept, gzipped or not.
        cache.set("corgi https://r.test/b", b"<html>", Some(&gz), 3, None, None);
        assert!(cache.get("corgi https://r.test/b").is_none());
        // A torn gzip reads as nothing kept.
        let file = cache.file(key);
        let text = std::fs::read(&file).unwrap();
        let head = &text[..=text.iter().position(|b| *b == b'\n').unwrap()];
        std::fs::write(&file, [head, &gz[..gz.len() / 2]].concat()).unwrap();
        assert!(cache.get(key).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keeps_publish_dates_beside_the_full_document() {
        let dir = std::env::temp_dir().join(format!("jpm-times-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = Config { registry: "https://r.test".into(), offline: true, ..Config::default() };
        let times = || Registry::new(&config, Some(&dir)).kept_times("a").map(|t| t["1.0.0"].clone());
        let cache = DocCache { dir: dir.clone(), mode: CacheMode::Only };
        let keep = |date: &str| {
            let body = format!(r#"{{"name":"a","versions":{{"1.0.0":{{}}}},"time":{{"1.0.0":"{date}"}}}}"#);
            cache.set("full https://r.test/a", body.as_bytes(), None, 0, None, None);
        };
        let side = dir.join("r.test/a/_full.times");
        keep("2020-01-01");
        // Older than any sidecar written from it: a stamp from the same clock tick proves nothing.
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let full = std::fs::File::options().write(true).open(cache.file("full https://r.test/a")).unwrap();
        full.set_modified(hour_ago).unwrap();
        assert_eq!(times().unwrap(), "2020-01-01");
        let text = std::fs::read_to_string(&side).unwrap();
        // Read from beside the document while its stamp is the document's.
        std::fs::write(&side, text.replace("2020-01-01", "2021-01-01")).unwrap();
        assert_eq!(times().unwrap(), "2021-01-01");
        // The document written again: stale, so read from the document and written again.
        std::thread::sleep(std::time::Duration::from_millis(10));
        keep("2022-01-01");
        assert_eq!(times().unwrap(), "2022-01-01");
        assert!(std::fs::read_to_string(&side).unwrap().contains("2022-01-01"));
        // Unreadable, or with no dates: the document answers.
        let stamp = std::fs::read_to_string(&side).unwrap().lines().next().unwrap().to_string();
        for bad in ["{\"time\":", "{}", ""] {
            std::fs::write(&side, format!("{stamp}\n{bad}")).unwrap();
            assert_eq!(times().unwrap(), "2022-01-01", "{bad}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn doc() -> Packument {
        Packument::parse(
            br#"{"name":"a","dist-tags":{"latest":"1.1.0","next":"2.0.0-rc.1"},"versions":{
            "1.0.0":{"name":"a","version":"1.0.0"},
            "1.1.0":{"name":"a","version":"1.1.0"},
            "1.2.0":{"name":"a","version":"1.2.0","deprecated":"no"},
            "2.0.0-rc.1":{"name":"a","version":"2.0.0-rc.1"}}}"#
                .to_vec(),
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
        assert_eq!(pick("*").unwrap(), "1.1.0");
        assert_eq!(pick("^3").unwrap_err().code, "ETARGET");
        assert_eq!(pick("nope").unwrap_err().code, "ETARGET");
    }

    #[test]
    fn star_takes_a_prerelease_latest_only_when_there_is_no_release() {
        // pnpm's registry-mock has-prerelease and has-beta-only.
        let doc = |versions: &[&str]| {
            let list: Vec<String> =
                versions.iter().map(|v| format!(r#""{v}":{{"name":"a","version":"{v}"}}"#)).collect();
            let text = format!(
                r#"{{"name":"a","dist-tags":{{"latest":"{}"}},"versions":{{{}}}}}"#,
                versions[0],
                list.join(",")
            );
            Packument::parse(text.into_bytes()).unwrap()
        };
        let star = |d: &Packument| pick_manifest(d, &parse_dep("a", "*").unwrap()).unwrap().version.clone();
        assert_eq!(star(&doc(&["3.0.0-rc.0", "1.0.0", "2.0.0"])), "2.0.0");
        assert_eq!(star(&doc(&["1.0.0-beta.1"])), "1.0.0-beta.1");
    }

    type Asked = Arc<Mutex<Vec<(String, String)>>>;

    /// A registry of documents by path, each `(abbreviated, full)`, either missing (a 404).
    /// Every request is kept as `(kind, path)`, the kind `corgi` or `full` by what it accepts.
    fn registry_of(docs: HashMap<String, (Option<String>, Option<String>)>) -> (String, Asked) {
        use std::io::{BufRead, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let asked: Asked = Arc::default();
        let (docs, a) = (Arc::new(docs), asked.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (docs, asked) = (docs.clone(), a.clone());
                std::thread::spawn(move || {
                    let mut reader = std::io::BufReader::new(stream);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                        let mut corgi = false;
                        line.clear();
                        while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                            corgi |= line.to_ascii_lowercase().starts_with("accept: application/vnd.npm.install-v1");
                            line.clear();
                        }
                        asked.lock().unwrap().push((if corgi { "corgi" } else { "full" }.to_string(), path.clone()));
                        let body = docs.get(&path).and_then(|(c, f)| if corgi { c.clone() } else { f.clone() });
                        let (status, body) = body.map_or(("404 Not Found", "{}".to_string()), |b| ("200 OK", b));
                        let head = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n\r\n", body.len());
                        if reader.get_mut().write_all(format!("{head}{body}").as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (base, asked)
    }

    /// A platform package's two documents: each `(version, published)` for `os`, the full one
    /// with its libc and dates.
    fn platform_docs(name: &str, os: &str, versions: &[(&str, &str)]) -> (Option<String>, Option<String>) {
        let manifest = |v: &str, libc: &str| {
            format!(
                r#""{v}":{{"name":"{name}","version":"{v}","os":["{os}"],"cpu":["x64"]{libc},"dist":{{"tarball":"http://t/t.tgz","integrity":"sha512-AAAA"}}}}"#
            )
        };
        let latest = versions.last().unwrap().0;
        let doc = |libc: &str, extra: String| {
            let list: Vec<String> = versions.iter().map(|(v, _)| manifest(v, libc)).collect();
            format!(
                r#"{{"name":"{name}","dist-tags":{{"latest":"{latest}"}},"versions":{{{}}}{extra}}}"#,
                list.join(",")
            )
        };
        let newest = versions.iter().map(|(_, t)| *t).max().unwrap();
        let times: Vec<String> = versions.iter().map(|(v, t)| format!(r#""{v}":"{t}""#)).collect();
        let corgi = doc("", format!(r#","modified":"{newest}""#));
        let full = doc(r#","libc":["glibc"]"#, format!(r#","time":{{"modified":"{newest}",{}}}"#, times.join(",")));
        (Some(corgi), Some(full))
    }

    #[test]
    fn reads_a_scoped_linux_package_from_its_full_document_alone() {
        let old = "2000-01-01T00:00:00.000Z";
        let (linux, darwin) = ("@s/binding-linux-x64-gnu", "@s/binding-darwin-x64");
        let docs = [
            ("/@s%2fbinding-linux-x64-gnu".to_string(), platform_docs(linux, "linux", &[("1.0.0", old)])),
            ("/@s%2fbinding-darwin-x64".to_string(), platform_docs(darwin, "darwin", &[("1.0.0", old)])),
        ];
        let (base, asked) = registry_of(docs.into_iter().collect());
        let config = Config { registry: base, before: Some(now_ms()), ..Config::default() };
        let registry = Registry::new(&config, None);
        let m = registry.pick(&parse_dep(linux, "1.0.0").unwrap(), Some("1.0.0"), false).unwrap();
        assert_eq!((m.version.as_str(), m.libc.clone()), ("1.0.0", Some(vec!["glibc".to_string()])));
        // libc, and the release cutoff's dates, came with it: nothing more is asked.
        assert_eq!(registry.manifest(linux, "1.0.0").unwrap().libc, Some(vec!["glibc".to_string()]));
        registry.pick(&parse_dep(darwin, "1.0.0").unwrap(), Some("1.0.0"), false).unwrap();
        let asked = asked.lock().unwrap().clone();
        let each = |kind: &str, path: &str| (kind.to_string(), path.to_string());
        assert_eq!(asked, [each("full", "/@s%2fbinding-linux-x64-gnu"), each("corgi", "/@s%2fbinding-darwin-x64")]);
    }

    #[test]
    fn cuts_a_full_document_at_the_release_cutoff_by_its_own_dates() {
        let name = "@s/tool-linux-x64";
        let versions = [("1.0.0", "2000-01-01T00:00:00.000Z"), ("2.0.0", "2999-01-01T00:00:00.000Z")];
        let docs = [("/@s%2ftool-linux-x64".to_string(), platform_docs(name, "linux", &versions))];
        let (base, _) = registry_of(docs.into_iter().collect());
        let config = Config { registry: base.clone(), before: Some(now_ms()), ..Config::default() };
        let registry = Registry::new(&config, None);
        // Too new: gone from the pick, and `latest` moved back to what is left.
        assert_eq!(registry.pick(&parse_dep(name, "*").unwrap(), None, false).unwrap().version, "1.0.0");
        let pinned = registry.pick(&parse_dep(name, "2.0.0").unwrap(), Some("2.0.0"), false);
        assert_eq!(pinned.unwrap_err().code, "ETARGET");
        // A version the lockfile names is past the cutoff, as before.
        assert_eq!(registry.pick(&parse_dep(name, "2.0.0").unwrap(), Some("2.0.0"), true).unwrap().version, "2.0.0");
        // Excluded, or with no cutoff, the newest is there.
        let excluded = Config { release_age_exclude: vec!["@s/*".into()], ..config.clone() };
        let pick = |c: &Config| Registry::new(c, None).pick(&parse_dep(name, "*").unwrap(), None, false).unwrap();
        assert_eq!(pick(&excluded).version, "2.0.0");
        assert_eq!(pick(&Config { before: None, ..config }).version, "2.0.0");
    }

    #[test]
    fn falls_back_to_the_abbreviated_document_without_a_full_one() {
        let name = "@s/binding-linux-arm64-musl";
        let (corgi, _) = platform_docs(name, "linux", &[("1.0.0", "2000-01-01T00:00:00.000Z")]);
        let docs = [("/@s%2fbinding-linux-arm64-musl".to_string(), (corgi, None))];
        let (base, asked) = registry_of(docs.into_iter().collect());
        let registry = Registry::new(&Config { registry: base, ..Config::default() }, None);
        let m = registry.pick(&parse_dep(name, "1.0.0").unwrap(), Some("1.0.0"), false).unwrap();
        assert_eq!((m.version.as_str(), m.libc.as_ref()), ("1.0.0", None));
        let kinds: Vec<String> = asked.lock().unwrap().iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(kinds, ["full", "corgi"]);
    }
}
