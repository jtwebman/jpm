//! `jpm.lock`: a flat lockfile keyed by identity, in upm's format, so a project can move between
//! the two. Written with fixed field order and sorted maps, so the same resolution is always the
//! same bytes.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bin;
use crate::error::{Error, Result};
use crate::graph::{Deps, Package, Peers, Resolution, Root, Specs, same_specs, split_key};
use crate::project::{RootManifest, Workspace, local_path, local_shape};
use crate::registry::tarball_url;
use crate::semver;
use crate::spec::{self, Kind};
use crate::util::write_atomic;

pub const LOCKFILE: &str = "jpm.lock";
/// upm's lockfile has the same format, and is read when there is no `jpm.lock`.
pub const UPM_LOCKFILE: &str = "upm.lock";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LockEntry {
    /// Only for a tarball dependency, whose key ends in its source: the version inside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Only when the tarball is not where the registry would put it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    pub integrity: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: Deps,
    #[serde(default, rename = "optionalDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    pub optional_dependencies: Deps,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bin: Deps,
    #[serde(default, rename = "peerDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_dependencies: Deps,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peers: Peers,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpu: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libc: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specs: Option<Specs>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: Deps,
    #[serde(default, rename = "optionalDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    pub optional_dependencies: Deps,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bin: Deps,
    #[serde(default, rename = "peerDependencies", skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_dependencies: Deps,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peers: Peers,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LockRoot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specs: Option<Specs>,
    pub dependencies: Deps,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspaces: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Lockfile {
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,
    pub root: LockRoot,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub workspaces: BTreeMap<String, WorkspaceEntry>,
    pub packages: BTreeMap<String, LockEntry>,
}

fn fail(message: impl Into<String>) -> Error {
    Error::new("ELOCK", message)
}

fn opt_map(m: &Deps) -> Option<Deps> {
    (!m.is_empty()).then(|| m.clone())
}

fn root_of(root: &Root) -> LockRoot {
    LockRoot {
        name: root.name.clone(),
        version: root.version.clone(),
        specs: Specs::canonical(root.specs.as_ref()),
        dependencies: root.dependencies.clone(),
        workspaces: root.workspaces.clone().filter(|w| !w.is_empty()),
    }
}

/// `base_for` gives each name's registry, to tell a derivable tarball url from one to keep.
pub fn to_lockfile(res: &Resolution, base_for: &dyn Fn(&str) -> String) -> Lockfile {
    let mut packages = BTreeMap::new();
    let mut workspaces = BTreeMap::new();
    for (key, p) in &res.packages {
        if let Some(path) = &p.local {
            workspaces.insert(
                path.clone(),
                WorkspaceEntry {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    specs: Specs::canonical(p.specs.as_ref()),
                    dependencies: p.dependencies.clone(),
                    optional_dependencies: p.optional_dependencies.clone(),
                    bin: p.bin.clone(),
                    peer_dependencies: p.peer_dependencies.clone().unwrap_or_default(),
                    peers: p.peers.clone().unwrap_or_default(),
                },
            );
            continue;
        }
        let (version, resolved) = if p.source.is_some() {
            (Some(p.version.clone()), None)
        } else {
            let derivable = p.resolved == tarball_url(&base_for(&p.name), &p.name, &p.version);
            (None, (!derivable).then(|| p.resolved.clone()))
        };
        packages.insert(
            key.clone(),
            LockEntry {
                version,
                resolved,
                integrity: p.integrity.clone(),
                dependencies: p.dependencies.clone(),
                optional_dependencies: p.optional_dependencies.clone(),
                bin: p.bin.clone(),
                peer_dependencies: p.peer_dependencies.clone().unwrap_or_default(),
                peers: p.peers.clone().unwrap_or_default(),
                os: p.os.clone().unwrap_or_default(),
                cpu: p.cpu.clone().unwrap_or_default(),
                libc: p.libc.clone().unwrap_or_default(),
            },
        );
    }
    Lockfile { lockfile_version: VERSION, root: root_of(&res.root), workspaces, packages }
}

/// No packument, no version pick, no semver: the whole point of a lockfile. `lock` must have
/// passed `validate`.
pub fn from_lockfile(lock: &Lockfile, base_for: &dyn Fn(&str) -> String) -> Resolution {
    let shipped = reach(lock, &|top, name| top.prod.contains(name), true);
    let required =
        reach(lock, &|top, name| !top.specs.as_ref().is_some_and(|s| s.optional().contains_key(name)), false);
    let mut packages = BTreeMap::new();
    for (path, ws) in &lock.workspaces {
        packages.insert(
            format!("{}@link:{path}", ws.name),
            Package {
                name: ws.name.clone(),
                version: ws.version.clone(),
                local: Some(path.clone()),
                specs: ws.specs.clone(),
                dependencies: ws.dependencies.clone(),
                optional_dependencies: ws.optional_dependencies.clone(),
                bin: bin::clean_map(&ws.bin),
                peer_dependencies: opt_map(&ws.peer_dependencies),
                peers: (!ws.peers.is_empty()).then(|| ws.peers.clone()),
                ..Package::default()
            },
        );
    }
    for (key, e) in &lock.packages {
        let Some((name, tail)) = split_key(key) else { continue };
        let source = e.version.as_ref().map(|_| tail.to_string());
        let version = e.version.clone().unwrap_or_else(|| tail.to_string());
        let resolved = source
            .clone()
            .or_else(|| e.resolved.clone())
            .unwrap_or_else(|| tarball_url(&base_for(name), name, &version));
        let list = |l: &Vec<String>| (!l.is_empty()).then(|| l.clone());
        packages.insert(
            key.clone(),
            Package {
                name: name.to_string(),
                version,
                resolved,
                integrity: e.integrity.clone(),
                source,
                dependencies: e.dependencies.clone(),
                optional_dependencies: e.optional_dependencies.clone(),
                optional: !required.contains(key),
                dev: !shipped.contains(key),
                bin: bin::clean_map(&e.bin),
                os: list(&e.os),
                cpu: list(&e.cpu),
                libc: list(&e.libc),
                peer_dependencies: opt_map(&e.peer_dependencies),
                peers: (!e.peers.is_empty()).then(|| e.peers.clone()),
                ..Package::default()
            },
        );
    }
    let root = Root {
        name: lock.root.name.clone(),
        version: lock.root.version.clone(),
        specs: lock.root.specs.clone(),
        dependencies: lock.root.dependencies.clone(),
        workspaces: lock.root.workspaces.clone(),
    };
    Resolution { root, packages, warnings: Vec::new() }
}

struct Top<'a> {
    specs: Option<&'a Specs>,
    deps: Deps,
    prod: HashSet<String>,
}

fn top<'a>(specs: Option<&'a Specs>, deps: Deps, peers: &Deps) -> Top<'a> {
    let mut prod: HashSet<String> = HashSet::new();
    if let Some(s) = specs {
        prod.extend(s.dependencies.iter().flatten().map(|(k, _)| k.clone()));
        prod.extend(s.optional().keys().cloned());
    }
    let dev = specs.map(Specs::dev);
    prod.extend(peers.keys().filter(|p| !dev.is_some_and(|d| d.contains_key(*p))).cloned());
    Top { specs, deps, prod }
}

/// Every workspace, and what the tops' edges `seed` accepts lead to. `optional` also follows
/// optional edges (for what ships); without it only required ones (for what is required).
fn reach(lock: &Lockfile, seed: &dyn Fn(&Top, &str) -> bool, optional: bool) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut tops = vec![top(lock.root.specs.as_ref(), lock.root.dependencies.clone(), &Deps::new())];
    for (path, ws) in &lock.workspaces {
        seen.insert(format!("{}@link:{path}", ws.name));
        let mut edges = ws.dependencies.clone();
        edges.extend(ws.optional_dependencies.clone());
        tops.push(top(ws.specs.as_ref(), edges, &ws.peer_dependencies));
    }
    let mut queue = Vec::new();
    for t in &tops {
        for (name, version) in &t.deps {
            let key = format!("{name}@{version}");
            if seed(t, name) && lock.packages.contains_key(&key) && seen.insert(key.clone()) {
                queue.push(key);
            }
        }
    }
    while let Some(key) = queue.pop() {
        let e = &lock.packages[&key];
        let maps: &[&Deps] = if optional { &[&e.dependencies, &e.optional_dependencies] } else { &[&e.dependencies] };
        for (name, version) in maps.iter().flat_map(|m| m.iter()) {
            let k = format!("{name}@{version}");
            if lock.packages.contains_key(&k) && seen.insert(k.clone()) {
                queue.push(k);
            }
        }
    }
    seen
}

pub fn format_lockfile(lock: &Lockfile) -> Result<String> {
    validate(lock)?; // a lockfile our own reader would reject must never reach disk
    let mut lock = lock.clone();
    lock.root.specs = Specs::canonical(lock.root.specs.as_ref());
    for ws in lock.workspaces.values_mut() {
        ws.specs = Specs::canonical(ws.specs.as_ref());
    }
    Ok(crate::util::pretty(&lock))
}

pub fn parse_lockfile(text: &str, file: &str) -> Result<Lockfile> {
    let lock: Lockfile = serde_json::from_str(text).map_err(|e| {
        let version =
            serde_json::from_str::<serde_json::Value>(text).ok().and_then(|v| v.get("lockfileVersion").cloned());
        match version {
            Some(v) if v != serde_json::json!(VERSION) => {
                fail(format!("unsupported lockfileVersion {v}, expected {VERSION}"))
            }
            _ => fail(format!("{file} is not a valid lockfile: {e}")),
        }
    })?;
    validate(&lock)?;
    Ok(lock)
}

/// The lockfile in `dir`: `jpm.lock`, else upm's. `None` when there is neither.
pub fn read_lockfile(dir: &Path) -> Result<Option<(Lockfile, &'static str)>> {
    for name in [LOCKFILE, UPM_LOCKFILE] {
        let file = dir.join(name);
        match std::fs::read_to_string(&file) {
            Ok(text) => return parse_lockfile(&text, name).map(|l| Some((l, name))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&e, format!("cannot read {}", file.display())).with_code("ELOCK")),
        }
    }
    Ok(None)
}

pub fn write_lockfile(dir: &Path, lock: &Lockfile) -> Result<()> {
    write_atomic(&dir.join(LOCKFILE), format_lockfile(lock)?.as_bytes())
}

/// Whether the lockfile was made from this tree: the same workspace patterns, workspaces and
/// declared ranges. Anything else means a resolve.
pub fn same_tree(lock: &Lockfile, manifest: &RootManifest, workspaces: &[Workspace]) -> bool {
    let patterns = manifest.workspaces.clone().unwrap_or_default();
    if patterns != lock.root.workspaces.clone().unwrap_or_default() {
        return false;
    }
    if !same_specs(manifest.specs().as_ref(), lock.root.specs.as_ref()) {
        return false;
    }
    if lock.workspaces.len() != workspaces.len() {
        return false;
    }
    workspaces.iter().all(|ws| {
        let Some(entry) = lock.workspaces.get(&ws.path) else { return false };
        if entry.name != ws.name || entry.version != ws.version {
            return false;
        }
        let shape = local_shape(&ws.manifest);
        same_specs(shape.specs.as_ref(), entry.specs.as_ref())
            && shape.bin == entry.bin
            && shape.peer_dependencies.unwrap_or_default() == entry.peer_dependencies
            && shape.peers.unwrap_or_default() == entry.peers
    })
}

/// What `read_lockfile` checks: every edge closed, every key and path safe to become a path.
pub fn validate(lock: &Lockfile) -> Result<()> {
    if lock.lockfile_version != VERSION {
        return Err(fail(format!("unsupported lockfileVersion {}, expected {VERSION}", lock.lockfile_version)));
    }
    let mut known: HashSet<String> = lock.packages.keys().cloned().collect();
    let mut named: BTreeMap<&str, &str> = BTreeMap::new();
    for (path, ws) in &lock.workspaces {
        let at = format!("workspaces[{path:?}]");
        if !local_path(path) {
            return Err(fail(format!("{at} is not a relative path inside the project")));
        }
        if !semver::is_exact(&ws.version) || spec::parse_dep(&ws.name, &ws.version).is_err() {
            return Err(fail(format!("{at}.version must be an exact version")));
        }
        if let Some(other) = named.insert(&ws.name, path) {
            return Err(fail(format!("workspaces[{other:?}] and {at} are both named {}", ws.name)));
        }
        known.insert(format!("{}@link:{path}", ws.name));
    }
    for (key, e) in &lock.packages {
        let at = format!("packages[{key:?}]");
        let source = check_key(key)?;
        if e.integrity.is_empty() {
            return Err(fail(format!("{at}.integrity must be a non-empty string")));
        }
        if source.is_some() {
            if !e.version.as_deref().is_some_and(semver::is_exact) {
                return Err(fail(format!("{at}.version must be an exact version")));
            }
            if e.resolved.is_some() {
                return Err(fail(format!("{at}.resolved is its key's to say")));
            }
        } else if e.version.is_some() {
            return Err(fail(format!("{at}.version is only for a tarball, whose key names where it is")));
        } else if let Some(r) = &e.resolved {
            // A `data:` url would let a lockfile carry a payload that was never on a registry.
            if !(r.starts_with("http://") || r.starts_with("https://")) {
                return Err(fail(format!("{at}.resolved must be an http or https url")));
            }
        }
        // A store entry links to packages only: a workspace is reached from a top, never from it.
        check_edges(&at, &e.bin, &e.peers, &e.peer_dependencies, [&e.dependencies, &e.optional_dependencies], &|k| {
            lock.packages.contains_key(k)
        })?;
    }
    for (path, ws) in &lock.workspaces {
        let at = format!("workspaces[{path:?}]");
        check_edges(
            &at,
            &ws.bin,
            &ws.peers,
            &ws.peer_dependencies,
            [&ws.dependencies, &ws.optional_dependencies],
            &|k| known.contains(k),
        )?;
        let me = format!("{}@link:{path}", ws.name);
        let mut edges = ws.dependencies.clone();
        edges.extend(ws.optional_dependencies.clone());
        if edges.iter().any(|(n, v)| format!("{n}@{v}") == me) {
            return Err(fail(format!("{at} depends on itself")));
        }
        check_top(ws.specs.as_ref(), &edges, &at, &ws.peer_dependencies)?;
    }
    for (name, version) in &lock.root.dependencies {
        if !known.contains(&format!("{name}@{version}")) {
            let place = if version.starts_with("link:") { "workspaces" } else { "packages" };
            return Err(fail(format!(
                "root.dependencies[{name:?}] points at {name}@{version}, which is not in {place}"
            )));
        }
    }
    check_top(lock.root.specs.as_ref(), &lock.root.dependencies, "root", &Deps::new())
}

/// Every direct dep of a top is in its specs: `dev` is read out of them.
fn check_top(specs: Option<&Specs>, deps: &Deps, at: &str, peers: &Deps) -> Result<()> {
    for name in deps.keys() {
        if !specs.is_some_and(|s| s.has(name)) && !peers.contains_key(name) {
            return Err(fail(format!("{at}.dependencies[{name:?}] is in no {at}.specs group, so it has no dev flag")));
        }
    }
    Ok(())
}

fn check_edges(
    at: &str,
    bins: &Deps,
    peers: &Peers,
    ranges: &Deps,
    maps: [&Deps; 2],
    known: &dyn Fn(&str) -> bool,
) -> Result<()> {
    for (name, target) in bins {
        if escapes(name) || escapes(target) {
            return Err(fail(format!("{at}.bin[{name:?}] escapes the package directory")));
        }
    }
    for (field, map) in ["dependencies", "optionalDependencies"].iter().zip(maps) {
        for (name, version) in map {
            if !known(&format!("{name}@{version}")) {
                let place = if version.starts_with("link:") { "workspaces" } else { "packages" };
                return Err(fail(format!(
                    "{at}.{field}[{name:?}] points at {name}@{version}, which is not in {place}"
                )));
            }
        }
    }
    for name in peers.keys() {
        if !ranges.contains_key(name) {
            return Err(fail(format!("{at}.peers[{name:?}] is not in {at}.peerDependencies")));
        }
    }
    Ok(())
}

/// A bin name or target that climbs out of its directory would let a lockfile write anywhere.
fn escapes(value: &str) -> bool {
    let clean = value.replace('\\', "/");
    clean.starts_with('/') || clean.split('/').any(|p| p == "..")
}

/// A key is `name@version` or `name@<source>`, and both halves become path segments.
fn check_key(key: &str) -> Result<Option<String>> {
    let bad = || fail(format!("package key {key:?} is not name@version"));
    let (name, version) = split_key(key).filter(|(_, v)| !v.is_empty()).ok_or_else(bad)?;
    let spec =
        spec::parse_dep(name, version).map_err(|_| fail(format!("package key {key:?} is not a valid package name")))?;
    if spec.kind == Kind::Tarball {
        if spec.fetch_spec != version {
            return Err(fail(format!("package key {key:?} does not name its tarball as a lockfile does")));
        }
        return Ok(Some(version.to_string()));
    }
    if !semver::is_exact(version) {
        return Err(fail(format!("package key {key:?} does not end in an exact version")));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lockfile {
        parse_lockfile(
            r#"{
  "lockfileVersion": 1,
  "root": {
    "name": "app",
    "specs": { "dependencies": { "a": "^1" }, "devDependencies": { "d": "^1" } },
    "dependencies": { "a": "1.0.0", "d": "1.0.0" }
  },
  "packages": {
    "a@1.0.0": { "integrity": "sha512-a", "dependencies": { "b": "1.0.0" }, "optionalDependencies": { "c": "1.0.0" } },
    "b@1.0.0": { "integrity": "sha512-b", "bin": { "b": "cli.js" } },
    "c@1.0.0": { "integrity": "sha512-c", "os": ["darwin"] },
    "d@1.0.0": { "integrity": "sha512-d", "dependencies": { "b": "1.0.0" } }
  }
}
"#,
            LOCKFILE,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_byte_for_byte() {
        let lock = sample();
        let base = |_: &str| "https://registry.npmjs.org".to_string();
        let res = from_lockfile(&lock, &base);
        assert!(!res.packages["b@1.0.0"].dev);
        assert!(res.packages["d@1.0.0"].dev);
        assert!(res.packages["c@1.0.0"].optional);
        assert!(!res.packages["b@1.0.0"].optional);
        assert_eq!(res.packages["a@1.0.0"].resolved, "https://registry.npmjs.org/a/-/a-1.0.0.tgz");
        let again = to_lockfile(&res, &base);
        assert_eq!(format_lockfile(&again).unwrap(), format_lockfile(&lock).unwrap());
    }

    #[test]
    fn refuses_unsafe_lockfiles() {
        let mut lock = sample();
        lock.packages.get_mut("b@1.0.0").unwrap().bin.insert("x".into(), "../../etc".into());
        assert!(validate(&lock).is_err());
        let mut lock = sample();
        lock.packages.get_mut("a@1.0.0").unwrap().dependencies.insert("z".into(), "1.0.0".into());
        assert!(validate(&lock).unwrap_err().message.contains("not in packages"));
        let mut lock = sample();
        lock.packages.get_mut("a@1.0.0").unwrap().resolved = Some("data:x".into());
        assert!(validate(&lock).is_err());
        let mut lock = sample();
        let e = lock.packages.remove("b@1.0.0").unwrap();
        lock.packages.insert("../b@1.0.0".into(), e);
        assert!(validate(&lock).is_err());
        assert!(
            parse_lockfile(r#"{"lockfileVersion":2,"root":{"dependencies":{}},"packages":{}}"#, "x")
                .unwrap_err()
                .message
                .contains("unsupported")
        );
    }
}
