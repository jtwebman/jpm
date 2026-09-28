//! The lockfile npm, pnpm or bun left in a project, read so jpm installs the tree it holds and
//! writes no `jpm.lock` beside it. Every format is a set of `name@version` nodes with edges once
//! npm's and bun's path-keyed maps are walked the way Node resolves and pnpm's peer suffixes are
//! stripped. Read only when a project has one of these files and no `jpm.lock`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::json::{self, Object as Map, Value};

use crate::bin::{self, Bins};
use crate::error::{Error, Result};
use crate::graph::{Deps, PeerKind, Peers, Specs};
use crate::lock::{self, LockEntry, LockRoot, Lockfile};
use crate::project::{GROUPS, RootManifest};
use crate::registry::tarball_url;
use crate::semver::max_satisfying;

pub const FOREIGN: [&str; 4] = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lock"];

pub struct ForeignLock {
    pub lock: Lockfile,
    /// Keys of packages whose bins the file does not name (pnpm records only hasBin).
    pub binless: Vec<String>,
    pub warnings: Vec<String>,
}

/// One package as the file records it, edges already exact versions.
#[derive(Debug, Clone, Default)]
struct Node {
    /// What it is installed as.
    name: String,
    /// The registry package, when `name` is an alias for it.
    real: Option<String>,
    version: String,
    resolved: Option<String>,
    integrity: String,
    dependencies: Deps,
    optional_dependencies: Deps,
    peer_dependencies: Deps,
    peers: Peers,
    bin: Bins,
    has_bin: bool,
    os: Vec<String>,
    cpu: Vec<String>,
    libc: Vec<String>,
}

struct Source {
    nodes: Vec<Node>,
    /// The ranges the file recorded for the root: what package.json is held to.
    specs: Specs,
    /// Root edges, name -> version.
    root: Deps,
    /// The overrides the file was resolved under, where it records them (bun).
    overrides: Option<Value>,
}

/// What an edge finds: a version, a copy inside the parent's tarball, or nothing from a registry.
enum Target {
    Version(String),
    Bundled,
    Missing,
}

/// Another manager's lockfile as jpm's, when it still describes package.json exactly: the same
/// tree, nothing resolved. What it cannot say exactly is refused here; `pins` then reads its
/// versions for a resolve. `file` is one of FOREIGN. `has_workspaces` is true when the project declares or has workspaces.
/// `base_for(name)` gives the registry base url for a package name.
pub fn load(
    file: &str,
    text: &str,
    manifest: &RootManifest,
    has_workspaces: bool,
    base_for: &dyn Fn(&str) -> String,
) -> Result<ForeignLock> {
    if has_workspaces {
        return Err(fail(format!("{file} has workspaces, which jpm reads only for their versions")));
    }
    let mut source = match file {
        "package-lock.json" | "npm-shrinkwrap.json" => read_npm(text)?,
        "pnpm-lock.yaml" => read_pnpm(text)?,
        "bun.lock" => read_bun(text)?,
        _ => return Err(fail(format!("jpm does not read {file}"))),
    };
    hold_to(file, &mut source, manifest)?;
    build(file, source, manifest, base_for)
}

/// Every registry package version the file names, as `(name, version)`, read loosely: what a
/// file that cannot be brought over whole (out of date, with workspaces, an older format) still
/// says about which versions the project used. npm, pnpm (any version) and bun.
pub fn pins(file: &str, text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    match file {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            let doc = json::parse(text).map_err(|e| fail(format!("{file} cannot be read: {}", e.message)))?;
            // v2 and v3 list every path; v1 nests `dependencies`.
            let mut stack: Vec<(String, &Value)> = Vec::new();
            if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
                for (path, entry) in packages {
                    let Some(at) = path.rfind(NM) else { continue };
                    let name = entry.get("name").and_then(Value::as_str).unwrap_or(&path[at + NM.len()..]);
                    if let Some(v) = npm_version(entry) {
                        out.push((name.to_string(), v.to_string()));
                    }
                }
            } else if let Some(deps) = doc.get("dependencies") {
                stack.push((String::new(), deps));
            }
            while let Some((_, deps)) = stack.pop() {
                for (name, entry) in deps.as_object().into_iter().flatten() {
                    if let Some(v) = entry.get("version").and_then(Value::as_str) {
                        // An alias is written `npm:real@version`.
                        match v.strip_prefix("npm:").map(split_id) {
                            Some((real, version)) => out.push((real, version)),
                            None if crate::semver::is_exact(v) => out.push((name.clone(), v.to_string())),
                            None => {}
                        }
                    }
                    if let Some(nested) = entry.get("dependencies") {
                        stack.push((name.clone(), nested));
                    }
                }
            }
        }
        "pnpm-lock.yaml" => {
            let doc = pnpm_doc(text)?;
            for (id, _) in doc.get("packages").and_then(Value::as_object).into_iter().flatten() {
                // `name@1.0.0` (v9), `/name@1.0.0(peer@1)` (v6-8) or `/name/1.0.0_peer@1` (v5).
                let id = strip_peers(id.trim_start_matches('/'));
                let id = id.split('_').next().unwrap_or(id);
                let (name, version) = match id.rfind('@').filter(|at| *at > 0) {
                    Some(at) => (id[..at].to_string(), id[at + 1..].to_string()),
                    None => match id.rsplit_once('/') {
                        Some((n, v)) => (n.to_string(), v.to_string()),
                        None => continue,
                    },
                };
                if crate::semver::is_exact(&version) {
                    out.push((name, version));
                }
            }
        }
        "bun.lock" => {
            let doc = json::parse(&strip_trailing_commas(text))
                .map_err(|e| fail(format!("bun.lock cannot be read: {}", e.message)))?;
            for (_, tuple) in doc.get("packages").and_then(Value::as_object).into_iter().flatten() {
                if let Some(t) = bun_tuple(tuple) {
                    out.push(split_id(t.id));
                }
            }
        }
        _ => return Err(fail(format!("jpm does not read {file}"))),
    }
    Ok(out)
}

fn fail(message: impl Into<String>) -> Error {
    Error::new("ELOCK", message)
}

/// Refuse a file that was not written for this package.json: every name it declares at the root
/// must have the range package.json gives it, and no more names. Managers file a name declared
/// twice under different groups (optional wins in all three, pnpm puts dependencies over dev),
/// so the groups kept are package.json's. pnpm also records the root's own peers, which jpm,
/// like npm without a consumer, does not install.
fn hold_to(file: &str, source: &mut Source, manifest: &RootManifest) -> Result<()> {
    let doc = &manifest.doc;
    let pnpm = doc.get("pnpm").and_then(|p| p.get("patchedDependencies"));
    if truthy(doc.get("patchedDependencies")) || truthy(pnpm) {
        return Err(fail("jpm does not apply the patches package.json names"));
    }
    let stale = || fail(format!("{file} is out of date with package.json"));
    let specs = manifest.specs();
    let declared = flat(specs.as_ref());
    let recorded = flat(Some(&source.specs));
    for (name, range) in &recorded {
        if declared.get(name) == Some(range) {
            continue;
        }
        let peer = manifest.peer_dependencies.as_ref().and_then(|p| p.get(name));
        if declared.contains_key(name) || peer != Some(range) {
            return Err(stale());
        }
        source.root.remove(name);
    }
    if declared.keys().any(|name| !recorded.contains_key(name)) {
        return Err(stale());
    }
    if let Some(overrides) = &source.overrides {
        let given = [doc.get("overrides"), doc.get("resolutions")].into_iter().flatten().find(|v| !v.is_null());
        let empty = Value::Object(Map::new());
        // The same overrides written in another order are the same.
        if !overrides.same_as(given.unwrap_or(&empty)) {
            return Err(stale());
        }
    }
    source.specs = specs.unwrap_or_default();
    Ok(())
}

/// Name -> range, the later group winning: dev, then dependencies, then optional.
fn flat(specs: Option<&Specs>) -> Deps {
    let mut out = Deps::new();
    if let Some(s) = specs {
        for group in [&s.dev_dependencies, &s.dependencies, &s.optional_dependencies] {
            out.extend(group.iter().flatten().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
    out
}

// --- npm package-lock.json v2/v3 --------------------------------------------------------

const NM: &str = "node_modules/";

fn read_npm(text: &str) -> Result<Source> {
    let doc = json::parse(text).map_err(|e| fail(format!("package-lock.json cannot be read: {}", e.message)))?;
    let Some(listed) = doc.get("packages").and_then(Value::as_object) else {
        let v = doc.get("lockfileVersion").filter(|v| !v.is_null()).map_or_else(|| "1".to_string(), string_of);
        return Err(fail(format!("package-lock.json v{v} has no packages map; npm 7 and later write one")));
    };
    let mut nodes = Vec::new();
    let paths = listed.index();
    for (path, entry) in listed {
        // A bundled copy is inside its parent's tarball; a workspace path was refused before this.
        if !path.starts_with(NM) || truthy(entry.get("inBundle")) {
            continue;
        }
        let Some(version) = npm_version(entry) else { continue };
        let name = &path[path.rfind(NM).map_or(0, |i| i + NM.len())..];
        let real = entry.get("name").and_then(Value::as_str).filter(|n| !n.is_empty());
        let from = format!("{path}/");
        let node = Node {
            name: name.to_string(),
            real: real.filter(|r| *r != name).map(str::to_string),
            version: version.to_string(),
            resolved: entry.get("resolved").and_then(Value::as_str).filter(|r| !r.is_empty()).map(str::to_string),
            // npm leaves it out now and then (npm/cli#4460).
            integrity: entry.get("integrity").and_then(Value::as_str).unwrap_or_default().to_string(),
            bin: bin::normalize(Some(real.unwrap_or(name)), entry.get("bin")),
            os: list(entry.get("os")),
            cpu: list(entry.get("cpu")),
            libc: list(entry.get("libc")),
            ..Node::default()
        };
        nodes.push(with_edges(node, &Declared::of(entry), &|dep| match npm_find(&paths, &from, dep) {
            Some(hit) if truthy(hit.get("inBundle")) => Target::Bundled,
            hit => hit.and_then(npm_version).map_or(Target::Missing, |v| Target::Version(v.to_string())),
        }));
    }
    let (specs, root) = root_of(groups_of(paths.get("").copied()), &|name| {
        npm_find(&paths, "", name).and_then(npm_version).map(str::to_string)
    });
    Ok(Source { nodes, specs, root, overrides: None })
}

/// The `node_modules/<name>` a walk up from `from` finds, as Node's resolution does.
fn npm_find<'a>(paths: &HashMap<&str, &'a Value>, from: &str, name: &str) -> Option<&'a Value> {
    let mut dir = from;
    loop {
        if let Some(hit) = paths.get(format!("{dir}{NM}{name}").as_str()).filter(|v| truthy(Some(v))) {
            return Some(*hit);
        }
        if dir.is_empty() {
            return None;
        }
        dir = dir.rfind(NM).map_or("", |up| &dir[..up]);
    }
}

/// The version of an entry from a registry: not a link, not git or a file.
fn npm_version(entry: &Value) -> Option<&str> {
    let version = entry.get("version")?.as_str().filter(|v| !v.is_empty())?;
    let resolved = entry.get("resolved").and_then(Value::as_str).unwrap_or_default();
    let web = resolved.is_empty() || resolved.starts_with("http:") || resolved.starts_with("https:");
    (web && !truthy(entry.get("link"))).then_some(version)
}

/// The edges a package declares, as npm and bun record them.
#[derive(Default)]
struct Declared {
    dependencies: Deps,
    optional: Deps,
    peers: Deps,
    optional_peers: BTreeSet<String>,
}

impl Declared {
    fn of(entry: &Value) -> Self {
        let optional_peers = entry
            .get("peerDependenciesMeta")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter(|(_, v)| truthy(v.get("optional"))).map(|(k, _)| k.clone()).collect())
            .unwrap_or_default();
        Self {
            dependencies: deps(entry.get("dependencies")),
            optional: deps(entry.get("optionalDependencies")),
            peers: deps(entry.get("peerDependencies")),
            optional_peers,
        }
    }
}

/// Own edges, then declared peers, each to whatever `target` finds: how npm and bun lay a tree
/// out. A missing required edge is kept as `""`, to fail the closure check by name; a missing
/// optional one just did not install.
fn with_edges(mut node: Node, declared: &Declared, target: &dyn Fn(&str) -> Target) -> Node {
    for dep in declared.dependencies.keys().chain(declared.optional.keys()) {
        let found = target(dep);
        if matches!(found, Target::Bundled) {
            continue;
        }
        if declared.optional.contains_key(dep) {
            if let Target::Version(v) = found {
                node.optional_dependencies.insert(dep.clone(), v);
            }
        } else {
            let v = if let Target::Version(v) = found { v } else { String::new() };
            node.dependencies.insert(dep.clone(), v);
        }
    }
    for peer in declared.peers.keys() {
        if node.dependencies.contains_key(peer) || node.optional_dependencies.contains_key(peer) {
            continue; // its own edge
        }
        let optional = declared.optional_peers.contains(peer);
        node.peers.insert(peer.clone(), if optional { PeerKind::Optional } else { PeerKind::Required });
        if let Target::Version(v) = target(peer).filter_empty() {
            let edges = if optional { &mut node.optional_dependencies } else { &mut node.dependencies };
            edges.insert(peer.clone(), v);
        }
    }
    node.peer_dependencies = declared.peers.clone();
    node
}

impl Target {
    fn filter_empty(self) -> Self {
        match self {
            Target::Version(v) if v.is_empty() => Target::Missing,
            t => t,
        }
    }
}

/// The root's three groups as a file records them.
fn groups_of(top: Option<&Value>) -> [Deps; 3] {
    GROUPS.map(|g| deps(top.and_then(|t| t.get(g))))
}

/// The root's recorded ranges and its edges, each name resolved by `target`.
fn root_of(groups: [Deps; 3], target: &dyn Fn(&str) -> Option<String>) -> (Specs, Deps) {
    let mut root = Deps::new();
    for (group, declared) in GROUPS.iter().zip(&groups) {
        for name in declared.keys() {
            // Missing is kept, to fail by name; an optional one just did not install.
            let version = target(name).filter(|v| !v.is_empty());
            if version.is_some() || *group != "optionalDependencies" {
                root.insert(name.clone(), version.unwrap_or_default());
            }
        }
    }
    let [dependencies, dev, optional] = groups;
    (Specs::declared(&dependencies, &dev, &optional).unwrap_or_default(), root)
}

// --- pnpm-lock.yaml v9 ------------------------------------------------------------------
// `packages` describes each version, `snapshots` each version with its peer set, and edges
// are exact already. Bins are only `hasBin: true`, so install reads them out of the package.

/// The document that is the lockfile: pnpm 11 and later may write two, its own dependencies
/// first.
fn pnpm_doc(text: &str) -> Result<Value> {
    let mut parts = vec![String::new()];
    for line in text.split('\n') {
        match line.strip_prefix("---") {
            Some(rest) if rest.trim().is_empty() => parts.push(String::new()),
            _ => {
                if let Some(part) = parts.last_mut() {
                    part.push_str(line);
                    part.push('\n');
                }
            }
        }
    }
    let mut doc = Value::Null;
    for part in &parts {
        let d = yaml(part)?;
        if truthy(d.get("lockfileVersion")) {
            doc = d;
        }
    }
    Ok(doc)
}

fn read_pnpm(text: &str) -> Result<Source> {
    let doc = pnpm_doc(text)?;
    let version = doc.get("lockfileVersion").map(string_of).unwrap_or_default();
    if !version.starts_with('9') {
        let v = if version.is_empty() { "v5" } else { &version };
        return Err(fail(format!("pnpm-lock.yaml {v} is not read; pnpm 9 and later write 9.0")));
    }
    let importers = doc.get("importers").and_then(Value::as_object);
    if importers.is_some_and(|i| i.keys().any(|path| path != ".")) {
        return Err(fail("jpm does not read workspaces from pnpm-lock.yaml"));
    }
    if truthy(doc.get("patchedDependencies")) {
        return Err(fail("jpm does not apply the patches pnpm-lock.yaml names"));
    }
    let empty = Map::new();
    let packages = doc.get("packages").and_then(Value::as_object).unwrap_or(&empty);
    let snapshots = doc.get("snapshots").and_then(Value::as_object).unwrap_or(&empty);
    let package_index = packages.index();
    let mut aliases = BTreeMap::new(); // alias@version -> real name
    let mut nodes = Vec::new();
    for (key, snap) in snapshots {
        let id = strip_peers(key);
        let Some(pkg) = package_index.get(id).copied().filter(|p| !p.is_null()) else { continue };
        let resolution = pkg.get("resolution");
        let field = |f: &str| resolution.and_then(|r| r.get(f)).and_then(Value::as_str).filter(|s| !s.is_empty());
        let Some(integrity) = field("integrity") else { continue }; // a git, file or tarball-url package
        let (name, version) = split_id(id);
        let mut node = Node {
            name,
            version,
            resolved: field("tarball").map(str::to_string),
            integrity: integrity.to_string(),
            has_bin: pkg.get("hasBin") == Some(&Value::Bool(true)),
            os: list(pkg.get("os")),
            cpu: list(pkg.get("cpu")),
            libc: list(pkg.get("libc")),
            ..Node::default()
        };
        for (dep, r) in deps(snap.get("dependencies")) {
            let v = pnpm_edge(&mut aliases, &dep, &r)?;
            node.dependencies.insert(dep, v);
        }
        for (dep, r) in deps(snap.get("optionalDependencies")) {
            let v = pnpm_edge(&mut aliases, &dep, &r)?;
            node.optional_dependencies.insert(dep, v);
        }
        let ranges = deps(pkg.get("peerDependencies"));
        // A snapshot lists its settled peers among its deps; the declared list tells them apart.
        for peer in ranges.keys() {
            let meta = pkg.get("peerDependenciesMeta").and_then(|m| m.get(peer));
            let optional = truthy(meta.and_then(|m| m.get("optional")));
            node.peers.insert(peer.clone(), if optional { PeerKind::Optional } else { PeerKind::Required });
            if optional && let Some(v) = node.dependencies.remove(peer) {
                node.optional_dependencies.insert(peer.clone(), v);
            }
        }
        node.peer_dependencies = ranges;
        nodes.push(node);
    }
    let top = importers.and_then(|i| i.get("."));
    let mut groups: [Deps; 3] = Default::default();
    let mut versions = Deps::new();
    for (group, specs) in GROUPS.iter().zip(&mut groups) {
        let Some(map) = top.and_then(|t| t.get(group)).and_then(Value::as_object) else { continue };
        for (name, dep) in map {
            specs.insert(name.clone(), dep.get("specifier").map(string_of).unwrap_or_default());
            let r = dep.get("version").map(string_of).unwrap_or_default();
            versions.insert(name.clone(), pnpm_edge(&mut aliases, name, &r)?);
        }
    }
    // pnpm keys an alias by the real package; jpm gives the alias a node of its own.
    let by_id: HashMap<String, usize> =
        nodes.iter().enumerate().map(|(i, n)| (format!("{}@{}", n.name, n.version), i)).collect();
    for (key, real) in &aliases {
        let (alias, version) = split_id(key);
        let Some(&i) = by_id.get(&format!("{real}@{version}")) else { continue };
        let node = Node { name: alias, real: Some(real.clone()), ..nodes[i].clone() };
        nodes.push(node);
    }
    let (specs, root) = root_of(groups, &|name| versions.get(name).cloned());
    Ok(Source { nodes, specs, root, overrides: None })
}

/// The version an edge `dep: ref` points at, `""` when not from a registry. An alias is noted:
/// one node per `name@version`, so two packages under one alias cannot share it.
fn pnpm_edge(aliases: &mut BTreeMap<String, String>, dep: &str, r: &str) -> Result<String> {
    let Some((real, version)) = pnpm_target(dep, r) else { return Ok(String::new()) };
    if real != dep {
        let key = format!("{dep}@{version}");
        if aliases.get(&key).is_some_and(|have| *have != real) {
            return Err(fail(format!(
                "pnpm-lock.yaml holds two packages as {key}; jpm keeps one per name and version"
            )));
        }
        aliases.insert(key, real.to_string());
    }
    Ok(version.to_string())
}

/// `1.2.3`, `1.2.3(peer@1)`, `real@1.2.3(peer@1)` for an alias; nothing for `link:`, `file:`.
fn pnpm_target<'a>(dep: &'a str, r: &'a str) -> Option<(&'a str, &'a str)> {
    let bare = strip_peers(r);
    if bare.is_empty() || bare.contains(':') {
        return None;
    }
    match bare.rfind('@') {
        Some(at) if at > 0 => Some((&bare[..at], &bare[at + 1..])),
        _ => Some((dep, bare)),
    }
}

fn strip_peers(key: &str) -> &str {
    key.find('(').map_or(key, |open| &key[..open])
}

// --- bun.lock ---------------------------------------------------------------------------
// JSON with trailing commas. `packages` is keyed by hoisted path (`a`, `c/a`), a registry
// package a tuple of `[name@version, registry, meta, integrity]`; edges are ranges resolved by
// walking up the path like npm. bun records no libc.

fn read_bun(text: &str) -> Result<Source> {
    let doc = json::parse(&strip_trailing_commas(text))
        .map_err(|e| fail(format!("bun.lock cannot be read: {}", e.message)))?;
    let workspaces = doc.get("workspaces").and_then(Value::as_object);
    if workspaces.is_some_and(|w| w.keys().any(|path| !path.is_empty())) {
        return Err(fail("jpm does not read workspaces from bun.lock"));
    }
    if truthy(doc.get("patchedDependencies")) {
        return Err(fail("jpm does not apply the patches bun.lock names"));
    }
    let empty = Map::new();
    let listed = doc.get("packages").and_then(Value::as_object).unwrap_or(&empty);
    let paths = listed.index();
    let mut nodes = Vec::new();
    for (path, tuple) in listed {
        let Some(t) = bun_tuple(tuple).filter(|t| !t.bundled) else { continue };
        let (real, version) = split_id(t.id);
        let chain = names(path);
        let name = chain.last().cloned().unwrap_or_default();
        // bun writes an os or cpu it does not know as "none": unknown, so no restriction.
        let known = |v: Option<&Value>| list(v).into_iter().filter(|x| x != "none").collect();
        let node = Node {
            real: (name != real).then(|| real.clone()),
            name,
            // An empty host is the default registry; another is written out in full.
            resolved: (!t.host.is_empty()).then(|| tarball_url(t.host.trim_end_matches('/'), &real, &version)),
            integrity: t.integrity.to_string(),
            bin: bin::normalize(Some(&real), t.meta.get("bin")),
            os: known(t.meta.get("os")),
            cpu: known(t.meta.get("cpu")),
            version,
            ..Node::default()
        };
        let mut declared = Declared::of(t.meta);
        declared.optional_peers = list(t.meta.get("optionalPeers")).into_iter().collect();
        nodes.push(with_edges(node, &declared, &|dep| bun_find(&paths, &chain, dep)));
    }
    let (specs, root) =
        root_of(groups_of(workspaces.and_then(|w| w.get(""))), &|name| match bun_find(&paths, &[], name) {
            Target::Version(v) => Some(v),
            _ => None,
        });
    let overrides = doc.get("overrides").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Object(Map::new()));
    Ok(Source { nodes, specs, root, overrides: Some(overrides) })
}

struct BunTuple<'a> {
    id: &'a str,
    host: &'a str,
    meta: &'a Value,
    integrity: &'a str,
    /// A bundled copy is inside its parent's tarball, as npm's `inBundle` is.
    bundled: bool,
}

/// Git, file and workspace tuples have another shape; only a registry one ends in integrity.
fn bun_tuple(value: &Value) -> Option<BunTuple<'_>> {
    let [id, host, meta, integrity] = value.as_array()?.as_slice() else { return None };
    Some(BunTuple {
        id: id.as_str()?,
        host: host.as_str()?,
        meta,
        integrity: integrity.as_str()?,
        bundled: meta.get("bundled") == Some(&Value::Bool(true)),
    })
}

/// The nearest `name` up the hoisted path `from`.
fn bun_find(paths: &HashMap<&str, &Value>, from: &[String], name: &str) -> Target {
    for depth in (0..=from.len()).rev() {
        let mut key = from[..depth].join("/");
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(name);
        let Some(hit) = paths.get(key.as_str()).copied().filter(|v| truthy(Some(v))) else { continue };
        return match bun_tuple(hit) {
            None => Target::Missing,
            Some(t) if t.bundled => Target::Bundled,
            Some(t) => Target::Version(split_id(t.id).1),
        };
    }
    Target::Missing
}

/// A path is package names joined by "/", and a scoped name has a "/" of its own.
fn names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut parts = path.split('/');
    while let Some(part) = parts.next() {
        if part.starts_with('@') {
            out.push(format!("{part}/{}", parts.next().unwrap_or_default()));
        } else {
            out.push(part.to_string());
        }
    }
    out
}

/// Drop each `,` that only a `}` or `]` follows, leaving string literals as they are.
fn strip_trailing_commas(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for (i, c) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = text[i + 1..].trim_start_matches([' ', '\t', '\n', '\r']).chars().next();
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

// --- shared -----------------------------------------------------------------------------

/// Fold the nodes onto one per `name@version`, keep what the root reaches, and check the result
/// as `read_lockfile` would. A copy with other edges is a peer settled two ways, which jpm's one
/// node cannot hold: the highest version the peer range allows wins, as the resolver would pick.
fn build(
    file: &str,
    source: Source,
    manifest: &RootManifest,
    base_for: &dyn Fn(&str) -> String,
) -> Result<ForeignLock> {
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut twice = BTreeSet::new();
    for node in source.nodes {
        let key = format!("{}@{}", node.name, node.version);
        let Some(have) = nodes.get_mut(&key) else {
            nodes.insert(key, node);
            continue;
        };
        if have.integrity != node.integrity {
            return Err(fail(format!("{file} holds two packages as {key}; jpm keeps one per name and version")));
        }
        let theirs = [
            (node.dependencies, &mut have.dependencies),
            (node.optional_dependencies, &mut have.optional_dependencies),
        ];
        for (edges, mine) in theirs {
            for (dep, version) in edges {
                let range = have.peer_dependencies.get(&dep).map_or("*", String::as_str);
                let pick = match mine.get(&dep) {
                    Some(m) if *m == version => continue,
                    Some(m) if !m.is_empty() => {
                        max_satisfying([m.as_str(), version.as_str()], range).unwrap_or(m).to_string()
                    }
                    _ => version,
                };
                twice.insert(key.clone());
                mine.insert(dep, pick);
            }
        }
    }

    let mut reached: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for (name, version) in &source.root {
        let key = edge_key(&nodes, file, "package.json", name, version)?;
        if seen.insert(key.clone()) {
            reached.push(key);
        }
    }
    let mut i = 0;
    while let Some(key) = reached.get(i).cloned() {
        i += 1;
        let Some(node) = nodes.get(&key) else { continue };
        // An optional edge not from a registry may go.
        let optional: Deps = node
            .optional_dependencies
            .iter()
            .filter(|(n, v)| nodes.contains_key(&format!("{n}@{v}")))
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        let mut next = Vec::new();
        for (name, version) in node.dependencies.iter().chain(&optional) {
            next.push(edge_key(&nodes, file, &key, name, version)?);
        }
        if let Some(node) = nodes.get_mut(&key) {
            node.optional_dependencies = optional;
        }
        for k in next {
            if seen.insert(k.clone()) {
                reached.push(k);
            }
        }
    }

    let mut packages = BTreeMap::new();
    let mut binless = Vec::new();
    for key in &reached {
        let Some(node) = nodes.remove(key) else { continue };
        if node.integrity.is_empty() {
            return Err(fail(format!("{file} gives {key} no integrity")));
        }
        if node.bin.is_empty() && node.has_bin {
            binless.push(key.clone());
        }
        let resolved = if derivable(&node) {
            None
        } else if let Some(real) = &node.real {
            Some(tarball_url(&base_for(real), real, &node.version))
        } else {
            node.resolved
        };
        let entry = LockEntry {
            version: None,
            resolved,
            integrity: node.integrity,
            dependencies: node.dependencies,
            optional_dependencies: node.optional_dependencies,
            bin: node.bin,
            peer_dependencies: node.peer_dependencies,
            peers: node.peers,
            os: node.os,
            cpu: node.cpu,
            libc: node.libc,
            subgraph: None,
        };
        packages.insert(key.clone(), entry);
    }
    let root = LockRoot {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        specs: Specs::canonical(Some(&source.specs)),
        dependencies: source.root,
        workspaces: None,
    };
    let lock = Lockfile { lockfile_version: 1, root, workspaces: BTreeMap::new(), packages, hash: None };
    lock::validate(&lock).map_err(|e| fail(format!("{file} does not map onto jpm: {}", e.message)))?;
    let warnings = twice
        .into_iter()
        .filter(|key| seen.contains(key))
        .map(|key| format!("{file} settles a peer of {key} two ways; jpm links the highest"))
        .collect();
    Ok(ForeignLock { lock, binless, warnings })
}

/// The key an edge reaches, refused when the file has it from no registry.
fn edge_key(nodes: &HashMap<String, Node>, file: &str, from: &str, name: &str, version: &str) -> Result<String> {
    let key = format!("{name}@{version}");
    if version.is_empty() || !nodes.contains_key(&key) {
        return Err(fail(format!("{from} depends on {name}, which {file} has from no registry")));
    }
    Ok(key)
}

/// Whether install rebuilds the url on its own. The registry shape on any host counts: a file
/// written behind a mirror names the mirror everywhere, and keeping that would pin the install
/// to it. An alias, or a url of another shape, is kept.
fn derivable(node: &Node) -> bool {
    if node.real.is_some() {
        return false;
    }
    let Some(resolved) = &node.resolved else { return true };
    let base = node.name.split_once('/').map_or(node.name.as_str(), |(_, b)| b);
    resolved.ends_with(&format!("/{}/-/{base}-{}.tgz", node.name, node.version))
}

fn split_id(id: &str) -> (String, String) {
    match id.rfind('@') {
        Some(at) => (id[..at].to_string(), id[at + 1..].to_string()),
        None => (String::new(), id.to_string()),
    }
}

/// A group's string ranges; anything else in it is not a range.
fn deps(value: Option<&Value>) -> Deps {
    let Some(map) = value.and_then(Value::as_object) else { return Deps::new() };
    map.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()
}

/// `os: darwin` and `os: [darwin]` alike.
fn list(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.iter().map(string_of).collect(),
        Some(v) => vec![string_of(v)],
    }
}

fn string_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// JavaScript's truthiness, which the other managers' own readers go by.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.parse::<f64>().is_ok_and(|f| f != 0.0),
        Some(_) => true,
    }
}

// --- the YAML pnpm writes ---------------------------------------------------------------
// Block maps, block lists, flow `{}` and `[]`, quoted and plain scalars. Nothing else appears.

/// Deeper than any lockfile nests; past it the file is hostile, not pnpm's.
const MAX_DEPTH: usize = 64;

fn yaml(text: &str) -> Result<Value> {
    let lines: Vec<&str> =
        text.split('\n').filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).collect();
    let indent = lines.first().map_or(0, |l| indent_of(l));
    Yaml { lines, i: 0 }.block(indent, 0)
}

struct Yaml<'a> {
    lines: Vec<&'a str>,
    i: usize,
}

impl Yaml<'_> {
    fn block(&mut self, indent: usize, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(too_deep());
        }
        let item = |l: &&str| l.trim().starts_with("- ");
        if self.lines.get(self.i).is_some_and(item) {
            let mut out = Vec::new();
            while let Some(line) = self.lines.get(self.i).copied().filter(|l| indent_of(l) == indent && item(l)) {
                self.i += 1;
                out.push(scalar(&line.trim()[2..], depth + 1)?);
            }
            return Ok(Value::Array(out));
        }
        let mut out = Map::new();
        while let Some(line) = self.lines.get(self.i).copied().filter(|l| indent_of(l) == indent) {
            self.i += 1;
            let line = line.trim();
            let colon = key_end(line);
            let key = unquote(&line[..colon]);
            let rest = line.get(colon + 1..).unwrap_or_default().trim();
            let value = if !rest.is_empty() {
                scalar(rest, depth + 1)?
            } else {
                match self.lines.get(self.i).map(|l| indent_of(l)) {
                    Some(next) if next > indent => self.block(next, depth + 1)?,
                    _ => Value::Object(Map::new()),
                }
            };
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}

fn too_deep() -> Error {
    fail("pnpm-lock.yaml cannot be read: nested too deeply")
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Index of the `:` that ends a key. A quoted key ends at its quote; a plain one may hold colons
/// of its own (`name@file:path:`), so it ends at the first `: ` or a trailing `:`.
fn key_end(line: &str) -> usize {
    let b = line.as_bytes();
    if let Some(&q @ (b'"' | b'\'')) = b.first() {
        let mut j = 1;
        while j < b.len() {
            if b[j] == b'\\' {
                j += 1;
            } else if b[j] == q && b.get(j + 1) == Some(&b':') {
                return j + 1;
            }
            j += 1;
        }
    }
    if let Some(sep) = line.find(": ") {
        return sep;
    }
    if line.ends_with(':') { line.len() - 1 } else { line.find(':').unwrap_or(line.len()) }
}

fn scalar(text: &str, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    let v = text.trim();
    let inner = || &v[1..v.len() - 1];
    Ok(match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ if v.len() >= 2 && v.starts_with('{') && v.ends_with('}') => {
            let mut out = Map::new();
            for part in split_flow(inner()) {
                let item = part.trim();
                let colon = key_end(item);
                out.insert(unquote(&item[..colon]), scalar(item.get(colon + 1..).unwrap_or_default(), depth + 1)?);
            }
            Value::Object(out)
        }
        _ if v.len() >= 2 && v.starts_with('[') && v.ends_with(']') => {
            Value::Array(split_flow(inner()).into_iter().map(|p| Value::String(unquote(p))).collect())
        }
        _ => Value::String(unquote(v)),
    })
}

/// Split a flow collection's body on the commas at its own level.
fn split_flow(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut quote, mut start) = (0i32, None, 0);
    for (j, &c) in text.as_bytes().iter().enumerate() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == b'"' || c == b'\'' {
            quote = Some(c);
        } else if c == b'{' || c == b'[' {
            depth += 1;
        } else if c == b'}' || c == b']' {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            out.push(&text[start..j]);
            start = j + 1;
        }
    }
    if !text[start..].trim().is_empty() {
        out.push(&text[start..]);
    }
    out
}

fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        return json::parse(v)
            .ok()
            .and_then(|p| p.as_str().map(str::to_string))
            .unwrap_or_else(|| v[1..v.len() - 1].to_string());
    }
    if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        return v[1..v.len() - 1].replace("''", "'");
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{LOCKFILE, parse_lockfile};
    // The tests write documents with serde_json's `json!`; the reader is handed them as text.
    use serde_json::{Value, json};
    use std::path::Path;

    fn npmjs(_: &str) -> String {
        "https://registry.npmjs.org".to_string()
    }

    fn manifest(doc: Value) -> RootManifest {
        RootManifest::parse(&doc.to_string(), Path::new("package.json")).unwrap()
    }

    fn read(file: &str, text: &str, doc: Value) -> Result<ForeignLock> {
        load(file, text, &manifest(doc), false, &npmjs)
    }

    fn err(file: &str, text: &str, doc: Value) -> String {
        match read(file, text, doc) {
            Ok(_) => panic!("{file} was read"),
            Err(e) => {
                assert_eq!(e.code, "ELOCK");
                e.message
            }
        }
    }

    const NPM: &str = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "dependencies": { "tool": "^1.0.0" } },
    "node_modules/tool": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/tool/-/tool-1.0.0.tgz",
      "integrity": "sha512-tool",
      "dependencies": { "dep": "^1.0.0" },
      "optionalDependencies": { "@s/native": "1.0.0" },
      "bin": { "tool": "cli.js" }
    },
    "node_modules/dep": {
      "version": "1.0.0",
      "resolved": "https://mirror.example/dep/-/dep-1.0.0.tgz",
      "integrity": "sha512-dep"
    },
    "node_modules/@s/native": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/@s/native/-/native-1.0.0.tgz",
      "integrity": "sha512-native",
      "optional": true,
      "os": ["darwin"]
    }
  }
}"#;

    const PNPM: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      tool:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  '@s/native@1.0.0':
    resolution: {integrity: sha512-native}
    os: [darwin]

  dep@1.0.0:
    resolution: {integrity: sha512-dep}

  tool@1.0.0:
    resolution: {integrity: sha512-tool}
    hasBin: true

snapshots:

  '@s/native@1.0.0':
    optional: true

  dep@1.0.0: {}

  tool@1.0.0:
    dependencies:
      dep: 1.0.0
    optionalDependencies:
      '@s/native': 1.0.0
";

    const BUN: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": { "tool": "^1.0.0", },
    },
  },
  "packages": {
    "@s/native": ["@s/native@1.0.0", "", { "os": "darwin", "cpu": "none" }, "sha512-native"],
    "dep": ["dep@1.0.0", "https://mirror.example/", {}, "sha512-dep"],
    "tool": ["tool@1.0.0", "", { "dependencies": { "dep": "^1.0.0" }, "optionalDependencies": { "@s/native": "1.0.0" }, "bin": { "tool": "cli.js" } }, "sha512-tool"],
  }
}
"#;

    const EXPECTED: &str = r#"{
  "lockfileVersion": 1,
  "root": {
    "name": "demo",
    "specs": { "dependencies": { "tool": "^1.0.0" } },
    "dependencies": { "tool": "1.0.0" }
  },
  "packages": {
    "@s/native@1.0.0": { "integrity": "sha512-native", "os": ["darwin"] },
    "dep@1.0.0": { "integrity": "sha512-dep" },
    "tool@1.0.0": {
      "integrity": "sha512-tool",
      "dependencies": { "dep": "1.0.0" },
      "optionalDependencies": { "@s/native": "1.0.0" },
      "bin": { "tool": "cli.js" }
    }
  }
}"#;

    fn demo() -> Value {
        json!({ "name": "demo", "dependencies": { "tool": "^1.0.0" } })
    }

    #[test]
    fn maps_each_manager_onto_the_same_lock() {
        let expected = parse_lockfile(EXPECTED, LOCKFILE).unwrap();
        let npm = read("package-lock.json", NPM, demo()).unwrap();
        assert_eq!(npm.lock, expected);
        assert!(npm.binless.is_empty() && npm.warnings.is_empty());
        let bun = read("bun.lock", BUN, demo()).unwrap();
        assert_eq!(bun.lock, expected);
        // pnpm says only hasBin: bins are left to the store.
        let pnpm = read("pnpm-lock.yaml", PNPM, demo()).unwrap();
        let mut binless = expected.clone();
        binless.packages.get_mut("tool@1.0.0").unwrap().bin.clear();
        assert_eq!(pnpm.lock, binless);
        assert_eq!(pnpm.binless, ["tool@1.0.0"]);
    }

    #[test]
    fn folds_a_peer_settled_two_ways_and_keeps_an_alias_tarball() {
        let at = |name: &str, version: &str, rest: Value| {
            let mut v = json!({ "version": version, "integrity": format!("sha512-{name}{version}") });
            if let (Some(o), Value::Object(r)) = (v.as_object_mut(), rest) {
                o.extend(r);
            }
            v
        };
        let deps = json!({ "plugin": "^1", "host": "^2", "b": "^1", "str": "npm:string-width@^4" });
        let text = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": deps },
                "node_modules/plugin": at("plugin", "1.0.0", json!({ "peerDependencies": { "host": ">=1" } })),
                "node_modules/host": at("host", "2.0.0", json!({})),
                "node_modules/b": at("b", "1.0.0", json!({ "dependencies": { "plugin": "^1", "host": "^1" } })),
                "node_modules/b/node_modules/host": at("host", "1.0.0", json!({})),
                "node_modules/b/node_modules/plugin": at("plugin", "1.0.0", json!({ "peerDependencies": { "host": ">=1" } })),
                "node_modules/str": at("string-width", "4.2.3", json!({ "name": "string-width" })),
            }
        })
        .to_string();
        let read = read("package-lock.json", &text, json!({ "dependencies": deps })).unwrap();
        let plugin = &read.lock.packages["plugin@1.0.0"];
        assert_eq!(plugin.dependencies, Deps::from([("host".into(), "2.0.0".into())]));
        assert_eq!(plugin.peers, Peers::from([("host".into(), PeerKind::Required)]));
        let b = &read.lock.packages["b@1.0.0"].dependencies;
        assert_eq!(b, &Deps::from([("plugin".into(), "1.0.0".into()), ("host".into(), "1.0.0".into())]));
        assert_eq!(read.warnings, ["package-lock.json settles a peer of plugin@1.0.0 two ways; jpm links the highest"]);
        assert_eq!(
            read.lock.packages["str@4.2.3"].resolved.as_deref(),
            Some("https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz")
        );
    }

    #[test]
    fn gives_a_pnpm_alias_a_node_of_its_own() {
        let text = "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      str:
        specifier: npm:string-width@^4
        version: string-width@4.2.3
packages:
  string-width@4.2.3:
    resolution: {integrity: sha512-sw}
snapshots:
  string-width@4.2.3: {}
";
        // pnpm's own dependencies may come first, as a document of their own.
        let env = "---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    packageManagerDependencies: {}\n";
        let doc = json!({ "dependencies": { "str": "npm:string-width@^4" } });
        let lock = read("pnpm-lock.yaml", &format!("{env}---\n{text}"), doc).unwrap().lock;
        let specs = Specs {
            dependencies: Some(Deps::from([("str".into(), "npm:string-width@^4".into())])),
            ..Specs::default()
        };
        assert_eq!(lock.root.specs, Some(specs));
        assert_eq!(lock.root.dependencies, Deps::from([("str".into(), "4.2.3".into())]));
        assert_eq!(lock.packages.keys().collect::<Vec<_>>(), ["str@4.2.3"]);
        assert!(
            lock.packages["str@4.2.3"].resolved.as_deref().unwrap().ends_with("/string-width/-/string-width-4.2.3.tgz")
        );
    }

    #[test]
    fn refuses_what_it_cannot_map() {
        let npm = |packages: Value| json!({ "lockfileVersion": 3, "packages": packages }).to_string();
        let git = npm(json!({
            "": { "dependencies": { "a": "github:x/a" } },
            "node_modules/a": { "version": "1.0.0", "resolved": "git+ssh://git@github.com/x/a.git#abc" },
        }));
        assert_eq!(
            err("package-lock.json", &git, json!({ "dependencies": { "a": "github:x/a" } })),
            "package.json depends on a, which package-lock.json has from no registry"
        );
        let bare = npm(json!({ "": { "dependencies": { "a": "1" } }, "node_modules/a": { "version": "1.0.0" } }));
        assert_eq!(
            err("package-lock.json", &bare, json!({ "dependencies": { "a": "1" } })),
            "package-lock.json gives a@1.0.0 no integrity"
        );
        let workspace = "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/a: {}\n";
        assert!(err("pnpm-lock.yaml", workspace, json!({})).contains("workspaces"));
        let patched = "lockfileVersion: '9.0'\npatchedDependencies:\n  a: patches/a.patch\n";
        assert!(err("pnpm-lock.yaml", patched, json!({})).contains("patches"));
        let bun_patched = r#"{"lockfileVersion":1,"patchedDependencies":{"a@1.0.0":"patches/a.patch"}}"#;
        assert!(err("bun.lock", bun_patched, json!({})).contains("patches"));
        assert!(err("pnpm-lock.yaml", "lockfileVersion: '6.0'\n", json!({})).contains("pnpm 9 and later"));
        assert!(err("bun.lock", "{", json!({})).contains("bun.lock cannot be read"));
        assert!(err("package-lock.json", r#"{"lockfileVersion":1}"#, json!({})).contains("v1 has no packages map"));
        let empty = r#"{"lockfileVersion":1,"packages":{}}"#;
        let patches = json!({ "a@1.0.0": "patches/a.patch" });
        assert!(err("bun.lock", empty, json!({ "patchedDependencies": patches })).contains("patches"));
        let pnpm_patches = json!({ "pnpm": { "patchedDependencies": patches } });
        assert!(err("package-lock.json", &npm(json!({})), pnpm_patches).contains("patches"));
    }

    #[test]
    fn leaves_a_bundled_copy_to_its_parent_tarball() {
        let text = json!({
            "lockfileVersion": 1,
            "workspaces": { "": { "dependencies": { "a": "^1" } } },
            "packages": {
                "a": ["a@1.0.0", "", { "dependencies": { "b": "^1" } }, "sha512-a"],
                "a/b": ["b@1.0.0", "", { "bundled": true, "dependencies": { "c": "^1" } }, "sha512-b"],
                "a/c": ["c@1.0.0", "", {}, "sha512-c"],
            }
        })
        .to_string();
        let lock = read("bun.lock", &text, json!({ "dependencies": { "a": "^1" } })).unwrap().lock;
        assert_eq!(lock.packages.keys().collect::<Vec<_>>(), ["a@1.0.0"]);
        assert!(lock.packages["a@1.0.0"].dependencies.is_empty());
    }

    #[test]
    fn refuses_two_packages_under_one_pnpm_alias() {
        let text = "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: '1', version: 1.0.0}
      b: {specifier: '1', version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-a}}
  b@1.0.0: {resolution: {integrity: sha512-b}}
  foo@1.0.0: {resolution: {integrity: sha512-foo}}
  bar@1.0.0: {resolution: {integrity: sha512-bar}}
snapshots:
  a@1.0.0:
    dependencies:
      x: foo@1.0.0
  b@1.0.0:
    dependencies:
      x: bar@1.0.0
  foo@1.0.0: {}
  bar@1.0.0: {}
";
        let doc = json!({ "dependencies": { "a": "1", "b": "1" } });
        assert!(err("pnpm-lock.yaml", text, doc).starts_with("pnpm-lock.yaml holds two packages as x@1.0.0"));
    }

    fn npm_root(root: Value) -> String {
        json!({
            "lockfileVersion": 3,
            "packages": { "": root, "node_modules/a": { "version": "1.0.0", "integrity": "sha512-a" } }
        })
        .to_string()
    }

    #[test]
    fn takes_the_groups_from_package_json() {
        // All three managers file a name declared twice under optionalDependencies alone.
        let both = json!({ "dependencies": { "a": "^1" }, "optionalDependencies": { "a": "^1" } });
        let text = npm_root(json!({ "optionalDependencies": { "a": "^1" } }));
        let root = read("package-lock.json", &text, both.clone()).unwrap().lock.root;
        assert_eq!(root.specs, manifest(both).specs());
        assert_eq!(root.dependencies, Deps::from([("a".into(), "1.0.0".into())]));
        // pnpm files a dependency that is also a devDependency under dependencies.
        let dev = json!({ "dependencies": { "a": "^1" }, "devDependencies": { "a": "^1" } });
        let text = npm_root(json!({ "dependencies": { "a": "^1" } }));
        let root = read("package-lock.json", &text, dev.clone()).unwrap().lock.root;
        assert_eq!(root.specs, manifest(dev).specs());
    }

    #[test]
    fn leaves_out_root_peers_and_refuses_any_other_difference() {
        let text = "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-a}}
snapshots:
  a@1.0.0: {}
";
        let root = read("pnpm-lock.yaml", text, json!({ "peerDependencies": { "a": "^1" } })).unwrap().lock.root;
        assert_eq!(root, LockRoot::default());
        for doc in [
            json!({ "peerDependencies": { "a": "^2" } }),
            json!({ "dependencies": { "a": "^2" } }),
            json!({ "dependencies": { "a": "^1", "b": "^1" } }),
            json!({}),
        ] {
            assert!(err("pnpm-lock.yaml", text, doc).starts_with("pnpm-lock.yaml is out of date with package.json"));
        }
    }

    #[test]
    fn refuses_a_bun_lock_resolved_under_other_overrides() {
        let text = |overrides: Value| {
            json!({
                "lockfileVersion": 1,
                "workspaces": { "": { "dependencies": { "a": "^1" } } },
                "overrides": overrides,
                "packages": { "a": ["a@1.0.0", "", {}, "sha512-a"] },
            })
            .to_string()
        };
        let a = Deps::from([("a".into(), "1.0.0".into())]);
        let doc = json!({ "dependencies": { "a": "^1" }, "overrides": { "b": "1.0.0", "c": "1" } });
        let same = text(json!({ "c": "1", "b": "1.0.0" }));
        assert_eq!(read("bun.lock", &same, doc.clone()).unwrap().lock.root.dependencies, a);
        let resolutions = json!({ "dependencies": { "a": "^1" }, "resolutions": { "b": "1.0.0", "c": "1" } });
        assert_eq!(read("bun.lock", &same, resolutions).unwrap().lock.root.dependencies, a);
        assert!(err("bun.lock", &text(json!({ "b": "2.0.0", "c": "1" })), doc.clone()).contains("out of date"));
        assert!(err("bun.lock", &text(json!({})), doc).contains("out of date"));
    }

    #[test]
    fn refuses_workspaces_exactly() {
        let e = load("pnpm-lock.yaml", PNPM, &manifest(demo()), true, &npmjs).err().unwrap();
        assert_eq!(e.message, "pnpm-lock.yaml has workspaces, which jpm reads only for their versions");
    }

    #[test]
    fn pins_every_format() {
        let npm = pins("package-lock.json", NPM).unwrap();
        assert!(npm.contains(&("tool".to_string(), "1.0.0".to_string())));
        assert!(npm.contains(&("@s/native".to_string(), "1.0.0".to_string())));
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.2.3","dependencies":{"b":{"version":"2.0.0"}}},"c":{"version":"npm:real@3.0.0"}}}"#;
        let mut v1 = pins("npm-shrinkwrap.json", v1).unwrap();
        v1.sort();
        assert_eq!(v1, [("a".into(), "1.2.3".into()), ("b".into(), "2.0.0".into()), ("real".into(), "3.0.0".into())]);
        assert!(!pins("pnpm-lock.yaml", PNPM).unwrap().is_empty());
        let old = "lockfileVersion: 5.4\npackages:\n  /a/1.0.0:\n    resolution: {integrity: x}\n  /@s/b/2.0.0_c@1.0.0:\n    dev: true\n";
        let mut old = pins("pnpm-lock.yaml", old).unwrap();
        old.sort();
        assert_eq!(old, [("@s/b".into(), "2.0.0".into()), ("a".into(), "1.0.0".into())]);
    }

    #[test]
    fn reads_the_yaml_pnpm_writes() {
        let text = "# comment\nkey: 'it''s'\n\"q:k\": \"a\\\"b\"\nlist:\n  - a\n  - 'b'\nflow: {x: [1, '2,3'], y: {z: true}}\nname@file:a:b:\n  deep: {}\nempty:\n";
        assert_eq!(
            yaml(text).unwrap().to_string(),
            json!({
                "key": "it's",
                "q:k": "a\"b",
                "list": ["a", "b"],
                "flow": { "x": ["1", "2,3"], "y": { "z": true } },
                "name@file:a:b": { "deep": {} },
                "empty": {},
            })
            .to_string()
        );
        let deep = "{a: ".repeat(100) + &"}".repeat(100);
        assert!(yaml(&format!("k: {deep}\n")).is_err());
    }

    #[test]
    fn strips_trailing_commas_outside_strings() {
        let text = r#"{"a": ["x,]", "y\",}",], "b": {"c": 1 ,
  },}"#;
        let v: Value = serde_json::from_str(&strip_trailing_commas(text)).unwrap();
        assert_eq!(v, json!({ "a": ["x,]", "y\",}"], "b": { "c": 1 } }));
    }
}
