//! `jpm.lock`: a flat lockfile keyed by identity, in upm's format, so a project can move between
//! the two. Written with fixed field order and sorted maps, so the same resolution is always the
//! same bytes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::bin;
use crate::error::{Error, Result};
use crate::extensions::Extension;
use crate::graph::{
    Deps, Package, PeerKind, Peers, Resolution, Root, Specs, WITHIN, same_specs, split_key, split_peers, split_within,
};
use crate::json::{self, Object, Value};
use crate::project::{RootManifest, Workspace, local_path, local_shape};
use crate::registry::tarball_url;
use crate::rules::Override;
use crate::runtime::{self, Variant};
use crate::semver;
use crate::spec::{self, Kind};
use crate::util::write_atomic;

pub const LOCKFILE: &str = "jpm.lock";
/// upm's lockfile has the same format, and is read when there is no `jpm.lock`.
/// upm's format, which jpm still reads.
const VERSION: u32 = 1;
/// jpm's own text format.
pub const TEXT_VERSION: u32 = 2;
const TEXT_VERSION_TEXT: &str = "2";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LockEntry {
    /// Only for a tarball dependency, whose key ends in its source: the version inside.
    pub version: Option<String>,
    /// Only when the tarball is not where the registry would put it.
    pub resolved: Option<String>,
    pub integrity: String,
    pub dependencies: Deps,
    pub optional_dependencies: Deps,
    pub bin: Deps,
    pub peer_dependencies: Deps,
    pub peers: Peers,
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
    /// The digest of the store entry's name, `<name>@<version>-<subgraph>`: a hash of everything
    /// the package reaches, written down so an install need not hash the graph again.
    pub subgraph: Option<String>,
    /// Has install scripts.
    pub scripts: bool,
    /// Its install scripts are approved at this version, and run when the package.json trusts
    /// its name too.
    pub build: bool,
    /// The sha256 of the patch applied to it.
    pub patch: Option<String>,
    /// A runtime's builds, one per platform, in place of `integrity`.
    pub variants: Vec<Variant>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkspaceEntry {
    pub name: String,
    pub version: String,
    pub specs: Option<Specs>,
    pub dependencies: Deps,
    pub optional_dependencies: Deps,
    pub bin: Deps,
    pub peer_dependencies: Deps,
    pub peers: Peers,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LockRoot {
    pub name: Option<String>,
    pub version: Option<String>,
    pub specs: Option<Specs>,
    pub dependencies: Deps,
    pub workspaces: Option<Vec<String>>,
    /// The overrides the tree was resolved under, resolved and in the order they apply.
    pub overrides: Vec<Override>,
    /// The packageExtensions the tree was resolved under, in the order they apply.
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Lockfile {
    pub lockfile_version: u32,
    pub root: LockRoot,
    pub workspaces: BTreeMap<String, WorkspaceEntry>,
    pub packages: BTreeMap<String, LockEntry>,
    /// A hash of the file's content, when it is known to match: read from a file whose content
    /// still has it, or computed when the file was written. The subgraphs are trusted only then.
    pub hash: Option<String>,
}

// --- the file's shape: fixed field order, empty fields left out -------------------------------

fn put_map(o: &mut Object, key: &str, map: &Deps) {
    if !map.is_empty() {
        o.insert(key, json::str_map(map));
    }
}

fn put_peers(o: &mut Object, peers: &Peers) {
    if !peers.is_empty() {
        o.insert("peers", Value::Object(peers.iter().map(|(k, v)| (k.clone(), v.as_str().into())).collect()));
    }
}

fn put_list(o: &mut Object, key: &str, list: &[String]) {
    if !list.is_empty() {
        o.insert(key, Value::from(list.to_vec()));
    }
}

fn put_specs(o: &mut Object, specs: Option<&Specs>) {
    if let Some(s) = Specs::canonical(specs) {
        o.insert("specs", s.to_value());
    }
}

impl LockEntry {
    fn to_value(&self) -> Value {
        let mut o = Object::new();
        if let Some(v) = &self.version {
            o.insert("version", v.into());
        }
        if let Some(r) = &self.resolved {
            o.insert("resolved", r.into());
        }
        if !self.integrity.is_empty() {
            o.insert("integrity", (&self.integrity).into());
        }
        put_map(&mut o, "dependencies", &self.dependencies);
        put_map(&mut o, "optionalDependencies", &self.optional_dependencies);
        put_map(&mut o, "bin", &self.bin);
        put_map(&mut o, "peerDependencies", &self.peer_dependencies);
        put_peers(&mut o, &self.peers);
        put_list(&mut o, "os", &self.os);
        put_list(&mut o, "cpu", &self.cpu);
        put_list(&mut o, "libc", &self.libc);
        if self.scripts {
            o.insert("hasInstallScript", true.into());
        }
        if self.build {
            o.insert("build", true.into());
        }
        if let Some(h) = &self.patch {
            o.insert("patch", h.into());
        }
        if !self.variants.is_empty() {
            let one = |v: &Variant| json::obj([("integrity", (&v.integrity).into()), ("file", (&v.file).into())]);
            o.insert("variants", Value::Object(self.variants.iter().map(|v| (v.platform.clone(), one(v))).collect()));
        }
        o.into()
    }
}

impl WorkspaceEntry {
    fn to_value(&self) -> Value {
        let mut o = Object::new();
        o.insert("name", (&self.name).into());
        o.insert("version", (&self.version).into());
        put_specs(&mut o, self.specs.as_ref());
        put_map(&mut o, "dependencies", &self.dependencies);
        put_map(&mut o, "optionalDependencies", &self.optional_dependencies);
        put_map(&mut o, "bin", &self.bin);
        put_map(&mut o, "peerDependencies", &self.peer_dependencies);
        put_peers(&mut o, &self.peers);
        o.into()
    }
}

impl Lockfile {
    fn to_value(&self) -> Value {
        let mut root = Object::new();
        if let Some(n) = &self.root.name {
            root.insert("name", n.into());
        }
        if let Some(v) = &self.root.version {
            root.insert("version", v.into());
        }
        put_specs(&mut root, self.root.specs.as_ref());
        root.insert("dependencies", json::str_map(&self.root.dependencies));
        if let Some(w) = self.root.workspaces.as_ref().filter(|w| !w.is_empty()) {
            root.insert("workspaces", Value::from(w.clone()));
        }
        if !self.root.overrides.is_empty() {
            let rule =
                |o: &Override| Value::from(vec![o.by.as_str().to_string(), o.selector(), o.value_text().to_string()]);
            root.insert("overrides", Value::Array(self.root.overrides.iter().map(rule).collect()));
        }
        if !self.root.extensions.is_empty() {
            let ext = |e: &Extension| (e.selector(), e.to_value());
            root.insert("packageExtensions", Value::Object(self.root.extensions.iter().map(ext).collect()));
        }
        let mut o = Object::new();
        // The JSON view is upm's format, whatever format the lockfile was read from.
        o.insert("lockfileVersion", u64::from(VERSION).into());
        o.insert("root", root.into());
        if !self.workspaces.is_empty() {
            o.insert(
                "workspaces",
                Value::Object(self.workspaces.iter().map(|(k, w)| (k.clone(), w.to_value())).collect()),
            );
        }
        o.insert("packages", Value::Object(self.packages.iter().map(|(k, e)| (k.clone(), e.to_value())).collect()));
        o.into()
    }
}

fn fail(message: impl Into<String>) -> Error {
    Error::new("ELOCK", message)
}

fn root_of(root: &Root) -> LockRoot {
    LockRoot {
        name: root.name.clone(),
        version: root.version.clone(),
        specs: Specs::canonical(root.specs.as_ref()),
        dependencies: root.dependencies.clone(),
        workspaces: root.workspaces.clone().filter(|w| !w.is_empty()),
        overrides: root.overrides.clone(),
        extensions: root.extensions.clone(),
    }
}

/// `base_for` gives each name's registry, to tell a derivable tarball url from one to keep.
pub fn to_lockfile(res: &Resolution, base_for: &dyn Fn(&str) -> String) -> Lockfile {
    let keys = crate::keys::store_keys(&res.packages);
    let mut packages = BTreeMap::new();
    let mut workspaces = BTreeMap::new();
    for (key, p) in &res.packages {
        if p.linked {
            // Only where it is and what it is: its dependencies are its own.
            let e = LockEntry { version: Some(p.version.clone()), bin: p.bin.clone(), ..LockEntry::default() };
            packages.insert(key.clone(), e);
            continue;
        }
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
            let real = p.alias.as_deref().unwrap_or(&p.name);
            let derivable = p.resolved == tarball_url(&base_for(real), real, &p.version);
            (None, (!derivable).then(|| p.resolved.clone()))
        };
        // A runtime's integrity, bins and platform are this machine's: its variants are the facts.
        if let Some(variants) = &p.runtime {
            let subgraph = keys.get(key).and_then(|k| k.get(k.len().saturating_sub(22)..)).map(str::to_string);
            let e = LockEntry { version, subgraph, variants: variants.clone(), ..LockEntry::default() };
            packages.insert(key.clone(), e);
            continue;
        }
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
                // The digest is the key's last 22 characters: base64url, which may hold a `-`.
                subgraph: keys.get(key).and_then(|k| k.get(k.len().saturating_sub(22)..)).map(str::to_string),
                scripts: p.scripts,
                build: p.build,
                patch: p.patch.clone(),
                variants: Vec::new(),
            },
        );
    }
    Lockfile { lockfile_version: TEXT_VERSION, root: root_of(&res.root), workspaces, packages, hash: None }
}

/// No packument, no version pick, no semver: the whole point of a lockfile. `lock` must have
/// passed `validate`.
pub fn from_lockfile(lock: &Lockfile, base_for: &dyn Fn(&str) -> String) -> Resolution {
    into_resolution(lock.clone(), base_for)
}

/// `from_lockfile`, taking the lockfile apart instead of copying it.
pub fn into_resolution(lock: Lockfile, base_for: &dyn Fn(&str) -> String) -> Resolution {
    let (shipped, required) = shipped_required(&lock);
    let mut packages = BTreeMap::new();
    for (path, ws) in lock.workspaces {
        packages.insert(
            format!("{}@link:{path}", ws.name),
            Package {
                name: ws.name,
                version: ws.version,
                local: Some(path),
                specs: ws.specs,
                dependencies: ws.dependencies,
                optional_dependencies: ws.optional_dependencies,
                bin: bin::clean_map(&ws.bin),
                peer_dependencies: (!ws.peer_dependencies.is_empty()).then_some(ws.peer_dependencies),
                peers: (!ws.peers.is_empty()).then_some(ws.peers),
                ..Package::default()
            },
        );
    }
    for (key, e) in lock.packages {
        // A copy for one set of peers: `name@version(peer@version)`.
        let (base, suffix) = split_peers(&key);
        let Some((name, tail)) = split_key(base) else { continue };
        // A linked directory: where it is, never stored.
        let link = tail.strip_prefix("link:").map(str::to_string);
        let source = e.version.as_ref().filter(|_| link.is_none()).map(|_| tail.to_string());
        // An alias: `name@npm:<real>@<version>`, served where the real package is.
        let alias = crate::graph::split_alias(tail).filter(|_| source.is_none());
        let version = match (e.version, alias) {
            (Some(v), _) => v,
            (None, Some((_, v))) => v.to_string(),
            (None, None) => tail.to_string(),
        };
        let resolved = match (&source, e.resolved) {
            (Some(s), _) => s.clone(),
            (None, Some(r)) => r,
            (None, None) => {
                let real = alias.map_or(name, |(r, _)| r);
                tarball_url(&base_for(real), real, &version)
            }
        };
        let list = |l: Vec<String>| (!l.is_empty()).then_some(l);
        let mut package = Package {
            name: name.to_string(),
            version,
            resolved,
            integrity: e.integrity,
            source,
            linked: link.is_some(),
            local: link,
            dependencies: e.dependencies,
            optional_dependencies: e.optional_dependencies,
            optional: !required.contains(&key),
            dev: !shipped.contains(&key),
            bin: bin::clean_map(&e.bin),
            os: list(e.os),
            cpu: list(e.cpu),
            libc: list(e.libc),
            peer_dependencies: (!e.peer_dependencies.is_empty()).then_some(e.peer_dependencies),
            peers: (!e.peers.is_empty()).then_some(e.peers),
            scripts: e.scripts,
            build: e.build,
            patch: e.patch,
            runtime: (!e.variants.is_empty()).then_some(e.variants),
            alias: alias.map(|(r, _)| r.to_string()),
            peer_suffix: suffix.to_string(),
            ..Package::default()
        };
        if package.runtime.is_some() {
            runtime::apply(&mut package, base_for);
        }
        packages.insert(key, package);
    }
    // A directory inside a package is fetched as that package is, from its url.
    let urls: Vec<(String, String)> = packages
        .iter()
        .filter_map(|(key, p)| {
            let (parent, _) = p.within()?;
            let mut copies = packages.range(parent.to_string()..).take_while(|(k, _)| k.starts_with(parent));
            let (_, from) = copies.find(|(k, _)| split_peers(k).0 == parent)?;
            Some((key.clone(), from.resolved.clone()))
        })
        .collect();
    for (key, url) in urls {
        if let Some(p) = packages.get_mut(&key) {
            p.resolved = url;
        }
    }
    let root = Root {
        name: lock.root.name,
        version: lock.root.version,
        specs: lock.root.specs,
        dependencies: lock.root.dependencies,
        workspaces: lock.root.workspaces,
        overrides: lock.root.overrides,
        extensions: lock.root.extensions,
    };
    Resolution { root, packages, warnings: Vec::new() }
}

/// What ships (the rest is dev-only) and what is required (the rest is optional).
fn shipped_required(lock: &Lockfile) -> (HashSet<String>, HashSet<String>) {
    let shipped = reach(lock, &|top, name| top.prod.contains(name), true);
    let required =
        reach(lock, &|top, name| !top.specs.as_ref().is_some_and(|s| s.optional().contains_key(name)), false);
    (shipped, required)
}

/// The packages, and how many are optional and dev-only, as `into_resolution` marks them,
/// without converting the lockfile.
pub fn tally(lock: &Lockfile) -> (usize, usize, usize) {
    let (shipped, required) = shipped_required(lock);
    let keys = lock.packages.keys().filter(|k| split_key(k).is_some() && !is_link(k));
    keys.fold((0, 0, 0), |(all, optional, dev), k| {
        (all + 1, optional + usize::from(!required.contains(k)), dev + usize::from(!shipped.contains(k)))
    })
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

/// jpm's text format: sorted, one fact a line, so it diffs cleanly and reads without building a
/// tree. The hash covers everything after its own line.
pub fn format_lockfile(lock: &Lockfile) -> Result<String> {
    validate(lock)?; // a lockfile our own reader would reject must never reach disk
    let body = text_body(lock);
    Ok(format!("{HEADER}jpm-lock {TEXT_VERSION}\nhash {}\n{body}", content_digest(&body)))
}

/// The lockfile as upm writes it, which `jpm lock --json` prints.
pub fn format_json(lock: &Lockfile) -> Result<String> {
    validate(lock)?;
    Ok(json::to_pretty(&lock.to_value(), "  "))
}

pub fn parse_lockfile(text: &str, file: &str) -> Result<Lockfile> {
    let lock = parse_text(text).map_err(|e| e.context(file))?;
    validate(&lock)?;
    Ok(lock)
}

const HEADER: &str = "# jpm lockfile: written by jpm. A hand edit is fine; the hash below tells jpm to check it.\n";

/// A token, quoted as a JSON string when it holds anything that would split it.
fn token(out: &mut String, t: &str) {
    out.push(' ');
    let plain = !t.is_empty() && !t.bytes().any(|b| b <= b' ' || b == b'"' || b == b'#' || b == 0x7f);
    if plain {
        out.push_str(t);
    } else {
        json::quote(out, t);
    }
}

fn line(out: &mut String, indent: bool, word: &str, tokens: &[&str]) {
    if indent {
        out.push_str("  ");
    }
    out.push_str(word);
    for t in tokens {
        token(out, t);
    }
    out.push('\n');
}

fn text_edges(out: &mut String, deps: &Deps, optional: &Deps, bins: &Deps, ranges: &Deps, peers: &Peers) {
    for (n, v) in deps {
        line(out, true, "dep", &[n, v]);
    }
    for (n, v) in optional {
        line(out, true, "optional", &[n, v]);
    }
    for (n, t) in bins {
        line(out, true, "bin", &[n, t]);
    }
    for (n, r) in ranges {
        line(out, true, "peer", &[n, r]);
    }
    for (n, k) in peers {
        line(out, true, "settled", &[n, k.as_str()]);
    }
}

fn text_specs(out: &mut String, specs: Option<&Specs>) {
    if let Some(specs) = Specs::canonical(specs) {
        for (group, map) in specs.groups() {
            for (n, r) in map.into_iter().flatten() {
                line(out, true, "spec", &[group, n, r]);
            }
        }
    }
}

fn text_body(lock: &Lockfile) -> String {
    let mut out = String::with_capacity(lock.packages.len() * 256);
    out.push_str("root\n");
    if let Some(n) = &lock.root.name {
        line(&mut out, true, "name", &[n]);
    }
    if let Some(v) = &lock.root.version {
        line(&mut out, true, "version", &[v]);
    }
    for p in lock.root.workspaces.iter().flatten() {
        line(&mut out, true, "workspace", &[p]);
    }
    for o in &lock.root.overrides {
        line(&mut out, true, "override", &[o.by.as_str(), &o.selector(), o.value_text()]);
    }
    for e in &lock.root.extensions {
        let selector = e.selector();
        for (field, name, value) in e.entries() {
            line(&mut out, true, "extension", &[&selector, field, name, value]);
        }
    }
    text_specs(&mut out, lock.root.specs.as_ref());
    for (n, v) in &lock.root.dependencies {
        line(&mut out, true, "dep", &[n, v]);
    }
    for (path, ws) in &lock.workspaces {
        line(&mut out, false, "workspace", &[path]);
        line(&mut out, true, "name", &[&ws.name]);
        line(&mut out, true, "version", &[&ws.version]);
        text_specs(&mut out, ws.specs.as_ref());
        text_edges(&mut out, &ws.dependencies, &ws.optional_dependencies, &ws.bin, &ws.peer_dependencies, &ws.peers);
    }
    for (key, e) in &lock.packages {
        line(&mut out, false, "package", &[key]);
        if let Some(v) = &e.version {
            line(&mut out, true, "version", &[v]);
        }
        if let Some(r) = &e.resolved {
            line(&mut out, true, "resolved", &[r]);
        }
        if !e.integrity.is_empty() {
            line(&mut out, true, "integrity", &[&e.integrity]);
        }
        if let Some(g) = &e.subgraph {
            line(&mut out, true, "subgraph", &[g]);
        }
        text_edges(&mut out, &e.dependencies, &e.optional_dependencies, &e.bin, &e.peer_dependencies, &e.peers);
        for (word, list) in [("os", &e.os), ("cpu", &e.cpu), ("libc", &e.libc)] {
            if !list.is_empty() {
                let items: Vec<&str> = list.iter().map(String::as_str).collect();
                line(&mut out, true, word, &items);
            }
        }
        for (word, set) in [("scripts", e.scripts), ("build", e.build)] {
            if set {
                line(&mut out, true, word, &[]);
            }
        }
        if let Some(h) = &e.patch {
            line(&mut out, true, "patch", &[h]);
        }
        for v in &e.variants {
            line(&mut out, true, "variant", &[&v.platform, &v.integrity, &v.file]);
        }
    }
    out
}

/// A 64-bit hash of the file's body, eight bytes at a time: it only has to notice an edit, not
/// withstand one (every fact is validated whatever the hash says), so no cryptographic hash.
fn content_digest(body: &str) -> String {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    let bytes = body.as_bytes();
    let (mut a, mut b) = (0x243F_6A88_85A3_08D3_u64 ^ bytes.len() as u64, 0x1319_8A2E_0370_7344_u64);
    let (blocks, rest) = bytes.as_chunks::<16>();
    for c in blocks {
        let x = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        let y = u64::from_le_bytes([c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]]);
        a = (a ^ x).wrapping_mul(K).rotate_left(29);
        b = (b ^ y).wrapping_mul(K).rotate_left(31);
    }
    for (i, &byte) in rest.iter().enumerate() {
        a = (a ^ (u64::from(byte) << ((i % 8) * 8))).wrapping_mul(K).rotate_left(29);
    }
    let mix = |mut h: u64| {
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        h ^= h >> 33;
        h = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
        h ^ (h >> 33)
    };
    format!("{:016x}{:016x}", mix(a ^ b.rotate_left(17)), mix(b ^ a.rotate_left(43)))
}

/// The tokens of one line, a quoted one read as a JSON string. A plain loop over bytes: under
/// the size-first build an iterator chain here is not inlined, and this runs once per line.
fn tokens(text: &str) -> Result<Vec<std::borrow::Cow<'_, str>>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(4);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            let mut scan = json::Scan::new(&text[i..]);
            out.push(scan.string()?);
            i += scan.pos;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b' ' {
            i += 1;
        }
        out.push(std::borrow::Cow::Borrowed(&text[start..i]));
    }
    Ok(out)
}

/// The section being read: its entry is built here and filed when the next section starts.
enum Section {
    None,
    Root,
    Workspace(String, WorkspaceEntry),
    Package(String, LockEntry),
}

fn file_section(lock: &mut Lockfile, section: Section) {
    match section {
        Section::Workspace(path, ws) => {
            lock.workspaces.insert(path, ws);
        }
        Section::Package(key, e) => {
            lock.packages.insert(key, e);
        }
        Section::None | Section::Root => {}
    }
}

fn parse_text(text: &str) -> Result<Lockfile> {
    let mut lines = text.lines().enumerate().filter(|(_, l)| !l.starts_with('#') && !l.trim().is_empty());
    let bad = |n: usize, why: &str| fail(format!("line {}: {why}", n + 1));
    match lines.next() {
        Some((_, l)) if l.trim_end().strip_prefix("jpm-lock ") == Some(TEXT_VERSION_TEXT) => {}
        Some((n, l)) => return Err(bad(n, &format!("unsupported lockfile header {:?}", l.trim_end()))),
        None => return Err(fail("the lockfile is empty")),
    }
    let (n, hash_line) = lines.next().ok_or_else(|| fail("no hash line"))?;
    let stored = hash_line.strip_prefix("hash ").ok_or_else(|| bad(n, "expected the hash line"))?.trim();
    // Everything after the hash line, exactly as written.
    let at = text.find(hash_line).map_or(text.len(), |i| i + hash_line.len());
    let body = text[at..].strip_prefix("\r\n").or_else(|| text[at..].strip_prefix('\n')).unwrap_or(&text[at..]);
    let mut lock = Lockfile { lockfile_version: TEXT_VERSION, ..Lockfile::default() };
    let mut section = Section::None;
    let mut root_seen = false;
    for (n, raw) in lines {
        let raw = raw.trim_end_matches('\r');
        let indented = raw.starts_with("  ");
        let t = tokens(raw.trim_start()).map_err(|e| bad(n, &e.message))?;
        let word = t.first().map_or("", |w| w.as_ref());
        let arg =
            |i: usize| t.get(i).map(|v| v.to_string()).ok_or_else(|| bad(n, &format!("{word} is missing a value")));
        if !indented {
            let next = match (word, t.len()) {
                ("root", 1) if !root_seen => {
                    root_seen = true;
                    Section::Root
                }
                ("workspace", 2) => Section::Workspace(arg(1)?, WorkspaceEntry::default()),
                ("package", 2) => Section::Package(arg(1)?, LockEntry::default()),
                _ => return Err(bad(n, &format!("unexpected line {raw:?}"))),
            };
            file_section(&mut lock, std::mem::replace(&mut section, next));
            continue;
        }
        let pair = || Ok::<_, Error>((arg(1)?, arg(2)?));
        match &mut section {
            Section::None => return Err(bad(n, "a field outside any section")),
            Section::Root => {
                let r = &mut lock.root;
                match word {
                    "name" => r.name = Some(arg(1)?),
                    "version" => r.version = Some(arg(1)?),
                    "workspace" => r.workspaces.get_or_insert_with(Vec::new).push(arg(1)?),
                    "override" => {
                        let o = Override::parse(&arg(1)?, &arg(2)?, &arg(3)?);
                        r.overrides.push(o.ok_or_else(|| bad(n, "override is not manager, selector and value"))?);
                    }
                    // One entry of an extension; the entries of one are written together.
                    "extension" => {
                        let selector = arg(1)?;
                        let what = || bad(n, "extension is not selector, field, name and value");
                        if r.extensions.last().is_none_or(|e| e.selector() != selector) {
                            r.extensions.push(Extension::parse_selector(&selector).ok_or_else(what)?);
                        }
                        let e = r.extensions.last_mut().ok_or_else(what)?;
                        e.add_entry(&arg(2)?, &arg(3)?, &arg(4)?).ok_or_else(what)?;
                    }
                    "spec" => add_spec(&mut r.specs, &arg(1)?, arg(2)?, arg(3)?).map_err(|e| bad(n, &e))?,
                    "dep" => {
                        let (k, v) = pair()?;
                        r.dependencies.insert(k, v);
                    }
                    _ => return Err(bad(n, &format!("unknown root field {word:?}"))),
                }
            }
            Section::Workspace(_, ws) => match word {
                "name" => ws.name = arg(1)?,
                "version" => ws.version = arg(1)?,
                "spec" => add_spec(&mut ws.specs, &arg(1)?, arg(2)?, arg(3)?).map_err(|e| bad(n, &e))?,
                _ => edge(
                    word,
                    &t,
                    &mut ws.dependencies,
                    &mut ws.optional_dependencies,
                    &mut ws.bin,
                    &mut ws.peer_dependencies,
                    &mut ws.peers,
                )
                .map_err(|e| bad(n, &e))?,
            },
            Section::Package(_, e) => match word {
                "version" => e.version = Some(arg(1)?),
                "resolved" => e.resolved = Some(arg(1)?),
                "integrity" => e.integrity = arg(1)?,
                "subgraph" => e.subgraph = Some(arg(1)?),
                "os" => e.os = t[1..].iter().map(|v| v.to_string()).collect(),
                "cpu" => e.cpu = t[1..].iter().map(|v| v.to_string()).collect(),
                "libc" => e.libc = t[1..].iter().map(|v| v.to_string()).collect(),
                "scripts" if t.len() == 1 => e.scripts = true,
                "build" if t.len() == 1 => e.build = true,
                "patch" => e.patch = Some(arg(1)?),
                "variant" if t.len() == 4 => {
                    e.variants.push(Variant { platform: arg(1)?, integrity: arg(2)?, file: arg(3)? })
                }
                _ => edge(
                    word,
                    &t,
                    &mut e.dependencies,
                    &mut e.optional_dependencies,
                    &mut e.bin,
                    &mut e.peer_dependencies,
                    &mut e.peers,
                )
                .map_err(|e| bad(n, &e))?,
            },
        }
    }
    file_section(&mut lock, section);
    if !root_seen {
        return Err(fail("no root section"));
    }
    if content_digest(body) == stored {
        lock.hash = Some(stored.to_string());
    } else {
        // Edited by hand, or merged: every fact is still checked, but nothing derived is trusted.
        for e in lock.packages.values_mut() {
            e.subgraph = None;
        }
    }
    Ok(lock)
}

fn add_spec(specs: &mut Option<Specs>, group: &str, name: String, range: String) -> std::result::Result<(), String> {
    let s = specs.get_or_insert_with(Specs::default);
    let map = match group {
        "dependencies" => &mut s.dependencies,
        "devDependencies" => &mut s.dev_dependencies,
        "optionalDependencies" => &mut s.optional_dependencies,
        _ => return Err(format!("unknown dependency group {group:?}")),
    };
    map.get_or_insert_with(Deps::new).insert(name, range);
    Ok(())
}

/// One of the edge lines a workspace and a package share.
fn edge(
    word: &str,
    t: &[std::borrow::Cow<'_, str>],
    deps: &mut Deps,
    optional: &mut Deps,
    bins: &mut Deps,
    ranges: &mut Deps,
    peers: &mut Peers,
) -> std::result::Result<(), String> {
    let (Some(a), Some(b), 3) = (t.get(1), t.get(2), t.len()) else {
        return Err(format!("{word} takes two values"));
    };
    let (a, b) = (a.to_string(), b.to_string());
    match word {
        "dep" => deps.insert(a, b),
        "optional" => optional.insert(a, b),
        "bin" => bins.insert(a, b),
        "peer" => ranges.insert(a, b),
        "settled" => {
            let kind = PeerKind::parse(&b).ok_or_else(|| format!("settled {a} must be required or optional"))?;
            peers.insert(a, kind);
            return Ok(());
        }
        _ => return Err(format!("unknown field {word:?}")),
    };
    Ok(())
}

/// Whether the file at `path` is in jpm's current format, from its first bytes alone.
pub fn is_current(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 128];
    let n = std::fs::File::open(path).and_then(|mut f| f.read(&mut head)).unwrap_or(0);
    let head = String::from_utf8_lossy(&head[..n]);
    head.lines().find(|l| !l.starts_with('#')).is_some_and(|l| l.trim_end() == format!("jpm-lock {TEXT_VERSION}"))
}

/// The hash of the lockfile's content: the one stored when it still matches, else computed.
pub fn content_hash(lock: &Lockfile) -> String {
    lock.hash.clone().unwrap_or_else(|| content_digest(&text_body(lock)))
}

/// Each package's store entry name, by key, when the lockfile's hash says the subgraphs it
/// records are its own; `None` means hashing the graph (`keys::store_keys`).
pub fn recorded_keys(lock: &Lockfile) -> Option<std::collections::HashMap<String, String>> {
    lock.hash.as_ref()?;
    lock.packages
        .iter()
        .filter(|(key, _)| !is_link(key))
        .map(|(key, e)| {
            let (name, tail) = split_key(split_peers(key).0)?;
            // An alias's `npm:<real>@<version>`: its real name and version, as `keys::store_keys`
            // names it.
            let alias = crate::graph::split_alias(tail);
            let name = alias.map_or(name, |(real, _)| real);
            let version = e.version.as_deref().or(alias.map(|(_, v)| v)).unwrap_or(tail);
            Some((key.clone(), format!("{}@{version}-{}", name.replace('/', "+"), e.subgraph.as_ref()?)))
        })
        .collect()
}

/// A linked directory's key, `name@link:<path>`: no store entry, so no subgraph.
fn is_link(key: &str) -> bool {
    split_key(key).is_some_and(|(_, tail)| tail.starts_with("link:"))
}

/// `jpm.lock` in `dir`, or `None` when there is none.
pub fn read_lockfile(dir: &Path) -> Result<Option<(Lockfile, &'static str)>> {
    let file = dir.join(LOCKFILE);
    match std::fs::read_to_string(&file) {
        Ok(text) => parse_lockfile(&text, LOCKFILE).map(|l| Some((l, LOCKFILE))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(&e, format!("cannot read {}", file.display())).with_code("ELOCK")),
    }
}

/// Brought over from a format without them, or changed: the subgraphs are hashed once, here.
fn fill_subgraphs(lock: &mut Lockfile) {
    if lock.packages.iter().any(|(k, e)| e.subgraph.is_none() && !is_link(k)) {
        let keys = crate::keys::store_keys(&from_lockfile(lock, &|_| String::new()).packages);
        for (key, e) in &mut lock.packages {
            e.subgraph = keys.get(key).and_then(|k| k.get(k.len().saturating_sub(22)..)).map(str::to_string);
        }
    }
}

/// Mark each package the project's patches apply to. Whether that changed anything: then the
/// subgraphs are hashed again, and the file no longer has the content it was read with.
pub fn mark_patches(lock: &mut Lockfile, patches: &[crate::patch::Patch]) -> Result<bool> {
    // An alias by the package it installs, as pnpm patches it: anthropic-sdk-typescript's
    // `tsc-multi` is @stainless-api/tsc-multi, and its patch names that.
    let packages = lock.packages.iter().filter(|(k, _)| !is_link(k)).filter_map(|(k, e)| {
        let (name, tail) = split_key(split_peers(k).0)?;
        let (name, tail) = crate::graph::split_alias(tail).unwrap_or((name, tail));
        Some((k.as_str(), name, e.version.as_deref().unwrap_or(tail)))
    });
    let chosen = crate::patch::select(patches, packages)?;
    let mut changed = false;
    for (key, e) in &mut lock.packages {
        let want = chosen.get(key);
        if e.patch.as_ref() != want {
            e.patch = want.cloned();
            changed = true;
        }
    }
    if changed {
        lock.hash = None;
        lock.packages.values_mut().for_each(|e| e.subgraph = None);
        fill_subgraphs(lock);
    }
    Ok(changed)
}

/// Write `jpm.lock`; the lock then carries the hash of what was written.
pub fn write_lockfile(dir: &Path, lock: &mut Lockfile) -> Result<()> {
    lock.lockfile_version = TEXT_VERSION;
    fill_subgraphs(lock);
    let text = format_lockfile(lock)?;
    write_atomic(&dir.join(LOCKFILE), text.as_bytes())?;
    lock.hash = parse_text(&text)?.hash;
    Ok(())
}

/// Whether the lockfile was made from this tree: the same workspace patterns, workspaces and
/// declared ranges. Anything else means a resolve.
pub fn same_tree(lock: &Lockfile, manifest: &RootManifest, workspaces: &[Workspace]) -> bool {
    let patterns = manifest.workspaces.clone().unwrap_or_default();
    if patterns != lock.root.workspaces.clone().unwrap_or_default() {
        return false;
    }
    if !same_specs(manifest.specs().as_ref(), lock.root.specs.as_ref())
        || manifest.overrides != lock.root.overrides
        || manifest.extensions != lock.root.extensions
    {
        return false;
    }
    // The root listed as a workspace, there while something links to it: its specs say that.
    let root = lock.workspaces.get(crate::project::ROOT_PATH);
    let version = manifest.version.as_deref().unwrap_or("0.0.0");
    if root.is_some_and(|r| manifest.name.as_ref() != Some(&r.name) || r.version != version || r.bin != manifest.bins())
    {
        return false;
    }
    if lock.workspaces.len() != workspaces.len() + usize::from(root.is_some()) {
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
    if lock.lockfile_version != VERSION && lock.lockfile_version != TEXT_VERSION {
        return Err(fail(format!("unsupported lockfileVersion {}", lock.lockfile_version)));
    }
    let mut known: HashSet<String> = lock.packages.keys().cloned().collect();
    for (path, ws) in &lock.workspaces {
        let at = format!("workspaces[{path:?}]");
        if !local_path(path) {
            return Err(fail(format!("{at} is not a relative path inside the project")));
        }
        if !semver::is_exact(&ws.version) || spec::parse_dep(&ws.name, &ws.version).is_err() {
            return Err(fail(format!("{at}.version must be an exact version")));
        }
        known.insert(format!("{}@link:{path}", ws.name));
    }
    // Every copy of a package is one tarball: the facts that name it are the same.
    let whole = Whole::new(lock);
    let mut bases: HashMap<&str, &LockEntry> = HashMap::new();
    for (key, e) in &lock.packages {
        let at = format!("packages[{key:?}]");
        let (base, suffix) = split_peers(key);
        let source = check_key(base)?;
        if !suffix.is_empty() {
            check_suffix(&at, base, suffix, e, &whole)?;
        }
        if let Some(first) = bases.insert(base, e)
            && (first.integrity != e.integrity || first.resolved != e.resolved || first.version != e.version)
        {
            return Err(fail(format!("{at} is a copy of {base}, and names another tarball than its other copies")));
        }
        // The registry package whose tarball this one's files are in, if they are, else its own.
        let own = split_key(base).and_then(|(_, v)| split_within(v)).map_or(base, |(parent, _)| parent);
        // A linked directory's dependencies are its own; the rest of an entry is not read.
        if is_link(key) {
            let bare = e.dependencies.is_empty() && e.optional_dependencies.is_empty();
            if !bare || !e.version.as_deref().is_some_and(semver::is_exact) {
                return Err(fail(format!("{at} is a linked directory: an exact version and bins only")));
            }
            check_edges(&at, &e.bin, &e.peers, &e.peer_dependencies, [&e.dependencies; 2], &|_| false)?;
            continue;
        }
        // A directory is linked from a top, and from a package only as a peer the project
        // provides, as pnpm links `(@nuxt/schema@packages+schema)`, or as the workspace of its
        // name (npm's tree, pnpm's `linkWorkspacePackages: deep`): a published package never
        // names a path of its own.
        for (name, v) in e.dependencies.iter().chain(&e.optional_dependencies) {
            let peer = || e.peer_dependencies.contains_key(name) && known.contains(&format!("{name}@{v}"));
            let workspace =
                || v.strip_prefix("link:").is_some_and(|p| lock.workspaces.get(p).is_some_and(|w| w.name == *name));
            if v.starts_with("link:") && !peer() && !workspace() {
                return Err(fail(format!(
                    "{at}.dependencies[{name:?}] is {v}: a package links a directory only to the workspace of its name"
                )));
            }
            // A directory inside a package, only from that package's own tarball.
            if split_within(crate::graph::edge_base(name, v)).is_some_and(|(parent, _)| parent != own) {
                return Err(fail(format!(
                    "{at}.dependencies[{name:?}] is {v}: a package links a directory only inside its own tarball"
                )));
            }
        }
        // It becomes part of a directory name, so it is exactly what `short_hash` writes.
        if e.subgraph
            .as_ref()
            .is_some_and(|g| g.len() != 22 || !g.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(fail(format!("{at}.subgraph is not a digest")));
        }
        if let Some((name, version)) = split_key(base).and_then(|(n, v)| Some((n, v.strip_prefix(runtime::PROTOCOL)?)))
        {
            check_runtime(&at, name, version, e)?;
        } else if !e.variants.is_empty() {
            return Err(fail(format!("{at} has variants, which only a runtime has")));
        } else if e.integrity.is_empty() {
            return Err(fail(format!("{at}.integrity must be a non-empty string")));
        }
        if e.patch.as_ref().is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(fail(format!("{at}.patch is not a sha256")));
        }
        if e.build && !e.scripts {
            return Err(fail(format!("{at} approves install scripts it does not have")));
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
        check_edges(&at, &e.bin, &e.peers, &e.peer_dependencies, [&e.dependencies, &e.optional_dependencies], &|k| {
            known.contains(k)
        })?;
    }
    // A directory inside a package has that package's integrity: its files are that tarball's.
    for (key, e) in &lock.packages {
        let Some((parent, _)) = split_key(split_peers(key).0).and_then(|(_, v)| split_within(v)) else { continue };
        if !bases.get(parent).is_some_and(|p| p.integrity == e.integrity) {
            return Err(fail(format!(
                "packages[{key:?}] is inside {parent}, which packages has with no such integrity"
            )));
        }
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
        let mut edges = ws.dependencies.clone();
        edges.extend(ws.optional_dependencies.clone());
        check_top(ws.specs.as_ref(), &edges, &at, &ws.peer_dependencies)?;
        let link = format!("link:{path}");
        let parent = Some((ws.name.as_str(), link.as_str()));
        let top = Asks { specs: ws.specs.as_ref(), peers: &ws.peer_dependencies, base: path, parent };
        check_links(&top, &edges, &at, &whole)?;
    }
    let root = Asks { specs: lock.root.specs.as_ref(), peers: &Deps::new(), base: "", parent: None };
    check_links(&root, &lock.root.dependencies, "root", &whole)?;
    for (name, version) in &lock.root.dependencies {
        spec::check_name(name, name).map_err(|_| fail(format!("root.dependencies[{name:?}] is not a package name")))?;
        if !known.contains(&format!("{name}@{version}")) {
            let place = if version.starts_with("link:") { "workspaces" } else { "packages" };
            return Err(fail(format!(
                "root.dependencies[{name:?}] points at {name}@{version}, which is not in {place}"
            )));
        }
    }
    check_top(lock.root.specs.as_ref(), &lock.root.dependencies, "root", &Deps::new())
}

/// A runtime is its builds and nothing else: no edges, bins, scripts or patch of its own, and one
/// build per platform, each checked before it names a download.
fn check_runtime(at: &str, name: &str, version: &str, e: &LockEntry) -> Result<()> {
    let bare = e.version.as_deref() == Some(version)
        && e.integrity.is_empty()
        && e.dependencies.is_empty()
        && e.optional_dependencies.is_empty()
        && e.bin.is_empty()
        && e.peer_dependencies.is_empty()
        && e.os.is_empty()
        && e.cpu.is_empty()
        && e.libc.is_empty()
        && !e.scripts
        && e.patch.is_none();
    if !bare || e.variants.is_empty() {
        return Err(fail(format!("{at} is a runtime: a version and one variant per platform only")));
    }
    for (i, v) in e.variants.iter().enumerate() {
        runtime::check_variant(name, v).map_err(|why| fail(format!("{at}: {why}")))?;
        if e.variants[..i].iter().any(|o| o.platform == v.platform) {
            return Err(fail(format!("{at} has two variants for {}", v.platform)));
        }
    }
    Ok(())
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

/// The top at `base` (the root, `parent` `None`, or the workspace `parent`), as its specs and
/// peer ranges ask for each name once the overrides have their say.
struct Asks<'a> {
    specs: Option<&'a Specs>,
    peers: &'a Deps,
    base: &'a str,
    parent: Option<(&'a str, &'a str)>,
}

/// A top links a directory, or takes a git or tarball package, only where its own spec for the
/// name says so: an edit cannot point a name at another directory, repository, commit or url.
/// A name linked by name alone is a workspace, and never a `file:` directory another top names
/// by its path, which may share the name.
fn check_links(top: &Asks, deps: &Deps, at: &str, whole: &Whole) -> Result<()> {
    let lock = whole.lock;
    for (name, version) in deps {
        let version = &crate::graph::edge_base(name, version).to_string();
        if version.starts_with(WITHIN) {
            return Err(fail(format!(
                "{at}.dependencies[{name:?}] is {version}: only the package that ships it links it"
            )));
        }
        // Only a link, a source or an alias is checked against what is asked: a registry version,
        // nearly every edge, never matches its ranges against the overrides.
        let asked = std::cell::OnceCell::new();
        let asked = || {
            asked.get_or_init(|| {
                let ranges = top.specs.into_iter().flat_map(Specs::groups).filter_map(|(_, g)| g?.get(name));
                ranges
                    .chain(top.peers.get(name))
                    .filter_map(|range| whole.ask(top.parent, name, range))
                    .collect::<Vec<_>>()
            })
        };
        if let Some(path) = version.strip_prefix("link:") {
            let asked = asked();
            let dirs: Vec<&spec::Spec> = asked.iter().filter(|s| s.kind == Kind::Directory).collect();
            let named = if dirs.is_empty() && !lock.packages.contains_key(&format!("{name}@{version}")) {
                by_name(path, whole)
            } else {
                // The project's own directory (`file:.`, `file:../../`) is the root's path, `.`.
                let at = |s: &&spec::Spec| spec::join_path(top.base, &s.fetch_spec[5..]);
                dirs.iter().any(|s| at(s) == path || (at(s).is_empty() && path == crate::project::ROOT_PATH))
            };
            // pnpm's `workspace:<other>@<range>`: the one workspace so named, under this name.
            let aliased = || {
                let ws = lock.workspaces.get(path);
                asked.iter().any(|s| {
                    s.kind == Kind::Workspace
                        && s.fetch_name != *name
                        && ws.is_some_and(|w| w.name == s.fetch_name)
                        && whole.named(&s.fetch_name) == 1
                })
            };
            // A peer settled on a directory of its name the tree has (a host that depends on its
            // plugin by path), in its range or out of it, as the walk links a workspace so named.
            let peer = || {
                let ws = lock.workspaces.get(path);
                top.peers.contains_key(name) && ws.is_some_and(|w| w.name == *name)
            };
            if !named && !aliased() && !peer() {
                return Err(fail(format!("{at}.dependencies[{name:?}] links {path}, which its specs do not name")));
            }
        } else if (spec::is_git(version) || version.contains("://") || version.starts_with("file:"))
            && !asked().iter().any(|s| spec::names_source(s, top.base, version))
        {
            return Err(fail(format!("{at}.dependencies[{name:?}] is {version}, which its specs do not name")));
        } else if let Some((real, _)) = crate::graph::split_alias(version)
            && !asked().iter().any(|s| s.fetch_name == real)
            && !(top.peers.contains_key(name) && a_top_aliases(whole, name, real))
        {
            // An edit cannot put another package under a name a spec gave to one it names.
            return Err(fail(format!("{at}.dependencies[{name:?}] is {version}, which its specs do not name")));
        }
    }
    Ok(())
}

/// Whether the root or a workspace declares `name` as an alias of `real`: a workspace's peer by
/// that name settles on that copy, as pnpm has it and as npm hoists it (hono's root has typescript
/// as an alias of @typescript/typescript6; gutenberg's workspaces have prettier as wp-prettier).
fn a_top_aliases(whole: &Whole, name: &str, real: &str) -> bool {
    let aliases = whole.aliases.get_or_init(|| {
        let mut out = HashSet::new();
        for (_, specs) in whole.tops() {
            let ranges = specs.into_iter().flat_map(Specs::groups).flat_map(|(_, g)| g.into_iter().flatten());
            for (name, range) in ranges {
                if let Ok(s) = spec::parse_dep(name, range) {
                    out.insert((name.clone(), s.fetch_name));
                }
            }
        }
        out
    });
    aliases.contains(&(name.to_string(), real.to_string()))
}

/// Whether `spec` asks the registry for `name` itself: a version, range or tag, not an alias,
/// a directory, a workspace or a source.
fn registry_version(name: &str, spec: &str) -> bool {
    spec::parse_dep(name, spec)
        .is_ok_and(|s| matches!(s.kind, Kind::Version | Kind::Range | Kind::Tag) && s.fetch_name == name)
}

/// Whether the workspace entry at `path` may be linked by its name: the one entry so named, or
/// one no top reaches by a `file:` or `link:` path.
fn by_name(path: &str, whole: &Whole) -> bool {
    let Some(target) = whole.lock.workspaces.get(path) else { return false };
    if whole.named(&target.name) == 1 {
        return true;
    }
    // ponytail: a workspace that is also some top's `file:` path, sharing its name with another
    // `file:` directory, is refused here; tell the two apart in the lockfile if that turns up.
    let paths = whole.paths.get_or_init(|| {
        let mut out = HashSet::new();
        for (base, specs) in whole.tops() {
            let ranges = specs.into_iter().flat_map(Specs::groups).flat_map(|(_, g)| g.into_iter().flatten());
            for (name, range) in ranges {
                if let Some(s) = spec::parse_dep(name, range).ok().filter(|s| s.kind == Kind::Directory) {
                    out.insert(spec::join_path(base, &s.fetch_spec[5..]));
                }
            }
        }
        out
    });
    !paths.contains(path)
}

/// What some checks ask of the whole lockfile, worked out the first time one asks and kept for
/// the rest of `validate`. Worked out again for each entry or edge, as it was, a lockfile of a
/// few thousand peer suffixes or workspaces (a few hundred KB) took minutes to check.
struct Whole<'a> {
    lock: &'a Lockfile,
    /// Each package key without its peer suffix.
    bases: std::cell::OnceCell<HashSet<&'a str>>,
    /// How many workspace entries have each name.
    names: std::cell::OnceCell<HashMap<&'a str, usize>>,
    /// Every directory a top's `file:` or `link:` spec names, by its path.
    paths: std::cell::OnceCell<HashSet<String>>,
    /// Every `(name, package)` a top's spec asks for under that name: an alias's real package.
    aliases: std::cell::OnceCell<HashSet<(String, String)>>,
    /// The root's overrides, by the name they override.
    overrides: std::cell::OnceCell<HashMap<&'a str, Rules>>,
    /// What `ask` made of each `(parent, name, range)`.
    asked: std::cell::RefCell<HashMap<AskKey, Option<spec::Spec>>>,
}

/// A parent (where it matters), a name and a range.
type AskKey = (Option<(String, String)>, String, String);

/// The overrides of one name, in order.
struct Rules {
    rules: Vec<Override>,
    /// Each asks for a registry version of the name (see `ask`).
    registry: bool,
    /// Some apply only under a parent.
    scoped: bool,
}

impl<'a> Whole<'a> {
    fn new(lock: &'a Lockfile) -> Self {
        Self {
            lock,
            bases: Default::default(),
            names: Default::default(),
            paths: Default::default(),
            aliases: Default::default(),
            overrides: Default::default(),
            asked: Default::default(),
        }
    }

    /// What a top asks for under `name` with `range`, once the overrides have their say.
    /// Matching a range against every override of its name is an intersection each, so it is
    /// skipped where the answer cannot matter: when the range and every override of the name
    /// ask for a registry version of it, whichever applies asks for one. What the checks read
    /// of what is asked (a directory, a workspace, a source, the package an alias names) is the
    /// same either way.
    fn ask(&self, parent: Option<(&str, &str)>, name: &str, range: &str) -> Option<spec::Spec> {
        let by_name = self.overrides.get_or_init(|| {
            let mut out: HashMap<&str, Rules> = HashMap::new();
            for o in &self.lock.root.overrides {
                let rules =
                    out.entry(o.name.as_str()).or_insert(Rules { rules: Vec::new(), registry: true, scoped: false });
                rules.registry &= o.value.as_deref().is_some_and(|v| registry_version(&o.name, v));
                rules.scoped |= o.parent.is_some();
                rules.rules.push(o.clone());
            }
            out
        });
        let Some(rules) = by_name.get(name) else { return spec::parse_dep(name, range).ok() };
        if rules.registry && registry_version(name, range) {
            return spec::parse_dep(name, range).ok();
        }
        // Each range once, and for each parent only where an override names one.
        let key = (
            rules.scoped.then(|| parent.map(|(n, v)| (n.to_string(), v.to_string()))).flatten(),
            name.to_string(),
            range.to_string(),
        );
        if let Some(hit) = self.asked.borrow().get(&key) {
            return hit.clone();
        }
        let asked = match crate::rules::find(&rules.rules, parent, name, range) {
            Some(Some(value)) => spec::parse_dep(name, value).ok(),
            Some(None) => None,
            None => spec::parse_dep(name, range).ok(),
        };
        self.asked.borrow_mut().insert(key, asked.clone());
        asked
    }

    /// How many workspace entries are named `name`.
    fn named(&self, name: &str) -> usize {
        let names = self.names.get_or_init(|| {
            let mut out = HashMap::new();
            for w in self.lock.workspaces.values() {
                *out.entry(w.name.as_str()).or_default() += 1;
            }
            out
        });
        names.get(name).copied().unwrap_or(0)
    }

    /// The root and each workspace: its directory and its specs.
    fn tops(&self) -> impl Iterator<Item = (&'a str, Option<&'a Specs>)> {
        let lock = self.lock;
        std::iter::once(("", lock.root.specs.as_ref()))
            .chain(lock.workspaces.iter().map(|(p, w)| (p.as_str(), w.specs.as_ref())))
    }
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
            // Each name becomes a link in node_modules: a `/` past a scope or a `..` would climb out.
            spec::check_name(name, name).map_err(|_| fail(format!("{at}.{field}[{name:?}] is not a package name")))?;
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
/// A `:` is a drive (`C:/x`, `C:x`) or a stream on Windows.
fn escapes(value: &str) -> bool {
    let clean = value.replace('\\', "/");
    clean.starts_with('/') || clean.contains(':') || clean.split('/').any(|p| p == "..")
}

/// A copy's peer suffix, `(peer@version)...` as pnpm writes it: groups sorted as text, one per
/// name, each a copy the lockfile has (or its package, where a cycle cut the key short), and
/// each the copy it links under that name. A linked directory and a runtime have no peers.
fn check_suffix(at: &str, base: &str, suffix: &str, e: &LockEntry, whole: &Whole) -> Result<()> {
    let lock = whole.lock;
    let bad = |why: &str| Err(fail(format!("{at} has a peer suffix that {why}")));
    if is_link(base) || split_key(base).is_some_and(|(_, v)| v.starts_with(runtime::PROTOCOL)) {
        return bad("only a registry, git or tarball package may have");
    }
    let Some(groups) = crate::graph::peer_groups(suffix) else { return bad("is not groups of keys") };
    let known = |k: &str| {
        lock.packages.contains_key(k)
            || split_key(k).is_some_and(|(n, v)| {
                v.strip_prefix("link:").is_some_and(|p| lock.workspaces.get(p).is_some_and(|w| w.name == n))
            })
    };
    let mut names: HashSet<&str> = HashSet::new();
    for (i, inner) in groups.iter().enumerate() {
        let Some((name, _)) = split_key(inner) else { return bad("is not groups of keys") };
        if !names.insert(name) || (i > 0 && format!("({})", groups[i - 1]) >= format!("({inner})")) {
            return bad("is not sorted, one group a name");
        }
        let cut = || {
            split_peers(inner).1.is_empty()
                && whole.bases.get_or_init(|| lock.packages.keys().map(|k| split_peers(k).0).collect()).contains(inner)
        };
        if !known(inner) && !cut() {
            return bad(&format!("names {inner}, which is not in packages"));
        }
        if let Some(v) = e.dependencies.get(name).or_else(|| e.optional_dependencies.get(name)) {
            let linked = format!("{name}@{v}");
            if linked != *inner && split_peers(&linked).0 != *inner {
                return bad(&format!("names {inner}, and it links {linked}"));
            }
        }
    }
    Ok(())
}

/// A key is `name@version` or `name@<source>`, and both halves become path segments.
fn check_key(key: &str) -> Result<Option<String>> {
    let bad = || fail(format!("package key {key:?} is not name@version"));
    let (name, version) = split_key(key).filter(|(_, v)| !v.is_empty()).ok_or_else(bad)?;
    if let Some(v) = version.strip_prefix(runtime::PROTOCOL) {
        if !runtime::NAMES.contains(&name) || runtime::check_version(name, v).is_err() {
            return Err(fail(format!("package key {key:?} is not a runtime at an exact version")));
        }
        return Ok(Some(version.to_string()));
    }
    // A directory inside a registry package's tarball: that package's key, and a plain path.
    if let Some((parent, at)) = split_within(version) {
        let plain = crate::tar::plain(at) && !at.contains(['%', '(', ')']);
        if !plain || spec::check_name(name, key).is_err() || !matches!(check_key(parent), Ok(None)) {
            return Err(fail(format!("package key {key:?} is not a directory inside a registry package")));
        }
        return Ok(Some(version.to_string()));
    }
    // An alias: `name@npm:<real>@<version>`, both names package names and the version exact.
    if let Some((real, v)) = crate::graph::split_alias(version) {
        let named = |n: &str| spec::check_name(n, key).is_ok();
        if !named(name) || !named(real) || !semver::is_exact(v) {
            return Err(fail(format!("package key {key:?} is not an alias of a package at an exact version")));
        }
        return Ok(None);
    }
    // Almost every key is `name@1.2.3`: checked directly, without building a spec.
    if version.as_bytes()[0].is_ascii_digit() && semver::is_exact(version) {
        spec::check_name(name, key).map_err(|_| fail(format!("package key {key:?} is not a valid package name")))?;
        return Ok(None);
    }
    let spec =
        spec::parse_dep(name, version).map_err(|_| fail(format!("package key {key:?} is not a valid package name")))?;
    // A directory is only ever `link:`: one inside the project whose dependencies install is a
    // workspace entry, not a package.
    let dir = spec.kind == Kind::Directory && version.len() > 5 && version.starts_with("link:");
    // A git package is locked to a commit, never to a branch.
    let git = spec.kind == Kind::Git && spec::is_commit(crate::git::split(version).1);
    if spec.kind == Kind::Tarball || dir || git {
        if spec.fetch_spec != version {
            return Err(fail(format!("package key {key:?} does not name its source as a lockfile does")));
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
            r#"jpm-lock 2
hash 0
root
  name app
  spec dependencies a ^1
  spec devDependencies d ^1
  dep a 1.0.0
  dep d 1.0.0
package a@1.0.0
  integrity sha512-a
  dep b 1.0.0
  optional c 1.0.0
package b@1.0.0
  integrity sha512-b
  bin b cli.js
package c@1.0.0
  integrity sha512-c
  os darwin
package d@1.0.0
  integrity sha512-d
  dep b 1.0.0
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
        // upm's JSON in, jpm's text out, and the text reads back to the same text.
        let text = format_lockfile(&to_lockfile(&res, &base)).unwrap();
        let again = parse_lockfile(&text, LOCKFILE).unwrap();
        assert!(again.hash.is_some(), "an untouched file keeps its hash");
        assert_eq!(format_lockfile(&to_lockfile(&from_lockfile(&again, &base), &base)).unwrap(), text);
        // And the JSON view is upm's shape.
        assert_eq!(format_json(&again).unwrap(), format_json(&lock).unwrap());
        // The stored subgraphs are the ones hashing the graph gives.
        assert_eq!(recorded_keys(&again).unwrap(), crate::keys::store_keys(&res.packages));
    }

    #[test]
    fn tallies_as_the_graph_marks() {
        let linked = "jpm-lock 2\nhash 0\nroot\n  spec dependencies l link:../l\n  spec optionalDependencies a ^1\n  dep l link:../l\n  dep a 1.0.0\n\
                      package l@link:../l\n  version 1.0.0\npackage a@1.0.0\n  integrity sha512-a\n";
        for lock in [sample(), parse_lockfile(linked, LOCKFILE).unwrap()] {
            let res = from_lockfile(&lock, &|_| String::new());
            let all: Vec<&Package> = res.packages.values().filter(|p| p.local.is_none()).collect();
            let optional = all.iter().filter(|p| p.optional).count();
            let dev = all.iter().filter(|p| p.dev).count();
            assert_eq!(tally(&lock), (all.len(), optional, dev));
        }
        assert_eq!(tally(&sample()), (4, 1, 1));
        assert_eq!(tally(&parse_lockfile(linked, LOCKFILE).unwrap()), (1, 1, 0));
    }

    #[test]
    fn distrusts_an_edited_file() {
        let base = |_: &str| "https://registry.npmjs.org".to_string();
        let text = format_lockfile(&to_lockfile(&from_lockfile(&sample(), &base), &base)).unwrap();
        let edited = text.replace("integrity sha512-b", "integrity sha512-B");
        let lock = parse_lockfile(&edited, LOCKFILE).unwrap();
        assert!(lock.hash.is_none());
        assert!(lock.packages.values().all(|e| e.subgraph.is_none()));
        assert!(parse_lockfile(&text.replace("jpm-lock 2", "jpm-lock 9"), LOCKFILE).is_err());
        assert!(parse_lockfile(&text.replace("  dep b 1.0.0\n", "  dep b\n"), LOCKFILE).is_err());
        let quoted = text.replace("bin b cli.js", "bin \"my tool\" \"a b.js\"");
        let lock = parse_lockfile(&quoted, LOCKFILE).unwrap();
        assert_eq!(lock.packages["b@1.0.0"].bin["my tool"], "a b.js");
        assert!(format_lockfile(&lock).unwrap().contains("bin \"my tool\" \"a b.js\""));
    }

    #[test]
    fn keeps_overrides_in_order() {
        let mut lock = sample();
        let rule = |by, sel, value| Override::parse(by, sel, value).unwrap();
        lock.root.overrides = vec![rule("pnpm", "a@1>b", "-"), rule("yarn", "b@^1", "1.0.0"), rule("npm", "b", "$x")];
        let text = format_lockfile(&lock).unwrap();
        assert!(text.contains("  override pnpm a@1>b -\n  override yarn b@^1 1.0.0\n  override npm b $x\n"), "{text}");
        let back = parse_lockfile(&text, LOCKFILE).unwrap();
        assert_eq!(back.root.overrides, lock.root.overrides);
        assert!(back.hash.is_some());
        assert!(
            format_json(&back)
                .unwrap()
                .contains("\"overrides\": [\n      [\n        \"pnpm\",\n        \"a@1>b\",\n        \"-\"")
        );
        for bad in ["  override bun b 1\n", "  override npm ../x 1\n", "  override npm b\n"] {
            let text = text.replace("  override npm b $x\n", bad);
            assert!(parse_lockfile(&text, LOCKFILE).is_err(), "{bad}");
        }
    }

    #[test]
    fn keeps_linked_directories_to_what_package_json_says() {
        let text = "jpm-lock 2\nhash 0\nroot\n  spec dependencies l link:../l\n  dep l link:../l\n\
                    package l@link:../l\n  version 1.0.0\n  bin l cli.js\n";
        let base = |_: &str| String::new();
        let res = from_lockfile(&parse_lockfile(text, LOCKFILE).unwrap(), &base);
        let l = &res.packages["l@link:../l"];
        assert!(l.linked && l.local.as_deref() == Some("../l") && l.version == "1.0.0", "{l:?}");
        let again = format_lockfile(&to_lockfile(&res, &base)).unwrap();
        assert!(again.ends_with(&text[text.find("root").unwrap()..]), "{again}");
        assert!(recorded_keys(&parse_lockfile(&again, LOCKFILE).unwrap()).is_some(), "no subgraph to hash");
        let dep = "package a@1.0.0\n  integrity sha512-a\n  dep l link:../l\n";
        for bad in [
            text.replace("  bin l cli.js\n", "  bin l cli.js\n  dep a 1.0.0\n"),
            text.replace("  version 1.0.0\n", "  version ^1\n"),
            text.replace("link:../l", "link:a/../../l"),
            text.replace("link:../l", "link:"),
            text.replace("dependencies l link:../l", "dependencies l ^1"),
            text.replace("dependencies l link:../l", "dependencies l link:../m"),
            text.replace("bin l cli.js", "bin l ../../x"),
            text.replace("  dep l link:../l\n", "  dep l link:../l\n  dep a 1.0.0\n")
                .replace("\n  spec", "\n  spec dependencies a 1\n  spec")
                + dep,
        ] {
            assert!(parse_lockfile(&bad, LOCKFILE).is_err(), "{bad}");
        }
    }

    #[test]
    fn locks_a_git_package_to_a_commit() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let text = format!(
            "jpm-lock 2\nhash 0\nroot\n  spec dependencies g github:u/r#main\n  dep g \"git+https://github.com/u/r.git#{commit}\"\n\
             package \"g@git+https://github.com/u/r.git#{commit}\"\n  version 1.0.0\n  integrity sha512-g\n"
        );
        let lock = parse_lockfile(&text, LOCKFILE).unwrap();
        let res = from_lockfile(&lock, &|_| String::new());
        let g = &res.packages[&format!("g@git+https://github.com/u/r.git#{commit}")];
        assert_eq!(
            (g.version.as_str(), g.source.as_deref()),
            ("1.0.0", Some(&*format!("git+https://github.com/u/r.git#{commit}")))
        );
        let again = format_lockfile(&to_lockfile(&res, &|_| String::new())).unwrap();
        assert!(
            again.contains(&format!("package \"g@git+https://github.com/u/r.git#{commit}\"\n  version 1.0.0\n")),
            "{again}"
        );
        for bad in [
            text.replace(&format!("#{commit}"), "#main"),
            text.replace(&format!("#{commit}"), &format!("#{}", &commit[..12])),
            text.replace("git+https://github.com/u/r.git", "git+https://-oProxyCommand=x/r.git"),
            text.replace("git+https://github.com/u/r.git", "git+https://github.com/u/r"),
            text.replace("  version 1.0.0\n", ""),
        ] {
            assert!(parse_lockfile(&bad, LOCKFILE).is_err(), "{bad}");
        }
    }

    #[test]
    fn locks_a_runtime_with_every_platforms_build() {
        let sha = "sha256-dLsPOoAwfFKUIcPthFF7j1Q4Z3CfQeU81z35nmRCr00=";
        let here = crate::runtime::platform_key(&crate::sys::Platform::current());
        let text = format!(
            "jpm-lock 2\nhash 0\nroot\n  spec devDependencies node runtime:22\n  dep node runtime:22.0.0\n\
             package node@runtime:22.0.0\n  version 22.0.0\n  variant {here} {sha} node-v22.0.0-{here}.tar.gz\n\
             \x20 variant zz-other {sha} node-v22.0.0-zz.tar.gz\n"
        );
        let lock = parse_lockfile(&text, LOCKFILE).unwrap();
        crate::runtime::configure(None, true);
        let res = from_lockfile(&lock, &|_| String::new());
        let node = &res.packages["node@runtime:22.0.0"];
        assert_eq!((node.version.as_str(), node.integrity.as_str(), node.dev), ("22.0.0", sha, true));
        assert_eq!(node.resolved, format!("https://nodejs.org/download/release/v22.0.0/node-v22.0.0-{here}.tar.gz"));
        assert!(node.bin.contains_key("node") && node.os.is_none());
        let again = format_lockfile(&to_lockfile(&res, &|_| String::new())).unwrap();
        assert!(again.contains(&format!("  variant {here} {sha} node-v22.0.0-{here}.tar.gz\n")), "{again}");
        assert!(!again.contains("integrity") && !again.contains("  bin "), "this machine's facts stay out: {again}");
        // A platform with no build: the package says it does not run here.
        let other = text.replace(&format!("variant {here} "), "variant yy-other ");
        let res = from_lockfile(&parse_lockfile(&other, LOCKFILE).unwrap(), &|_| String::new());
        assert!(res.packages["node@runtime:22.0.0"].os.is_some());
        for bad in [
            text.replace("  version 22.0.0\n", ""),
            text.replace("  version 22.0.0\n", "  version 22.0.1\n"),
            text.replace("node@runtime:22.0.0\n", "npm@runtime:22.0.0\n"),
            text.replace("runtime:22.0.0", "runtime:22"),
            text.replace("  version 22.0.0\n", "  version 22.0.0\n  integrity sha512-x\n"),
            text.replace("  version 22.0.0\n", "  version 22.0.0\n  dep a 1.0.0\n"),
            text.replace("  version 22.0.0\n", "  version 22.0.0\n  bin node ../../x\n"),
            text.replace("node-v22.0.0-zz.tar.gz", "../../zz.tar.gz"),
            text.replace("zz-other", &here),
            text.replace(" node-v22.0.0-zz.tar.gz", ""),
            text.replace(&format!("{sha} node-v22.0.0-zz"), "md5-x node-v22.0.0-zz"),
            format!("{text}package a@1.0.0\n  integrity sha512-a\n  variant linux-x64 {sha} a.tgz\n"),
            text.replace(&format!("  variant {here} {sha} node-v22.0.0-{here}.tar.gz\n"), "")
                .replace(&format!("  variant zz-other {sha} node-v22.0.0-zz.tar.gz\n"), ""),
        ] {
            assert!(parse_lockfile(&bad, LOCKFILE).is_err(), "{bad}");
        }
    }

    #[test]
    fn keeps_install_script_approvals() {
        let mut lock = sample();
        let b = lock.packages.get_mut("b@1.0.0").unwrap();
        b.scripts = true;
        b.build = true;
        let text = format_lockfile(&lock).unwrap();
        assert!(text.contains("package b@1.0.0\n  integrity sha512-b\n") && text.contains("  scripts\n  build\n"));
        let back = parse_lockfile(&text, LOCKFILE).unwrap();
        assert!(back.packages["b@1.0.0"].scripts && back.packages["b@1.0.0"].build);
        // An approval of scripts a package does not have is refused.
        let mut lock = sample();
        lock.packages.get_mut("b@1.0.0").unwrap().build = true;
        assert!(validate(&lock).unwrap_err().message.contains("does not have"));
        // Approving a package changes its entry, and its dependents' too.
        let base = |_: &str| String::new();
        let plain = crate::keys::store_keys(&from_lockfile(&sample(), &base).packages);
        let mut lock = sample();
        let b = lock.packages.get_mut("b@1.0.0").unwrap();
        b.scripts = true;
        b.build = true;
        let built = crate::keys::store_keys(&from_lockfile(&lock, &base).packages);
        assert_ne!(plain["b@1.0.0"], built["b@1.0.0"]);
        assert_ne!(plain["a@1.0.0"], built["a@1.0.0"]);
        assert_eq!(plain["c@1.0.0"], built["c@1.0.0"]);
    }

    const COPIES: &str = r#"jpm-lock 2
hash 0
root
  spec dependencies a ^1
  spec dependencies b ^1
  dep a 1.0.0
  dep b 1.0.0
package a@1.0.0
  integrity sha512-a
  dep host 1.0.0
  dep ui 1.0.0(host@1.0.0)
package b@1.0.0
  integrity sha512-b
  dep host 2.0.0
  dep ui 1.0.0(host@2.0.0)
package host@1.0.0
  integrity sha512-h1
package host@2.0.0
  integrity sha512-h2
package ui@1.0.0(host@1.0.0)
  integrity sha512-ui
  dep host 1.0.0
  peer host *
  settled host required
package ui@1.0.0(host@2.0.0)
  integrity sha512-ui
  dep host 2.0.0
  peer host *
  settled host required
"#;

    #[test]
    fn keeps_a_copy_per_set_of_peers() {
        let lock = parse_lockfile(COPIES, LOCKFILE).unwrap();
        let base = |_: &str| "https://registry.npmjs.org".to_string();
        let res = from_lockfile(&lock, &base);
        let ui = &res.packages["ui@1.0.0(host@2.0.0)"];
        assert_eq!((ui.version.as_str(), ui.peer_suffix.as_str()), ("1.0.0", "(host@2.0.0)"));
        assert_eq!(ui.resolved, "https://registry.npmjs.org/ui/-/ui-1.0.0.tgz");
        assert_eq!(ui.key(), "ui@1.0.0(host@2.0.0)");
        // Each copy is an entry of its own, named without its suffix.
        let keys = crate::keys::store_keys(&res.packages);
        let (one, two) = (&keys["ui@1.0.0(host@1.0.0)"], &keys["ui@1.0.0(host@2.0.0)"]);
        assert!(one != two && one.starts_with("ui@1.0.0-") && two.starts_with("ui@1.0.0-"), "{one} {two}");
        let text = format_lockfile(&to_lockfile(&res, &base)).unwrap();
        let again = parse_lockfile(&text, LOCKFILE).unwrap();
        assert_eq!(format_lockfile(&to_lockfile(&from_lockfile(&again, &base), &base)).unwrap(), text);
        assert_eq!(recorded_keys(&again).unwrap(), keys);
        // The walk takes the copies as one package.
        let merged = crate::graph::merge_copies(&res);
        assert!(merged.packages.contains_key("ui@1.0.0") && merged.packages.len() == 5);
        assert_eq!(merged.packages["a@1.0.0"].dependencies["ui"], "1.0.0");
    }

    #[test]
    fn refuses_a_malformed_peer_suffix() {
        let refused = |from: &str, to: &str, why: &str| {
            let text = COPIES.replace(from, to);
            let e = parse_lockfile(&text, LOCKFILE).unwrap_err();
            assert!(e.message.contains(why), "{to}: {}", e.message);
        };
        // The edge to the copy is renamed with it, so the key is what is refused.
        for bad in ["1.0.0(host@1.0.0", "1.0.0(host@1.0.0)x", "1.0.0()", "1.0.0(host)", "1.0.0)(host@1.0.0"] {
            refused("1.0.0(host@1.0.0)", bad, "package key");
        }
        // A copy that names a peer it does not link, or one that is not there.
        refused(
            "package ui@1.0.0(host@1.0.0)
  integrity sha512-ui
  dep host 1.0.0",
            "package ui@1.0.0(host@1.0.0)
  integrity sha512-ui
  dep host 2.0.0",
            "it links host@2.0.0",
        );
        refused("1.0.0(host@1.0.0)", "1.0.0(host@3.0.0)", "not in packages");
        // One group a name, in order.
        refused("1.0.0(host@1.0.0)", "1.0.0(host@1.0.0)(host@2.0.0)", "sorted");
        refused("1.0.0(host@2.0.0)", "1.0.0(host@2.0.0)(b@1.0.0)", "sorted");
        // Every copy is the same tarball.
        refused(
            "package ui@1.0.0(host@2.0.0)
  integrity sha512-ui",
            "package ui@1.0.0(host@2.0.0)
  integrity sha512-other",
            "another tarball",
        );
        // A linked directory has no peers.
        let linked = "jpm-lock 2
hash 0
root
  spec dependencies l link:../l
  dep l link:../l(h@1.0.0)
                      package l@link:../l(h@1.0.0)
  version 1.0.0
package h@1.0.0
  integrity sha512-h
";
        assert!(parse_lockfile(linked, LOCKFILE).is_err());
    }

    /// Found while fuzzing jpm.lock: a peer suffix cut short by a cycle was looked for among
    /// every key, for each entry, and a workspace linked by a name others share looked through
    /// every top's specs, for each edge. 20,000 such entries (1 MB) or 1,000 such workspaces over
    /// 10,000 specs (370 KB) took minutes to check.
    #[test]
    fn checks_in_linear_time() {
        let mut text = String::from("jpm-lock 2\nhash 0\nroot\n");
        for i in 0..20_000 {
            text.push_str(&format!("package a{i:05}@1.0.0(p@1.0.0)\n  integrity sha512-a\n"));
        }
        text.push_str(
            "package p@1.0.0(x@1.0.0)\n  integrity sha512-p\n  dep x 1.0.0\n  peer x ^1\n  settled x required\n",
        );
        text.push_str("package x@1.0.0\n  integrity sha512-x\n");
        assert_eq!(parse_lockfile(&text, LOCKFILE).unwrap().packages.len(), 20_002);
        let mut text = String::from("jpm-lock 2\nhash 0\nroot\n");
        for i in 0..10_000 {
            text.push_str(&format!("  spec dependencies q{i} ^1\n"));
        }
        for i in 0..1_000 {
            text.push_str(&format!(
                "workspace w{i}\n  name n\n  version 1.0.0\n  spec dependencies n workspace:*\n  dep n link:w0\n"
            ));
        }
        assert_eq!(parse_lockfile(&text, LOCKFILE).unwrap().workspaces.len(), 1_000);
    }

    /// Found while fuzzing: each workspace edge was matched against every override of its name,
    /// a range intersection each. 4,000 overrides of one name over 2,000 workspaces, each asking
    /// for its own range (310 KB), took 3.8 s in a release build and over 30 s in a test build.
    #[test]
    fn checks_overrides_in_linear_time() {
        let lockfile = |link: bool| {
            let mut text = String::from("jpm-lock 2\nhash 0\nroot\n");
            for i in 0..10_000 {
                text.push_str(&format!("  override npm x@>={}.0.0 1.0.0\n", 100 + i));
            }
            text.push_str("package x@1.0.0\n  integrity sha512-x\n");
            if link {
                text.push_str("workspace x\n  name x\n  version 1.0.0\n");
            }
            let dep = if link { "link:x" } else { "1.0.0" };
            for i in 0..4_000 {
                text.push_str(&format!(
                    "workspace w{i}\n  name w{i}\n  version 1.0.0\n  spec dependencies x ^1.0.{i}\n  dep x {dep}\n"
                ));
            }
            text
        };
        for link in [false, true] {
            let text = lockfile(link);
            let start = std::time::Instant::now();
            let lock = parse_lockfile(&text, LOCKFILE).unwrap();
            assert_eq!(lock.root.overrides.len(), 10_000);
            assert!(start.elapsed() < std::time::Duration::from_secs(2), "{link}: {:?}", start.elapsed());
        }
    }

    #[test]
    fn refuses_unsafe_lockfiles() {
        let mut lock = sample();
        lock.packages.get_mut("b@1.0.0").unwrap().bin.insert("x".into(), "../../etc".into());
        assert!(validate(&lock).is_err());
        for target in ["C:/Windows/x.exe", "c:i.js", "a:stream"] {
            let mut lock = sample();
            lock.packages.get_mut("b@1.0.0").unwrap().bin.insert("x".into(), target.into());
            assert!(validate(&lock).unwrap_err().message.contains("escapes"), "{target}");
        }
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
        // A subgraph becomes part of a directory name: a traversal in one is refused, even
        // under a hash that matches.
        let mut lock = sample();
        lock.packages.get_mut("b@1.0.0").unwrap().subgraph = Some("a/../../../../../escaped".into());
        assert!(validate(&lock).unwrap_err().message.contains("subgraph"));
        let body = text_body(&lock);
        let text = format!("{HEADER}jpm-lock {TEXT_VERSION}\nhash {}\n{body}", content_digest(&body));
        assert!(parse_lockfile(&text, LOCKFILE).unwrap_err().message.contains("subgraph"));
        // A dependency name becomes a link in node_modules: a path in one is refused.
        for name in ["../x", "a/b/c", "@s/../../x", "a@https://h/../../x"] {
            let mut lock = sample();
            lock.packages.get_mut("a@1.0.0").unwrap().dependencies.insert(name.into(), "1.0.0".into());
            assert!(validate(&lock).unwrap_err().message.contains("not a package name"), "{name}");
            let mut lock = sample();
            lock.root.dependencies.insert(name.into(), "1.0.0".into());
            assert!(validate(&lock).is_err(), "{name}");
        }
        assert!(
            parse_lockfile(r#"{"lockfileVersion":2,"root":{"dependencies":{}},"packages":{}}"#, "x")
                .unwrap_err()
                .message
                .contains("unsupported")
        );
    }
}

/// `JPM_LOCK_BENCH=<jpm.lock> cargo test --release lock_bench -- --ignored --nocapture`
#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn lock_bench() {
        let file = std::env::var("JPM_LOCK_BENCH").expect("set JPM_LOCK_BENCH");
        for _ in 0..3 {
            let t = Instant::now();
            let text = std::fs::read_to_string(&file).unwrap();
            let read = t.elapsed();
            let t = Instant::now();
            let t0 = Instant::now();
            let mut n = 0usize;
            for l in text.lines() {
                n += tokens(l.trim_start()).map(|t| t.len()).unwrap_or(0);
            }
            let tokenize = t0.elapsed();
            let t0 = Instant::now();
            let _ = content_digest(&text);
            let digest = t0.elapsed();
            println!("tokenize {tokenize:?} ({n} tokens) digest {digest:?}");
            let lock = parse_text(&text).unwrap();
            let parse = t.elapsed();
            let t = Instant::now();
            validate(&lock).unwrap();
            let check = t.elapsed();
            let t = Instant::now();
            let res = into_resolution(lock.clone(), &|_| "https://registry.npmjs.org".to_string());
            let convert = t.elapsed();
            let platform = crate::sys::Platform::current();
            let keys_at = Instant::now();
            let _ = recorded_keys(&lock).unwrap_or_else(|| crate::keys::store_keys(&res.packages));
            let keys = keys_at.elapsed();
            let t = Instant::now();
            let _filtered = crate::graph::filter_platform(res, &platform).unwrap();
            let filter = t.elapsed();
            let t = Instant::now();
            let _ = crate::state::state_hash(
                &content_hash(&lock),
                false,
                std::path::Path::new("/s"),
                "salt",
                true,
                &platform,
                &[],
            );
            let hash = t.elapsed();
            println!(
                "{} bytes: read {read:?} parse {parse:?} validate {check:?} to-graph {convert:?} platform {filter:?} state-hash {hash:?} store-keys {keys:?}",
                text.len()
            );
        }
    }
}
