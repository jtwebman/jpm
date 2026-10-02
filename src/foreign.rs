//! The lockfile npm, pnpm or bun left in a project, read so jpm installs the tree it holds and
//! writes no `jpm.lock` beside it. Every format is a set of `name@version` nodes with edges once
//! npm's and bun's path-keyed maps are walked the way Node resolves; pnpm's copies per set of
//! peers keep their keys, `name@version(peer@version)`, as jpm's do. Read only when a project has
//! one of these files and no `jpm.lock`.

use crate::graph::alias_edge;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::json::{self, Object as Map, Value};

use crate::bin::{self, Bins};
use crate::error::{Error, Result};
use crate::graph::{Deps, PeerKind, Peers, Specs};
use crate::integrity::Integrity;
use crate::lock::{self, LockEntry, LockRoot, Lockfile};
use crate::project::{GROUPS, RootManifest};
use crate::registry::tarball_url;
use crate::resolve::Prefer;
use crate::rules;
use crate::semver::{max_satisfying, max_satisfying_peer};

/// In the order one is read when a project has several: a newer manager's first, as a project that
/// moved to one usually leaves the old one's lockfile behind; npm's shrinkwrap before its
/// package-lock, as npm reads them.
pub const FOREIGN: [&str; 5] = ["bun.lock", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json", "package-lock.json"];

pub struct ForeignLock {
    pub lock: Lockfile,
    /// Keys of packages whose bins the file does not name (pnpm records only hasBin).
    pub binless: Vec<String>,
    /// The file never says which packages have install scripts (bun.lock).
    pub scriptless: bool,
    pub warnings: Vec<String>,
    /// Runtimes the root depends on (pnpm's `runtime:`), left for install to fetch the builds of.
    pub runtimes: Runtimes,
}

/// Runtime name -> the exact version the file locked, and the builds it recorded for it, each
/// `(url, integrity)`.
pub type Runtimes = BTreeMap<String, (String, Vec<(String, String)>)>;

/// One package as the file records it, edges already exact versions.
#[derive(Debug, Clone, Default)]
struct Node {
    /// What it is installed as.
    name: String,
    /// The registry package, when `name` is an alias for it.
    real: Option<String>,
    version: String,
    /// pnpm's peer suffix of this copy, `(react@18.2.0)`: its key ends in it.
    suffix: String,
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
    /// npm's `hasInstallScript`, pnpm's `requiresBuild`.
    scripts: bool,
}

struct Source {
    nodes: Vec<Node>,
    /// The ranges the file recorded for the root: what package.json is held to.
    specs: Specs,
    /// Root edges, name -> version.
    root: Deps,
    /// The overrides the file was resolved under, where it records them (bun).
    overrides: Option<Value>,
    /// `patchedDependencies`: pnpm's key -> `{ path, hash }` or hash, bun's key -> path.
    patches: Value,
    /// pnpm's `packageExtensionsChecksum`; npm and bun apply no packageExtensions.
    extensions: Option<String>,
    runtimes: Runtimes,
    /// The optional peers it settled were installed: pnpm installs one its snapshot names, npm
    /// and bun only one something else brings in.
    optional_peers: bool,
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
        "package-lock.json" | "npm-shrinkwrap.json" => read_npm(file, text)?,
        "pnpm-lock.yaml" => read_pnpm(text)?,
        "bun.lock" => read_bun(text)?,
        "yarn.lock" => return Err(fail("yarn.lock names no peers, platforms or bins")),
        _ => return Err(fail(format!("jpm does not read {file}"))),
    };
    hold_to(file, &mut source, manifest)?;
    let mut out = build(file, source, manifest, base_for)?;
    out.scriptless = file == "bun.lock";
    Ok(out)
}

/// The versions a file that cannot be brought over whole (out of date, with workspaces, an older
/// format, or yarn.lock, which names too little) still says the project used, for a resolve to
/// prefer. yarn.lock also says which version each range got.
pub fn prefer(file: &str, text: &str) -> Result<Prefer> {
    if file == "yarn.lock" {
        return Ok(read_yarn(text));
    }
    let mut prefer = Prefer::default();
    for (name, version) in pins(file, text)? {
        prefer.versions.entry(name).or_default().push(version);
    }
    // The optional peers its snapshots settled: pnpm installed them.
    if file == "pnpm-lock.yaml" {
        let doc = pnpm_doc(text)?;
        let empty = Map::new();
        let packages = doc.get("packages").and_then(Value::as_object).unwrap_or(&empty).index();
        for (key, snap) in doc.get("snapshots").and_then(Value::as_object).into_iter().flatten() {
            let id = strip_peers(key);
            let Some(meta) = packages.get(id).and_then(|p| p.get("peerDependenciesMeta")) else { continue };
            for (peer, _) in deps(snap.get("dependencies")).into_iter().chain(deps(snap.get("optionalDependencies"))) {
                if truthy(meta.get(&peer).and_then(|m| m.get("optional"))) {
                    prefer.optional_peers.insert((split_id(id).0, peer));
                }
            }
        }
    }
    prefer.ranges = top_ranges(file, text)?;
    Ok(prefer)
}

/// The version each range the root and the workspaces declare got: bun.lock nests a
/// workspace's own copy under its name, pnpm-lock.yaml gives each importer's specifier its
/// version. Without it a range takes the highest version the file names, which may be one only
/// a package deep below uses (cline's @ai-sdk/anthropic), and a tag the registry's latest. A
/// range two tops got different versions for is left out.
fn top_ranges(file: &str, text: &str) -> Result<HashMap<String, String>> {
    let mut got: Vec<(String, String)> = Vec::new();
    match file {
        "pnpm-lock.yaml" => {
            let doc = pnpm_doc(text)?;
            for (_, top) in doc.get("importers").and_then(Value::as_object).into_iter().flatten() {
                for group in GROUPS {
                    for (name, dep) in top.get(group).and_then(Value::as_object).into_iter().flatten() {
                        let field = |f: &str| dep.get(f).and_then(Value::as_str);
                        if let (Some(range), Some(version)) = (field("specifier"), field("version")) {
                            got.push((format!("{name}@{range}"), strip_peers(version).to_string()));
                        }
                    }
                }
            }
        }
        "bun.lock" => {
            let doc = json::parse(&strip_trailing_commas(text))
                .map_err(|e| fail(format!("bun.lock cannot be read: {}", e.message)))?;
            let mut tree = Tree::default();
            for (path, tuple) in doc.get("packages").and_then(Value::as_object).into_iter().flatten() {
                tree.add(names(path).into_iter(), tuple);
            }
            for (path, top) in doc.get("workspaces").and_then(Value::as_object).into_iter().flatten() {
                let name = top.get("name").and_then(Value::as_str).unwrap_or_default();
                let from = if path.is_empty() { Some(0) } else { tree.find_at(0, name) };
                let Some(from) = from.filter(|_| !tree.up.is_empty()) else { continue };
                for (dep, range) in groups_of(Some(top)).iter().flatten() {
                    if let Some(t) = tree.find(from, dep).and_then(bun_tuple).filter(|t| !t.bundled) {
                        let (real, version) = split_id(t.id);
                        if real == *dep {
                            got.push((format!("{dep}@{range}"), version));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut out = HashMap::new();
    let mut twice = HashSet::new();
    for (range, version) in got {
        if !crate::semver::is_exact(&version) {
            continue;
        }
        if out.get(&range).is_some_and(|v| *v != version) {
            twice.insert(range.clone());
        }
        out.insert(range, version);
    }
    out.retain(|r, _| !twice.contains(r));
    Ok(out)
}

/// yarn.lock, v1 or berry: each block is a list of `name@range` keys, then its fields, the one
/// read here being `version`. Keys that are not registry ranges (git, files, workspaces, patches)
/// are left out.
fn read_yarn(text: &str) -> Prefer {
    let mut out = Prefer::default();
    let berry = text.lines().any(|l| l == "__metadata:");
    let mut keys: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            keys = line
                .trim_end_matches(':')
                .split(',')
                .filter_map(|d| yarn_key(d.trim().trim_matches('"'), berry))
                .collect();
            continue;
        }
        let Some(field) = line.strip_prefix("  ").filter(|f| !f.starts_with(' ')) else { continue };
        let Some(v) = field.strip_prefix("version") else { continue };
        let v = v.trim_start_matches(':').trim().trim_matches('"');
        if !crate::semver::is_exact(v) {
            continue;
        }
        for (name, range) in keys.drain(..) {
            out.versions.entry(name.clone()).or_default().push(v.to_string());
            out.ranges.insert(format!("{name}@{range}"), v.to_string());
        }
    }
    out
}

/// yarn's own `node_modules/.yarn-state.yml` for a berry yarn.lock: each locked package's locator
/// (its `resolution`) and its places in the tree, from `at` by `name@version`. Workspaces are
/// left out: yarn finds those itself.
pub fn yarn_state(text: &str, at: &HashMap<String, Vec<String>>) -> String {
    let mut found: BTreeMap<String, &Vec<String>> = BTreeMap::new();
    let (mut version, mut resolution) = (String::new(), String::new());
    let mut take = |version: &mut String, resolution: &mut String| {
        let name = resolution.get(1..).and_then(|r| r.find('@')).map(|i| &resolution[..i + 1]);
        if let Some(name) = name.filter(|n| !resolution[n.len() + 1..].starts_with("workspace:"))
            && let Some(places) = at.get(&format!("{name}@{version}"))
        {
            found.insert(std::mem::take(resolution), places);
        }
        version.clear();
        resolution.clear();
    };
    for line in text.lines() {
        if !line.starts_with(' ') {
            take(&mut version, &mut resolution);
        } else if let Some(field) = line.strip_prefix("  ").filter(|f| !f.starts_with(' ')) {
            let (k, v) = field.split_once(':').unwrap_or((field, ""));
            let v = v.trim().trim_matches('"');
            match k {
                "version" => version = v.to_string(),
                "resolution" => resolution = v.to_string(),
                _ => {}
            }
        }
    }
    take(&mut version, &mut resolution);
    let mut out = String::from(
        "# Warning: This file is automatically generated. Removing it is fine, but will\n\
         # cause your node_modules installation to become invalidated.\n\n\
         __metadata:\n  version: 1\n  nmMode: classic\n",
    );
    for (locator, places) in found {
        out.push('\n');
        json::quote(&mut out, &locator);
        out.push_str(":\n  locations:\n");
        for place in places {
            out.push_str("    - ");
            json::quote(&mut out, place);
            out.push('\n');
        }
    }
    out
}

/// A key as the resolver asks for it: registry name and range. Berry writes `name@npm:range`
/// for a plain range, where yarn 1 would mean an alias; `name@npm:real@range` is one in both.
fn yarn_key(key: &str, berry: bool) -> Option<(String, String)> {
    // A patched package, `name@patch:<source>#<path>`: the range of its source.
    let at = crate::graph::name_end(key)?;
    if let Some((range, _)) = crate::patch::yarn(&key[..at], &key[at + 1..]) {
        return yarn_key(&format!("{}@{range}", &key[..at]), false);
    }
    let plain = crate::graph::find_after_name(key, "@npm:").filter(|&at| berry && !key[at + 5..].contains('@'));
    let key = match plain {
        Some(at) => format!("{}@{}", &key[..at], &key[at + 5..]),
        None => key.to_string(),
    };
    let spec = crate::spec::parse_spec(&key).ok()?;
    matches!(spec.kind, crate::spec::Kind::Version | crate::spec::Kind::Range | crate::spec::Kind::Tag)
        .then_some((spec.fetch_name, spec.fetch_spec))
}

/// Every registry package version the file names, as `(name, version)`, read loosely. npm, pnpm
/// (any version) and bun.
fn pins(file: &str, text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    match file {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            let doc = json::parse(text).map_err(|e| unreadable(file, text, e))?;
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
            // A broken file's empty names and odd versions pin nothing.
            out.retain(|(name, version)| !name.is_empty() && crate::semver::is_exact(version));
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
                // A runtime is preferred at the version pnpm locked, `runtime:` and all.
                let runtime = version.strip_prefix(crate::runtime::PROTOCOL).unwrap_or(&version);
                if crate::semver::is_exact(runtime) {
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

/// A lockfile that is not JSON. npm reads one git left mid-merge, taking both sides; jpm says
/// what it found.
fn unreadable(file: &str, text: &str, e: Error) -> Error {
    let merge = text.lines().any(|l| l.starts_with("<<<<<<< ")) && text.lines().any(|l| l.starts_with(">>>>>>> "));
    let hint = if merge { " (it has git conflict markers left in it)" } else { "" };
    fail(format!("{file} cannot be read{hint}: {}", e.message))
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
    let stale = || fail(format!("{file} is out of date with package.json"));
    // pnpm and bun write down the patches they applied; npm knows none.
    let path = |p: &str| p.trim_start_matches("./").to_string();
    let patched = |p: &crate::patch::Patch| {
        let v = source.patches.get(&p.selector()).map(|v| v.get("path").unwrap_or(v)).and_then(Value::as_str);
        v.is_some_and(|v| path(v) == path(&p.path) || v == p.hash)
    };
    let recorded = source.patches.as_object().map_or(0, |o| o.len());
    if file != "package-lock.json"
        && file != "npm-shrinkwrap.json"
        && (recorded != manifest.patches.len() || !manifest.patches.iter().all(patched))
    {
        return Err(fail(format!("{file} is out of date with the patches")));
    }
    // The packageExtensions it was resolved under: pnpm's, by its checksum of them. npm and bun
    // apply none, and none of the three reads .yarnrc.yml's.
    let pnpm = file == "pnpm-lock.yaml";
    let extended = &manifest.extended;
    if extended.yarn || (pnpm && source.extensions != extended.pnpm) || (!pnpm && !manifest.extensions.is_empty()) {
        return Err(fail(format!("{file} is out of date with the packageExtensions")));
    }
    let specs = manifest.specs();
    let declared = flat(specs.as_ref());
    let recorded = flat(Some(&source.specs));
    for (name, range) in &recorded {
        // pnpm records the range an override gave a root edge.
        let overridden = |d: &String| rules::find(&manifest.overrides, None, name, d) == Some(Some(range.as_str()));
        if declared.get(name).is_some_and(|d| d == range || overridden(d)) {
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
        let empty = Value::Object(Map::new());
        // The same overrides written in another order are the same.
        let same = if file == "pnpm-lock.yaml" {
            let pnpm = manifest.overrides.iter().filter(|o| o.by == rules::Manager::Pnpm);
            overrides.same_as(&Value::Object(pnpm.map(|o| (o.selector(), o.value_text().into())).collect()))
        } else {
            let given = [doc.get("overrides"), doc.get("resolutions")].into_iter().flatten().find(|v| !v.is_null());
            // bun writes the rules it read, not package.json's text: the same rules are the same.
            let rule = |o: &rules::Override| (o.parent.clone(), o.name.clone(), o.range.clone(), o.value.clone());
            overrides.same_as(given.unwrap_or(&empty))
                || (file == "bun.lock"
                    && rules::npm_form(overrides).iter().map(rule).collect::<BTreeSet<_>>()
                        == manifest.overrides.iter().map(rule).collect())
        };
        if !same {
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

fn read_npm(file: &str, text: &str) -> Result<Source> {
    let doc = json::parse(text).map_err(|e| unreadable(file, text, e))?;
    let Some(listed) = doc.get("packages").and_then(Value::as_object) else {
        let v = doc.get("lockfileVersion").filter(|v| !v.is_null()).map_or_else(|| "1".to_string(), string_of);
        return Err(fail(format!("{file} v{v} has no packages map; npm 7 and later write one")));
    };
    let mut nodes = Vec::new();
    // Each package read, its edges found once all are: `Tree::find_all`.
    let mut read = Vec::new();
    let mut tree = Tree::default();
    let at: Vec<Option<usize>> = listed
        .iter()
        .map(|(path, entry)| Some(tree.add(path.strip_prefix(NM)?.split("/node_modules/"), entry)))
        .collect();
    for ((path, entry), from) in listed.iter().zip(at) {
        // What a dependency bundles is inside its tarball; a workspace path was refused before this.
        let Some(from) = from.filter(|&f| !in_dep_bundle(&tree, f)) else { continue };
        let Some(version) = npm_version(entry) else { continue };
        let name = path[NM.len()..].rsplit("/node_modules/").next().unwrap_or_default();
        let real = entry.get("name").and_then(Value::as_str).filter(|n| !n.is_empty());
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
            scripts: truthy(entry.get("hasInstallScript")),
            ..Node::default()
        };
        read.push((node, Declared::of(entry), from));
    }
    let found = tree.find_all(read.iter().flat_map(|(_, d, from)| d.names().map(|n| (*from, n.to_string()))));
    for (node, declared, from) in read {
        nodes.push(with_edges(node, &declared, &|dep| match found.get(&(from, dep.to_string())).copied().flatten() {
            Some(hit) if in_dep_bundle(&tree, hit) => Target::Bundled,
            hit => hit.and_then(|h| npm_edge(dep, tree.entry[h]?)).map_or(Target::Missing, Target::Version),
        }));
    }
    let (specs, root) = root_of(groups_of(listed.get("")), &|name| tree.find(0, name).and_then(|h| npm_edge(name, h)));
    Ok(Source {
        nodes,
        specs,
        root,
        overrides: None,
        patches: Value::Null,
        extensions: None,
        runtimes: Runtimes::new(),
        optional_peers: false,
    })
}

/// Whether the package in folder `at` comes inside a dependency's tarball: bundled, below a
/// package that is not. What the root bundles npm marks `inBundle` too, and installs as any
/// other package (arborist's `inDepBundle`).
fn in_dep_bundle(tree: &Tree, mut at: usize) -> bool {
    let bundled = |at: usize| tree.entry[at].is_some_and(|e| truthy(e.get("inBundle")));
    if !bundled(at) {
        return false;
    }
    while at != 0 && bundled(at) {
        at = tree.up[at];
    }
    at != 0
}

/// The edge to the entry `dep` finds: its version, or an alias's `npm:<real>@<version>`.
fn npm_edge(dep: &str, entry: &Value) -> Option<String> {
    let version = npm_version(entry)?;
    let real = entry.get("name").and_then(Value::as_str).filter(|r| !r.is_empty() && *r != dep);
    Some(real.map_or_else(|| version.to_string(), |r| alias_edge(r, version)))
}

/// npm's and bun's paths as the folders they name, each a list of the packages up to it, so
/// that a walk up is a step a level: joining each parent's path to look it up would take time
/// in the square of its length. Folder 0 is the root.
#[derive(Default)]
struct Tree<'a> {
    up: Vec<usize>,
    entry: Vec<Option<&'a Value>>,
    children: Vec<HashMap<&'a str, usize>>,
}

impl<'a> Tree<'a> {
    /// The folder at the end of `names`, which holds `entry`.
    fn add(&mut self, names: impl Iterator<Item = &'a str>, entry: &'a Value) -> usize {
        if self.up.is_empty() {
            self.up.push(0);
            self.entry.push(None);
            self.children.push(HashMap::new());
        }
        let mut at = 0;
        for name in names {
            at = match self.children[at].get(name) {
                Some(&child) => child,
                None => {
                    let child = self.up.len();
                    self.up.push(at);
                    self.entry.push(None);
                    self.children.push(HashMap::new());
                    self.children[at].insert(name, child);
                    child
                }
            };
        }
        self.entry[at] = Some(entry);
        at
    }

    /// The `name` nearest `from` on the walk up, as Node's resolution finds it.
    fn find(&self, from: usize, name: &str) -> Option<&'a Value> {
        self.find_at(from, name).and_then(|at| self.entry[at])
    }

    /// The folder `find` finds.
    fn find_at(&self, from: usize, name: &str) -> Option<usize> {
        let mut at = from;
        loop {
            let hit = self.children.get(at).and_then(|c| c.get(name)).copied();
            if let Some(hit) = hit.filter(|&c| self.entry[c].is_some_and(|v| truthy(Some(v)))) {
                return Some(hit);
            }
            if at == 0 {
                return None;
            }
            at = self.up[at];
        }
    }

    /// What `find_at` finds for each `(from, name)`, in one walk down the tree rather than a
    /// walk up per name: a package thousands of folders deep with thousands of dependencies
    /// took minutes. On the way down, each name's stack holds the folders that have it, the
    /// nearest on top.
    fn find_all(&self, queries: impl Iterator<Item = (usize, String)>) -> HashMap<(usize, String), Option<usize>> {
        let mut asked: HashMap<usize, Vec<String>> = HashMap::new();
        for (from, name) in queries {
            asked.entry(from).or_default().push(name);
        }
        let mut out = HashMap::new();
        let mut nearest: HashMap<&str, Vec<usize>> = HashMap::new();
        let held =
            |at: usize| self.children[at].iter().filter(|(_, c)| self.entry[**c].is_some_and(|v| truthy(Some(v))));
        // Each folder is pushed to be entered, and once entered, again to be left.
        let mut todo = if self.up.is_empty() { Vec::new() } else { vec![(0, true)] };
        while let Some((at, enter)) = todo.pop() {
            if !enter {
                for (name, _) in held(at) {
                    nearest.get_mut(name).map(Vec::pop);
                }
                continue;
            }
            for (name, &child) in held(at) {
                nearest.entry(name).or_default().push(child);
            }
            for name in asked.remove(&at).unwrap_or_default() {
                let hit = nearest.get(name.as_str()).and_then(|s| s.last().copied());
                out.insert((at, name), hit);
            }
            todo.push((at, false));
            todo.extend(self.children[at].values().map(|&c| (c, true)));
        }
        out
    }
}

/// The version of an entry from a registry: not a link, not git or a file, and not a tarball
/// url of some other site (marked's `marked-repo`, a GitHub tarball), which would pass as the
/// registry's package and its dependency skip `block-exotic-subdeps`. Any mirror's
/// `…/-/<name>-<version>.tgz` is a registry's.
// ponytail: GitHub Packages' `/download/…` urls are not recognized; such a lock is resolved again.
fn npm_version(entry: &Value) -> Option<&str> {
    let version = entry.get("version")?.as_str().filter(|v| !v.is_empty())?;
    let resolved = entry.get("resolved").and_then(Value::as_str).unwrap_or_default();
    let registry = resolved.contains("/-/") && resolved.ends_with(&format!("-{version}.tgz"));
    let web = resolved.is_empty() || ((resolved.starts_with("http:") || resolved.starts_with("https:")) && registry);
    (web && !truthy(entry.get("link"))).then_some(version)
}

/// The version another manager put in the root's `node_modules` for each name, where its
/// lockfile beside the project says: package-lock.json's `node_modules/<name>`, bun.lock's keys
/// that are a name alone. npm's placement turns on the order packages were added in, so no walk
/// of the tree finds it again (echarts' @types/node 12, where a walk finds 16 first).
pub fn root_placement(dir: &std::path::Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for file in ["package-lock.json", "npm-shrinkwrap.json"] {
        let Ok(text) = std::fs::read_to_string(dir.join(file)) else { continue };
        let Ok(doc) = json::parse(&text) else { continue };
        for (path, entry) in doc.get("packages").and_then(Value::as_object).into_iter().flatten() {
            // An alias (`string-width-cjs`, `npm:string-width@4`) is in its folder's name only.
            let Some(rest) = path.strip_prefix(NM).filter(|r| !r.contains(NM)) else { continue };
            let real = entry.get("name").and_then(Value::as_str).is_none_or(|n| n == rest);
            if let Some(v) = npm_version(entry).filter(|_| real) {
                out.insert(rest.to_string(), v.to_string());
            }
        }
        return out;
    }
    if let Ok(text) = std::fs::read_to_string(dir.join("bun.lock"))
        && let Ok(doc) = json::parse(&strip_trailing_commas(&text))
    {
        for (path, tuple) in doc.get("packages").and_then(Value::as_object).into_iter().flatten() {
            if names(path).len() == 1
                && let Some(t) = bun_tuple(tuple).filter(|t| !t.bundled)
            {
                let (real, version) = split_id(t.id);
                if real == *path {
                    out.insert(real, version);
                }
            }
        }
    }
    out
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
        let optional_peers: BTreeSet<String> = entry
            .get("peerDependenciesMeta")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter(|(_, v)| truthy(v.get("optional"))).map(|(k, _)| k.clone()).collect())
            .unwrap_or_default();
        let mut peers = deps(entry.get("peerDependencies"));
        // One in peerDependenciesMeta alone is any version, as `Manifest::parse` reads it.
        for name in &optional_peers {
            peers.entry(name.clone()).or_insert_with(|| "*".into());
        }
        Self {
            dependencies: deps(entry.get("dependencies")),
            optional: deps(entry.get("optionalDependencies")),
            peers,
            optional_peers,
        }
    }

    /// Every name `with_edges` looks for.
    fn names(&self) -> impl Iterator<Item = &str> {
        self.dependencies.keys().chain(self.optional.keys()).chain(self.peers.keys()).map(String::as_str)
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
/// The root's groups, its required peers among the dependencies where no group names them, as
/// `RootManifest::install_own_peers` has it: npm, pnpm and bun install them. Optional peers are
/// npm's `peerDependenciesMeta` or bun's `optionalPeers`.
fn groups_of(top: Option<&Value>) -> [Deps; 3] {
    let mut groups = GROUPS.map(|g| deps(top.and_then(|t| t.get(g))));
    let get = |k: &str| top.and_then(|t| t.get(k));
    let optional = |n: &str| {
        list(get("optionalPeers")).iter().any(|p| p == n)
            || truthy(get("peerDependenciesMeta").and_then(|m| m.get(n)).and_then(|m| m.get("optional")))
    };
    for (name, range) in deps(get("peerDependencies")) {
        if !optional(&name) && groups.iter().all(|g| !g.contains_key(&name)) {
            groups[0].insert(name, range);
        }
    }
    groups
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
    let empty = Map::new();
    let packages = doc.get("packages").and_then(Value::as_object).unwrap_or(&empty);
    let snapshots = doc.get("snapshots").and_then(Value::as_object).unwrap_or(&empty);
    let package_index = packages.index();
    let mut aliases = BTreeSet::new(); // (alias, real, version)
    let mut nodes = Vec::new();
    for (key, snap) in snapshots {
        let id = strip_peers(key);
        // A copy per set of peers, keyed as pnpm keys it.
        let suffix = peer_suffix(key)?;
        let Some(pkg) = package_index.get(id).copied().filter(|p| !p.is_null()) else { continue };
        let resolution = pkg.get("resolution");
        let field = |f: &str| resolution.and_then(|r| r.get(f)).and_then(Value::as_str).filter(|s| !s.is_empty());
        let Some(integrity) = field("integrity") else { continue }; // a git, file or tarball-url package
        let (name, version) = split_id(id);
        let mut node = Node {
            name,
            version,
            suffix,
            resolved: field("tarball").map(str::to_string),
            integrity: integrity.to_string(),
            has_bin: pkg.get("hasBin") == Some(&Value::Bool(true)),
            scripts: truthy(pkg.get("requiresBuild")),
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
    let mut runtimes = Runtimes::new();
    for (group, specs) in GROUPS.iter().zip(&mut groups) {
        let Some(map) = top.and_then(|t| t.get(group)).and_then(Value::as_object) else { continue };
        for (name, dep) in map {
            let specifier = dep.get("specifier").map(string_of).unwrap_or_default();
            // `catalog:` is recorded as written; `catalogs` holds the range it stood for.
            let listed =
                |c: &str| doc.get("catalogs")?.get(catalog_name(c))?.get(name)?.get("specifier").map(string_of);
            let specifier = specifier.strip_prefix("catalog:").and_then(listed).unwrap_or(specifier);
            specs.insert(name.clone(), specifier);
            let r = dep.get("version").map(string_of).unwrap_or_default();
            // A runtime's builds are pnpm's own archives: install reads the release for jpm's.
            if let Some(v) =
                r.strip_prefix(crate::runtime::PROTOCOL).filter(|_| crate::runtime::NAMES.contains(&name.as_str()))
            {
                crate::runtime::check_version(name, v).map_err(|_| {
                    fail(format!("pnpm-lock.yaml locks {name} at runtime:{v:?}, which is not a version"))
                })?;
                let variants = package_index
                    .get(format!("{name}@{r}").as_str())
                    .and_then(|p| p.get("resolution")?.get("variants")?.as_array());
                let builds = variants.into_iter().flatten().filter_map(|b| {
                    let r = b.get("resolution")?;
                    Some((r.get("url")?.as_str()?.to_string(), r.get("integrity")?.as_str()?.to_string()))
                });
                runtimes.insert(name.clone(), (v.to_string(), builds.collect()));
                continue;
            }
            versions.insert(name.clone(), pnpm_edge(&mut aliases, name, &r)?);
        }
    }
    // pnpm keys an alias by the real package; jpm gives the alias a node of its own.
    let by_id: HashMap<String, usize> =
        nodes.iter().enumerate().map(|(i, n)| (format!("{}@{}{}", n.name, n.version, n.suffix), i)).collect();
    for (alias, real, version) in &aliases {
        let Some(&i) = by_id.get(&format!("{real}@{version}")) else { continue };
        let node = Node { name: alias.clone(), real: Some(real.clone()), ..nodes[i].clone() };
        nodes.push(node);
    }
    let (specs, mut root) = root_of(groups, &|name| versions.get(name).cloned());
    root.retain(|name, _| !runtimes.contains_key(name));
    // The overrides it was resolved under, as pnpm-workspace.yaml or `pnpm.overrides` give them.
    let overrides = doc.get("overrides").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Object(Map::new()));
    Ok(Source {
        nodes,
        specs,
        root,
        overrides: Some(overrides),
        patches: doc.get("patchedDependencies").cloned().unwrap_or(Value::Null),
        extensions: doc.get("packageExtensionsChecksum").and_then(Value::as_str).map(str::to_string),
        runtimes,
        optional_peers: true,
    })
}

/// The version an edge `dep: ref` points at, the peer suffix of the copy included, `""` when not
/// from a registry; an alias's `npm:<real>@<version>`, noted for a node of its own.
fn pnpm_edge(aliases: &mut BTreeSet<(String, String, String)>, dep: &str, r: &str) -> Result<String> {
    let Some((real, version)) = pnpm_target(dep, r) else { return Ok(String::new()) };
    let suffix = peer_suffix(r)?;
    if real == dep {
        return Ok(format!("{version}{suffix}"));
    }
    aliases.insert((dep.to_string(), real.to_string(), format!("{version}{suffix}")));
    Ok(alias_edge(real, version) + &suffix)
}

/// The peer groups after a pnpm key or version, each peer's own nested, without the
/// `(patch_hash=...)` pnpm writes among them: jpm marks a patch on the entry. Nested past
/// `MAX_DEPTH`, an error: each level reads the rest again, and the recursion is as deep as the
/// nesting, so a key of 100,000 nested groups took minutes and could overflow the stack.
fn peer_suffix(key: &str) -> Result<String> {
    peer_suffix_at(key, 0)
}

fn peer_suffix_at(key: &str, depth: usize) -> Result<String> {
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    let mut out = String::new();
    let mut rest = &key[strip_peers(key).len()..];
    while rest.starts_with('(') {
        let mut open = 0usize;
        let Some(end) = rest.bytes().position(|b| {
            open = match b {
                b'(' => open + 1,
                b')' => open - 1,
                _ => open,
            };
            open == 0
        }) else {
            break;
        };
        let inner = &rest[1..end];
        if crate::graph::name_end(inner).is_some() && !inner.starts_with("patch_hash=") {
            out.push('(');
            out.push_str(strip_peers(inner));
            out.push_str(&peer_suffix_at(inner, depth + 1)?);
            out.push(')');
        }
        rest = &rest[end + 1..];
    }
    Ok(out)
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

/// The catalog `catalog:<name>` names; a bare `catalog:` is the default one.
fn catalog_name(after: &str) -> &str {
    match after.trim() {
        "" => "default",
        name => name,
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
    let empty = Map::new();
    let listed = doc.get("packages").and_then(Value::as_object).unwrap_or(&empty);
    let mut tree = Tree::default();
    let at: Vec<usize> = listed.iter().map(|(path, tuple)| tree.add(names(path).into_iter(), tuple)).collect();
    let mut nodes = Vec::new();
    let mut read = Vec::new();
    for ((path, tuple), from) in listed.iter().zip(at) {
        let Some(t) = bun_tuple(tuple).filter(|t| !t.bundled) else { continue };
        let (real, version) = split_id(t.id);
        let name = names(path).last().map_or_else(String::new, |n| n.to_string());
        // bun writes an os or cpu it does not know as "none" (netbsd, loong64): kept, it matches
        // no platform, where dropping it installed every such build everywhere.
        let known = |v: Option<&Value>| list(v);
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
        read.push((node, declared, from));
    }
    let found = tree.find_all(read.iter().flat_map(|(_, d, from)| d.names().map(|n| (*from, n.to_string()))));
    for (node, declared, from) in read {
        let hit = |dep: &str| found.get(&(from, dep.to_string())).copied().flatten().and_then(|h| tree.entry[h]);
        nodes.push(with_edges(node, &declared, &|dep| bun_target(hit(dep), dep)));
    }
    let mut groups = groups_of(workspaces.and_then(|w| w.get("")));
    // bun records `catalog:` as written, and the catalogs beside it.
    for (name, range) in groups.iter_mut().flat_map(|g| g.iter_mut()) {
        let listed = range.strip_prefix("catalog:").and_then(|c| match catalog_name(c) {
            "default" => doc.get("catalog")?.get(name),
            c => doc.get("catalogs")?.get(c)?.get(name),
        });
        if let Some(r) = listed.and_then(Value::as_str) {
            *range = r.to_string();
        }
    }
    let (specs, root) = root_of(groups, &|name| match bun_target(tree.find(0, name), name) {
        Target::Version(v) => Some(v),
        _ => None,
    });
    let overrides = doc.get("overrides").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Object(Map::new()));
    Ok(Source {
        nodes,
        specs,
        root,
        overrides: Some(overrides),
        patches: doc.get("patchedDependencies").cloned().unwrap_or(Value::Null),
        extensions: None,
        runtimes: Runtimes::new(),
        optional_peers: false,
    })
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

/// The edge to `name` that `found`, its nearest entry up the hoisted path, makes.
fn bun_target(found: Option<&Value>, name: &str) -> Target {
    match found.map(bun_tuple) {
        None | Some(None) => Target::Missing,
        Some(Some(t)) if t.bundled => Target::Bundled,
        Some(Some(t)) => {
            let (real, version) = split_id(t.id);
            Target::Version(if real == name { version } else { alias_edge(&real, &version) })
        }
    }
}

/// A path is package names joined by "/", and a scoped name has a "/" of its own.
fn names(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut parts = path.split('/');
    while let Some(part) = parts.next() {
        let mut end = start + part.len();
        if part.starts_with('@')
            && let Some(rest) = parts.next()
        {
            end += 1 + rest.len();
        }
        out.push(&path[start..end]);
        start = end + 1;
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
/// as `read_lockfile` would. A copy with other edges (a peer settled two ways, or a dependency
/// npm resolved at two times) is one jpm's one node cannot hold: the highest version wins, the
/// highest the peer range allows for a peer, as the resolver would pick.
fn build(
    file: &str,
    source: Source,
    manifest: &RootManifest,
    base_for: &dyn Fn(&str) -> String,
) -> Result<ForeignLock> {
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut twice = BTreeSet::new();
    for node in source.nodes {
        let key = match &node.real {
            Some(real) => format!("{}@{}{}", node.name, alias_edge(real, &node.version), node.suffix),
            None => format!("{}@{}{}", node.name, node.version, node.suffix),
        };
        let Some(have) = nodes.get_mut(&key) else {
            nodes.insert(key, node);
            continue;
        };
        // A copy the file gives no integrity is the same registry package (npm/cli#4460).
        let unknown = have.integrity.is_empty() || node.integrity.is_empty();
        if !unknown && !same_integrity(&have.integrity, &node.integrity) {
            return Err(fail(format!("{file} holds two packages as {key}; jpm keeps one per name and version")));
        }
        if have.integrity.is_empty() || strength(&node.integrity) > strength(&have.integrity) {
            have.integrity = node.integrity;
        }
        let theirs = [
            (node.dependencies, &mut have.dependencies),
            (node.optional_dependencies, &mut have.optional_dependencies),
        ];
        for (edges, mine) in theirs {
            for (dep, version) in edges {
                let peer = have.peer_dependencies.get(&dep);
                let was = match mine.get(&dep) {
                    Some(m) if *m == version => continue,
                    Some(m) if !m.is_empty() => m.clone(),
                    _ => String::new(),
                };
                let pick = if was.is_empty() {
                    version.clone()
                } else {
                    let both = [was.as_str(), version.as_str()];
                    peer.map_or_else(|| max_satisfying(both, "*"), |r| max_satisfying_peer(both, r))
                        .unwrap_or(&was)
                        .to_string()
                };
                let other = if pick == version { &was } else { &version };
                let other = if other.is_empty() { "none" } else { other };
                let what = match peer {
                    Some(_) => format!("settles peer {dep} of {key}"),
                    None => format!("resolves {dep}, a dependency of {key},"),
                };
                twice.insert((key.clone(), format!("{what} two ways ({other} and {pick}); jpm links {pick}")));
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
            // An optional peer brings nothing in: npm prunes a package only such edges reach.
            if source.optional_peers || node.peers.get(name) != Some(&PeerKind::Optional) {
                next.push(edge_key(&nodes, file, &key, name, version)?);
            }
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
        let Some(mut node) = nodes.remove(key) else { continue };
        // An optional peer stays settled only on a package something else brings in.
        let peers = &node.peers;
        node.optional_dependencies.retain(|n, v| {
            source.optional_peers || peers.get(n) != Some(&PeerKind::Optional) || seen.contains(&format!("{n}@{v}"))
        });
        if node.integrity.is_empty() {
            return Err(fail(format!("{file} gives {key} no integrity")));
        }
        // `validate` checks the key's name; the package it aliases goes into a url.
        if let Some(real) = &node.real
            && crate::spec::check_name(real, key).is_err()
        {
            return Err(fail(format!("{file} gives {key} the package name {real:?}, which is not one")));
        }
        // npm may list a sha1 beside the sha512; jpm.lock keeps the strongest alone.
        let integrity = Integrity::parse(&node.integrity).map_or_else(|_| node.integrity.clone(), |i| i.text());
        if node.bin.is_empty() && node.has_bin {
            binless.push(key.clone());
        }
        let resolved = if derivable(&node) {
            None
        } else if let Some(real) = node.real.as_deref().filter(|_| node.resolved.is_none()) {
            Some(tarball_url(&base_for(real), real, &node.version))
        } else {
            node.resolved
        };
        let entry = LockEntry {
            version: None,
            resolved,
            integrity,
            dependencies: node.dependencies,
            optional_dependencies: node.optional_dependencies,
            bin: node.bin,
            peer_dependencies: node.peer_dependencies,
            peers: node.peers,
            os: node.os,
            cpu: node.cpu,
            libc: node.libc,
            subgraph: None,
            // Scripts come over as known, never as approved: that is `jpm approve`'s to say.
            scripts: node.scripts,
            build: false,
            patch: None,
            variants: Vec::new(),
        };
        packages.insert(key.clone(), entry);
    }
    let root = LockRoot {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        specs: Specs::canonical(Some(&source.specs)),
        dependencies: source.root,
        workspaces: None,
        overrides: manifest.overrides.clone(),
        extensions: manifest.extensions.clone(),
    };
    let lock =
        Lockfile { lockfile_version: lock::TEXT_VERSION, root, workspaces: BTreeMap::new(), packages, hash: None };
    lock::validate(&lock).map_err(|e| fail(format!("{file} does not map onto jpm: {}", e.message)))?;
    let warnings = twice
        .into_iter()
        .filter(|(key, _)| seen.contains(key))
        .map(|(_, what)| format!("{file} {what} for every copy"))
        .collect();
    Ok(ForeignLock { lock, binless, scriptless: false, warnings, runtimes: source.runtimes })
}

/// Whether two integrity fields name one tarball: equal, or the same digests for the strongest
/// algorithm both carry. npm writes `sha1-… sha512-…` for some copies of a package and not
/// others. Several digests of one algorithm mean any of them will do, so the sets must be equal,
/// not just share one: the copies become one node that keeps one field, and it must not take a
/// tarball the other copy's field refuses.
fn same_integrity(a: &str, b: &str) -> bool {
    let hashes = |s: &str| s.split_whitespace().filter_map(|h| Integrity::parse(h).ok()).collect::<Vec<_>>();
    let (mine, theirs) = (hashes(a), hashes(b));
    let digests = |of: &[Integrity], algorithm| {
        of.iter().filter(|h| h.algorithm == algorithm).map(|h| h.digest.clone()).collect::<BTreeSet<_>>()
    };
    let strongest =
        mine.iter().filter(|m| theirs.iter().any(|t| t.algorithm == m.algorithm)).max_by_key(|m| m.digest.len());
    a == b || strongest.is_some_and(|s| digests(&mine, s.algorithm) == digests(&theirs, s.algorithm))
}

/// A longer digest is a stronger algorithm; 0 when nothing parses.
fn strength(integrity: &str) -> usize {
    Integrity::parse(integrity).map_or(0, |i| i.digest.len())
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
/// to it. A url of another shape is kept. An alias's is its real package's (its key names it).
fn derivable(node: &Node) -> bool {
    let Some(resolved) = &node.resolved else { return true };
    let name = node.real.as_deref().unwrap_or(&node.name);
    let base = name.split_once('/').map_or(name, |(_, b)| b);
    resolved.ends_with(&format!("/{name}/-/{base}-{}.tgz", node.version))
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
// Block maps, block lists, flow `{}` and `[]`, quoted and plain scalars. Nothing else appears in
// a lockfile; a hand-written `pnpm-workspace.yaml` or `.yarnrc.yml` adds comments, lists
// indented no deeper than their key, lists of maps (`- path: …`) and `|` or `>` text. A line
// the reader cannot place is an error, never dropped.

/// Deeper than any lockfile nests; past it the file is hostile, not pnpm's.
const MAX_DEPTH: usize = 64;

/// The YAML subset above, as JSON values.
pub fn read_yaml(text: &str) -> Result<Value> {
    yaml(text)
}

fn yaml(text: &str) -> Result<Value> {
    let lines: Vec<(usize, &str)> = text
        .split('\n')
        .map(strip_comment)
        .filter(|l| !l.trim().is_empty())
        .map(|l| (indent_of(l), l.trim()))
        .collect();
    let indent = lines.first().map_or(0, |l| l.0);
    // Written out as JSON for its parser, which indexes a big map's keys: inserting them one by
    // one would scan the map for each, and pnpm's `packages` can hold a hundred thousand.
    let mut out = String::new();
    let mut y = Yaml { lines, i: 0 };
    y.block(indent, 0, &mut out)?;
    if let Some((_, line)) = y.lines.get(y.i) {
        return Err(fail(format!("YAML cannot be read: `{line}` is indented where nothing can start")));
    }
    json::parse(&out).map_err(|e| fail(format!("pnpm-lock.yaml cannot be read: {}", e.message)))
}

/// A line without its comment: a `#` that starts the line or follows a space, outside quotes. A
/// quote opens only where a scalar can start, so a plain `don't` is no quote.
fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut quote = None;
    let mut j = 0;
    while j < b.len() {
        let c = b[j];
        let after = |set: &[u8]| j == 0 || set.contains(&b[j - 1]);
        match quote {
            // `''` inside single quotes and `\"` inside double quotes are the quote itself.
            Some(b'\'') if c == b'\'' && b.get(j + 1) == Some(&b'\'') => j += 1,
            Some(b'"') if c == b'\\' => j += 1,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if (c == b'"' || c == b'\'') && after(b" \t:[{,-") => quote = Some(c),
            None if c == b'#' && after(b" \t") => return line[..j].trim_end(),
            None => {}
        }
        j += 1;
    }
    line.trim_end_matches('\r')
}

struct Yaml<'a> {
    /// Each line's indent and its text, trimmed.
    lines: Vec<(usize, &'a str)>,
    i: usize,
}

impl Yaml<'_> {
    fn block(&mut self, indent: usize, depth: usize, out: &mut String) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(too_deep());
        }
        let item = |l: &str| l.starts_with("- ");
        let list = self.lines.get(self.i).is_some_and(|l| item(l.1));
        out.push(if list { '[' } else { '{' });
        let mut first = true;
        while let Some(&(at, line)) = self.lines.get(self.i).filter(|l| l.0 == indent) {
            if list && !item(line) {
                break;
            }
            if !std::mem::take(&mut first) {
                out.push(',');
            }
            if list {
                let body = line[1..].trim_start();
                if item(body) || is_pair(body) {
                    // `- key: value` starts a map, `- - x` a list, at the column its text is in.
                    let col = at + line.len() - body.len();
                    self.lines[self.i] = (col, body);
                    self.block(col, depth + 1, out)?;
                } else {
                    self.i += 1;
                    scalar(body, depth + 1, out)?;
                }
                continue;
            }
            self.i += 1;
            // `? key` and then `: value`, as js-yaml writes a key over 1024 characters (pnpm's
            // snapshot of a package whose peers nest deep, in bluesky's lockfile).
            if let Some(key) = line.strip_prefix('?').filter(|k| k.is_empty() || k.starts_with(' ')) {
                json::quote(out, &unquote(key.trim()));
                out.push(':');
                match self.lines.get(self.i) {
                    Some(&(at, value)) if at == indent && (value == ":" || value.starts_with(": ")) => {
                        let rest = value[1..].trim_start();
                        if rest.is_empty() {
                            self.i += 1;
                            match self.lines.get(self.i) {
                                Some(&(next, _)) if next > indent => self.block(next, depth + 1, out)?,
                                _ => out.push_str("null"),
                            }
                        } else if is_pair(rest) || item(rest) {
                            // A map or a list, starting at the column its first entry stands in.
                            let col = at + value.len() - rest.len();
                            self.lines[self.i] = (col, rest);
                            self.block(col, depth + 1, out)?;
                        } else {
                            self.i += 1;
                            scalar(rest, depth + 1, out)?;
                        }
                    }
                    _ => out.push_str("null"),
                }
                continue;
            }
            let colon = key_end(line);
            json::quote(out, &unquote(&line[..colon]));
            out.push(':');
            let rest = line.get(colon + 1..).unwrap_or_default().trim();
            if let Some(fold) = block_text(rest) {
                self.text(indent, fold, out);
            } else if !rest.is_empty() {
                scalar(rest, depth + 1, out)?;
            } else {
                match self.lines.get(self.i) {
                    Some(&(next, _)) if next > indent => self.block(next, depth + 1, out)?,
                    // `key:` then `- item` at the key's own indent: still the key's list.
                    Some(&(next, l)) if next == indent && item(l) => self.block(indent, depth + 1, out)?,
                    _ => out.push_str("{}"),
                }
            }
        }
        out.push(if list { ']' } else { '}' });
        Ok(())
    }
}

impl Yaml<'_> {
    /// The lines of a `|` or `>` block under a key at `indent`, as one string.
    // ponytail: blank lines, `#` lines and relative indents inside the block are lost; no file
    // jpm reads keeps anything it uses in one. Keep raw lines if that changes.
    fn text(&mut self, indent: usize, fold: bool, out: &mut String) {
        let mut text = String::new();
        while let Some(&(_, line)) = self.lines.get(self.i).filter(|l| l.0 > indent) {
            if !text.is_empty() {
                text.push(if fold { ' ' } else { '\n' });
            }
            text.push_str(line);
            self.i += 1;
        }
        json::quote(out, &text);
    }
}

/// `|` or `>` with its indicators starts block text: whether it folds lines into one.
fn block_text(rest: &str) -> Option<bool> {
    let fold = match rest.as_bytes().first()? {
        b'|' => false,
        b'>' => true,
        _ => return None,
    };
    rest[1..].bytes().all(|c| c == b'-' || c == b'+' || c.is_ascii_digit()).then_some(fold)
}

/// `key: value` or `key:`, not a scalar that holds a colon (`'a: b'`, `npm:x@1`, a URL).
fn is_pair(text: &str) -> bool {
    if text.starts_with(['{', '[']) {
        return false;
    }
    let colon = key_end(text);
    let key = &text[..colon];
    let quoted = key.starts_with(['"', '\'']);
    (!quoted || (key.len() >= 2 && key.ends_with(&key[..1])))
        && (text[colon..] == *":" || text[colon..].starts_with(": "))
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

fn scalar(text: &str, depth: usize, out: &mut String) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    let v = text.trim();
    let inner = || &v[1..v.len() - 1];
    match v {
        "true" | "false" => out.push_str(v),
        _ if v.len() >= 2 && v.starts_with('{') && v.ends_with('}') => {
            out.push('{');
            for (i, part) in split_flow(inner()).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let item = part.trim();
                let colon = key_end(item);
                json::quote(out, &unquote(&item[..colon]));
                out.push(':');
                scalar(item.get(colon + 1..).unwrap_or_default(), depth + 1, out)?;
            }
            out.push('}');
        }
        _ if v.len() >= 2 && v.starts_with('[') && v.ends_with(']') => {
            out.push('[');
            for (i, part) in split_flow(inner()).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json::quote(out, &unquote(part));
            }
            out.push(']');
        }
        _ => json::quote(out, &unquote(v)),
    }
    Ok(())
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

    #[test]
    fn keeps_what_each_importer_range_got() {
        let text = "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0(p@1.0.0)
      w:
        specifier: workspace:*
        version: link:w
  w:
    devDependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0
      b:
        specifier: latest
        version: 2.0.0
  v:
    dependencies:
      b:
        specifier: latest
        version: 3.0.0
";
        let got = top_ranges("pnpm-lock.yaml", text).unwrap();
        assert_eq!(got.get("a@^1.0.0").map(String::as_str), Some("1.0.0"));
        assert_eq!(got.len(), 1, "a link is no version, and a range two tops differ on is left out: {got:?}");
    }

    /// package.json as an install reads it: its overrides read too.
    fn manifest(doc: Value) -> RootManifest {
        let mut m = RootManifest::parse(&doc.to_string(), Path::new("package.json")).unwrap();
        crate::rules::read(Path::new(""), &m).unwrap().apply(&mut m).unwrap();
        m
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
    "@s/native": ["@s/native@1.0.0", "", { "os": "darwin" }, "sha512-native"],
    "dep": ["dep@1.0.0", "https://mirror.example/", {}, "sha512-dep"],
    "tool": ["tool@1.0.0", "", { "dependencies": { "dep": "^1.0.0" }, "optionalDependencies": { "@s/native": "1.0.0" }, "bin": { "tool": "cli.js" } }, "sha512-tool"],
  }
}
"#;

    const EXPECTED: &str = r#"jpm-lock 2
hash 0
root
  name demo
  spec dependencies tool ^1.0.0
  dep tool 1.0.0
package @s/native@1.0.0
  integrity sha512-native
  os darwin
package dep@1.0.0
  integrity sha512-dep
package tool@1.0.0
  integrity sha512-tool
  dep dep 1.0.0
  optional @s/native 1.0.0
  bin tool cli.js
"#;

    fn demo() -> Value {
        json!({ "name": "demo", "dependencies": { "tool": "^1.0.0" } })
    }

    #[test]
    fn reads_hand_written_yaml() {
        let doc = read_yaml(
            "# top\r\npackages:\r\n- 'apps/*' # apps\r\n- \"!**/test/**\"\r\ncatalog:\r\n  a: ^1 # pinned\r\n  b: 'it''s # not a comment'\r\n  c: don't\r\n",
        )
        .unwrap();
        let list: Vec<&str> = doc
            .get("packages")
            .and_then(crate::json::Value::as_array)
            .unwrap()
            .iter()
            .filter_map(crate::json::Value::as_str)
            .collect();
        assert_eq!(list, ["apps/*", "!**/test/**"]);
        let catalog = |k: &str| {
            doc.get("catalog").and_then(|c| c.get(k)).and_then(crate::json::Value::as_str).map(str::to_string)
        };
        assert_eq!(catalog("a").as_deref(), Some("^1"));
        assert_eq!(catalog("b").as_deref(), Some("it's # not a comment"));
        assert_eq!(catalog("c").as_deref(), Some("don't"));
    }

    #[test]
    fn maps_each_manager_onto_the_same_lock() {
        let expected = parse_lockfile(EXPECTED, LOCKFILE).unwrap();
        let npm = read("package-lock.json", NPM, demo()).unwrap();
        assert_eq!(npm.lock, expected);
        assert!(npm.binless.is_empty() && npm.warnings.is_empty());
        let bun = read("bun.lock", BUN, demo()).unwrap();
        assert_eq!(bun.lock, expected);
        let netbsd = BUN.replace(r#"{ "os": "darwin" }"#, r#"{ "os": "none", "cpu": "arm64" }"#);
        let native = &read("bun.lock", &netbsd, demo()).unwrap().lock.packages["@s/native@1.0.0"];
        assert_eq!(native.os, ["none"]);
        // pnpm says only hasBin: bins are left to the store.
        let pnpm = read("pnpm-lock.yaml", PNPM, demo()).unwrap();
        let mut binless = expected.clone();
        binless.packages.get_mut("tool@1.0.0").unwrap().bin.clear();
        assert_eq!(pnpm.lock, binless);
        assert_eq!(pnpm.binless, ["tool@1.0.0"]);
    }

    #[test]
    fn keeps_pnpm_copies_per_set_of_peers() {
        // pnpm's keys for copies of one version with different peers are jpm's too.
        let text = "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1
        version: 1.0.0(host@1.0.0)
      b:
        specifier: ^1
        version: 1.0.0
      host:
        specifier: ^1
        version: 1.0.0
packages:
  a@1.0.0:
    resolution: {integrity: sha512-a}
  b@1.0.0:
    resolution: {integrity: sha512-b}
  host@1.0.0:
    resolution: {integrity: sha512-h1}
  host@2.0.0:
    resolution: {integrity: sha512-h2}
  ui@1.0.0:
    resolution: {integrity: sha512-ui}
    peerDependencies:
      host: '*'
snapshots:
  a@1.0.0(host@1.0.0):
    dependencies:
      ui: 1.0.0(host@1.0.0)
  b@1.0.0:
    dependencies:
      host: 2.0.0
      ui: 1.0.0(host@2.0.0)
  host@1.0.0: {}
  host@2.0.0: {}
  ui@1.0.0(host@1.0.0):
    dependencies:
      host: 1.0.0
  ui@1.0.0(host@2.0.0):
    dependencies:
      host: 2.0.0
";
        let doc = json!({ "dependencies": { "a": "^1", "b": "^1", "host": "^1" } });
        let lock = read("pnpm-lock.yaml", text, doc).unwrap().lock;
        assert_eq!(lock.root.dependencies["a"], "1.0.0(host@1.0.0)");
        assert_eq!(lock.packages["a@1.0.0(host@1.0.0)"].dependencies["ui"], "1.0.0(host@1.0.0)");
        assert_eq!(lock.packages["b@1.0.0"].dependencies["ui"], "1.0.0(host@2.0.0)");
        assert_eq!(lock.packages["ui@1.0.0(host@1.0.0)"].dependencies["host"], "1.0.0");
        assert_eq!(lock.packages["ui@1.0.0(host@2.0.0)"].dependencies["host"], "2.0.0");
        // A copy linked to a peer its key does not name is refused.
        let wrong = text.replacen(
            "  ui@1.0.0(host@2.0.0):
    dependencies:
      host: 2.0.0",
            "  ui@1.0.0(host@2.0.0):
    dependencies:
      host: 1.0.0",
            1,
        );
        let doc = json!({ "dependencies": { "a": "^1", "b": "^1", "host": "^1" } });
        assert!(read("pnpm-lock.yaml", &wrong, doc).err().unwrap().message.contains("peer suffix"));
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
        assert_eq!(
            read.warnings,
            [
                "package-lock.json settles peer host of plugin@1.0.0 two ways (1.0.0 and 2.0.0); jpm links 2.0.0 for every copy"
            ]
        );
        assert!(read.lock.packages["str@npm:string-width@4.2.3"].resolved.is_none());
    }

    #[test]
    fn reads_two_hashes_as_one_package() {
        let sha512 = crate::integrity::sha512(b"ms");
        let both = format!("sha1-{} {sha512}", crate::util::to_base64(&[7; 20]));
        let deps = json!({ "ms": "2.0.0", "a": "1.0.0" });
        let text = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": deps },
                "node_modules/ms": { "version": "2.0.0", "integrity": both },
                "node_modules/a": { "version": "1.0.0", "integrity": crate::integrity::sha512(b"a"), "dependencies": { "ms": "2.0.0" } },
                "node_modules/a/node_modules/ms": { "version": "2.0.0", "integrity": sha512 },
            }
        })
        .to_string();
        let read = read("package-lock.json", &text, json!({ "dependencies": deps })).unwrap();
        assert_eq!(read.lock.packages["ms@2.0.0"].integrity, sha512);
        // Another sha512 is another package, whatever sha1 rides along.
        let other = format!("sha1-{} {}", crate::util::to_base64(&[7; 20]), crate::integrity::sha512(b"other"));
        let text = text.replace(&both, &other);
        assert!(
            err("package-lock.json", &text, json!({ "dependencies": deps })).contains("holds two packages as ms@2.0.0")
        );
    }

    #[test]
    fn says_which_dependency_went_two_ways() {
        let at = |name: &str, version: &str, deps: Value| json!({ "version": version, "integrity": format!("sha512-{name}{version}"), "dependencies": deps });
        let deps = json!({ "through2": "^2", "b": "^1" });
        let text = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": deps },
                "node_modules/through2": at("through2", "2.0.5", json!({ "readable-stream": "~2.3.6" })),
                "node_modules/readable-stream": at("readable-stream", "2.3.8", json!({})),
                "node_modules/b": at("b", "1.0.0", json!({ "through2": "^2" })),
                "node_modules/b/node_modules/through2": at("through2", "2.0.5", json!({ "readable-stream": "~2.3.6" })),
                "node_modules/b/node_modules/readable-stream": at("readable-stream", "2.3.7", json!({})),
            }
        })
        .to_string();
        let read = read("package-lock.json", &text, json!({ "dependencies": deps })).unwrap();
        assert_eq!(read.lock.packages["through2@2.0.5"].dependencies["readable-stream"], "2.3.8");
        assert_eq!(
            read.warnings,
            [
                "package-lock.json resolves readable-stream, a dependency of through2@2.0.5, two ways (2.3.7 and 2.3.8); jpm links 2.3.8 for every copy"
            ]
        );
    }

    #[test]
    fn leaves_a_pnpm_runtime_to_install_at_its_version() {
        let text = "lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      node:
        specifier: runtime:^22.0.0
        version: runtime:22.11.0
packages:
  node@runtime:22.11.0:
    hasBin: true
    resolution:
      type: variations
      variants:
        - resolution:
            archive: tarball
            integrity: sha256-x
            type: binary
            url: https://nodejs.org/download/release/v22.11.0/node-v22.11.0-linux-x64.tar.gz
          targets:
            - cpu: x64
              os: linux
    version: 22.11.0
snapshots:
  node@runtime:22.11.0: {}
";
        let doc =
            json!({ "devEngines": { "runtime": { "name": "node", "version": "^22.0.0", "onFail": "download" } } });
        let read = read("pnpm-lock.yaml", text, doc).unwrap();
        assert!(read.lock.packages.is_empty() && read.lock.root.dependencies.is_empty());
        let url = "https://nodejs.org/download/release/v22.11.0/node-v22.11.0-linux-x64.tar.gz";
        assert_eq!(read.runtimes["node"], ("22.11.0".into(), vec![(url.into(), "sha256-x".into())]));
        // Out of date, it is still the version preferred.
        assert_eq!(prefer("pnpm-lock.yaml", text).unwrap().versions["node"], ["runtime:22.11.0"]);
        let stale = json!({ "devEngines": { "runtime": { "name": "node", "version": "22", "onFail": "download" } } });
        assert!(err("pnpm-lock.yaml", text, stale).contains("out of date"));
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
        assert_eq!(lock.root.dependencies, Deps::from([("str".into(), "npm:string-width@4.2.3".into())]));
        assert_eq!(lock.packages.keys().collect::<Vec<_>>(), ["str@npm:string-width@4.2.3"]);
        // Its key names the package, so its url is the registry's own for it: not written.
        assert!(lock.packages["str@npm:string-width@4.2.3"].resolved.is_none());
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
        assert!(err("pnpm-lock.yaml", "lockfileVersion: '6.0'\n", json!({})).contains("pnpm 9 and later"));
        assert!(err("bun.lock", "{", json!({})).contains("bun.lock cannot be read"));
        assert!(err("package-lock.json", r#"{"lockfileVersion":1}"#, json!({})).contains("v1 has no packages map"));
    }

    #[test]
    fn holds_patches_to_the_project() {
        let mut m = manifest(json!({}));
        let patch = |path: &str| crate::patch::Patch {
            name: "a".into(),
            range: Some("1.0.0".into()),
            path: path.into(),
            hash: "f".repeat(64),
            text: Vec::new(),
            yarn: false,
        };
        let load_with = |file: &str, text: &str, m: &RootManifest| load(file, text, m, false, &npmjs).map(|_| ());
        let pnpm =
            "lockfileVersion: '9.0'\npatchedDependencies:\n  a@1.0.0:\n    hash: abc\n    path: patches/a.patch\n";
        let bun = r#"{"lockfileVersion":1,"patchedDependencies":{"a@1.0.0":"patches/a.patch"}}"#;
        let npm = json!({ "lockfileVersion": 3, "packages": {} }).to_string();
        let stale = |file: &str, text: &str, m: &RootManifest| load_with(file, text, m).unwrap_err().message;
        // Written without the project's patches, or with others.
        assert_eq!(stale("pnpm-lock.yaml", pnpm, &m), "pnpm-lock.yaml is out of date with the patches");
        assert!(stale("bun.lock", bun, &m).contains("out of date with the patches"));
        m.patches = vec![patch("./patches/b.patch")];
        assert!(stale("pnpm-lock.yaml", pnpm, &m).contains("out of date with the patches"));
        assert!(stale("bun.lock", r#"{"lockfileVersion":1}"#, &m).contains("out of date with the patches"));
        // The same: by path, or by the hash where pnpm keeps only that.
        m.patches = vec![patch("./patches/a.patch")];
        load_with("pnpm-lock.yaml", pnpm, &m).unwrap();
        load_with("bun.lock", bun, &m).unwrap();
        let hashed = format!("lockfileVersion: '9.0'\npatchedDependencies:\n  a@1.0.0: {}\n", "f".repeat(64));
        load_with("pnpm-lock.yaml", &hashed, &m).unwrap();
        // npm knows no patches: its tree stands.
        load_with("package-lock.json", &npm, &m).unwrap();
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
    fn installs_what_the_root_bundles() {
        // npm marks the root's own bundleDependencies inBundle too; only a dependency's bundle
        // comes in a tarball (arborist's testing-rebuild-bundle/a, testing-bundledeps-sw).
        let text = json!({
            "lockfileVersion": 2,
            "packages": {
                "": { "dependencies": { "a": "1", "b": "1" }, "bundleDependencies": ["a"] },
                "node_modules/a": { "version": "1.0.0", "integrity": "sha512-a", "inBundle": true, "dependencies": { "c": "1" } },
                "node_modules/a/node_modules/c": { "version": "1.0.0", "integrity": "sha512-c", "inBundle": true },
                "node_modules/b": { "version": "1.0.0", "integrity": "sha512-b", "dependencies": { "d": "1" } },
                "node_modules/b/node_modules/d": { "version": "1.0.0", "integrity": "sha512-d", "inBundle": true },
            }
        })
        .to_string();
        let lock = read("package-lock.json", &text, json!({ "dependencies": { "a": "1", "b": "1" } })).unwrap().lock;
        assert_eq!(lock.packages.keys().collect::<Vec<_>>(), ["a@1.0.0", "b@1.0.0", "c@1.0.0"]);
        assert_eq!(lock.packages["a@1.0.0"].dependencies, Deps::from([("c".into(), "1.0.0".into())]));
        assert!(lock.packages["b@1.0.0"].dependencies.is_empty());
    }

    #[test]
    fn takes_a_copy_with_no_integrity_for_one_that_has_it() {
        // arborist's dep-missing-resolved: one copy of minimist has neither resolved nor integrity.
        let text = json!({
            "lockfileVersion": 2,
            "packages": {
                "": { "dependencies": { "a": "1", "m": "1" } },
                "node_modules/a": { "version": "1.0.0", "integrity": "sha512-a", "dependencies": { "m": "1" } },
                "node_modules/a/node_modules/m": { "version": "1.0.0" },
                "node_modules/m": { "version": "1.0.0", "integrity": "sha512-m" },
            }
        })
        .to_string();
        let lock = read("package-lock.json", &text, json!({ "dependencies": { "a": "1", "m": "1" } })).unwrap().lock;
        assert_eq!(lock.packages["m@1.0.0"].integrity, "sha512-m");
    }

    #[test]
    fn installs_nothing_only_an_optional_peer_reaches() {
        // npm prunes what only optional peers reach (arborist's calc-dep-flags); a peer another
        // edge brings in stays settled.
        let text = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "a": "1", "b": "1" } },
                "node_modules/a": {
                    "version": "1.0.0", "integrity": "sha512-a",
                    "peerDependencies": { "p": "1", "q": "1" },
                    "peerDependenciesMeta": { "p": { "optional": true }, "q": { "optional": true } }
                },
                "node_modules/b": { "version": "1.0.0", "integrity": "sha512-b", "dependencies": { "q": "1" } },
                "node_modules/p": { "version": "1.0.0", "integrity": "sha512-p", "dependencies": { "r": "1" } },
                "node_modules/q": { "version": "1.0.0", "integrity": "sha512-q" },
                "node_modules/r": { "version": "1.0.0", "integrity": "sha512-r" },
            }
        })
        .to_string();
        let lock = read("package-lock.json", &text, json!({ "dependencies": { "a": "1", "b": "1" } })).unwrap().lock;
        assert_eq!(lock.packages.keys().collect::<Vec<_>>(), ["a@1.0.0", "b@1.0.0", "q@1.0.0"]);
        assert_eq!(lock.packages["a@1.0.0"].optional_dependencies, Deps::from([("q".into(), "1.0.0".into())]));
        assert_eq!(lock.packages["a@1.0.0"].peers.len(), 2);
    }

    #[test]
    fn names_the_file_it_cannot_read() {
        assert!(
            err("npm-shrinkwrap.json", "this isn't json", json!({})).starts_with("npm-shrinkwrap.json cannot be read:")
        );
        assert!(
            err("npm-shrinkwrap.json", r#"{"lockfileVersion":1}"#, json!({})).starts_with("npm-shrinkwrap.json v1")
        );
        let merge = "{
<<<<<<< HEAD
  \"lockfileVersion\": 2
=======
  \"lockfileVersion\": 3
>>>>>>> other
}
";
        assert!(err("package-lock.json", merge, json!({})).contains("git conflict markers"));
    }

    #[test]
    fn keeps_an_alias_beside_the_real_package_at_its_version() {
        // grafana's shape: typescript is @typescript/typescript6 at the top, and a dependency
        // takes the real typescript at the same version.
        let text = json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "typescript": "npm:@typescript/typescript6@^6", "b": "1" } },
                "node_modules/typescript": { "name": "@typescript/typescript6", "version": "6.0.2", "integrity": "sha512-t6" },
                "node_modules/b": { "version": "1.0.0", "integrity": "sha512-b", "dependencies": { "typescript": "6.0.2" } },
                "node_modules/b/node_modules/typescript": { "version": "6.0.2", "integrity": "sha512-ts" },
            }
        })
        .to_string();
        let doc = json!({ "dependencies": { "typescript": "npm:@typescript/typescript6@^6", "b": "1" } });
        let lock = read("package-lock.json", &text, doc).unwrap().lock;
        assert_eq!(lock.root.dependencies["typescript"], "npm:@typescript/typescript6@6.0.2");
        assert_eq!(lock.packages["b@1.0.0"].dependencies["typescript"], "6.0.2");
        assert_eq!(lock.packages["typescript@npm:@typescript/typescript6@6.0.2"].integrity, "sha512-t6");
        assert_eq!(lock.packages["typescript@6.0.2"].integrity, "sha512-ts");
    }

    #[test]
    fn keeps_two_packages_under_one_pnpm_alias() {
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
        // Each alias is keyed by the package it names: `x@npm:foo@1.0.0` and `x@npm:bar@1.0.0`.
        let doc = json!({ "dependencies": { "a": "1", "b": "1" } });
        let lock = read("pnpm-lock.yaml", text, doc).unwrap().lock;
        assert_eq!(lock.packages["a@1.0.0"].dependencies["x"], "npm:foo@1.0.0");
        assert_eq!(lock.packages["b@1.0.0"].dependencies["x"], "npm:bar@1.0.0");
        assert!(lock.packages.contains_key("x@npm:foo@1.0.0") && lock.packages.contains_key("x@npm:bar@1.0.0"));
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
    fn holds_a_pnpm_lock_to_its_overrides() {
        let text = "lockfileVersion: '9.0'
overrides:
  b: 2.0.0
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
      b: {specifier: 2.0.0, version: 2.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-a}}
  b@2.0.0: {resolution: {integrity: sha512-b}}
snapshots:
  a@1.0.0:
    dependencies:
      b: 2.0.0
  b@2.0.0: {}
";
        // pnpm records the overridden range for a root edge: package.json's `^1` became `2.0.0`.
        let mut m = manifest(json!({ "dependencies": { "a": "^1", "b": "^1" } }));
        let rule = crate::rules::Override::parse("pnpm", "b", "2.0.0").unwrap();
        m.overrides = vec![rule.clone()];
        let lock = load("pnpm-lock.yaml", text, &m, false, &npmjs).unwrap().lock;
        assert_eq!(lock.root.specs, m.specs());
        assert_eq!(lock.root.overrides, std::slice::from_ref(&rule));
        assert_eq!(lock.packages["a@1.0.0"].dependencies["b"], "2.0.0");
        // Other overrides than the file was resolved under, or none: out of date.
        m.overrides = vec![crate::rules::Override::parse("pnpm", "b", "^2").unwrap()];
        assert!(load("pnpm-lock.yaml", text, &m, false, &npmjs).err().unwrap().message.contains("out of date"));
        m.overrides.clear();
        assert!(load("pnpm-lock.yaml", text, &m, false, &npmjs).is_err());
        // npm's and yarn's rules are not pnpm's to record.
        m.overrides = vec![rule, crate::rules::Override::parse("npm", "c", "1.0.0").unwrap()];
        assert!(load("pnpm-lock.yaml", text, &m, false, &npmjs).is_ok());
    }

    #[test]
    fn reads_catalog_ranges_from_pnpm_and_bun_locks() {
        let pnpm = |a: &str| {
            format!(
                "lockfileVersion: '9.0'
catalogs:
  default:
    a: {{specifier: '{a}', version: 1.0.0}}
  x:
    b: {{specifier: ^2, version: 2.0.0}}
importers:
  .:
    dependencies:
      a: {{specifier: 'catalog:', version: 1.0.0}}
      b: {{specifier: 'catalog:x', version: 2.0.0}}
packages:
  a@1.0.0: {{resolution: {{integrity: sha512-a}}}}
  b@2.0.0: {{resolution: {{integrity: sha512-b}}}}
snapshots:
  a@1.0.0: {{}}
  b@2.0.0: {{}}
"
            )
        };
        let bun = |a: &str| {
            json!({
                "lockfileVersion": 1,
                "workspaces": { "": { "dependencies": { "a": "catalog:", "b": "catalog:x" } } },
                "catalog": { "a": a },
                "catalogs": { "x": { "b": "^2" } },
                "packages": { "a": ["a@1.0.0", "", {}, "sha512-a"], "b": ["b@2.0.0", "", {}, "sha512-b"] },
            })
            .to_string()
        };
        // package.json's ranges as the project reads them: catalogs already applied.
        let doc = json!({ "dependencies": { "a": "^1", "b": "^2" } });
        let want = Deps::from([("a".into(), "1.0.0".into()), ("b".into(), "2.0.0".into())]);
        assert_eq!(read("pnpm-lock.yaml", &pnpm("^1"), doc.clone()).unwrap().lock.root.dependencies, want);
        assert_eq!(read("bun.lock", &bun("^1"), doc.clone()).unwrap().lock.root.dependencies, want);
        // The catalog has moved since the file was written.
        assert!(err("pnpm-lock.yaml", &pnpm("^1.5"), doc.clone()).contains("out of date"));
        assert!(err("bun.lock", &bun("^1.5"), doc).contains("out of date"));
    }

    #[test]
    fn reads_lists_of_maps_and_block_text() {
        // .yarnrc.yml as yarn writes it: plugins before the catalog.
        let doc = read_yaml(
            "nodeLinker: node-modules\nplugins:\n  - path: .yarn/plugins/a.cjs\n    spec: \"a\"\n  - - nested\n  - plain\nnote: |\n  one\n  two\nfold: >-\n  a\n  b\ncatalog:\n  a: ^1\n",
        )
        .unwrap();
        let expect = json!({
            "nodeLinker": "node-modules",
            "plugins": [{ "path": ".yarn/plugins/a.cjs", "spec": "a" }, ["nested"], "plain"],
            "note": "one\ntwo",
            "fold": "a b",
            "catalog": { "a": "^1" },
        });
        assert_eq!(serde_json::from_str::<Value>(&crate::json::to_string(&doc)).unwrap(), expect);
        // A scalar with a colon in it is no map.
        let doc = read_yaml("l:\n- 'a: b'\n- npm:x@1\n- https://x\n").unwrap();
        assert_eq!(doc.get("l").and_then(crate::json::Value::as_array).map(Vec::len), Some(3));
        // An explicit key, as js-yaml writes one over 1024 characters: a map under it, whose
        // first entry shares the `:` line; a scalar; nothing.
        let long = format!("drawer@4.2.3({})", "x".repeat(1100));
        let text = format!(
            "snapshots:\n  a@1: {{}}\n\n  ? {long}\n  : dependencies:\n      color: 4.2.3\n    transitivePeerDependencies:\n      - y\n\n  ? 'q: r'\n  : 1.0.0\n  ? bare\n  b@2: {{}}\n"
        );
        let doc = read_yaml(&text).unwrap();
        let snaps = doc.get("snapshots").unwrap();
        let entry = snaps.get(&long).unwrap_or_else(|| panic!("{doc}"));
        assert_eq!(entry.get("dependencies").and_then(|d| d.get("color")).map(string_of).as_deref(), Some("4.2.3"));
        assert_eq!(list(entry.get("transitivePeerDependencies")), vec!["y".to_string()]);
        assert_eq!(snaps.get("q: r").map(string_of).as_deref(), Some("1.0.0"));
        assert!(snaps.get("bare").is_some_and(|v| matches!(v, crate::json::Value::Null)) && snaps.get("b@2").is_some());
        // A line with no place is an error, not the end of the file.
        for bad in ["a:\n  b: 1\n    c: 2\nd: 3\n", "a: 1\n  b: 2\n", "- x\n    y: 1\n"] {
            assert!(read_yaml(bad).is_err(), "{bad}");
        }
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

    #[test]
    fn reads_yarn_ranges() {
        let v1 = "# yarn lockfile v1\n\n\n\"@s/a@^1.0.0\", \"@s/a@^1.1.0\":\n  version \"1.2.0\"\n  resolved \"https://r/@s/a/-/a-1.2.0.tgz\"\n  dependencies:\n    version \"^2\"\n\nb@npm:c@^2:\n  version \"2.0.1\"\n\nd@github:x/d:\n  version \"1.0.0\"\n";
        let p = read_yarn(v1);
        assert_eq!(p.ranges["@s/a@^1.0.0"], "1.2.0");
        assert_eq!(p.ranges["@s/a@^1.1.0"], "1.2.0");
        assert_eq!(p.ranges["c@^2"], "2.0.1", "an alias asks for the real package");
        assert_eq!(p.ranges.len(), 3, "not the git one: {:?}", p.ranges);
        let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"@s/a@npm:^1.0.0, @s/a@npm:~1.1.0\":\n  version: 1.2.0\n  resolution: \"@s/a@npm:1.2.0\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n";
        let p = read_yarn(berry);
        assert_eq!(p.ranges["@s/a@^1.0.0"], "1.2.0");
        assert_eq!(p.ranges["@s/a@~1.1.0"], "1.2.0");
        assert_eq!(p.ranges.len(), 2, "{:?}", p.ranges);
        assert_eq!(p.versions["@s/a"], ["1.2.0", "1.2.0"]);
    }

    #[test]
    fn compares_integrity_both_ways() {
        let (p, q) = (crate::integrity::sha512(b"p"), crate::integrity::sha512(b"q"));
        let sha1 = format!("sha1-{}", crate::util::to_base64(&[7; 20]));
        for (a, b, same) in [
            (format!("{q} {p}"), p.clone(), false),
            (format!("{q} {p}"), format!("{p} {q}"), true),
            (format!("{sha1} {p}"), p.clone(), true),
            (format!("{sha1} {p}"), format!("{sha1} {q}"), false),
        ] {
            assert_eq!(same_integrity(&a, &b), same, "{a} | {b}");
            assert_eq!(same_integrity(&b, &a), same, "{b} | {a}");
        }
    }

    #[test]
    fn refuses_a_real_name_that_is_not_one() {
        let doc = json!({ "dependencies": { "a": "1.0.0" } });
        let integrity = crate::integrity::sha512(b"a");
        let npm = json!({
            "lockfileVersion": 3,
            "packages": {
                "": doc,
                "node_modules/a": { "version": "1.0.0", "name": "../evil", "integrity": integrity },
            }
        })
        .to_string();
        let bun = json!({
            "lockfileVersion": 1,
            "workspaces": { "": doc },
            "packages": { "a": ["../evil@1.0.0", "", {}, integrity] },
        })
        .to_string();
        for (file, text) in [("package-lock.json", npm), ("bun.lock", bun)] {
            let e = err(file, &text, doc.clone());
            assert!(e.contains("package name \"../evil\""), "{file}: {e}");
        }
        let pnpm = format!(
            "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: ../evil@1.0.0
packages:
  ../evil@1.0.0:
    resolution: {{integrity: {integrity}}}
snapshots:
  ../evil@1.0.0: {{}}
"
        );
        assert!(err("pnpm-lock.yaml", &pnpm, doc.clone()).contains("package name \"../evil\""));
    }

    // Each of these took seconds, in the square of the file's size, and quite a bit longer
    // without optimizations.
    #[test]
    fn walks_up_a_deep_npm_path_a_level_at_a_time() {
        let deep = format!("node_modules/a{}", "/node_modules/a".repeat(3000));
        let missing: serde_json::Map<String, Value> = (0..20).map(|i| (format!("d{i}"), json!("1"))).collect();
        let text =
            json!({ "lockfileVersion": 3, "packages": { deep: { "version": "1.0.0", "dependencies": missing } } })
                .to_string();
        let start = std::time::Instant::now();
        let source = read_npm("package-lock.json", &text).unwrap();
        // Quadratic takes seconds here; a debug build on a busy CI runner can take a second.
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
        assert_eq!(source.nodes[0].name, "a");
        assert_eq!(source.nodes[0].dependencies.len(), 20);
    }

    #[test]
    fn walks_up_a_deep_bun_path_a_level_at_a_time() {
        let deep = vec!["a"; 3000].join("/");
        let missing: serde_json::Map<String, Value> = (0..20).map(|i| (format!("d{i}"), json!("1"))).collect();
        let text = json!({
            "lockfileVersion": 1,
            "packages": { deep: ["a@1.0.0", "", { "dependencies": missing }, "sha512-a"] },
        })
        .to_string();
        let start = std::time::Instant::now();
        let source = read_bun(&text).unwrap();
        assert!(start.elapsed().as_millis() < 300, "{:?}", start.elapsed());
        assert_eq!(source.nodes[0].dependencies.len(), 20);
        // Scoped names are one step.
        assert_eq!(names("a/@s/b/c"), ["a", "@s/b", "c"]);
    }

    /// Found while fuzzing the importers: a level at a time was still a walk up per dependency,
    /// so one package 30,000 folders deep with 50,000 dependencies (1 MB) took minutes.
    #[test]
    fn finds_every_dependency_in_one_walk() {
        let missing: serde_json::Map<String, Value> = (0..50_000).map(|i| (format!("d{i}"), json!("1"))).collect();
        let deep = format!("node_modules/a{}", "/node_modules/a".repeat(30_000));
        let npm = json!({ "lockfileVersion": 3, "packages": {
            "node_modules/d7": { "version": "7.0.0" },
            deep: { "version": "1.0.0", "dependencies": missing },
        }})
        .to_string();
        let bun = json!({ "lockfileVersion": 1, "packages": {
            "d7": ["d7@7.0.0", "", {}, "sha512-a"],
            vec!["a"; 30_000].join("/"): ["a@1.0.0", "", { "dependencies": missing }, "sha512-a"],
        }})
        .to_string();
        let start = std::time::Instant::now();
        for source in [read_npm("package-lock.json", &npm).unwrap(), read_bun(&bun).unwrap()] {
            let deep = source.nodes.iter().find(|n| n.name == "a").unwrap();
            assert_eq!((deep.dependencies.len(), deep.dependencies["d7"].as_str()), (50_000, "7.0.0"));
            assert_eq!(deep.dependencies["d8"], "");
        }
        assert!(start.elapsed().as_millis() < 5000, "{:?}", start.elapsed());
    }

    #[test]
    fn counts_only_registry_tarballs_as_registry_packages() {
        let at = |resolved: &str| {
            let entry = json::parse(&format!(r#"{{"version":"18.0.11","resolved":"{resolved}"}}"#)).unwrap();
            npm_version(&entry).is_some()
        };
        assert!(at(""));
        assert!(at("https://registry.npmjs.org/marked/-/marked-18.0.11.tgz"));
        assert!(at("https://mirror.example/api/npm/@s/n/-/n-18.0.11.tgz"));
        assert!(!at("https://codeload.github.com/markedjs/marked/tar.gz/0123abc"));
        assert!(!at("https://gitlab.com/g/p/-/archive/v18.0.11/p-v18.0.11.tar.gz"));
        assert!(!at("git+ssh://git@github.com/markedjs/marked.git#0123abc"));
    }

    #[test]
    fn reads_a_big_yaml_map_in_linear_time() {
        let mut text = String::from("packages:\n");
        for i in 0..10_000 {
            text.push_str(&format!("  p{i}@1.0.0:\n    resolution: {{integrity: sha512-x}}\n"));
        }
        text.push_str("  p0@1.0.0: {}\n");
        let start = std::time::Instant::now();
        let doc = yaml(&text).unwrap();
        assert!(start.elapsed().as_millis() < 300, "{:?}", start.elapsed());
        let packages = doc.get("packages").and_then(|p| p.as_object()).unwrap();
        assert_eq!(packages.len(), 10_000);
        // A key given twice keeps its first place and its last value.
        assert_eq!(packages.iter().next().map(|(k, v)| (k.as_str(), v.to_string())), Some(("p0@1.0.0", "{}".into())));
    }

    /// Found while fuzzing the importers: a peer suffix was read a level of nesting at a time,
    /// each level reading the rest again, so a key of 100,000 nested groups (1.7 MB) took minutes
    /// and recursed as deep as it nested.
    #[test]
    fn refuses_a_peer_suffix_nested_past_any_real_one() {
        let nested = |n: usize| format!("{}{}", "(b@1.0.0".repeat(n), ")".repeat(n));
        assert_eq!(peer_suffix(&format!("a@1.0.0{}(c@2.0.0)", nested(3))).unwrap(), format!("{}(c@2.0.0)", nested(3)));
        assert_eq!(peer_suffix(&nested(MAX_DEPTH)).unwrap(), nested(MAX_DEPTH));
        for n in [MAX_DEPTH + 1, 100_000] {
            let key = format!("a@1.0.0{}", nested(n));
            let text = format!(
                "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        \
                 version: 1.0.0\npackages:\n  a@1.0.0:\n    resolution: {{integrity: sha512-x}}\nsnapshots:\n  {key}: {{}}\n"
            );
            assert!(
                err("pnpm-lock.yaml", &text, json!({ "dependencies": { "a": "^1" } })).contains("nested too deeply")
            );
        }
    }
}

#[cfg(test)]
#[path = "../tests/conformance/arborist.rs"]
mod arborist;

#[cfg(test)]
#[path = "../tests/conformance/bun_lock.rs"]
mod bun_lock;
