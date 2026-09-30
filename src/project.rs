//! package.json: reading it, finding the project and its workspaces, and editing its
//! dependency groups the way the file is already written.

use std::path::{Path, PathBuf};

use crate::json::{self, Object, Value};

use crate::bin::{self, Bins};
use crate::error::{Error, Result};
use crate::graph::{Deps, PeerKind, Peers, Specs};
use crate::spec::Spec;
use crate::{glob, semver, spec};

pub const GROUPS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];

/// A package.json as the resolver reads it, with the parsed document kept for edits and scripts.
#[derive(Debug, Clone, Default)]
pub struct RootManifest {
    pub name: Option<String>,
    pub version: Option<String>,
    pub dependencies: Deps,
    pub dev_dependencies: Deps,
    pub optional_dependencies: Deps,
    pub peer_dependencies: Option<Deps>,
    pub peer_optional: Vec<String>,
    pub workspaces: Option<Vec<String>>,
    /// The root's overrides, resolved (`rules::Rules::apply`); empty for a workspace.
    pub overrides: Vec<crate::rules::Override>,
    /// The root's patches, each file read for its hash (`rules::Rules::apply`).
    pub patches: Vec<crate::patch::Patch>,
    /// `devEngines.runtime` and `engines.runtime` entries that only check the system's runtime
    /// (`onFail` other than `download` and `ignore`), as `(field, name, range)`.
    pub runtime_checks: Vec<(&'static str, String, String)>,
    pub doc: Object,
}

impl RootManifest {
    pub fn parse(text: &str, file: &Path) -> Result<Self> {
        let value: Value = json::parse(text.trim_start_matches('\u{feff}'))
            .map_err(|e| manifest_error(format!("{} is not valid JSON: {e}", file.display())))?;
        let Value::Object(doc) = value else {
            return Err(manifest_error(format!("{} is not a JSON object", file.display())));
        };
        Self::from_doc(doc, file)
    }

    pub fn from_doc(doc: Object, file: &Path) -> Result<Self> {
        let group = |name: &str| -> Result<Option<Deps>> {
            match doc.get(name) {
                None => Ok(None),
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| match v {
                        Value::String(s) if s.starts_with("catalog:") => Ok((k.clone(), catalog_range(file, k, s)?)),
                        Value::String(s) => Ok((k.clone(), s.clone())),
                        _ => Err(manifest_error(format!("{}: {name} is not a map of ranges", file.display()))),
                    })
                    .collect::<Result<Deps>>()
                    .map(Some),
                Some(_) => Err(manifest_error(format!("{}: {name} is not a map of ranges", file.display()))),
            }
        };
        let string = |name: &str| doc.get(name).and_then(Value::as_str).map(str::to_string);
        let workspaces = match doc.get("workspaces") {
            None => None,
            Some(Value::Array(list)) => Some(list),
            Some(Value::Object(o)) => o.get("packages").and_then(Value::as_array),
            Some(_) => None,
        }
        .map(|list| {
            list.iter()
                .map(|p| {
                    p.as_str().map(str::to_string).ok_or_else(|| {
                        workspace_error("workspaces must be an array of patterns, or { packages: [...] }")
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .or_else(|| pnpm_workspace(file.parent()?)?.get("packages")?.as_array().map(|l| strings(l)));
        let peer_optional = doc
            .get("peerDependenciesMeta")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.get("optional").and_then(Value::as_bool) == Some(true))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut dependencies = group("dependencies")?.unwrap_or_default();
        let mut dev_dependencies = group("devDependencies")?.unwrap_or_default();
        let mut runtime_checks = Vec::new();
        // pnpm's form of a runtime dependency, which `add` writes too: `onFail: "download"` makes
        // it one, in the group its field stands for. A range in the group itself comes first.
        for (field, deps) in [("engines", &mut dependencies), ("devEngines", &mut dev_dependencies)] {
            for entry in runtime_entries(&doc, field) {
                let text = |k: &str| entry.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let (name, version, on_fail) = (text("name"), text("version"), text("onFail"));
                if !crate::runtime::NAMES.contains(&name.as_str()) {
                    continue;
                }
                match on_fail.as_str() {
                    "download" => {
                        deps.entry(name).or_insert_with(|| format!("{}{version}", crate::runtime::PROTOCOL));
                    }
                    "ignore" => {}
                    _ => runtime_checks.push((field, name, version)),
                }
            }
        }
        Ok(Self {
            name: string("name"),
            version: string("version"),
            dependencies,
            dev_dependencies,
            optional_dependencies: group("optionalDependencies")?.unwrap_or_default(),
            peer_dependencies: group("peerDependencies")?,
            peer_optional,
            workspaces,
            overrides: Vec::new(),
            patches: Vec::new(),
            runtime_checks,
            doc,
        })
    }

    pub fn specs(&self) -> Option<Specs> {
        Specs::declared(&self.dependencies, &self.dev_dependencies, &self.optional_dependencies)
    }

    pub fn bins(&self) -> Bins {
        bin::normalize(self.name.as_deref(), self.doc.get("bin"))
    }

    /// Direct edges as `(name, range, optional)`. A name in two groups is optional first, then a
    /// dependency, then dev.
    pub fn edges(&self) -> Vec<(String, String, bool)> {
        let mut out: Vec<_> = self.optional_dependencies.iter().map(|(n, r)| (n.clone(), r.clone(), true)).collect();
        for group in [&self.dependencies, &self.dev_dependencies] {
            for (name, range) in group {
                if !out.iter().any(|(n, _, _)| n == name) {
                    out.push((name.clone(), range.clone(), false));
                }
            }
        }
        out
    }

    /// The names of the non-dev edges: a peer ships too, unless a devDependency gives the edge.
    pub fn prod(&self) -> std::collections::HashSet<String> {
        let mut prod: std::collections::HashSet<String> =
            self.dependencies.keys().chain(self.optional_dependencies.keys()).cloned().collect();
        for peer in self.peer_dependencies.iter().flatten().map(|(k, _)| k) {
            if !self.dev_dependencies.contains_key(peer) {
                prod.insert(peer.clone());
            }
        }
        prod
    }

    pub fn scripts(&self, file: &Path) -> Result<Object> {
        match self.doc.get("scripts") {
            None => Ok(Object::new()),
            Some(Value::Object(m)) if m.iter().all(|(_, v)| v.as_str().is_some()) => Ok(m.clone()),
            Some(_) => Err(manifest_error(format!("{}: scripts is not a map of commands", file.display()))),
        }
    }

    /// Whether any group declares anything.
    pub fn declares(&self) -> bool {
        !(self.dependencies.is_empty() && self.dev_dependencies.is_empty() && self.optional_dependencies.is_empty())
    }
}

/// The peers the walk settles as peers: one the package also depends on is its own edge.
pub fn declared_peers(deps: &Deps, optional: &Deps, peers: Option<&Deps>, is_optional: &dyn Fn(&str) -> bool) -> Peers {
    peers
        .into_iter()
        .flatten()
        .filter(|(name, _)| !deps.contains_key(*name) && !optional.contains_key(*name))
        .map(|(name, _)| (name.clone(), if is_optional(name) { PeerKind::Optional } else { PeerKind::Required }))
        .collect()
}

/// What a workspace's lockfile entry carries besides its edges.
pub struct LocalShape {
    pub specs: Option<Specs>,
    pub bin: Bins,
    pub peer_dependencies: Option<Deps>,
    pub peers: Option<Peers>,
}

pub fn local_shape(m: &RootManifest) -> LocalShape {
    let peers = declared_peers(&m.dependencies, &m.optional_dependencies, m.peer_dependencies.as_ref(), &|n| {
        m.peer_optional.iter().any(|p| p == n)
    });
    LocalShape {
        specs: m.specs(),
        bin: m.bins(),
        peer_dependencies: m.peer_dependencies.clone(),
        peers: (!peers.is_empty()).then_some(peers),
    }
}

/// Whether a workspace path can be trusted where it is used: relative, `/`-separated, never up.
/// `.` is the root, listed as a workspace of its own. No `:` either: on Windows `C:x` is on
/// another drive and `a:b` a stream of `a`.
pub fn local_path(path: &str) -> bool {
    path == ROOT_PATH
        || !path.is_empty()
            && !path.contains(['\\', ':'])
            && !path.split('/').any(|p| p.is_empty() || p == "." || p == "..")
}

/// The path of the root when its own `workspaces` lists it (`.`): a workspace others link to
/// by its name, installed once, as the root.
pub const ROOT_PATH: &str = ".";

/// Whether the root lists itself as a workspace, and has a name to be linked by.
pub fn lists_root(m: &RootManifest) -> bool {
    patterns(m).is_ok_and(|(p, _)| root_listed(m, &p))
}

fn root_listed(m: &RootManifest, patterns: &[String]) -> bool {
    m.name.as_ref().is_some_and(|n| !n.is_empty()) && patterns.iter().any(|p| p.is_empty() || p == ".")
}

#[derive(Debug, Clone)]
pub struct Workspace {
    /// Relative to the root, `/` separators.
    pub path: String,
    pub dir: PathBuf,
    pub name: String,
    pub version: String,
    pub manifest: RootManifest,
}

// --- pnpm-workspace.yaml and catalogs --------------------------------------------------------

/// `pnpm-workspace.yaml` in `dir`, when there is one: pnpm's list of workspaces (taken when
/// package.json lists none) and its catalogs.
fn pnpm_workspace(dir: &Path) -> Option<Object> {
    let text = std::fs::read_to_string(dir.join("pnpm-workspace.yaml")).ok()?;
    match crate::foreign::read_yaml(&text) {
        Ok(Value::Object(o)) => Some(o),
        _ => None,
    }
}

fn strings(list: &[Value]) -> Vec<String> {
    list.iter().filter_map(Value::as_str).map(str::to_string).collect()
}

/// Catalog name -> package -> range: `catalog` is `default`, `catalogs` holds the named ones.
type Catalogs = std::collections::BTreeMap<String, Deps>;

/// A root's catalogs, wherever its package manager keeps them: `pnpm-workspace.yaml`,
/// `.yarnrc.yml`, or package.json at the top or under `workspaces` (bun). `None` when the
/// directory defines none; an error when its `.yarnrc.yml` cannot be read.
fn catalogs_in(dir: &Path) -> std::result::Result<Option<Catalogs>, String> {
    let file = dir.join(".yarnrc.yml");
    let yarnrc = match std::fs::read_to_string(&file) {
        Ok(t) => Some(crate::foreign::read_yaml(&t).map_err(|e| format!("{}: {}", file.display(), e.message))?),
        Err(_) => None,
    };
    let manifest = std::fs::read_to_string(dir.join("package.json")).ok().and_then(|t| json::parse(&t).ok());
    let workspaces = manifest.as_ref().and_then(|m| m.get("workspaces")).filter(|w| w.as_object().is_some());
    let docs = [pnpm_workspace(dir).map(Value::Object), yarnrc, manifest.clone(), workspaces.cloned()];
    let mut out = Catalogs::new();
    let mut found = false;
    for doc in docs.iter().flatten() {
        let map = |v: &Value| -> Deps {
            v.as_object()
                .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                .unwrap_or_default()
        };
        if let Some(c) = doc.get("catalog") {
            found = true;
            out.entry("default".into()).or_default().extend(map(c));
        }
        for (name, c) in doc.get("catalogs").and_then(Value::as_object).into_iter().flatten() {
            found = true;
            out.entry(name.clone()).or_default().extend(map(c));
        }
    }
    Ok(found.then_some(out))
}

/// The range a `catalog:` or `catalog:<name>` stands for, from the nearest directory at or above
/// the package.json that defines catalogs: the workspace root.
pub fn catalog_range(file: &Path, name: &str, spec: &str) -> Result<String> {
    type Found = std::result::Result<Option<Catalogs>, String>;
    static FOUND: std::sync::Mutex<Option<std::collections::HashMap<PathBuf, Found>>> = std::sync::Mutex::new(None);
    let which = match spec["catalog:".len()..].trim() {
        "" => "default",
        other => other,
    };
    let start = std::path::absolute(file).unwrap_or_else(|_| file.to_path_buf());
    let mut cache = FOUND.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = cache.get_or_insert_with(Default::default);
    for dir in start.ancestors().skip(1) {
        let catalogs = cache.entry(dir.to_path_buf()).or_insert_with(|| catalogs_in(dir));
        let catalogs =
            catalogs.as_ref().map_err(|why| manifest_error(format!("{}: {name}@{spec}: {why}", file.display())))?;
        if let Some(catalogs) = catalogs {
            return catalogs.get(which).and_then(|c| c.get(name)).cloned().ok_or_else(|| {
                manifest_error(format!(
                    "{}: {name}@{spec} names no entry: catalog {which} under {} has no {name}",
                    file.display(),
                    dir.display()
                ))
            });
        }
        // Not past the repository or the home directory: a catalog above them is someone else's.
        if dir.join(".git").exists() || dir == crate::config::home() {
            break;
        }
    }
    Err(manifest_error(format!("{}: {name}@{spec}, but no catalogs are defined here or above", file.display())))
}

pub fn read_manifest(file: &Path) -> Result<RootManifest> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::io(&e, format!("cannot read {}", file.display())).keep_enoent("EMANIFEST"))?;
    RootManifest::parse(&text, file)
}

trait KeepEnoent {
    fn keep_enoent(self, code: &'static str) -> Self;
}

impl KeepEnoent for Error {
    /// Keeps a missing file's `ENOENT` visible: `jpm nope` tells a typo from a broken file by it.
    fn keep_enoent(mut self, code: &'static str) -> Self {
        if self.code != "ENOENT" {
            self.code = code;
        }
        self
    }
}

/// All of `workspaces` together, in bytes.
const MAX_WORKSPACES: usize = 32 * 1024;

/// The declared patterns, the negations applied the way npm's map-workspaces does. Each
/// negation is matched against each pattern, and against each directory found: the time that
/// takes grows with the product of their sizes, so the whole list is capped, and a package.json
/// past the caps is refused.
fn patterns(m: &RootManifest) -> Result<(Vec<String>, Vec<String>)> {
    let mut patterns = Vec::new();
    let mut negated: Vec<String> = Vec::new();
    let (mut bytes, mut expanded) = (0, 0);
    for raw in m.workspaces.iter().flatten() {
        let bangs = raw.len() - raw.trim_start_matches('!').len();
        let body = raw[bangs..].trim_start_matches("./").trim_start_matches('/');
        let alternatives = glob::braces(body);
        bytes += raw.len();
        expanded += alternatives.len();
        if glob::too_big(body) || bytes > MAX_WORKSPACES || expanded > glob::MAX_BRACES {
            return Err(workspace_error(&format!(
                "workspaces is more than jpm reads: over {} bytes in one pattern or {MAX_WORKSPACES} in all, \
                 or over {} patterns once braces are expanded",
                glob::MAX_PATTERN,
                glob::MAX_BRACES
            )));
        }
        // After braces too: `{../x,y}` hides a `..` from a plain look.
        if alternatives.iter().any(|b| b.split('/').any(|p| p == "..")) {
            return Err(workspace_error(&format!("workspace pattern {raw} reaches outside the project")));
        }
        if bangs % 2 == 1 {
            negated.push(body.to_string());
        } else {
            negated.retain(|other| !glob::matches(other, body));
            patterns.push(body.to_string());
        }
    }
    patterns.retain(|p| !negated.iter().any(|n| glob::matches(n, p)));
    Ok((patterns, negated))
}

/// Every workspace under `dir`, pattern by pattern, sorted within one, each at its first match.
/// Of two with one name the first is kept and the other left out with a warning, as pnpm lets
/// a test fixture share its parent's name; but when something would link to that name, which
/// one it means is ambiguous, and that is an error. The root, when it lists itself, is first.
pub fn find_workspaces(dir: &Path, m: &RootManifest) -> Result<Vec<Workspace>> {
    let (patterns, mut exclude) = patterns(m)?;
    exclude.push("**/node_modules/**".into());
    let mut found: Vec<Workspace> = Vec::new();
    // (kept path, its version, left-out path, its version, name)
    let mut twins: Vec<(String, String, String, String, String)> = Vec::new();
    let root =
        root_listed(m, &patterns).then(|| (m.name.clone().unwrap_or_default(), m.version.clone().unwrap_or_default()));
    for pattern in &patterns {
        let mut paths = glob::expand(dir, pattern, &exclude);
        paths.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then(a.cmp(b)));
        for path in paths {
            if path.is_empty() || found.iter().any(|w| w.path == path) {
                continue;
            }
            let at = dir.join(&path);
            let file = at.join("package.json");
            if !file.is_file() {
                continue;
            }
            let manifest = read_manifest(&file)?;
            let name = manifest.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| basename(&path));
            let version = manifest.version.clone().filter(|v| semver::is_exact(v)).unwrap_or_else(|| "0.0.0".into());
            let first = match &root {
                Some((n, v)) if *n == name => Some((ROOT_PATH.to_string(), v.clone())),
                _ => found.iter().find(|w| w.name == name).map(|w| (w.path.clone(), w.version.clone())),
            };
            if let Some((first, first_version)) = first {
                twins.push((first, first_version, path, version, name));
                continue;
            }
            found.push(Workspace { path, dir: at, name, version, manifest });
        }
    }
    for (first, first_version, path, version, name) in &twins {
        let links = |t: &RootManifest| {
            [&t.dependencies, &t.dev_dependencies, &t.optional_dependencies]
                .into_iter()
                .chain(t.peer_dependencies.as_ref())
                .filter_map(|group| group.get(name))
                .any(|range| {
                    spec::parse_dep(name, range).is_ok_and(|s| links_to(&s, first_version) || links_to(&s, version))
                })
        };
        if std::iter::once(m).chain(found.iter().map(|w| &w.manifest)).any(links) {
            return Err(workspace_error(&format!(
                "workspaces {first} and {path} are both named {name}, and a dependency on {name} could mean either"
            )));
        }
        crate::ui::warn(&format!("workspaces {first} and {path} are both named {name}; jpm installs only {first}"));
    }
    Ok(found)
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// The project a directory belongs to, found by npm's walk up.
pub struct Found {
    pub dir: PathBuf,
    pub manifest: Option<RootManifest>,
    pub workspaces: Option<Vec<Workspace>>,
    /// The workspace `cwd` is in, when a root above lists it.
    pub workspace: Option<Workspace>,
}

/// The nearest package.json is the project, unless one above lists that directory as a
/// workspace. Nothing found means `cwd` itself.
pub fn find_root(cwd: &Path) -> Found {
    let mut candidate: Option<Found> = None;
    let mut dir = cwd.to_path_buf();
    loop {
        let file = dir.join("package.json");
        let manifest = if file.is_file() { read_manifest(&file).ok() } else { None };
        match (manifest, &candidate) {
            (Some(m), None) => {
                candidate = Some(Found { dir: dir.clone(), manifest: Some(m), workspaces: None, workspace: None });
            }
            (Some(m), Some(c)) if m.workspaces.is_some() => {
                if let Ok(all) = find_workspaces(&dir, &m)
                    && let Some(ws) = all.iter().find(|w| w.dir == c.dir).cloned()
                {
                    return Found { dir, manifest: Some(m), workspaces: Some(all), workspace: Some(ws) };
                }
            }
            _ => {}
        }
        if !dir.pop() {
            return candidate.unwrap_or(Found {
                dir: cwd.to_path_buf(),
                manifest: None,
                workspaces: None,
                workspace: None,
            });
        }
    }
}

// --- edits ------------------------------------------------------------------------------------

pub struct Added {
    pub name: String,
    pub range: String,
    pub group: &'static str,
}

/// The range `add` saves: what was typed, except that a bare name, `*` or a tag becomes a caret
/// on the resolved version (or the version itself with `exact`).
pub fn save_range(spec: &Spec, version: &str, exact: bool) -> String {
    if spec.kind == spec::Kind::Workspace {
        return spec.raw[spec.name.len() + 1..].to_string();
    }
    let derived = spec.kind == spec::Kind::Tag || spec.fetch_spec == "*";
    let range = if !derived {
        spec.fetch_spec.clone()
    } else if exact {
        version.to_string()
    } else {
        format!("^{version}")
    };
    if spec.fetch_name == spec.name { range } else { format!("npm:{}@{range}", spec.fetch_name) }
}

/// Put each dep in its group, out of any other. Groups stay sorted. A runtime goes where pnpm
/// puts it: `devEngines.runtime` for a dev dependency, else `engines.runtime`.
pub fn add_deps(doc: &mut Object, added: &[Added]) {
    for dep in added {
        let runtime = dep
            .range
            .strip_prefix(crate::runtime::PROTOCOL)
            .filter(|_| crate::runtime::is_runtime(&dep.name, &dep.range));
        let field = if dep.group == "devDependencies" { "devEngines" } else { "engines" };
        for group in GROUPS {
            if group != dep.group || runtime.is_some() {
                drop_dep(doc, group, &dep.name);
            }
        }
        for f in ["engines", "devEngines"] {
            if runtime.is_none() || f != field {
                drop_runtime(doc, f, &dep.name);
            }
        }
        if let Some(version) = runtime {
            set_runtime(doc, field, &dep.name, version);
            continue;
        }
        if !doc.get(dep.group).is_some_and(|g| g.as_object().is_some()) {
            doc.insert(dep.group, Value::Object(Object::new()));
        }
        if let Some(Value::Object(map)) = doc.get_mut(dep.group) {
            map.insert(dep.name.clone(), Value::String(dep.range.clone()));
            map.sort_keys();
        }
    }
}

/// Take each name out of every group, and a runtime out of `engines` and `devEngines`; the names
/// in none come back.
pub fn remove_deps(doc: &mut Object, names: &[String]) -> Vec<String> {
    let mut missing = Vec::new();
    for name in names {
        let groups = GROUPS.iter().filter(|g| drop_dep(doc, g, name)).count();
        let fields = ["engines", "devEngines"].iter().filter(|f| drop_runtime(doc, f, name)).count();
        if groups + fields == 0 {
            missing.push(name.clone());
        }
    }
    missing
}

/// `<field>.runtime` as a list: one object, or an array of them.
fn runtime_entries(doc: &Object, field: &str) -> Vec<Value> {
    match doc.get(field).and_then(|f| f.get("runtime")) {
        Some(Value::Array(list)) => list.clone(),
        Some(one @ Value::Object(_)) => vec![one.clone()],
        _ => Vec::new(),
    }
}

/// Write `<field>.runtime` back: one entry as an object, several as an array, none not at all.
fn put_runtime(doc: &mut Object, field: &str, entries: Vec<Value>) {
    if !doc.get(field).is_some_and(|f| f.as_object().is_some()) {
        if entries.is_empty() {
            return;
        }
        doc.insert(field, Value::Object(Object::new()));
    }
    let Some(Value::Object(f)) = doc.get_mut(field) else { return };
    match entries.len() {
        0 => {
            f.remove("runtime");
        }
        1 => f.insert("runtime", entries.into_iter().next().unwrap_or(Value::Null)),
        _ => f.insert("runtime", Value::Array(entries)),
    }
    if f.is_empty() {
        doc.remove(field);
    }
}

fn set_runtime(doc: &mut Object, field: &str, name: &str, version: &str) {
    let entry = json::obj([("name", name.into()), ("version", version.into()), ("onFail", "download".into())]);
    let mut entries = runtime_entries(doc, field);
    match entries.iter_mut().find(|e| e.get("name").and_then(Value::as_str) == Some(name)) {
        Some(e) => *e = entry,
        None => entries.push(entry),
    }
    put_runtime(doc, field, entries);
}

/// Take out a runtime `field` downloads; an entry that only checks the system's is left.
fn drop_runtime(doc: &mut Object, field: &str, name: &str) -> bool {
    let mut entries = runtime_entries(doc, field);
    let before = entries.len();
    entries.retain(|e| {
        e.get("name").and_then(Value::as_str) != Some(name)
            || e.get("onFail").and_then(Value::as_str) != Some("download")
    });
    if entries.len() == before {
        return false;
    }
    put_runtime(doc, field, entries);
    true
}

fn drop_dep(doc: &mut Object, group: &str, name: &str) -> bool {
    let Some(Value::Object(map)) = doc.get_mut(group) else { return false };
    if map.remove(name).is_none() {
        return false;
    }
    if map.is_empty() {
        doc.remove(group);
    }
    true
}

/// Serialized with the indent and line ending the file already uses.
pub fn format_manifest(doc: &Object, raw: &str) -> String {
    let indent = raw
        .lines()
        .find_map(|l| {
            let trimmed = l.trim_start_matches([' ', '\t']);
            (trimmed.starts_with('"') && trimmed.len() < l.len()).then(|| &l[..l.len() - trimmed.len()])
        })
        .unwrap_or("  ");
    let mut text = json::to_pretty(&Value::Object(doc.clone()), indent);
    text.pop(); // `to_pretty` ends in a newline; the file keeps the ending it had
    let eol = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    if eol != "\n" {
        text = text.replace('\n', eol);
    }
    if raw.ends_with('\n') {
        text.push_str(eol);
    }
    text
}

/// Whether the resolver links `spec` to a workspace at `version`.
pub fn links_to(spec: &Spec, version: &str) -> bool {
    match spec.kind {
        spec::Kind::Workspace => true,
        spec::Kind::Tag | spec::Kind::Tarball => false,
        _ => spec.name == spec.fetch_name && semver::satisfies(version, &spec.fetch_spec),
    }
}

pub fn manifest_error(message: String) -> Error {
    Error::new("EMANIFEST", message)
}

fn workspace_error(message: &str) -> Error {
    Error::new("EWORKSPACE", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_workspace_patterns_inside() {
        for bad in ["../sib", "a/../../x", "{../sib,x}", "p/{a,{b,../../c}}"] {
            let text = format!("{{\"workspaces\":[\"{bad}\"]}}");
            let m = RootManifest::parse(&text, Path::new("package.json")).unwrap();
            assert!(patterns(&m).unwrap_err().message.contains("reaches outside"), "{bad}");
        }
        let m = RootManifest::parse(r#"{"workspaces":["packages/{a,b}"]}"#, Path::new("package.json")).unwrap();
        assert_eq!(patterns(&m).unwrap().0, ["packages/{a,b}"]);
    }

    #[test]
    fn caps_workspace_patterns() {
        let refused = |list: Vec<String>| {
            let m = RootManifest { workspaces: Some(list), ..RootManifest::default() };
            patterns(&m).is_err_and(|e| e.message.contains("more than jpm reads"))
        };
        // One pattern too long, too many in all, or too many once braces are expanded: each
        // negation is matched against each pattern, in time that grows with both.
        assert!(refused(vec!["{a,b}".repeat(1000)]));
        let long = format!("!**/{}b", "a/".repeat(1500));
        assert!(!refused(vec![long.clone(); 2]) && refused(vec![long; 12]));
        assert!(refused(vec![format!("!n/{}", "{a,b}".repeat(9)), format!("p/{}", "{a,b}".repeat(10))]));
    }

    #[test]
    fn negates_patterns_quickly() {
        // A negation is matched against each pattern, and `**/` ten times took seconds.
        let deep = vec!["a"; 20].join("/");
        let text = format!(r#"{{"name":"r","workspaces":["!{}x","{deep}"]}}"#, "**/".repeat(10));
        let m = RootManifest::parse(&text, Path::new("package.json")).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(patterns(&m).unwrap().0, [deep]);
        assert!(!lists_root(&m));
        assert!(start.elapsed().as_millis() < 100, "{:?}", start.elapsed());
    }

    fn tree(files: &[(&str, &str)]) -> PathBuf {
        let dir = crate::store::tests::scratch("project");
        for (path, text) in files {
            let file = dir.join(path).join("package.json");
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, text).unwrap();
        }
        dir
    }

    #[test]
    fn keeps_the_first_of_two_workspaces_with_one_name() {
        let fixture = r#"{"name":"t","version":"0.0.0"}"#;
        let dir = tree(&[
            (".", r#"{"workspaces":["play/**"]}"#),
            ("play/a", fixture),
            ("play/a/dir/b", fixture),
            ("play/c", r#"{"name":"c","dependencies":{"t":"workspace:*"}}"#),
        ]);
        let found = |dir: &Path| find_workspaces(dir, &read_manifest(&dir.join("package.json")).unwrap());
        // Something links to the name: ambiguous.
        let e = found(&dir).unwrap_err();
        assert!(e.message.contains("play/a and play/a/dir/b are both named t, and a dependency"), "{}", e.message);
        // Nothing does: the first stays.
        std::fs::write(dir.join("play/c/package.json"), r#"{"name":"c","dependencies":{"t":"^2"}}"#).unwrap();
        let paths: Vec<String> = found(&dir).unwrap().into_iter().map(|w| w.path).collect();
        assert_eq!(paths, ["play/a", "play/c"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_the_root_listed_as_a_workspace() {
        let m = |w: &str| RootManifest::parse(&format!(r#"{{"name":"r","workspaces":{w}}}"#), Path::new("p")).unwrap();
        assert!(lists_root(&m(r#"[".", "a"]"#)) && lists_root(&m(r#"["./"]"#)));
        assert!(!lists_root(&m(r#"["a", "*"]"#)));
        assert!(local_path(".") && !local_path("./a") && !local_path("a/."));
        for windows in ["C:/x", "C:x", "a:b", "\\x", "a\\b", "/x"] {
            assert!(!local_path(windows), "{windows}");
        }
        // A workspace under the root's name is a second copy of it.
        let dir = tree(&[(".", r#"{"name":"r","workspaces":[".","a"]}"#), ("a", r#"{"name":"r"}"#)]);
        let ws = find_workspaces(&dir, &read_manifest(&dir.join("package.json")).unwrap()).unwrap();
        assert!(ws.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn edits_keep_the_file_shape() {
        let raw = "{\n    \"name\": \"x\",\n    \"devDependencies\": {\n        \"b\": \"1\"\n    }\n}\n";
        let mut m = RootManifest::parse(raw, Path::new("package.json")).unwrap();
        add_deps(&mut m.doc, &[Added { name: "b".into(), range: "^2".into(), group: "dependencies" }]);
        let text = format_manifest(&m.doc, raw);
        assert_eq!(text, "{\n    \"name\": \"x\",\n    \"dependencies\": {\n        \"b\": \"^2\"\n    }\n}\n");
        assert_eq!(remove_deps(&mut m.doc, &["b".into(), "c".into()]), ["c"]);
        assert!(!m.doc.contains_key("dependencies"));
    }

    #[test]
    fn saves_ranges() {
        let s = spec::parse_spec("a").unwrap();
        assert_eq!(save_range(&s, "1.2.3", false), "^1.2.3");
        assert_eq!(save_range(&s, "1.2.3", true), "1.2.3");
        let s = spec::parse_spec("a@~1").unwrap();
        assert_eq!(save_range(&s, "1.2.3", true), "~1");
        let s = spec::parse_spec("a@npm:b@latest").unwrap();
        assert_eq!(save_range(&s, "2.0.0", false), "npm:b@^2.0.0");
    }

    #[test]
    fn refuses_bad_groups() {
        let e = RootManifest::parse(r#"{"dependencies":{"a":1}}"#, Path::new("p")).unwrap_err();
        assert_eq!(e.code, "EMANIFEST");
    }

    #[test]
    fn orders_root_edges() {
        let m = RootManifest::parse(
            r#"{"dependencies":{"a":"1","b":"1"},"devDependencies":{"a":"2","c":"1"},"optionalDependencies":{"b":"3"}}"#,
            Path::new("p"),
        )
        .unwrap();
        let edges = m.edges();
        assert!(edges.contains(&("b".into(), "3".into(), true)));
        assert!(edges.contains(&("a".into(), "1".into(), false)));
        assert_eq!(edges.len(), 3);
    }
}
