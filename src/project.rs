//! package.json: reading it, finding the project and its workspaces, and editing its
//! dependency groups the way the file is already written.

use std::path::{Path, PathBuf};

use serde_json::{Map as JsonMap, Value};

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
    pub doc: JsonMap<String, Value>,
}

impl RootManifest {
    pub fn parse(text: &str, file: &Path) -> Result<Self> {
        let value: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|e| manifest_error(format!("{} is not valid JSON: {e}", file.display())))?;
        let Value::Object(doc) = value else {
            return Err(manifest_error(format!("{} is not a JSON object", file.display())));
        };
        Self::from_doc(doc, file)
    }

    pub fn from_doc(doc: JsonMap<String, Value>, file: &Path) -> Result<Self> {
        let group = |name: &str| -> Result<Option<Deps>> {
            match doc.get(name) {
                None => Ok(None),
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| match v {
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
        .transpose()?;
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
        Ok(Self {
            name: string("name"),
            version: string("version"),
            dependencies: group("dependencies")?.unwrap_or_default(),
            dev_dependencies: group("devDependencies")?.unwrap_or_default(),
            optional_dependencies: group("optionalDependencies")?.unwrap_or_default(),
            peer_dependencies: group("peerDependencies")?,
            peer_optional,
            workspaces,
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

    pub fn scripts(&self, file: &Path) -> Result<JsonMap<String, Value>> {
        match self.doc.get("scripts") {
            None => Ok(JsonMap::new()),
            Some(Value::Object(m)) if m.values().all(Value::is_string) => Ok(m.clone()),
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
pub fn local_path(path: &str) -> bool {
    !path.is_empty() && !path.contains('\\') && !path.split('/').any(|p| p.is_empty() || p == "." || p == "..")
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

/// The declared patterns, the negations applied the way npm's map-workspaces does.
fn patterns(m: &RootManifest) -> Result<(Vec<String>, Vec<String>)> {
    let mut patterns = Vec::new();
    let mut negated: Vec<String> = Vec::new();
    for raw in m.workspaces.iter().flatten() {
        let bangs = raw.len() - raw.trim_start_matches('!').len();
        let body = raw[bangs..].trim_start_matches("./").trim_start_matches('/');
        if body.split('/').any(|p| p == "..") {
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
pub fn find_workspaces(dir: &Path, m: &RootManifest) -> Result<Vec<Workspace>> {
    let (patterns, mut exclude) = patterns(m)?;
    exclude.push("**/node_modules/**".into());
    let mut found: Vec<Workspace> = Vec::new();
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
            let version = manifest.version.clone().filter(|v| !v.is_empty()).unwrap_or_else(|| "0.0.0".into());
            if let Some(other) = found.iter().find(|w| w.name == name) {
                return Err(workspace_error(&format!("workspaces {} and {path} are both named {name}", other.path)));
            }
            found.push(Workspace { path, dir: at, name, version, manifest });
        }
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

/// Put each dep in its group, out of any other. Groups stay sorted.
pub fn add_deps(doc: &mut JsonMap<String, Value>, added: &[Added]) {
    for dep in added {
        for group in GROUPS {
            if group != dep.group {
                drop_dep(doc, group, &dep.name);
            }
        }
        let entry = doc.entry(dep.group).or_insert_with(|| Value::Object(JsonMap::new()));
        if !entry.is_object() {
            *entry = Value::Object(JsonMap::new());
        }
        if let Value::Object(map) = entry {
            map.insert(dep.name.clone(), Value::String(dep.range.clone()));
            map.sort_keys();
        }
    }
}

/// Take each name out of every group; the names in no group come back.
pub fn remove_deps(doc: &mut JsonMap<String, Value>, names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|name| !GROUPS.iter().fold(false, |found, g| drop_dep(doc, g, name) || found))
        .cloned()
        .collect()
}

fn drop_dep(doc: &mut JsonMap<String, Value>, group: &str, name: &str) -> bool {
    let Some(Value::Object(map)) = doc.get_mut(group) else { return false };
    if map.shift_remove(name).is_none() {
        return false;
    }
    if map.is_empty() {
        doc.shift_remove(group);
    }
    true
}

/// Serialized with the indent and line ending the file already uses.
pub fn format_manifest(doc: &JsonMap<String, Value>, raw: &str) -> String {
    let indent = raw
        .lines()
        .find_map(|l| {
            let trimmed = l.trim_start_matches([' ', '\t']);
            (trimmed.starts_with('"') && trimmed.len() < l.len()).then(|| &l[..l.len() - trimmed.len()])
        })
        .unwrap_or("  ");
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut out, formatter);
    let _ = serde::Serialize::serialize(doc, &mut ser);
    let mut text = String::from_utf8(out).unwrap_or_default();
    if raw.contains("\r\n") {
        text = text.replace('\n', "\r\n");
    }
    if raw.ends_with('\n') {
        text.push_str(if raw.contains("\r\n") { "\r\n" } else { "\n" });
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
