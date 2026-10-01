//! What a project sets for its whole tree beyond its dependency ranges, from package.json and
//! pnpm-workspace.yaml: overrides, and which packages may build. Read once per command, before
//! anything resolves.
//!
//! Overrides replace an edge's range before it is resolved, in every package: npm's `overrides`,
//! yarn's `resolutions`, pnpm's `pnpm.overrides` and pnpm-workspace.yaml's `overrides` (bun reads
//! the first two). The root carries them, resolved, into jpm.lock, so a change makes it stale.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::extensions::{self, Extension};
use crate::json::Value;
use crate::patch::Patch;
use crate::project::RootManifest;
use crate::{semver, spec, ui};

pub const PNPM_WORKSPACE: &str = "pnpm-workspace.yaml";
const YARNRC: &str = ".yarnrc.yml";

/// pnpm-workspace.yaml settings that change what pnpm installs, which jpm does not read.
const UNREAD: [&str; 12] = [
    "hoistPattern",
    "nodeLinker",
    "hoistWorkspacePackages",
    "supportedArchitectures",
    "ignoredOptionalDependencies",
    "resolutionMode",
    "dedupePeerDependents",
    "linkWorkspacePackages",
    "injectWorkspacePackages",
    "configDependencies",
    "dangerouslyAllowAllBuilds",
    "pnpmfile",
];

/// Whose override it is, which decides how a `name@range` key matches an edge's range: npm's
/// where the two ranges meet, pnpm's where the edge's range lies inside the key's, yarn's where
/// they are the same. In this order a rule of one manager goes before an equal one of the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Pnpm,
    Npm,
    Yarn,
}

impl Manager {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pnpm => "pnpm",
            Self::Npm => "npm",
            Self::Yarn => "yarn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub by: Manager,
    /// Only the edges of this package, at a version in the range if one is given.
    pub parent: Option<(String, Option<String>)>,
    pub name: String,
    /// Only edges whose range this matches. `Some("")` is pnpm's convergence override: only edges
    /// whose range the value (an exact version) satisfies.
    pub range: Option<String>,
    /// The range the edge asks for instead; `None` takes the edge out (pnpm's `-`).
    pub value: Option<String>,
}

impl Override {
    /// pnpm's selector: `[parent[@range]>]name[@range]`.
    pub fn selector(&self) -> String {
        let at = |n: &str, r: &Option<String>| r.as_ref().map_or_else(|| n.to_string(), |r| format!("{n}@{r}"));
        match &self.parent {
            Some((p, r)) => format!("{}>{}", at(p, r), at(&self.name, &self.range)),
            None => at(&self.name, &self.range),
        }
    }

    pub fn value_text(&self) -> &str {
        self.value.as_deref().unwrap_or("-")
    }

    /// A rule as jpm.lock writes it: manager, selector, value.
    pub fn parse(by: &str, selector: &str, value: &str) -> Option<Self> {
        let by = match by {
            "pnpm" => Manager::Pnpm,
            "npm" => Manager::Npm,
            "yarn" => Manager::Yarn,
            _ => return None,
        };
        let (parent, name, range) = pnpm_selector(selector)?;
        Some(Self { by, parent, name, range, value: (value != "-").then(|| value.to_string()) })
    }

    /// More specific rules first: a parent's, then a range's, then a name's, convergence last.
    fn rank(&self) -> u8 {
        match (&self.parent, self.range.as_deref()) {
            (Some(_), _) => 0,
            (None, Some("")) => 3,
            (None, Some(_)) => 1,
            (None, None) => 2,
        }
    }

    fn matches(&self, parent: Option<(&str, &str)>, name: &str, range: &str) -> bool {
        if self.name != name {
            return false;
        }
        if let Some((p, r)) = &self.parent {
            let Some((n, v)) = parent else { return false };
            if n != p || r.as_ref().is_some_and(|r| !semver::satisfies(v, r)) {
                return false;
            }
        }
        match self.range.as_deref() {
            None => true,
            Some("") => self.value.as_deref().is_some_and(|v| semver::satisfies(v, range)),
            Some(r) => match self.by {
                Manager::Npm => semver::intersects(range, r),
                // As pnpm's read-package-hook (isIntersectingRange) has it, not a subset.
                Manager::Pnpm => range == r || semver::intersects(range, r),
                Manager::Yarn => range == r,
            },
        }
    }
}

/// What the overrides do to the edge `name@range` of `parent` (`(name, version)`, `None` for the
/// root): `None` leaves it, `Some(None)` takes it out, `Some(Some(r))` asks for `r` instead.
pub fn find<'a>(
    rules: &'a [Override],
    parent: Option<(&str, &str)>,
    name: &str,
    range: &str,
) -> Option<Option<&'a str>> {
    // An override of the npm package `bun` or `node` is not one of the runtime jpm installs.
    if range.starts_with("runtime:") {
        return None;
    }
    // A parent installed under an alias is the package it is, as npm and pnpm match a parent.
    let parent = parent.map(|(n, v)| crate::graph::split_alias(v).unwrap_or((n, v)));
    rules.iter().find(|o| o.matches(parent, name, range)).map(|o| o.value.as_deref())
}

/// Overrides written in npm's nested form, as rules: how bun.lock records whatever package.json
/// said, a pnpm `a>b` or a yarn `**/a/b` nested under `a`, a `$name` read.
pub fn npm_form(v: &Value) -> Vec<Override> {
    let mut rules = Rules::default();
    rules.npm(Some(v));
    rules.overrides
}

#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// The root's package.json, which a `catalog:` value is read for.
    file: PathBuf,
    /// As written, before `$name` and `catalog:` values are resolved.
    overrides: Vec<Override>,
    /// pnpm-workspace.yaml's word on which packages may run install scripts.
    pub builds: BTreeMap<String, bool>,
    /// `patchedDependencies`: each key, and the file it names.
    /// Key, path, and whether yarn named it (see `Patch::yarn`).
    patches: Vec<(String, String, bool)>,
    /// `packageExtensions`, in the order they apply (`extensions`).
    pub extensions: Vec<Extension>,
    /// What another manager's lockfile records of them (`project::Extended`).
    extended: crate::project::Extended,
    /// pnpm-workspace.yaml's `publicHoistPattern` (`shamefullyHoist: true` is `*`).
    pub public_hoist: Option<Vec<String>>,
}

fn read_yaml(file: &Path) -> Result<Option<Value>> {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&e, format!("cannot read {}", file.display()))),
    };
    let what = file.display();
    let doc = crate::foreign::read_yaml(text.trim_start_matches('\u{feff}'));
    doc.map(Some).map_err(|e| Error::new("EWORKSPACE", format!("{what} cannot be read: {}", e.message)))
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// The project's rules, from its root package.json and the files beside it.
pub fn read(dir: &Path, root: &RootManifest) -> Result<Rules> {
    let mut rules = Rules { file: dir.join("package.json"), ..Rules::default() };
    let doc = &root.doc;
    let pnpm = doc.get("pnpm");
    let mut workspace_extensions = None;
    if let Some(y) = read_yaml(&dir.join(PNPM_WORKSPACE))? {
        workspace_extensions = y.get("packageExtensions").filter(|v| !v.is_null()).cloned();
        rules.patched(y.get("patchedDependencies"), PNPM_WORKSPACE);
        for key in UNREAD {
            if truthy(y.get(key)) {
                ui::warn(&format!(
                    "{PNPM_WORKSPACE} sets {key}, which jpm does not read: the tree may differ from pnpm's"
                ));
            }
        }
        if y.get("autoInstallPeers") == Some(&Value::Bool(false)) {
            ui::warn(&format!("{PNPM_WORKSPACE} sets autoInstallPeers to false; jpm installs missing peers"));
        }
        rules.pnpm(y.get("overrides"), PNPM_WORKSPACE);
        rules.public_hoist = if y.get("shamefullyHoist") == Some(&Value::Bool(true)) {
            Some(vec!["*".to_string()])
        } else {
            y.get("publicHoistPattern")
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(Value::as_str).map(str::to_string).collect())
        };
        let built = y.get("onlyBuiltDependencies").and_then(Value::as_array).into_iter().flatten();
        for name in built.filter_map(Value::as_str) {
            rules.builds.insert(name.to_string(), true);
        }
        // pnpm 11: `name: true` or `false`, and `name@<versions or source>: true` for some.
        // jpm approves each version anyway (`jpm approve`), so a key's name is what counts.
        for (key, allowed) in y.get("allowBuilds").and_then(Value::as_object).into_iter().flatten() {
            let Some(allowed) = allowed.as_bool() else { continue };
            match crate::graph::name_end(key) {
                None => {
                    rules.builds.insert(key.clone(), allowed);
                }
                Some(at) if allowed => {
                    rules.builds.entry(key[..at].to_string()).or_insert(true);
                }
                Some(_) => {}
            }
        }
    }
    rules.patched(pnpm.and_then(|p| p.get("patchedDependencies")), "package.json pnpm.patchedDependencies");
    rules.patched(doc.get("patchedDependencies"), "package.json patchedDependencies");
    // yarn's `patch:` ranges; the root's only.
    for group in ["dependencies", "devDependencies", "optionalDependencies"] {
        for (name, range) in doc.get(group).and_then(Value::as_object).into_iter().flatten() {
            if let Some((_, Some((key, path)))) = range.as_str().and_then(|r| crate::patch::yarn(name, r)) {
                rules.add_patch(key, path, true);
            }
        }
    }
    rules.pnpm(pnpm.and_then(|p| p.get("overrides")), "package.json pnpm.overrides");
    rules.npm(doc.get("overrides"));
    rules.yarn(doc.get("resolutions"));
    // Read for its extensions alone: a .yarnrc.yml with none is left unparsed.
    let yarnrc_file = dir.join(YARNRC);
    let has = std::fs::read_to_string(&yarnrc_file).is_ok_and(|t| t.contains("packageExtensions"));
    let yarnrc = if has { read_yaml(&yarnrc_file)? } else { None };
    let manifest_extensions = pnpm.and_then(|p| p.get("packageExtensions")).filter(|v| !v.is_null());
    let yarn_extensions = yarnrc.as_ref().and_then(|y| y.get("packageExtensions")).filter(|v| !v.is_null());
    rules.extensions = read_extensions(workspace_extensions.as_ref(), manifest_extensions, yarn_extensions);
    rules.extended = crate::project::Extended {
        pnpm: workspace_extensions.as_ref().or(manifest_extensions).and_then(extensions::pnpm_checksum),
        yarn: yarn_extensions.and_then(Value::as_object).is_some_and(|o| !o.is_empty()),
    };
    Ok(rules)
}

/// The project's `packageExtensions`, in the order they apply, the first to name a dependency
/// giving its range: pnpm-workspace.yaml's, else package.json's `pnpm.packageExtensions` (pnpm
/// takes pnpm-workspace.yaml's setting in place of package.json's, not as well), then
/// `.yarnrc.yml`'s.
fn read_extensions(workspace: Option<&Value>, manifest: Option<&Value>, yarnrc: Option<&Value>) -> Vec<Extension> {
    let mut out = match (workspace, manifest) {
        (Some(w), m) => {
            if m.is_some() {
                ui::warn(&format!(
                    "package.json sets pnpm.packageExtensions and {PNPM_WORKSPACE} sets packageExtensions: {PNPM_WORKSPACE}'s are read, as pnpm reads them"
                ));
            }
            extensions::read(Some(w), extensions::Source::Pnpm, PNPM_WORKSPACE)
        }
        (None, m) => extensions::read(m, extensions::Source::Pnpm, "package.json pnpm.packageExtensions"),
    };
    out.extend(extensions::read(yarnrc, extensions::Source::Yarn, YARNRC));
    extensions::merged(out)
}

/// `rel` from the directory `dir`, both relative to the root, its `.` and `..` taken out; one
/// that climbs past the root keeps its `..`, for the patch reader to refuse.
fn under(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// `name` or `name@range`.
fn name_range(s: &str) -> (String, Option<String>) {
    match crate::graph::name_end(s) {
        Some(at) => (s[..at].to_string(), Some(s[at + 1..].trim().to_string())),
        None => (s.trim().to_string(), None),
    }
}

type Selector = (Option<(String, Option<String>)>, String, Option<String>);

/// `[parent[@range]>]name[@range]`. The `>` that splits is the one no range reads as its own:
/// not after `@`, a space, `|`, `<`, `>` or `=`, and not before `=`.
fn pnpm_selector(s: &str) -> Option<Selector> {
    let b = s.as_bytes();
    let split = (1..b.len())
        .find(|&i| b[i] == b'>' && !b"@ |<>=".contains(&b[i - 1]) && b.get(i + 1) != Some(&b'='))
        .map(|i| (&s[..i], &s[i + 1..]));
    let (parent, target) = match split {
        Some((p, t)) => (Some(name_range(p)), t),
        None => (None, s),
    };
    let (name, range) = name_range(target);
    let named = |n: &str| spec::check_name(n, s).is_ok();
    (named(&name) && parent.as_ref().is_none_or(|(p, _)| named(p))).then_some((parent, name, range))
}

impl Rules {
    /// pnpm's `name`, `name@version` and `name@range` keys, bun's `name@version`, each naming a
    /// diff. A key given twice keeps its first file: pnpm-workspace.yaml's, then package.json's.
    fn patched(&mut self, v: Option<&Value>, file: &str) {
        for (key, path) in v.and_then(Value::as_object).into_iter().flatten() {
            let (name, _) = name_range(key);
            match path.as_str() {
                Some(path) if spec::check_name(&name, key).is_ok() => {
                    self.add_patch(key.clone(), path.to_string(), false)
                }
                _ => ui::warn(&format!("{file}: patch {key} is not one jpm reads; it is ignored")),
            }
        }
    }

    /// yarn's `patch:` ranges in the package.json of the workspace at `dir` (relative to the
    /// root), read as the root's are: each patch taken, each range made the one it stands for
    /// (backstage's yarn plugin workspace has one). A patch's path is the workspace's own
    /// (twenty's `../../.yarn/patches/…`), or the root's under `~/`.
    pub fn workspace_patches(&mut self, dir: &str, m: &mut RootManifest) {
        for group in [&mut m.dependencies, &mut m.dev_dependencies, &mut m.optional_dependencies] {
            for (name, range) in group.iter_mut() {
                if let Some((source, patch)) = crate::patch::yarn(name, range) {
                    if let Some((key, path)) = patch {
                        let rooted = range.split_once('#').is_some_and(|(_, p)| p.starts_with("~/"));
                        self.add_patch(key, if rooted { path } else { under(dir, &path) }, true);
                    }
                    *range = source;
                }
            }
        }
    }

    fn add_patch(&mut self, key: String, path: String, yarn: bool) {
        if !self.patches.iter().any(|(k, ..)| *k == key) {
            self.patches.push((key, path, yarn));
        }
    }

    fn push(&mut self, by: Manager, (parent, name, range): Selector, value: &str) {
        let value = (!(by == Manager::Pnpm && value == "-")).then(|| value.to_string());
        self.overrides.push(Override { by, parent, name, range, value });
    }

    /// `name`, `name@range`, `parent@range>name@range`, and `-` to take the edge out.
    fn pnpm(&mut self, v: Option<&Value>, file: &str) {
        for (key, value) in entries(v) {
            match (pnpm_selector(key), value.as_str()) {
                (Some(sel), Some(value)) => self.push(Manager::Pnpm, sel, value),
                _ => ui::warn(&format!("{file}: override {key} is not one jpm reads; it is ignored")),
            }
        }
    }

    /// npm: `name` or `name@range`, nested `{ parent: { name: range } }` with `.` for the parent
    /// itself. npm applies a nested one anywhere under the parent; jpm keeps one copy of each
    /// version, so to the parent's own dependencies, and a deeper one to its nearest parent's.
    fn npm(&mut self, v: Option<&Value>) {
        for (key, value) in entries(v) {
            self.npm_rule(&[], key, value);
        }
    }

    fn npm_rule(&mut self, path: &[&str], key: &str, value: &Value) {
        let at = path.iter().chain([&key]).copied().collect::<Vec<_>>().join(" > ");
        let (name, range) = name_range(key);
        if spec::check_name(&name, key).is_err() || path.len() > 8 {
            return ui::warn(&format!("package.json overrides {at} is not one jpm reads; it is ignored"));
        }
        let parent = path.last().map(|p| name_range(p));
        match value {
            Value::String(s) => {
                if path.len() > 1 {
                    let p = path[path.len() - 1];
                    ui::warn(&format!("package.json overrides {at}: jpm applies it to every {p}'s {name}"));
                }
                self.push(Manager::Npm, (parent, name, range), s);
            }
            Value::Object(children) => {
                if let Some(own) = children.get(".") {
                    self.npm_rule(path, key, own);
                }
                let inner: Vec<&str> = path.iter().copied().chain([key]).collect();
                for (child, value) in children.iter().filter(|(k, _)| k.as_str() != ".") {
                    self.npm_rule(&inner, child, value);
                }
            }
            _ => ui::warn(&format!("package.json overrides {at} is not a range; it is ignored")),
        }
    }

    /// yarn: `name`, `**/name`, `parent/name`, each name maybe `@range` (berry's `npm:` taken off).
    /// A longer path is read as its last parent's, which jpm cannot tell apart.
    fn yarn(&mut self, v: Option<&Value>) {
        for (key, value) in entries(v) {
            let skip = || ui::warn(&format!("package.json resolutions {key} is not one jpm reads; it is ignored"));
            let Some(value) = value.as_str() else {
                skip();
                continue;
            };
            let mut path = key.as_str();
            while let Some(rest) = path.strip_prefix("**/") {
                path = rest;
            }
            let parts = segments(path);
            // Berry writes `npm:^1.2.3` for a range of the same package.
            let npm = |r: &str| r.strip_prefix("npm:").filter(|r| semver::valid_range(r)).unwrap_or(r).to_string();
            let (parent, target) = match parts.as_slice() {
                [target] => (None, *target),
                [.., parent, target] if !parts.contains(&"**") => (Some(name_range(parent)), *target),
                _ => {
                    skip();
                    continue;
                }
            };
            let (name, range) = name_range(target);
            let named = |n: &str| spec::check_name(n, key).is_ok();
            if !named(&name) || parent.as_ref().is_some_and(|(p, _)| !named(p)) {
                skip();
                continue;
            }
            if parts.len() > 2 {
                let p = parent.as_ref().map_or("", |(p, _)| p.as_str());
                ui::warn(&format!("package.json resolutions {key}: jpm applies it to every {p}'s {name}"));
            }
            let parent = parent.map(|(p, r)| (p, r.as_deref().map(npm)));
            let value = match crate::patch::yarn(&name, value) {
                Some((range, patch)) => {
                    if let Some((key, path)) = patch {
                        self.add_patch(key, path, true);
                    }
                    range
                }
                None => npm(value),
            };
            self.push(Manager::Yarn, (parent, name, range.as_deref().map(npm)), &value);
        }
    }

    /// The overrides the root resolves under: `$name` read from its own ranges, `catalog:` from
    /// its catalogs, the most specific first.
    pub fn apply(&self, root: &mut RootManifest) -> Result<()> {
        root.overrides = self.resolved(root)?;
        for group in [&mut root.dependencies, &mut root.dev_dependencies, &mut root.optional_dependencies] {
            for (name, range) in group.iter_mut() {
                if let Some((source, _)) = crate::patch::yarn(name, range) {
                    *range = source;
                }
            }
        }
        let dir = self.file.parent().unwrap_or(Path::new(""));
        root.patches.clear();
        for (key, path, yarn) in &self.patches {
            let (name, range) = name_range(key);
            let patch = Patch::read(dir, name, range.filter(|r| !r.is_empty()), path)?;
            root.patches.push(Patch { yarn: *yarn, ..patch });
        }
        root.extensions = self.extensions.clone();
        root.extended = self.extended.clone();
        extensions::extend_top(&self.extensions, root);
        Ok(())
    }

    fn resolved(&self, root: &RootManifest) -> Result<Vec<Override>> {
        let mut out = Vec::with_capacity(self.overrides.len());
        for o in &self.overrides {
            let mut o = o.clone();
            let selector = o.selector();
            let fail = |why: String| Error::new("EOVERRIDE", format!("override {selector}: {why}"));
            if let Some(dep) = o.value.as_deref().and_then(|v| v.strip_prefix('$')) {
                let groups = [&root.dependencies, &root.dev_dependencies, &root.optional_dependencies];
                let range = groups.into_iter().chain(root.peer_dependencies.as_ref()).find_map(|g| g.get(dep));
                let Some(range) = range else { return Err(fail(format!("package.json does not depend on {dep}"))) };
                o.value = Some(range.clone());
            } else if let Some(v) = o.value.as_deref().filter(|v| v.starts_with("catalog:")) {
                o.value = Some(crate::project::catalog_range(&self.file, &o.name, v)?);
            }
            if o.range.as_deref() == Some("") && !o.value.as_deref().is_some_and(semver::is_exact) {
                return Err(fail("a convergence override takes an exact version".into()));
            }
            out.push(o);
        }
        out.sort_by_key(Override::rank);
        Ok(out)
    }
}

/// A field's rules, less its `//` keys: comments, as package.json has them (bun skips them too).
fn entries(v: Option<&Value>) -> impl Iterator<Item = (&String, &Value)> {
    v.and_then(Value::as_object).into_iter().flatten().filter(|(k, _)| !k.starts_with("//"))
}

/// A yarn path's package names: a scoped name holds a `/` of its own.
fn segments(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        let skip = if rest.starts_with('@') { rest.find('/').map_or(rest.len(), |i| i + 1) } else { 0 };
        let end = rest[skip..].find('/').map_or(rest.len(), |i| skip + i);
        out.push(&rest[..end]);
        rest = rest.get(end + 1..).unwrap_or("");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(text: &str) -> RootManifest {
        RootManifest::parse(text, Path::new("package.json")).unwrap()
    }

    fn rules_of(text: &str) -> (Rules, RootManifest) {
        let m = manifest(text);
        let mut r = Rules::default();
        r.pnpm(m.doc.get("pnpm").and_then(|p| p.get("overrides")), "package.json");
        r.npm(m.doc.get("overrides"));
        r.yarn(m.doc.get("resolutions"));
        (r, m)
    }

    fn resolved(text: &str) -> Vec<Override> {
        let (r, mut m) = rules_of(text);
        r.apply(&mut m).unwrap();
        m.overrides
    }

    #[test]
    fn reads_selectors() {
        let sel = |s: &str| pnpm_selector(s);
        assert_eq!(sel("foo"), Some((None, "foo".into(), None)));
        assert_eq!(sel("@s/foo@^2.1.0"), Some((None, "@s/foo".into(), Some("^2.1.0".into()))));
        assert_eq!(sel("qar@1>zoo"), Some((Some(("qar".into(), Some("1".into()))), "zoo".into(), None)));
        assert_eq!(sel("a@>=1>b@>2"), Some((Some(("a".into(), Some(">=1".into()))), "b".into(), Some(">2".into()))));
        assert_eq!(sel("a@>1 <3>@s/b"), Some((Some(("a".into(), Some(">1 <3".into()))), "@s/b".into(), None)));
        assert_eq!(sel("form-data@"), Some((None, "form-data".into(), Some(String::new()))));
        assert_eq!(sel("../x"), None);
        for s in ["foo", "@s/a@^1", "p@1>c", "p>c@^2", "x@"] {
            let o = Override::parse("pnpm", s, "1.0.0").unwrap();
            assert_eq!(o.selector(), s);
        }
        assert_eq!(segments("@s/a/@s/b"), ["@s/a", "@s/b"]);
        assert_eq!(segments("a/**/b"), ["a", "**", "b"]);
    }

    #[test]
    fn reads_every_managers_form() {
        let o = resolved(
            r#"{
            "dependencies": { "react": "^18.2.0" },
            "overrides": { "a": "1.0.0", "b@^1": "1.1.0", "p": { ".": "2.0.0", "c": "$react", "d": { ".": "3.0.0", "e": "1" } } },
            "resolutions": { "**/f": "1.0.0", "g/h": "npm:^2.0.0", "i@npm:^1": "1.2.0", "j/**/k": "1", "**/l/m/n": "2", "o": "npm:other" },
            "pnpm": { "overrides": { "q@1>r": "-", "s@": "4.0.6" } }
        }"#,
        );
        let lines: Vec<String> =
            o.iter().map(|o| format!("{} {} {}", o.by.as_str(), o.selector(), o.value_text())).collect();
        assert_eq!(
            lines,
            [
                "pnpm q@1>r -",
                "npm p>c ^18.2.0",
                "npm p>d 3.0.0",
                "npm d>e 1",
                "yarn g>h ^2.0.0",
                "yarn m>n 2",
                "npm b@^1 1.1.0",
                "yarn i@^1 1.2.0",
                "npm a 1.0.0",
                "npm p 2.0.0",
                "yarn f 1.0.0",
                "yarn o npm:other",
                "pnpm s@ 4.0.6",
            ]
        );
    }

    #[test]
    fn matches_edges() {
        let o = resolved(
            r#"{ "overrides": { "b@^1": "1.1.0", "p": { "c": "2.0.0" } },
                 "pnpm": { "overrides": { "q@1>r": "-", "s@": "4.0.6", "t@^2.1.0": "3.0.0" } },
                 "resolutions": { "u@npm:^1.0.0": "1.5.0" } }"#,
        );
        let at = |parent: Option<(&str, &str)>, name: &str, range: &str| find(&o, parent, name, range);
        // npm: the ranges meet.
        assert_eq!(at(None, "b", "^1.2.0"), Some(Some("1.1.0")));
        assert_eq!(at(None, "b", ">=0.5 <1.0.1"), Some(Some("1.1.0")));
        assert_eq!(at(None, "b", "^2"), None);
        // pnpm: the ranges meet, as its read-package-hook has it (isIntersectingRange).
        assert_eq!(at(None, "t", "^2.2.0"), Some(Some("3.0.0")));
        assert_eq!(at(None, "t", "^2.0.0"), Some(Some("3.0.0")));
        assert_eq!(at(None, "t", ">=2.2.0 <3.0.0"), Some(Some("3.0.0")));
        assert_eq!(at(None, "t", "<2.1.0"), None);
        // yarn: the same range.
        assert_eq!(at(None, "u", "^1.0.0"), Some(Some("1.5.0")));
        assert_eq!(at(None, "u", "^1.1.0"), None);
        // A parent's own edges only.
        assert_eq!(at(Some(("p", "1.0.0")), "c", "^1"), Some(Some("2.0.0")));
        assert_eq!(at(Some(("x", "1.0.0")), "c", "^1"), None);
        assert_eq!(at(None, "c", "^1"), None);
        assert_eq!(at(Some(("q", "1.2.0")), "r", "*"), Some(None));
        assert_eq!(at(Some(("q", "2.0.0")), "r", "*"), None);
        // A parent under an alias is its package (bun's nested-overrides "through an alias").
        assert_eq!(at(Some(("q1", "npm:q@1.2.0")), "r", "*"), Some(None));
        assert_eq!(at(Some(("q2", "npm:q@2.0.0")), "r", "*"), None);
        assert_eq!(at(Some(("q", "npm:x@1.0.0")), "r", "*"), None);
        // Convergence: only where the version fits the edge's range.
        assert_eq!(at(None, "s", "^4.0.5"), Some(Some("4.0.6")));
        assert_eq!(at(None, "s", "^3"), None);
    }

    #[test]
    fn refuses_what_it_cannot_resolve() {
        let err = |text: &str| {
            let (r, mut m) = rules_of(text);
            r.apply(&mut m).unwrap_err().message
        };
        assert!(err(r#"{ "overrides": { "a": "$nope" } }"#).contains("package.json does not depend on nope"));
        assert!(err(r#"{ "pnpm": { "overrides": { "a@": "^1" } } }"#).contains("exact version"));
    }

    #[test]
    fn reads_the_workspace_file() {
        let dir = crate::store::tests::scratch("rules");
        std::fs::write(
            dir.join(PNPM_WORKSPACE),
            "catalog:\n  c: ^2\noverrides:\n  b: 2.0.0 # pinned\n  c: 'catalog:'\nonlyBuiltDependencies:\n  - esbuild\nallowBuilds:\n  sharp: true\n  core-js: false\n  nx@21.6.4: true\n  esbuild: false\n",
        )
        .unwrap();
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        let mut m = manifest(r#"{ "overrides": { "b": "1.0.0" } }"#);
        let r = read(&dir, &m).unwrap();
        r.apply(&mut m).unwrap();
        let lines: Vec<String> =
            m.overrides.iter().map(|o| format!("{} {} {}", o.by.as_str(), o.selector(), o.value_text())).collect();
        // pnpm-workspace.yaml's before package.json's; `catalog:` read from the catalog.
        assert_eq!(lines, ["pnpm b 2.0.0", "pnpm c ^2", "npm b 1.0.0"]);
        let builds: Vec<(&str, bool)> = r.builds.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(builds, [("core-js", false), ("esbuild", false), ("nx", true), ("sharp", true)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_patches_from_every_place() {
        let dir = crate::store::tests::scratch("rules-patches");
        std::fs::write(
            dir.join(PNPM_WORKSPACE),
            "patchedDependencies:\n  a@1.0.0: patches/a.patch\n  '@s/b': p/b.patch\n",
        )
        .unwrap();
        for f in ["patches/a.patch", "p/b.patch", "c.patch", "d.patch"] {
            std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
            std::fs::write(dir.join(f), f).unwrap();
        }
        let mut m = manifest(
            r#"{ "pnpm": { "patchedDependencies": { "a@1.0.0": "other.patch", "c@^2": "c.patch" } },
                 "patchedDependencies": { "d@3.0.0": "d.patch", "../x": "d.patch" } }"#,
        );
        let r = read(&dir, &m).unwrap();
        r.apply(&mut m).unwrap();
        let got: Vec<(String, &str)> = m.patches.iter().map(|p| (p.selector(), p.path.as_str())).collect();
        // pnpm-workspace.yaml's first; a key already given keeps its file; a bad name is left out.
        assert_eq!(
            got,
            [
                ("a@1.0.0".into(), "patches/a.patch"),
                ("@s/b".into(), "p/b.patch"),
                ("c@^2".into(), "c.patch"),
                ("d@3.0.0".into(), "d.patch")
            ]
        );
        assert_eq!(m.patches[0].hash, crate::util::sha256_hex("patches/a.patch"));
        std::fs::remove_file(dir.join("c.patch")).unwrap();
        assert_eq!(r.apply(&mut m).unwrap_err().code, "EPATCH");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_patches_only_from_inside_the_project() {
        let dir = crate::store::tests::scratch("rules-patch-paths");
        let project = dir.join("p");
        std::fs::create_dir_all(project.join("sub")).unwrap();
        std::fs::write(project.join("package.json"), "{}").unwrap();
        std::fs::write(dir.join("outside.patch"), "x").unwrap();
        std::fs::write(project.join("big.patch"), vec![b'x'; (16 << 20) + 1]).unwrap();
        let outside = dir.join("outside.patch").to_string_lossy().into_owned();
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut cases = vec![
            ("../outside.patch", "is not a path inside the project"),
            (outside.as_str(), "is not a path inside the project"),
            ("sub", "not a file"),
            ("big.patch", "larger than 16 MiB"),
        ];
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("outside.patch"), project.join("link.patch")).unwrap();
            cases.extend([("link.patch", "is a link"), ("/dev/zero", "is not a path inside the project")]);
        }
        for (path, why) in cases {
            let text =
                format!(r#"{{ "pnpm": {{ "patchedDependencies": {{ "a": "{}" }} }} }}"#, path.replace('\\', "\\\\"));
            let mut m = manifest(&text);
            let e = read(&project, &m).unwrap().apply(&mut m).unwrap_err();
            assert_eq!(e.code, "EPATCH");
            let head = format!("cannot read the patch {path}: ");
            assert!(e.message.starts_with(&head) && e.message.contains(why), "{path}: {}", e.message);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
