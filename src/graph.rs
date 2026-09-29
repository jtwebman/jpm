//! The resolved graph: a flat set of packages keyed `name@version`, what the resolver makes, the
//! lockfile stores and the linker materializes. Plus what an install does to it on one machine:
//! drop other platforms' builds and recompute what is dev-only.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::bin::Bins;
use crate::error::{Error, Result};
use crate::semver;
use crate::sys::Platform;

pub type Deps = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerKind {
    Required,
    Optional,
}

impl PeerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "required" => Some(Self::Required),
            "optional" => Some(Self::Optional),
            _ => None,
        }
    }
}

pub type Peers = BTreeMap<String, PeerKind>;

/// The ranges a top (the root or a workspace) declared, verbatim. Empty groups are left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Specs {
    pub dependencies: Option<Deps>,
    pub dev_dependencies: Option<Deps>,
    pub optional_dependencies: Option<Deps>,
}

impl Specs {
    /// From a manifest's three groups, empty ones dropped; `None` when all are empty.
    pub fn declared(deps: &Deps, dev: &Deps, optional: &Deps) -> Option<Self> {
        let keep = |m: &Deps| (!m.is_empty()).then(|| m.clone());
        let s = Self { dependencies: keep(deps), dev_dependencies: keep(dev), optional_dependencies: keep(optional) };
        (!s.is_empty()).then_some(s)
    }

    /// The groups that have anything in them, in their fixed order.
    pub fn to_value(&self) -> crate::json::Value {
        let mut o = crate::json::Object::new();
        for (name, group) in self.groups() {
            if let Some(g) = group.filter(|g| !g.is_empty()) {
                o.insert(name, crate::json::str_map(g));
            }
        }
        o.into()
    }

    pub fn is_empty(&self) -> bool {
        self.groups().all(|(_, g)| g.is_none_or(BTreeMap::is_empty))
    }

    pub fn groups(&self) -> impl Iterator<Item = (&'static str, Option<&Deps>)> {
        [
            ("dependencies", self.dependencies.as_ref()),
            ("devDependencies", self.dev_dependencies.as_ref()),
            ("optionalDependencies", self.optional_dependencies.as_ref()),
        ]
        .into_iter()
    }

    pub fn has(&self, name: &str) -> bool {
        self.groups().any(|(_, g)| g.is_some_and(|g| g.contains_key(name)))
    }

    pub fn dev(&self) -> &Deps {
        static EMPTY: Deps = Deps::new();
        self.dev_dependencies.as_ref().unwrap_or(&EMPTY)
    }

    pub fn optional(&self) -> &Deps {
        static EMPTY: Deps = Deps::new();
        self.optional_dependencies.as_ref().unwrap_or(&EMPTY)
    }

    /// Canonical: empty groups dropped.
    pub fn canonical(spec: Option<&Self>) -> Option<Self> {
        let s = spec?;
        let keep = |m: Option<&Deps>| m.filter(|m| !m.is_empty()).cloned();
        let out = Self {
            dependencies: keep(s.dependencies.as_ref()),
            dev_dependencies: keep(s.dev_dependencies.as_ref()),
            optional_dependencies: keep(s.optional_dependencies.as_ref()),
        };
        (!out.is_empty()).then_some(out)
    }
}

pub fn same_specs(a: Option<&Specs>, b: Option<&Specs>) -> bool {
    Specs::canonical(a) == Specs::canonical(b)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// Where the tarball is; empty for a workspace.
    pub resolved: String,
    pub integrity: String,
    /// A workspace at this root-relative `/` path: linked from its directory, never stored.
    pub local: Option<String>,
    /// A workspace's declared ranges.
    pub specs: Option<Specs>,
    /// A tarball dependency: its url, or `file:` and a root-relative path. Its key ends in it.
    pub source: Option<String>,
    /// Required edges: name -> version, `link:<path>` for a workspace, or a tarball's source.
    pub dependencies: Deps,
    /// Edges a platform filter may drop. Disjoint from `dependencies`.
    pub optional_dependencies: Deps,
    /// Reachable only through optional edges.
    pub optional: bool,
    /// Reachable only through the tops' devDependencies.
    pub dev: bool,
    pub bin: Bins,
    pub os: Option<Vec<String>>,
    pub cpu: Option<Vec<String>>,
    pub libc: Option<Vec<String>>,
    /// As declared: the only record of the ranges a consumer asked its peers for.
    pub peer_dependencies: Option<Deps>,
    /// Which declared peers the walk settled against the tree, and how.
    pub peers: Option<Peers>,
    /// Has install scripts (`preinstall`, `install`, `postinstall`, or a `binding.gyp`).
    pub scripts: bool,
    /// Its install scripts are approved at this version (`jpm approve`).
    pub build: bool,
}

impl Package {
    /// What an edge to this package carries as its version.
    pub fn edge_version(&self) -> String {
        match (&self.local, &self.source) {
            (Some(path), _) => format!("link:{path}"),
            (None, Some(source)) => source.clone(),
            _ => self.version.clone(),
        }
    }

    /// The one identity: `name@version`, `name@link:<path>` or `name@<source>`.
    pub fn key(&self) -> String {
        format!("{}@{}", self.name, self.edge_version())
    }

    /// Both edge maps as one: to the linker and the store key an installed dep is a dep.
    pub fn all_deps(&self) -> Deps {
        let mut all = self.dependencies.clone();
        all.extend(self.optional_dependencies.iter().map(|(k, v)| (k.clone(), v.clone())));
        all
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Root {
    pub name: Option<String>,
    pub version: Option<String>,
    pub specs: Option<Specs>,
    pub dependencies: Deps,
    pub workspaces: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Resolution {
    pub root: Root,
    pub packages: BTreeMap<String, Package>,
    pub warnings: Vec<String>,
}

/// Split a key at the first `@` past a scope's: a url or a path may hold one.
pub fn split_key(key: &str) -> Option<(&str, &str)> {
    let at = key.get(1..)?.find('@')? + 1;
    Some((&key[..at], &key[at + 1..]))
}

/// npm's rule: `!x` blocks, a plain list allows, `any` and an empty list match all.
fn matches(list: Option<&Vec<String>>, value: &str) -> bool {
    let Some(list) = list else { return true };
    if list.is_empty() || (list.len() == 1 && list[0] == "any") {
        return true;
    }
    let mut negated = 0;
    let mut found = false;
    for entry in list {
        if let Some(not) = entry.strip_prefix('!') {
            negated += 1;
            if not == value {
                return false;
            }
        } else if entry == value {
            found = true;
        }
    }
    found || negated == list.len()
}

/// Whether what a package declares lets it run on `platform`. A package that declares a libc
/// cannot be trusted on a target whose libc is unknown.
pub fn runs_on(os: Option<&Vec<String>>, cpu: Option<&Vec<String>>, libc: Option<&Vec<String>>, p: &Platform) -> bool {
    matches(os, &p.os)
        && matches(cpu, &p.cpu)
        && match libc {
            Some(l) if !l.is_empty() => p.libc.as_deref().is_some_and(|c| matches(Some(l), c)),
            _ => true,
        }
}

/// Everything `keep` accepts that the tops reach, over both edge maps. A workspace is always in;
/// `from` filters the edges out of a top, so a devDependency of one does not ship through it.
/// Each package's key by the `(name, version)` an edge to it carries, so a walk over edges
/// looks keys up instead of spelling `name@version` for each one.
fn edge_index(res: &Resolution) -> HashMap<(&str, &str), &str> {
    let mut index = HashMap::with_capacity(res.packages.len());
    for key in res.packages.keys() {
        if let Some((name, tail)) = split_key(key) {
            index.insert((name, tail), key.as_str());
        }
    }
    index
}

fn reach<'a>(
    res: &'a Resolution,
    index: &HashMap<(&'a str, &'a str), &'a str>,
    keep: &dyn Fn(&str) -> bool,
    from: &dyn Fn(&str) -> bool,
) -> HashSet<&'a str> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(res.packages.len());
    let mut queue: Vec<&str> = Vec::new();
    let mut push = |key: Option<&&'a str>, top: bool, queue: &mut Vec<&'a str>| {
        let Some(&key) = key else { return };
        if seen.contains(key) || !keep(key) || (top && !from(key)) {
            return;
        }
        seen.insert(key);
        queue.push(key);
    };
    for (name, version) in &res.root.dependencies {
        push(index.get(&(name.as_str(), version.as_str())), true, &mut queue);
    }
    for (key, p) in &res.packages {
        if p.local.is_some() {
            push(Some(&key.as_str()), false, &mut queue);
        }
    }
    let mut i = 0;
    while i < queue.len() {
        let p = &res.packages[queue[i]];
        let top = p.local.is_some();
        for (name, version) in p.dependencies.iter().chain(&p.optional_dependencies) {
            push(index.get(&(name.as_str(), version.as_str())), top, &mut queue);
        }
        i += 1;
    }
    seen
}

/// Narrow a resolution to the packages that run here. The lockfile holds every platform's
/// builds; this needs no network, since `os`, `cpu` and `libc` were written down. A package
/// with a required edge to something that cannot run here goes too. A package that cannot run
/// here is an error only when a top's own dependency needs it through required edges: a workspace
/// may list every platform's build as a devDependency, as bun allows, and only this platform's
/// is linked.
pub fn filter_platform(mut res: Resolution, platform: &Platform) -> Result<Resolution> {
    let mut warnings: BTreeSet<String> = std::mem::take(&mut res.warnings).into_iter().collect();
    let mut gone: HashMap<String, String> = HashMap::new();
    let needed = needed(&res);
    let mut drop = |key: &str, why: String, chained: bool, gone: &mut HashMap<String, String>| -> Result<()> {
        let p = &res.packages[key];
        if let Some(who) = needed.get(key) {
            return Err(Error::new("EBADPLATFORM", format!("{key} {why} (required by {who})")));
        }
        if !p.optional {
            warnings.insert(format!("skipped dev-only {key}: {why}"));
        } else if chained {
            warnings.insert(format!("skipped optional {key}: {why}"));
        }
        gone.insert(key.to_string(), why);
        Ok(())
    };
    for (key, p) in &res.packages {
        if !runs_on(p.os.as_ref(), p.cpu.as_ref(), p.libc.as_ref(), platform) {
            drop(key, format!("does not run on {platform}"), false, &mut gone)?;
        }
    }
    // A required edge to a dropped package takes its owner with it, until nothing changes. A
    // workspace stays: what it can lose is dev-only.
    let mut changed = !gone.is_empty();
    while changed {
        changed = false;
        for (key, p) in &res.packages {
            if gone.contains_key(key) || p.local.is_some() {
                continue;
            }
            let lost = p.dependencies.iter().find_map(|(n, v)| {
                let dep = format!("{n}@{v}");
                gone.get(&dep).map(|why| format!("needs {dep}, which {why}"))
            });
            if let Some(why) = lost {
                drop(key, why, true, &mut gone)?;
                changed = true;
            }
        }
    }
    if gone.is_empty() {
        res.warnings = warnings.into_iter().collect();
        return Ok(res);
    }
    let gone_names: HashSet<String> = gone.keys().filter_map(|k| split_key(k).map(|(n, _)| n.to_string())).collect();
    let index = edge_index(&res);
    let keep = reach(&res, &index, &|k| !gone.contains_key(k), &|_| true);
    // Recomputed: a package the root shipped only through a build that just went is dev now.
    let shipped = reach(&res, &index, &|k| keep.contains(k), &|k| res.packages.get(k).is_some_and(|p| !p.dev));
    let keep: HashSet<String> = keep.into_iter().map(str::to_string).collect();
    let shipped: HashSet<String> = shipped.into_iter().map(str::to_string).collect();
    std::mem::drop(index);
    let present = |deps: &mut Deps| deps.retain(|n, v| keep.contains(&format!("{n}@{v}")));
    res.packages.retain(|k, _| keep.contains(k));
    for (key, p) in &mut res.packages {
        // Only the edges to what went need a look: most packages lost nothing.
        if p.dependencies.keys().chain(p.optional_dependencies.keys()).any(|n| gone_names.contains(n.as_str())) {
            present(&mut p.dependencies);
            present(&mut p.optional_dependencies);
        }
        p.dev = !shipped.contains(key);
    }
    present(&mut res.root.dependencies);
    res.warnings = warnings.into_iter().collect();
    Ok(res)
}

/// What installs whatever else goes: the root's and the workspaces' `dependencies` and what they
/// reach through required edges, each with the root, workspace path or package that needs it.
fn needed(res: &Resolution) -> HashMap<String, String> {
    let prod = |specs: &Option<Specs>, name: &str| {
        specs.as_ref().and_then(|s| s.dependencies.as_ref()).is_some_and(|d| d.contains_key(name))
    };
    let mut queue: Vec<(String, String)> = Vec::new();
    let tops = res.packages.values().filter_map(|p| Some((p.local.clone()?, &p.specs, &p.dependencies)));
    for (who, specs, deps) in std::iter::once(("root".to_string(), &res.root.specs, &res.root.dependencies)).chain(tops)
    {
        queue.extend(deps.iter().filter(|(n, _)| prod(specs, n)).map(|(n, v)| (format!("{n}@{v}"), who.clone())));
    }
    let mut out = HashMap::new();
    while let Some((key, who)) = queue.pop() {
        let Some(p) = res.packages.get(&key).filter(|p| p.local.is_none() && !out.contains_key(&key)) else { continue };
        queue.extend(p.dependencies.iter().map(|(n, v)| (format!("{n}@{v}"), key.clone())));
        out.insert(key, who);
    }
    out
}

/// Consumers whose declared peer range is not what the tree installed.
pub fn unmet_peers(res: &Resolution) -> Vec<String> {
    let mut out = Vec::new();
    for (key, p) in &res.packages {
        let deps = p.all_deps();
        for (name, range) in p.peer_dependencies.iter().flatten() {
            let Some(edge) = deps.get(name) else { continue };
            let have = res.packages.get(&format!("{name}@{edge}")).map_or(edge.as_str(), |d| d.version.as_str());
            if !semver::valid_range(range) {
                out.push(format!("{key} declares peer {name}@{range}, which is not a range we can read"));
            } else if !semver::satisfies(have, range) {
                out.push(format!("{key} needs peer {name}@{range}, and the tree installs {name}@{have}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> Platform {
        Platform { os: "linux".into(), cpu: "x64".into(), libc: Some("glibc".into()) }
    }

    fn v(list: &[&str]) -> Option<Vec<String>> {
        Some(list.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn matches_platform_lists() {
        let p = platform();
        assert!(runs_on(v(&["linux"]).as_ref(), None, None, &p));
        assert!(!runs_on(v(&["darwin"]).as_ref(), None, None, &p));
        assert!(runs_on(v(&["!win32"]).as_ref(), None, None, &p));
        assert!(!runs_on(v(&["any", "!linux"]).as_ref(), None, None, &p));
        assert!(!runs_on(None, None, v(&["musl"]).as_ref(), &p));
        let unknown = Platform { libc: None, ..p };
        assert!(!runs_on(None, None, v(&["glibc"]).as_ref(), &unknown));
    }

    fn pkg(name: &str, optional: bool, os: Option<Vec<String>>, deps: &[(&str, &str)]) -> Package {
        Package {
            name: name.into(),
            version: "1.0.0".into(),
            optional,
            os,
            dependencies: deps.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            ..Package::default()
        }
    }

    #[test]
    fn filters_a_platform() {
        let mut res = Resolution::default();
        res.root.dependencies.insert("a".into(), "1.0.0".into());
        let mut a = pkg("a", false, None, &[]);
        a.optional_dependencies.insert("bind".into(), "1.0.0".into());
        a.optional_dependencies.insert("wrap".into(), "1.0.0".into());
        res.packages.insert("a@1.0.0".into(), a);
        res.packages.insert("bind@1.0.0".into(), pkg("bind", true, v(&["darwin"]), &[]));
        res.packages.insert("wrap@1.0.0".into(), pkg("wrap", true, None, &[("bind", "1.0.0")]));
        let out = filter_platform(res.clone(), &platform()).unwrap();
        assert_eq!(out.packages.keys().collect::<Vec<_>>(), ["a@1.0.0"]);
        assert!(out.packages["a@1.0.0"].optional_dependencies.is_empty());
        assert_eq!(out.warnings.len(), 1);

        // Required by a, which the root's devDependencies bring: skipped.
        res.packages.get_mut("a@1.0.0").unwrap().dependencies.insert("bind".into(), "1.0.0".into());
        let deps: Deps = [("a".to_string(), "^1".to_string())].into();
        res.root.specs = Some(Specs { dev_dependencies: Some(deps.clone()), ..Specs::default() });
        let out = filter_platform(res.clone(), &platform()).unwrap();
        assert!(!out.packages.contains_key("bind@1.0.0") && out.warnings.iter().any(|w| w.contains("dev-only")));
        // Brought by its dependencies, it is needed.
        res.root.specs = Some(Specs { dependencies: Some(deps), ..Specs::default() });
        let e = filter_platform(res, &platform()).unwrap_err();
        assert_eq!((e.code, e.message.contains("(required by a@1.0.0)")), ("EBADPLATFORM", true), "{}", e.message);
    }
}
