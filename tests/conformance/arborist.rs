//! npm's own lockfiles, from @npmcli/arborist's test fixtures (tests/conformance/arborist, see
//! its README), each read as jpm reads a package-lock.json or npm-shrinkwrap.json it finds. A
//! file is imported, refused with a message, or found to panic the reader, and expected.json
//! holds which, with the message of each refusal and why jpm refuses. An imported file is
//! checked against the file itself, read here apart from jpm's reader: every registry package
//! npm installs from it is in jpm's lock, every edge reaches the version Node's walk up reaches
//! from each copy, and what npm marks dev or optional jpm marks so too. Built into jpm's own
//! tests from src/foreign.rs.
//!
//! `JPM_BLESS=1 cargo test arborist` rewrites expected.json from what jpm does now, keeping
//! each row's `why`.

use super::*;
use serde_json::{Map as JMap, Value as J, json};
use std::collections::BTreeMap;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/arborist")
}

/// A vendored file, gunzipped when it was stored as `<name>.gz`.
fn read_file(path: &Path) -> Option<Vec<u8>> {
    if let Ok(bytes) = std::fs::read(path) {
        return Some(bytes);
    }
    let gz = std::fs::read(path.with_extension("json.gz")).ok()?;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..]).read_to_end(&mut out).ok()?;
    Some(out)
}

/// Every vendored lockfile, as its path under fixtures/ with `/` between parts.
fn lockfiles() -> Vec<String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(at).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
                continue;
            }
            let name = e.file_name().to_string_lossy().trim_end_matches(".gz").to_string();
            if ["package-lock.json", "npm-shrinkwrap.json"].contains(&name.as_str()) {
                let rel = p.parent().unwrap().strip_prefix(root).unwrap().join(&name);
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    let root = dir().join("fixtures");
    walk(&root, &root, &mut out);
    out.sort();
    out
}

fn npmjs(_: &str) -> String {
    "https://registry.npmjs.org".to_string()
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

/// What jpm does with one lockfile, as its row in expected.json (less the `why`).
fn run(rel: &str) -> J {
    let lock_path = dir().join("fixtures").join(rel);
    let file = rel.rsplit('/').next().unwrap();
    // Arborist's tests fill `${REGISTRY}` in with their mock registry's url.
    let text =
        String::from_utf8_lossy(&read_file(&lock_path).unwrap()).replace("${REGISTRY}", "https://registry.npmjs.org");
    // A fixture with no package.json is read as an empty one, as npm reads it.
    let pj = read_file(&lock_path.with_file_name("package.json")).map(|b| String::from_utf8_lossy(&b).into_owned());
    // As `load_project` has it when jpm reads the lock: rules applied, the root's peers added.
    let manifest = RootManifest::parse(pj.as_deref().unwrap_or("{}"), Path::new("package.json")).and_then(|mut m| {
        rules::read(lock_path.parent().unwrap(), &m)?.apply(&mut m)?;
        m.install_own_peers();
        Ok(m)
    });
    let manifest = match manifest {
        Ok(m) => m,
        Err(e) => return json!({ "outcome": "bad package.json", "message": e.message }),
    };
    // The loose read a refusal falls back on must not fall over either.
    let pinned = match catch_unwind(|| pins(file, &text)) {
        Ok(Ok(p)) => json!(p.len()),
        Ok(Err(e)) => json!(e.message),
        Err(p) => json!(format!("panicked: {}", panic_text(p))),
    };
    let has_workspaces = manifest.workspaces.is_some();
    let loaded = catch_unwind(AssertUnwindSafe(|| load(file, &text, &manifest, has_workspaces, &npmjs)));
    let mut row = match loaded {
        Err(p) => json!({ "outcome": "panicked", "message": panic_text(p) }),
        Ok(Err(e)) => json!({ "outcome": "refused", "message": e.message }),
        Ok(Ok(got)) => {
            let differences = compare(&text, &got);
            let mut row = json!({ "outcome": "imported", "packages": got.lock.packages.len() });
            if !got.warnings.is_empty() {
                row["warnings"] = json!(got.warnings);
            }
            if !differences.is_empty() {
                row["differences"] = json!(differences);
            }
            row
        }
    };
    row["pins"] = pinned;
    row
}

/// A package npm installs at one path of the file.
struct Copy<'a> {
    path: &'a str,
    entry: &'a J,
    key: String,
}

fn truthy_j(v: Option<&J>) -> bool {
    !matches!(v, None | Some(J::Null | J::Bool(false))) && v != Some(&json!("")) && v != Some(&json!(0))
}

/// From a registry: a version, and no url or one of the registry's `…/-/<name>-<version>.tgz`.
fn registry(entry: &J) -> Option<&str> {
    let version = entry.get("version")?.as_str().filter(|v| !v.is_empty())?;
    let resolved = entry.get("resolved").and_then(J::as_str).unwrap_or_default();
    let tarball =
        resolved.starts_with("http") && resolved.contains("/-/") && resolved.ends_with(&format!("-{version}.tgz"));
    ((resolved.is_empty() || tarball) && !truthy_j(entry.get("link"))).then_some(version)
}

/// The edge to an entry: its version, or `npm:<real>@<version>` for an alias.
fn edge_to(name: &str, entry: &J) -> Option<String> {
    let version = registry(entry)?;
    Some(match entry.get("name").and_then(J::as_str).filter(|r| !r.is_empty() && *r != name) {
        Some(real) => alias_edge(real, version),
        None => version.to_string(),
    })
}

/// The path `name` resolves to from `path`, walking up as Node does.
fn walk_up<'a>(packages: &'a JMap<String, J>, path: &str, name: &str) -> Option<(&'a String, &'a J)> {
    let mut at = path.to_string();
    loop {
        let sep = if at.is_empty() { "" } else { "/" };
        if let Some(hit) = packages.get_key_value(&format!("{at}{sep}node_modules/{name}")) {
            return Some(hit);
        }
        if at.is_empty() {
            return None;
        }
        at = match at.rfind("/node_modules/") {
            Some(i) => at[..i].to_string(),
            None => String::new(),
        };
    }
}

/// Whether the copy at `path` comes in its bundler's tarball: npm marks what the root bundles
/// `inBundle` too, and installs it from the registry.
fn dep_bundled(packages: &JMap<String, J>, path: &str) -> bool {
    let bundled = |p: &str| truthy_j(packages.get(p).and_then(|e| e.get("inBundle")));
    let mut at = path;
    while !at.is_empty() && bundled(at) {
        at = at.rfind("/node_modules/").map_or("", |i| &at[..i]);
    }
    bundled(path) && !at.is_empty()
}

/// The paths npm installs, as its calc-dep-flags walk leaves them not extraneous: what the
/// root reaches over its own edges (dev included), its dependencies' edges and their required
/// peers. An optional peer alone keeps nothing (npm prunes it), and a link leads to its target.
fn installed(packages: &JMap<String, J>) -> BTreeSet<&str> {
    let mut seen = BTreeSet::from([""]);
    let mut queue = vec![""];
    while let Some(path) = queue.pop() {
        let entry = &packages[path];
        let mut next = Vec::new();
        if truthy_j(entry.get("link")) {
            next.extend(entry.get("resolved").and_then(J::as_str));
        }
        let optional_peer = |dep: &str| {
            truthy_j(entry.get("peerDependenciesMeta").and_then(|m| m.get(dep)).and_then(|m| m.get("optional")))
        };
        let groups: &[&str] = if path.is_empty() {
            &["dependencies", "optionalDependencies", "devDependencies", "peerDependencies"]
        } else {
            &["dependencies", "optionalDependencies", "peerDependencies"]
        };
        for group in groups {
            for (dep, _) in entry.get(*group).and_then(J::as_object).into_iter().flatten() {
                if *group == "peerDependencies" && optional_peer(dep) {
                    continue;
                }
                next.extend(walk_up(packages, path, dep).map(|(p, _)| p.as_str()));
            }
        }
        for p in next {
            if packages.contains_key(p) && seen.insert(packages.get_key_value(p).unwrap().0.as_str()) {
                queue.push(packages.get_key_value(p).unwrap().0.as_str());
            }
        }
    }
    seen
}

/// Where jpm's import says other than the file: packages missing or extra, edges to other
/// versions or of another kind, and dev and optional marks that differ from npm's.
fn compare(text: &str, got: &ForeignLock) -> Vec<String> {
    let doc: J = serde_json::from_str(text).unwrap();
    let packages = doc["packages"].as_object().unwrap();
    let lock = &got.lock;
    let mut out = Vec::new();
    let installed = installed(packages);
    let mut copies: Vec<Copy> = Vec::new();
    for (path, entry) in packages {
        let Some(at) = path.rfind("node_modules/").filter(|_| installed.contains(path.as_str())) else { continue };
        let skip = truthy_j(entry.get("link")) || dep_bundled(packages, path);
        let Some(version) = registry(entry).filter(|_| !skip) else { continue };
        let name = &path[at + "node_modules/".len()..];
        let key = match entry.get("name").and_then(J::as_str).filter(|r| !r.is_empty() && *r != name) {
            Some(real) => format!("{name}@{}", alias_edge(real, version)),
            None => format!("{name}@{version}"),
        };
        copies.push(Copy { path, entry, key });
    }
    let wanted: BTreeSet<&str> = copies.iter().map(|c| c.key.as_str()).collect();
    for key in &wanted {
        if !lock.packages.contains_key(*key) {
            out.push(format!("{key} is not in jpm's lock"));
        }
    }
    for key in lock.packages.keys() {
        if !wanted.contains(key.as_str()) {
            out.push(format!("{key} is in jpm's lock and not installed by npm"));
        }
    }
    // Root edges.
    let root = &packages[""];
    for group in ["dependencies", "devDependencies", "optionalDependencies"] {
        for (dep, _) in root.get(group).and_then(J::as_object).into_iter().flatten() {
            let want = walk_up(packages, "", dep).and_then(|(_, e)| edge_to(dep, e));
            let have = lock.root.dependencies.get(dep);
            if want.as_ref() != have {
                out.push(format!("the root's {dep} is {have:?} in jpm, {want:?} in npm"));
            }
        }
    }
    // Each copy's edges, unless jpm said it settled that edge one way for every copy.
    let warned = |key: &str, dep: &str| {
        got.warnings.iter().any(|w| {
            w.contains(&format!(" {dep}, a dependency of {key},")) || w.contains(&format!("peer {dep} of {key} "))
        })
    };
    for c in &copies {
        let Some(have) = lock.packages.get(&c.key) else { continue };
        let optional_peers: BTreeSet<&str> = c
            .entry
            .get("peerDependenciesMeta")
            .and_then(J::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, m)| truthy_j(m.get("optional")))
            .map(|(k, _)| k.as_str())
            .collect();
        let mut declared: BTreeMap<&str, bool> = BTreeMap::new();
        for (group, optional) in [("peerDependencies", false), ("dependencies", false), ("optionalDependencies", true)]
        {
            for (dep, _) in c.entry.get(group).and_then(J::as_object).into_iter().flatten() {
                let optional = optional || (group == "peerDependencies" && optional_peers.contains(dep.as_str()));
                declared.insert(dep, optional);
            }
        }
        for (dep, optional) in declared {
            let target = walk_up(packages, c.path, dep).filter(|(p, _)| installed.contains(p.as_str()));
            if target.is_some_and(|(p, _)| dep_bundled(packages, p)) {
                continue;
            }
            let want = target.and_then(|(_, e)| edge_to(dep, e));
            let edges = if optional { &have.optional_dependencies } else { &have.dependencies };
            let other = if optional { &have.dependencies } else { &have.optional_dependencies };
            let got_edge = edges.get(dep);
            if got_edge == want.as_ref() && !other.contains_key(dep) || warned(&c.key, dep) {
                continue;
            }
            let kind = if optional { "optional" } else { "required" };
            out.push(format!("{} ({}): {kind} {dep} is {got_edge:?} in jpm, {want:?} in npm", c.key, c.path));
        }
    }
    // npm marks a copy dev when only devDependencies reach it and optional when only optional
    // edges do; jpm marks a package so when every copy is.
    let resolution = lock::into_resolution(lock.clone(), &npmjs);
    for key in &wanted {
        let Some(p) = resolution.packages.get(*key) else { continue };
        let all = |flag: &str| copies.iter().filter(|c| c.key == *key).all(|c| truthy_j(c.entry.get(flag)));
        for (flag, jpm) in [("dev", p.dev), ("optional", p.optional)] {
            if all(flag) != jpm {
                out.push(format!("{key} is {}{flag} in jpm", if jpm { "" } else { "not " }));
            }
        }
    }
    // What each copy says of its tarball, platforms, bins and scripts.
    for c in &copies {
        let Some(have) = lock.packages.get(&c.key) else { continue };
        let integrity = c.entry.get("integrity").and_then(J::as_str).unwrap_or_default();
        if !integrity.is_empty() && !integrity.split_whitespace().any(|h| h == have.integrity) {
            out.push(format!("{} ({}): integrity {} in jpm, {integrity} in npm", c.key, c.path, have.integrity));
        }
        let list = |k: &str| match c.entry.get(k) {
            Some(J::Array(a)) => a.iter().filter_map(J::as_str).map(str::to_string).collect(),
            Some(J::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        };
        let bins: BTreeSet<String> = match c.entry.get("bin") {
            Some(J::Object(o)) => o.keys().cloned().collect(),
            Some(J::String(_)) => {
                let real = c
                    .entry
                    .get("name")
                    .and_then(J::as_str)
                    .unwrap_or(&c.path[c.path.rfind("node_modules/").unwrap() + 13..]);
                BTreeSet::from([real.rsplit('/').next().unwrap().to_string()])
            }
            _ => BTreeSet::new(),
        };
        let mine: BTreeSet<String> = have.bin.keys().cloned().collect();
        let scripts = truthy_j(c.entry.get("hasInstallScript"));
        if have.os != list("os")
            || have.cpu != list("cpu")
            || have.libc != list("libc")
            || mine != bins
            || have.scripts != scripts
        {
            out.push(format!("{} ({}): os, cpu, libc, bins or scripts differ", c.key, c.path));
        }
    }
    // What jpm writes of it reads back as the same lock.
    let written = lock::format_lockfile(lock);
    let again =
        written.as_ref().ok().map(|t| lock::parse_lockfile(t, "jpm.lock").and_then(|b| lock::format_lockfile(&b)));
    match (written, again) {
        (Ok(a), Some(Ok(b))) if a == b => {}
        (Err(e), _) | (_, Some(Err(e))) => out.push(format!("jpm.lock does not read back: {}", e.message)),
        _ => out.push("jpm.lock reads back as another lock".into()),
    }
    out
}

#[test]
fn reads_arborist_fixture_lockfiles() {
    let path = dir().join("expected.json");
    let expected: J = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| "{}".into())).unwrap();
    let mut table: BTreeMap<String, J> =
        expected.as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.clone())).collect();
    let found = lockfiles();
    let mut wrong = Vec::new();
    for rel in &found {
        let mut actual = run(rel);
        let why = table.get(rel).and_then(|r| r.get("why")).cloned();
        let mut want = table.get(rel).cloned().unwrap_or(J::Null);
        if let Some(o) = want.as_object_mut() {
            o.remove("why");
        }
        if actual != want {
            wrong.push(format!("{rel}:\n  expected {want}\n  actual   {actual}"));
        }
        if let Some(why) = why {
            actual["why"] = why;
        }
        table.insert(rel.clone(), actual);
    }
    for (rel, row) in &table {
        let outcome = row["outcome"].as_str().unwrap_or_default();
        if outcome == "skipped" {
            assert!(!found.iter().any(|f| f.starts_with(&format!("{rel}/"))), "{rel} is skipped and has a lockfile");
        } else if !found.contains(rel) {
            wrong.push(format!("{rel} is in expected.json and not vendored"));
        }
        if outcome != "imported" && !row["why"].as_str().is_some_and(|w| !w.is_empty()) {
            wrong.push(format!("{rel} is {outcome} with no why"));
        }
        if outcome == "panicked" {
            wrong.push(format!("{rel} panics jpm's reader"));
        }
    }
    if std::env::var_os("JPM_BLESS").is_some() {
        let text = serde_json::to_string_pretty(&J::Object(table.into_iter().collect())).unwrap();
        std::fs::write(&path, text + "\n").unwrap();
        return;
    }
    assert!(
        wrong.is_empty(),
        "{} of {} fixtures differ from expected.json:\n{}",
        wrong.len(),
        found.len(),
        wrong.join("\n")
    );
}
