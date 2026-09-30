//! The bun.lock files in bun's own install tests (tests/conformance/bun, see its README), each
//! brought over as `jpm install` brings one over: package.json and the lockfile in a directory,
//! the project's rules read, then `load`. Each either imports faithfully or is refused with the
//! reason `REFUSED` gives it; `prefer`, the fallback a refusal leads to, must read every one.
//!
//! Faithfully means, checked against the file itself and not against the importer: every
//! package bun reaches from the root through registry edges is in jpm's lock at the version its
//! folder holds, with its integrity, platforms and bins; each edge bun declares for it or for
//! the root goes to the copy Node's walk up bun's layout finds (none to a bundled one; an
//! optional peer only to a package something else installs, as npm and pnpm have it); and nothing
//! else is in the lock. Built into jpm's own tests from src/foreign.rs.

use super::*;
use serde_json::Value as J;

use std::path::{Path, PathBuf};

const CASES: &str = include_str!("bun/lockfiles.json");

// Every refusal leaves the install to resolve with the file's versions preferred (`prefer`).
const WORKSPACES: &str = "jpm imports no workspaces from another manager's lockfile (npm's alike)";
const LOCAL: &str = "a file: directory or tarball is no registry package, and only those come over";
const GIT: &str = "a git or GitHub dependency is no registry package, and only those come over";
const TARBALL: &str = "bun.lock does not say which version a tarball url holds, which jpm.lock keys it by";
const ROOT: &str = "a package's dependency on the project itself (bun's `root:`) is no registry package";
const PARTIAL: &str = "the fixture's lockfile lists only part of the tree, which bun fills in at install";
const NO_INTEGRITY: &str = "bun.lock gives a package no integrity (written by hand, or migrated from a lock with none), and jpm locks nothing unchecked";
const ESCAPE: &str = "a package name that climbs out of node_modules is refused, as bun refuses it";

/// Cases jpm refuses to import, by name: part of the message, and why.
const REFUSED: &[(&str, &str, &str)] = &[
    ("should reject GitHub tarball when integrity check fails", "has from no registry", GIT),
    ("should update lockfile with integrity when old format has none", "has from no registry", GIT),
    ("text lockfile workspace sorting 1", "has workspaces", WORKSPACES),
    ("text lockfile workspace sorting 2", "has workspaces", WORKSPACES),
    ("text lockfile --frozen-lockfile 1", "has workspaces", WORKSPACES),
    ("binaries each type of binary serializes correctly to text lockfile 1", "has from no registry", LOCAL),
    ("binaries root resolution bins 1", "has from no registry", ROOT),
    ("it should ignore peerDependencies within workspaces 1", "has workspaces", WORKSPACES),
    ("should handle modified git resolutions in bun.lock 1", "has from no registry", GIT),
    ("should write plaintext lockfiles 1", "has from no registry", LOCAL),
    ("should escape names 1", "has workspaces", WORKSPACES),
    ("should not change formatting unexpectedly 2", "has workspaces", WORKSPACES),
    ("basic detect changes (bun.lock) 1", "has workspaces", WORKSPACES),
    ("basic detect changes (bun.lock) 2", "has workspaces", WORKSPACES),
    ("basic detect changes (bun.lock) 3", "has workspaces", WORKSPACES),
    (
        "packages whose scoped registry does not answer the audit request are listed as skipped",
        "has workspaces",
        WORKSPACES,
    ),
    ("root resolution bins", "has from no registry", ROOT),
    ("rejects package names containing relative path components in bun.lock", "which is not one", ESCAPE),
    (
        "should install successfully from text lockfile without integrity hash (backward compat)",
        "has from no registry",
        TARBALL,
    ),
    (
        "should install successfully from text lockfile without integrity hash for local tarball (backward compat)",
        "has from no registry",
        LOCAL,
    ),
    ("should handle modified git resolutions in bun.lock", "has from no registry", GIT),
    ("should read install.saveTextLockfile from bunfig.toml", "has workspaces", WORKSPACES),
    (
        "refuses to install an escaping file: dependency that a registry package's own folder declares in the lockfile",
        "has from no registry",
        LOCAL,
    ),
    (
        "installs a file: dependency pointing outside the project when it came from root package.json \"${field}\" (existing lockfile)",
        "has from no registry",
        LOCAL,
    ),
    ("installs a nested \"${field}\" rule pointing at a file: path inside the project", "has from no registry", LOCAL),
    ("installs file: dependencies that depend on each other", "has from no registry", LOCAL),
    (
        "installs file: dependencies that depend on each other from a lockfile that only lists the root's copies",
        "has from no registry",
        LOCAL,
    ),
    (
        "installs file: dependencies that depend on each other from a lockfile that only lists the root's copies #2",
        "has from no registry",
        LOCAL,
    ),
    (
        "requires an integrity hash for an off-registry npm tarball URL at lockfileVersion 2",
        "no integrity",
        NO_INTEGRITY,
    ),
    ("escapes double quotes in npm registry tarball URLs when saving bun.lock", "no integrity", NO_INTEGRITY),
    ("hand-edited bun.lock that lists workspaces but has no packages object", "has workspaces", WORKSPACES),
    ("declared by a registry package", "no integrity", NO_INTEGRITY),
    ("declared by the root package and a workspace", "has workspaces", WORKSPACES),
    ("matching workspace devDependency and npm peerDependency", "has workspaces", WORKSPACES),
    (
        "update without --latest from root moves catalogs within range (${args.join(\" \") || \"no args\"})",
        "has workspaces",
        WORKSPACES,
    ),
    ("new projects use current config version", "has from no registry", LOCAL),
    ("new monorepos use isolated linker", "has workspaces", WORKSPACES),
    ("should add configVersion@v0 to an existing lockfile", "has workspaces", WORKSPACES),
    ("should add configVersion@v0 to an existing lockfile #2", "has workspaces", WORKSPACES),
    ("re-saving a v1 lockfile keeps it at version 1 even after adding a dependency", "has from no registry", LOCAL),
    ("re-saving a v0 lockfile floors it to version 1 so it stays parseable", "has workspaces", WORKSPACES),
    ("an existing v1 lockfile still loads (backward compatible)", "has from no registry", LOCAL),
    ("off-registry npm tarball integrity is enforced only at version 2", "no integrity", NO_INTEGRITY),
    ("unsafe git .bun-tag is rejected only at version 2", "has from no registry", GIT),
    (
        "a github resolution whose committish contains a slash reads back with owner, repo and tag intact",
        "has from no registry",
        GIT,
    ),
    ("re-saving a v1 off-registry lockfile keeps it at version 1", "no integrity", NO_INTEGRITY),
    ("re-saving keeps v1 for a tarball under a writer-only scoped registry", "no integrity", NO_INTEGRITY),
    ("package-lock.json migration fixes arborist fixtures audit-linked-package 1", "has from no registry", LOCAL),
    ("package-lock.json migration fixes arborist fixtures cli-750 1", "has from no registry", LOCAL),
    (
        "package-lock.json migration fixes arborist fixtures edit-package-json--workspaces-changed 1",
        "has workspaces",
        WORKSPACES,
    ),
    ("package-lock.json migration fixes arborist fixtures external-link-dep 1", "has from no registry", LOCAL),
    ("package-lock.json migration fixes arborist fixtures external-link--root 1", "has from no registry", LOCAL),
    ("package-lock.json migration fixes arborist fixtures link-dep-lifecycle-scripts 1", "has from no registry", LOCAL),
    ("package-lock.json migration fixes arborist fixtures minimist-git-dep 1", "has from no registry", GIT),
    ("package-lock.json migration fixes arborist fixtures minimist-git-metadep 1", "has from no registry", GIT),
    ("package-lock.json migration fixes arborist fixtures pnpm 1", "has from no registry", LOCAL),
    ("package-lock.json migration fixes arborist fixtures prune-lockfile-omit-dev 1", "no integrity", NO_INTEGRITY),
    (
        "package-lock.json migration fixes arborist fixtures prune-lockfile-optional-peer 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    ("package-lock.json migration fixes arborist fixtures rebuild-foreground-scripts 1", "no integrity", NO_INTEGRITY),
    (
        "package-lock.json migration fixes arborist fixtures testing-rebuild-script-env-flags 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    ("package-lock.json migration fixes arborist fixtures workspaces-add-new-dep 1", "has workspaces", WORKSPACES),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-conflicting-versions-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-ignore-nm-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    ("package-lock.json migration fixes arborist fixtures workspaces-non-simplistic 1", "has workspaces", WORKSPACES),
    ("package-lock.json migration fixes arborist fixtures workspaces-not-root 1", "has workspaces", WORKSPACES),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-prefer-linking-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-shared-deps-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-top-level-link-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-transitive-deps-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "package-lock.json migration fixes arborist fixtures workspaces-version-unsatisfied-virtual 1",
        "has workspaces",
        WORKSPACES,
    ),
    ("package-lock.json migration fixes arborist fixtures workspaces-with-overrides 1", "has workspaces", WORKSPACES),
    (
        "pnpm comprehensive migration tests large single package with many dependencies: large-single-package 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "pnpm comprehensive migration tests complex monorepo with cross-dependencies: complex-monorepo 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "pnpm comprehensive migration tests pnpm with patches and overrides: patches-overrides 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "pnpm comprehensive migration tests pnpm with peer dependencies and auto-install-peers: peer-deps-auto-install 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "pnpm-lock.yaml migration pnpm workspace lockfile migration: workspace-pnpm-migration 1",
        "has workspaces",
        WORKSPACES,
    ),
    ("pnpm-lock.yaml v9 v9 git and userinfo-tarball references migrate: bun.lock 1", "has from no registry", GIT),
    (
        "pnpm-lock.yaml v9 snapshot alias whose dep-path version is a file: directory or tarball: bun.lock 1",
        "has from no registry",
        LOCAL,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: canary-versions 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: monorepo-workspaces 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: patches-overrides 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: file-link-deps 1",
        "has from no registry",
        LOCAL,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: custom-registries 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: peer-dependencies 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: duplicate-packages 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: mixed-dependency-types 1",
        "no integrity",
        NO_INTEGRITY,
    ),
    (
        "PNPM Migration Complete Test Suite comprehensive PNPM migration with all edge cases: circular-workspaces 1",
        "has workspaces",
        WORKSPACES,
    ),
    (
        "yarn.lock migration basic complex yarn.lock with multiple dependencies and versions: complex-yarn-migration 1",
        "has from no registry",
        PARTIAL,
    ),
    (
        "yarn.lock migration basic yarn.lock with resolutions: resolutions-yarn-migration 1",
        "has from no registry",
        PARTIAL,
    ),
    (
        "yarn.lock migration basic yarn.lock with scoped packages and parent/child relationships: scoped-yarn-migration 1",
        "has from no registry",
        PARTIAL,
    ),
    (
        "yarn.lock migration basic migration with realistic complex yarn.lock: complex-realistic-yarn-migration 1",
        "has from no registry",
        PARTIAL,
    ),
    ("bun pm migrate for existing yarn.lock yarn-cli-repo: yarn-cli-repo 1", "has from no registry", LOCAL),
    (
        "bun pm migrate for existing yarn.lock yarn-lock-mkdirp-file-dep: yarn-lock-mkdirp-file-dep 1",
        "has from no registry",
        LOCAL,
    ),
    ("bun pm migrate for existing yarn.lock yarn-stuff: yarn-stuff 1", "has from no registry", GIT),
    ("monorepo with linker modes", "has workspaces", WORKSPACES),
];

struct Case {
    name: String,
    from: String,
    manifest: J,
    lock: String,
}

fn cases() -> Vec<Case> {
    let all: J = serde_json::from_str(CASES).unwrap();
    all.as_array()
        .unwrap()
        .iter()
        .map(|c| Case {
            name: c["name"].as_str().unwrap().to_string(),
            from: c["from"].as_str().unwrap().to_string(),
            manifest: c["package.json"].clone(),
            lock: c["bun.lock"].as_str().unwrap().to_string(),
        })
        .collect()
}

fn npmjs(_: &str) -> String {
    "https://registry.npmjs.org".to_string()
}

/// The case as a project on disk, read the way an install reads it, then `load`.
fn import(case: &Case, dir: &Path) -> Result<ForeignLock> {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("package.json"), serde_json::to_string_pretty(&case.manifest).unwrap()).unwrap();
    // A patch's content is not what the import checks: its path is.
    for path in case.manifest["patchedDependencies"].as_object().into_iter().flatten().filter_map(|(_, p)| p.as_str()) {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "").unwrap();
    }
    let mut manifest = crate::project::read_manifest(&dir.join("package.json"))?;
    crate::rules::read(dir, &manifest)?.apply(&mut manifest)?;
    manifest.install_own_peers();
    load("bun.lock", &case.lock, &manifest, manifest.workspaces.is_some(), &npmjs)
}

/// bun.lock as serde_json reads it.
fn doc(case: &Case) -> J {
    serde_json::from_str(&strip_trailing_commas(&case.lock)).unwrap()
}

/// The folder bun installs `name` from for the one at `from` (`None` for the root): the nearest
/// on the walk up, as Node resolves.
fn bun_at<'a>(listed: &'a serde_json::Map<String, J>, from: Option<&str>, name: &str) -> Option<(String, &'a J)> {
    let mut up: Vec<&str> = from.map(names).unwrap_or_default();
    loop {
        let path = if up.is_empty() { name.to_string() } else { format!("{}/{name}", up.join("/")) };
        if let Some(tuple) = listed.get(&path) {
            return Some((path, tuple));
        }
        up.pop()?;
    }
}

/// A registry package's tuple, `[id, host, meta, integrity]`, not bundled into its parent.
fn registry(tuple: &J) -> Option<(&str, &J, &str)> {
    let [id, _, meta, integrity] = tuple.as_array()?.as_slice() else { return None };
    (meta["bundled"] != J::Bool(true)).then_some((id.as_str()?, meta, integrity.as_str()?))
}

fn strings(v: &J) -> Vec<String> {
    match v {
        J::Array(a) => a.iter().filter_map(|s| s.as_str()).map(str::to_string).collect(),
        J::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Edge {
    Required,
    Optional,
    /// Settled where something else installs the package; it installs nothing itself, as npm
    /// and pnpm have it.
    OptionalPeer,
}

/// An optional peer: who declares it, its name, jpm's edge, and bun's folder and id for it.
type Peer = (String, String, Option<String>, Option<(String, String)>);

/// What in `lock` differs from what bun installs, each a line: the packages bun reaches from the
/// root through registry edges, each at the version its folder holds, and the edge to each.
fn unfaithful(case: &Case, lock: &Lockfile) -> Vec<String> {
    let doc = doc(case);
    let empty = serde_json::Map::new();
    let listed = doc["packages"].as_object().unwrap_or(&empty);
    let mut out = Vec::new();
    // The edge an install makes to the folder at `path`, as jpm writes it, and the key it reaches.
    let edge = |path: &str, id: &str| {
        let (real, version) = split_id(id);
        if real == *names(path).last().unwrap() { version } else { alias_edge(&real, &version) }
    };
    let key = |path: &str, id: &str| format!("{}@{}", names(path).last().unwrap(), edge(path, id));
    let declared = |meta: &J, root: bool| {
        let optional_peers = strings(&meta["optionalPeers"]);
        let mut all: Vec<(String, Edge)> = Vec::new();
        for group in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            for dep in meta[group].as_object().into_iter().flatten().map(|(d, _)| d) {
                let peer = group == "peerDependencies";
                let kind = match group {
                    // The root's optional peers are not installed; its required ones are.
                    _ if peer && root && optional_peers.contains(dep) => continue,
                    _ if peer && optional_peers.contains(dep) => Edge::OptionalPeer,
                    // A package's missing peer is a warning, not a refusal.
                    _ if peer && !root => Edge::Optional,
                    "optionalDependencies" => Edge::Optional,
                    _ => Edge::Required,
                };
                all.push((dep.clone(), kind));
            }
        }
        all
    };
    // Optional peers, checked once all else is reached.
    let mut peers: Vec<Peer> = Vec::new();
    let mut check = |from: Option<&str>, edges: &Deps, deps: Vec<(String, Edge)>, out: &mut Vec<String>| {
        let who = from.unwrap_or("package.json");
        let mut reached = Vec::new();
        for (dep, kind) in deps {
            let at = bun_at(listed, from, &dep);
            let mine = edges.get(&dep);
            // A bundled copy comes inside its parent's tarball: no edge, no package.
            if at.as_ref().is_some_and(|(_, t)| t[2]["bundled"] == J::Bool(true)) {
                if let Some(v) = mine {
                    out.push(format!("{who}: {dep} is {v}, and bun has it bundled"));
                }
                continue;
            }
            let found = at.and_then(|(p, t)| Some((p.clone(), registry(t)?.0.to_string())));
            if kind == Edge::OptionalPeer {
                peers.push((who.to_string(), dep, mine.cloned(), found));
                continue;
            }
            match (found, mine) {
                (Some((path, id)), Some(v)) if *v == edge(&path, &id) => reached.push(path),
                (Some((path, id)), Some(v)) => out.push(format!("{who}: {dep} is {v}, bun's {}", edge(&path, &id))),
                (Some((path, id)), None) => out.push(format!("{who}: no edge to {dep}, bun's {}", edge(&path, &id))),
                (None, Some(v)) => out.push(format!("{who}: {dep} is {v}, and bun installs none")),
                // A missing required edge is the import's to refuse; it did not.
                (None, None) if kind == Edge::Required => out.push(format!("{who}: bun installs no {dep}")),
                (None, None) => {}
            }
        }
        reached
    };
    let mut queue = check(None, &lock.root.dependencies, declared(&doc["workspaces"][""], true), &mut out);
    let mut seen: BTreeSet<String> = queue.iter().cloned().collect();
    let mut want = BTreeSet::new();
    while let Some(path) = queue.pop() {
        let (id, meta, integrity) = registry(&listed[&path]).unwrap();
        let key = key(&path, id);
        want.insert(key.clone());
        let Some(entry) = lock.packages.get(&key) else {
            out.push(format!("{path}: {key} is not in the lock"));
            continue;
        };
        if !same_integrity(&entry.integrity, integrity) {
            out.push(format!("{key}: integrity {} for {integrity}", entry.integrity));
        }
        if entry.os != strings(&meta["os"]) || entry.cpu != strings(&meta["cpu"]) {
            out.push(format!("{key}: os {:?} cpu {:?} for {} {}", entry.os, entry.cpu, meta["os"], meta["cpu"]));
        }
        if meta.get("bin").is_some() && entry.bin.is_empty() {
            out.push(format!("{key}: no bins for {}", meta["bin"]));
        }
        let mut edges = entry.dependencies.clone();
        edges.extend(entry.optional_dependencies.clone());
        for next in check(Some(&path), &edges, declared(meta, false), &mut out) {
            if seen.insert(next.clone()) {
                queue.push(next);
            }
        }
    }
    for (who, dep, mine, found) in peers {
        let settled = found.filter(|(path, id)| want.contains(&key(path, id)));
        let theirs = settled.as_ref().map(|(path, id)| edge(path, id));
        if mine != theirs {
            out.push(format!("{who}: optional peer {dep} is {mine:?}, bun's installed one {theirs:?}"));
        }
    }
    for key in lock.packages.keys().filter(|k| !want.contains(*k)) {
        out.push(format!("{key} is in the lock, and bun installs no such package"));
    }
    out
}

#[test]
fn bun_lock_imports_faithfully_or_refuses() {
    let base = std::env::temp_dir().join(format!("jpm-bun-lock-{}", std::process::id()));
    let mut failures = Vec::new();
    let (mut imported, mut refused) = (0, 0);
    for (i, case) in cases().iter().enumerate() {
        let dir: PathBuf = base.join(i.to_string());
        let what = format!("{} ({})", case.name, case.from);
        if let Err(e) = prefer("bun.lock", &case.lock) {
            failures.push(format!("{what}: prefer refused: {}", e.message));
        }
        let expected = REFUSED.iter().find(|(n, _, _)| *n == case.name);
        match (import(case, &dir), expected) {
            (Ok(loaded), None) => {
                imported += 1;
                let wrong = unfaithful(case, &loaded.lock);
                if !wrong.is_empty() {
                    failures.push(format!("{what}: not faithful"));
                    failures.extend(wrong.iter().take(8).map(|w| format!("    {w}")));
                }
            }
            (Ok(_), Some((_, message, _))) => failures.push(format!("{what}: imported; expected {message:?}")),
            (Err(e), Some((_, message, _))) if e.message.contains(message) => refused += 1,
            (Err(e), _) => failures.push(format!("{what}: refused: [{}] {}", e.code, e.message)),
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    let cases = cases();
    for (name, ..) in REFUSED {
        assert!(cases.iter().any(|c| c.name == *name), "no case named {name:?}");
    }
    assert!(failures.is_empty(), "{imported} imported, {refused} refused as expected;\n{}", failures.join("\n"));
}

/// bun.lock records the overrides bun read, not package.json's text: a `$name` read, yarn's and
/// pnpm's paths nested under their parent, a `//` comment left out. Pairs from bun's
/// test/cli/install/nested-overrides.test.ts, whose snapshots show what bun writes for each.
#[test]
fn reads_the_overrides_bun_wrote() {
    let lock = |overrides: J| {
        serde_json::json!({
            "lockfileVersion": 3,
            "workspaces": { "": { "dependencies": { "no-deps": "1.1.0", "one-dep": "1.0.0" } } },
            "overrides": overrides,
            "packages": {
                "no-deps": ["no-deps@1.1.0", "", {}, "sha512-n"],
                "one-dep": ["one-dep@1.0.0", "", { "dependencies": { "no-deps": "1.0.1" } }, "sha512-o"],
                "one-dep/no-deps": ["no-deps@2.0.0", "", {}, "sha512-t"],
            },
        })
        .to_string()
    };
    let deps = serde_json::json!({ "no-deps": "1.1.0", "one-dep": "1.0.0" });
    let nested = serde_json::json!({ "one-dep": { "no-deps": "2.0.0" } });
    let base = std::env::temp_dir().join(format!("jpm-bun-overrides-{}", std::process::id()));
    let run = |i: usize, field: &str, given: J, recorded: J| {
        let manifest = serde_json::json!({ "dependencies": deps, field: given });
        let case = Case { name: String::new(), from: String::new(), manifest, lock: lock(recorded) };
        import(&case, &base.join(i.to_string())).map(|l| l.lock.root.overrides.len())
    };
    assert_eq!(run(0, "overrides", nested.clone(), nested.clone()).unwrap(), 1);
    let by_name = serde_json::json!({ "one-dep": { "no-deps": "$no-deps" } });
    assert_eq!(run(1, "overrides", by_name, serde_json::json!({ "one-dep": { "no-deps": "1.1.0" } })).unwrap(), 1);
    for (i, path) in ["one-dep/no-deps", "**/one-dep/no-deps"].into_iter().enumerate() {
        let yarn = serde_json::json!({ path: "2.0.0" });
        assert_eq!(run(2 + i, "resolutions", yarn, nested.clone()).unwrap(), 1, "{path}");
    }
    let scoped = serde_json::json!({ "@scoped/app/@types/no-deps": "1.0.0" });
    let under = serde_json::json!({ "@scoped/app": { "@types/no-deps": "1.0.0" } });
    assert_eq!(run(4, "resolutions", scoped, under).unwrap(), 1);
    let parent = serde_json::json!({ "one-dep": { ".": "1.0.0", "no-deps": "2.0.0" } });
    assert_eq!(run(5, "overrides", parent.clone(), parent).unwrap(), 2);
    // Other rules are still other rules.
    let stale = run(6, "overrides", nested.clone(), serde_json::json!({ "one-dep": { "no-deps": "1.0.0" } }));
    assert!(stale.unwrap_err().message.contains("out of date"));
    let stale = run(7, "resolutions", serde_json::json!({ "no-deps": "2.0.0" }), nested);
    assert!(stale.unwrap_err().message.contains("out of date"));
    let _ = std::fs::remove_dir_all(&base);
}
