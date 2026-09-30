//! End to end: yarn berry's acceptance scenarios, run against jpm.
//!
//! Ported from yarnpkg/berry (https://github.com/yarnpkg/berry) at commit
//! e4e423a1eb117b5129f20ac626a03eb7a97aedff, BSD 2-Clause License, Copyright (c) 2016-present,
//! Yarn Contributors: the scenarios of `packages/acceptance-tests/pkg-tests-specs/sources`
//! (dragon.test.js and others, named above each test) and the manifests of the fixture packages
//! in `pkg-tests-fixtures/packages` they install, re-created on the mock registry.
//!
//! Yarn checks what `require` returns from inside each package. jpm's layout is isolated, as
//! pnpm's is, so these check the same thing without Node: which package, and which copy of it,
//! Node's resolution reaches from inside each package (`resolve`). Assertions that hold only
//! for Plug'n'Play, or only for a hoisted node_modules, are left out; each test says what.
//!
//! Left out whole: the .pnp.cjs runtime (pnp.test.js, pnpapi, require.test.js: Node's own
//! resolution), yarn's hoister and its settings (nmHoistingLimits, nmMode, winLinkType, focus,
//! self references, `node_modules/.yarn-state.yml`), yarn's @types optional peers, portals
//! outside the project, packageExtensions, and `enableTransparentWorkspaces`.

mod common;

use std::path::{Path, PathBuf};

use common::{Env, Registry, pkg};
use serde_json::{Value, json};

/// berry's fixture packages, from their package.json files (the ones these tests install).
fn fixtures() -> Vec<common::Pkg> {
    let plain = |name: &str, versions: &[&str]| versions.iter().map(|v| pkg(name, v, json!({}))).collect::<Vec<_>>();
    let bins = |version: &str| {
        let mut p = pkg(
            "has-bin-entries",
            version,
            json!({
                "bin": {
                    "has-bin-entries": "./bin.js",
                    "has-bin-entries-with-exit-code": "./bin-with-exit-code.js",
                    "has-bin-entries-with-require": "./bin-with-require.js",
                    "has-bin-entries-with-relative-require": "./bin-with-relative-require.js",
                    "has-bin-entries-get-pwd": "./bin-get-pwd.js"
                },
                "dependencies": { "no-deps": "1.0.0" }
            }),
        );
        for bin in ["bin", "bin-with-exit-code", "bin-with-require", "bin-with-relative-require", "bin-get-pwd"] {
            p = p.file(
                &format!("{bin}.js"),
                0o755,
                "#!/usr/bin/env node\nconsole.log(process.argv.slice(2).join('\\n'))\n",
            );
        }
        p
    };
    let peer = |name: &str, range: &str| pkg(name, "1.0.0", json!({ "peerDependencies": { "no-deps": range } }));
    let deps = |name: &str, version: &str, deps: Value| pkg(name, version, json!({ "dependencies": deps }));
    let mut all = vec![
        deps("one-fixed-dep", "1.0.0", json!({ "no-deps": "1.0.0" })),
        deps("one-fixed-dep", "2.0.0", json!({ "no-deps": "2.0.0" })),
        deps("one-range-dep", "1.0.0", json!({ "no-deps": "^1.0.0" })),
        deps("dep-loop-entry", "1.0.0", json!({ "dep-loop-exit": "1.0.0" })),
        deps("dep-loop-exit", "1.0.0", json!({ "dep-loop-entry": "1.0.0" })),
        peer("peer-deps", "*"),
        peer("peer-deps-too", "*"),
        peer("peer-deps-fixed", "^1.0.0"),
        deps("provides-peer-deps-1-0-0", "1.0.0", json!({ "peer-deps": "1.0.0", "no-deps": "1.0.0" })),
        deps("provides-peer-deps-1-0-0-too", "1.0.0", json!({ "peer-deps": "1.0.0", "no-deps": "1.0.0" })),
        deps("provides-peer-deps-2-0-0", "1.0.0", json!({ "peer-deps": "1.0.0", "no-deps": "2.0.0" })),
        deps("peer-deps-lvl0", "1.0.0", json!({ "no-deps": "1.0.0", "peer-deps-lvl1": "1.0.0" })),
        pkg(
            "peer-deps-lvl1",
            "1.0.0",
            json!({ "dependencies": { "peer-deps-lvl2": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        ),
        peer("peer-deps-lvl2", "*"),
        pkg(
            "fallback-peer-deps",
            "1.0.0",
            json!({ "dependencies": { "no-deps": "2.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        ),
        pkg(
            "forward-peer-deps",
            "1.0.0",
            json!({ "dependencies": { "peer-deps": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        ),
        pkg(
            "forward-peer-deps-too",
            "1.0.0",
            json!({ "dependencies": { "peer-deps": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        ),
        deps("broken-peer-deps", "1.0.0", json!({ "peer-deps": "1.0.0" })),
        pkg(
            "optional-peer-deps",
            "1.0.0",
            json!({ "peerDependencies": { "no-deps": "*" }, "peerDependenciesMeta": { "no-deps": { "optional": true } } }),
        ),
        pkg(
            "optional-peer-deps-implicit",
            "1.0.0",
            json!({ "peerDependenciesMeta": { "no-deps": { "optional": true } } }),
        ),
        pkg(
            "peer-deps-implicit-types-conflict",
            "1.0.0",
            json!({ "dependencies": { "@types/no-deps": "2.0.0" }, "peerDependencies": { "no-deps": "1.0.0" } }),
        ),
        pkg(
            "mismatched-peer-deps-lvl0",
            "1.0.0",
            json!({ "dependencies": { "mismatched-peer-deps-lvl1": "*" }, "peerDependencies": { "no-deps": "<=1.1.0" } }),
        ),
        pkg(
            "mismatched-peer-deps-lvl1",
            "1.0.0",
            json!({ "dependencies": { "mismatched-peer-deps-lvl2": "*" }, "peerDependencies": { "no-deps": "<=1.0.1" } }),
        ),
        peer("mismatched-peer-deps-lvl2", "1.0.0"),
        pkg(
            "hoisting-peer-check-parent",
            "1.0.0",
            json!({ "dependencies": { "hoisting-peer-check-child": "1.0.0", "no-deps": "2.0.0" } }),
        ),
        pkg("hoisting-peer-check-child", "1.0.0", json!({ "peerDependencies": { "no-deps": "2.0.0" } })),
        deps("self-require-dep", "1.0.0", json!({ "various-requires": "1.0.0" })),
        pkg("self-require-trap", "1.0.0", json!({ "dependencies": { "self-require-trap": "2.0.0" }, "bin": "./bin" }))
            .file("bin", 0o755, "#!/usr/bin/env node\n"),
        bins("1.0.0"),
        bins("2.0.0"),
        deps("one-dep-alias-bins", "1.0.0", json!({ "@fixture/old": "npm:has-bin-entries@1.0.0" })),
        pkg("no-deps-bins", "1.0.0", json!({ "bin": "./bin" })).file("bin", 0o755, "#!/usr/bin/env node\n"),
        pkg("no-deps-tags", "1.0.0", json!({ "dist-tags": { "latest": "1.0.0", "rc": "1.0.0-rc.1" } })),
        pkg("no-deps-tags", "1.0.0-rc.1", json!({ "dist-tags": { "latest": "1.0.0", "rc": "1.0.0-rc.1" } })),
        pkg("no-deps-failing", "1.0.0", json!({ "scripts": { "install": "exit 1" } })),
        deps(
            "native",
            "1.0.0",
            json!({ "native-bar-x64": "1.0.0", "native-foo-x64": "1.0.0", "native-foo-x86": "1.0.0" }),
        ),
        pkg("native-bar-x64", "1.0.0", json!({ "os": ["bar"], "cpu": ["x64"] })),
        pkg("native-foo-x64", "1.0.0", json!({ "os": ["foo"], "cpu": ["x64"] })),
        pkg("native-foo-x86", "1.0.0", json!({ "os": ["foo"], "cpu": ["x86"] })),
        pkg(
            "optional-native",
            "1.0.0",
            json!({ "optionalDependencies": { "native-bar-x64": "1.0.0", "native-foo-x64": "1.0.0", "native-foo-x86": "1.0.0" } }),
        ),
        pkg(
            "unconventional-tarball",
            "1.0.0",
            json!({ "dist": { "tarball": "/tralala/unconventional-tarball-1.0.0.tgz" } }),
        ),
        // The dragons.
        pkg("dragon-test-1-a", "1.0.0", json!({})),
        deps("dragon-test-1-b", "1.0.0", json!({ "dragon-test-1-a": "1.0.0" })),
        pkg("dragon-test-1-b", "2.0.0", json!({})),
        deps("dragon-test-1-c", "1.0.0", json!({ "dragon-test-1-b": "1.0.0" })),
        deps("dragon-test-1-d", "1.0.0", json!({ "dragon-test-1-c": "1.0.0" })),
        deps("dragon-test-1-e", "1.0.0", json!({ "dragon-test-1-b": "2.0.0", "dragon-test-1-c": "1.0.0" })),
        pkg(
            "dragon-test-3-a",
            "1.0.0",
            json!({ "dependencies": { "dragon-test-3-b": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        ),
        pkg("dragon-test-3-b", "1.0.0", json!({ "peerDependencies": { "dragon-test-3-a": "*" } })),
        deps("dragon-test-7-a", "1.0.0", json!({ "dragon-test-7-b": "1.0.0", "dragon-test-7-c": "2.0.0" })),
        deps("dragon-test-7-b", "1.0.0", json!({ "dragon-test-7-c": "1.0.0" })),
        pkg("dragon-test-7-b", "2.0.0", json!({})),
        deps("dragon-test-7-d", "1.0.0", json!({ "dragon-test-7-b": "1.0.0" })),
        deps(
            "dragon-test-8-a",
            "1.0.0",
            json!({ "dragon-test-8-b": "1.0.0", "dragon-test-8-c": "1.0.0", "dragon-test-8-d": "1.0.0" }),
        ),
        pkg(
            "dragon-test-8-b",
            "1.0.0",
            json!({ "peerDependencies": { "dragon-test-8-c": "1.0.0", "dragon-test-8-d": "1.0.0" } }),
        ),
        pkg("dragon-test-8-c", "1.0.0", json!({})),
        pkg("dragon-test-8-d", "1.0.0", json!({ "peerDependencies": { "dragon-test-8-c": "*" } })),
        pkg(
            "dragon-test-11-a",
            "1.0.0",
            json!({ "dependencies": { "dragon-test-11-b": "1.0.0" }, "peerDependenciesMeta": { "does-not-matter": { "optional": true } } }),
        ),
        pkg("dragon-test-11-b", "1.0.0", json!({ "peerDependencies": { "dragon-test-11-a": "*" } })),
    ];
    all.extend(plain("no-deps", &["1.0.0", "1.0.1", "1.1.0", "2.0.0"]));
    all.extend(plain("@types/no-deps", &["1.0.0", "2.0.0"]));
    all.extend(plain("various-requires", &["1.0.0"]));
    all.extend(plain("self-require-trap", &["2.0.0"]));
    all.extend(plain("prerelease-only", &["1.0.0-rc.1", "1.0.0-rc.2"]));
    all.extend(plain("no-deps-build-metadata", &["1.0.0+123"]));
    all.extend(plain("dragon-test-7-c", &["1.0.0", "2.0.0", "3.0.0"]));
    // Peers dragons 10 and 12 name and yarn's registry lacks: yarn leaves a peer unmet, jpm
    // installs a required one as npm and pnpm do, and those fail on a name no registry has.
    all.extend(plain("anything", &["1.0.0"]));
    all.extend(plain("whatever", &["1.0.0"]));
    all
}

fn berry() -> Registry {
    let r = Registry::start(fixtures());
    let odd = fixtures().into_iter().find(|p| p.name == "unconventional-tarball").unwrap();
    r.serve("/tralala/unconventional-tarball-1.0.0.tgz", odd.tarball());
    r
}

/// Where Node's `require(name)` from inside `from` lands, as Node finds it: from the real path
/// of the requiring package, each ancestor's `node_modules` (never one under a `node_modules`
/// itself), up to the scratch directory. The real path of what it finds, or None.
fn resolve(env: &Env, from: &Path, name: &str) -> Option<PathBuf> {
    let top = std::fs::canonicalize(&env.root).ok()?;
    let real = std::fs::canonicalize(from).ok()?;
    let mut at = Some(real.as_path());
    while let Some(dir) = at.filter(|d| d.starts_with(&top)) {
        if dir.file_name() != Some("node_modules".as_ref()) {
            let hit = dir.join("node_modules").join(name);
            if hit.join("package.json").is_file() {
                return std::fs::canonicalize(hit).ok();
            }
        }
        at = dir.parent();
    }
    None
}

/// Follows `require` from the project directory `from` through `chain`, each name required
/// from inside the package before it, as the fixtures' index.js does.
fn walk(env: &Env, from: &str, chain: &[&str]) -> Option<PathBuf> {
    let mut at = env.project().join(from);
    for name in chain {
        at = resolve(env, &at, name)?;
    }
    Some(at)
}

/// The `name@version` that `walk` reaches, or "missing".
fn id(env: &Env, from: &str, chain: &[&str]) -> String {
    let Some(dir) = walk(env, from, chain) else { return "missing".into() };
    let m: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("package.json")).unwrap()).unwrap();
    format!("{}@{}", m["name"].as_str().unwrap(), m["version"].as_str().unwrap_or(""))
}

/// Installs `manifest` with `files` beside it.
fn install(r: &Registry, manifest: Value, files: &[(&str, Value)]) -> Env {
    let env = Env::new(r);
    env.manifest(manifest);
    for (dir, m) in files {
        env.write(&format!("{dir}/package.json"), &serde_json::to_string_pretty(m).unwrap());
    }
    env.ok(&["install"]);
    env
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "jpm {args:?} succeeded:\n{text}");
    text
}

// dragon.test.js

#[test]
fn dragon_1_a_branch_hoisted_away_keeps_its_versions() {
    // . -> D -> C -> B@1 -> A
    //   -> E -> B@2
    //        -> C -> B@1 -> A
    // Yarn crashed hoisting A out of a branch it had removed; here each keeps its own B.
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "dragon-test-1-d": "1.0.0", "dragon-test-1-e": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["dragon-test-1-e", "dragon-test-1-b"]), "dragon-test-1-b@2.0.0");
    assert_eq!(id(&env, "", &["dragon-test-1-e", "dragon-test-1-c", "dragon-test-1-b"]), "dragon-test-1-b@1.0.0");
    assert_eq!(
        walk(&env, "", &["dragon-test-1-e", "dragon-test-1-c"]),
        walk(&env, "", &["dragon-test-1-d", "dragon-test-1-c"])
    );
    assert_eq!(
        id(&env, "", &["dragon-test-1-d", "dragon-test-1-c", "dragon-test-1-b", "dragon-test-1-a"]),
        "dragon-test-1-a@1.0.0"
    );
}

#[test]
fn dragon_2_a_workspace_with_a_peer_under_another_workspace() {
    // . -> A (workspace) -> B (workspace) --> no-deps (peer)
    //                    -> no-deps@1.0.0
    // A can always require B, and B's peer is A's no-deps.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["dragon-test-2-a", "dragon-test-2-b"], "dependencies": { "dragon-test-2-a": "1.0.0" } }),
        &[
            (
                "dragon-test-2-a",
                json!({ "name": "dragon-test-2-a", "version": "1.0.0", "dependencies": { "dragon-test-2-b": "1.0.0", "no-deps": "1.0.0" } }),
            ),
            (
                "dragon-test-2-b",
                json!({ "name": "dragon-test-2-b", "version": "1.0.0", "peerDependencies": { "no-deps": "*" } }),
            ),
        ],
    );
    assert_eq!(id(&env, "", &["dragon-test-2-a", "dragon-test-2-b"]), "dragon-test-2-b@1.0.0");
    assert_eq!(id(&env, "", &["dragon-test-2-a", "dragon-test-2-b", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn dragon_3_a_peer_on_the_parent_that_has_peers_of_its_own() {
    // . -> A -> B --> A (peer)
    //        --> no-deps (peer, missing)
    // Instantiating A for its peer, then B for its peer on A, must not loop.
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "dragon-test-3-a": "1.0.0" } }), &[]);
    assert_eq!(
        walk(&env, "", &["dragon-test-3-a", "dragon-test-3-b", "dragon-test-3-a"]),
        walk(&env, "", &["dragon-test-3-a"])
    );
}

#[test]
fn dragon_4_a_workspace_peer_that_is_also_its_dev_dependency() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["my-workspace"] }),
        &[(
            "my-workspace",
            json!({
                "name": "my-workspace",
                "peerDependencies": { "no-deps": "*", "peer-deps": "*" },
                "devDependencies": { "no-deps": "1.0.0", "peer-deps": "1.0.0" }
            }),
        )],
    );
    assert_eq!(id(&env, "my-workspace", &["peer-deps"]), "peer-deps@1.0.0");
    assert_eq!(id(&env, "my-workspace", &["peer-deps", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn dragon_5_a_workspace_with_peers_under_another_workspace() {
    // . -> A -> X -> Y (peer deps)
    //        -> Y
    //        -> Z (peer deps)
    //   -> B -> A
    //        -> Z
    // Yarn virtualized A's dependencies once and saw them changed on B's pass.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"] }),
        &[
            (
                "packages/a",
                json!({
                    "name": "a",
                    "peerDependencies": { "various-requires": "*" },
                    "devDependencies": { "no-deps": "1.0.0", "peer-deps": "1.0.0" }
                }),
            ),
            (
                "packages/b",
                json!({ "name": "b", "devDependencies": { "a": "workspace:*", "various-requires": "1.0.0" } }),
            ),
        ],
    );
    assert_eq!(id(&env, "packages/b", &["a", "peer-deps", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "packages/b", &["various-requires"]), "various-requires@1.0.0");
}

#[test]
fn dragon_6_workspaces_peering_on_each_other() {
    // Yarn unified virtual copies and lost a dependent on the way; the install must finish and
    // each workspace reach the others it names.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"] }),
        &[
            ("packages/a", json!({ "name": "a", "dependencies": { "z": "workspace:*" } })),
            ("packages/b", json!({ "name": "b", "dependencies": { "u": "workspace:*", "v": "workspace:*" } })),
            (
                "packages/c",
                json!({ "name": "c", "dependencies": { "u": "workspace:*", "v": "workspace:*", "y": "workspace:*", "z": "workspace:*" } }),
            ),
            ("packages/u", json!({ "name": "u" })),
            ("packages/v", json!({ "name": "v", "peerDependencies": { "u": "*" } })),
            ("packages/y", json!({ "name": "y", "peerDependencies": { "v": "*" } })),
            (
                "packages/z",
                json!({ "name": "z", "dependencies": { "y": "workspace:*" }, "peerDependencies": { "v": "*" } }),
            ),
        ],
    );
    let real = |p: &str| std::fs::canonicalize(env.path(p)).ok();
    assert_eq!(walk(&env, "packages/c", &["z", "y"]), real("packages/y"));
    assert_eq!(walk(&env, "packages/c", &["v", "u"]), real("packages/u"));
}

#[test]
fn dragon_7_one_package_twice_under_different_parents() {
    // . -> A -> B@1 -> C@1
    //        -> C@2
    //   -> D -> B@1 -> C@1
    //   -> B@2
    //   -> C@3
    // Both B@1 get C@1. (Yarn also checks where its hoister put each copy: layout only.)
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "dependencies": {
            "dragon-test-7-a": "1.0.0", "dragon-test-7-d": "1.0.0", "dragon-test-7-b": "2.0.0", "dragon-test-7-c": "3.0.0"
        } }),
        &[],
    );
    assert_eq!(id(&env, "", &["dragon-test-7-a", "dragon-test-7-b", "dragon-test-7-c"]), "dragon-test-7-c@1.0.0");
    assert_eq!(id(&env, "", &["dragon-test-7-d", "dragon-test-7-b", "dragon-test-7-c"]), "dragon-test-7-c@1.0.0");
    assert_eq!(id(&env, "", &["dragon-test-7-a", "dragon-test-7-c"]), "dragon-test-7-c@2.0.0");
    assert_eq!(id(&env, "", &["dragon-test-7-b"]), "dragon-test-7-b@2.0.0");
    assert_eq!(id(&env, "", &["dragon-test-7-c"]), "dragon-test-7-c@3.0.0");
}

#[test]
fn dragon_8_copies_with_the_same_peers_are_one() {
    // . -> A -> B --> C
    //             --> D
    //        -> C
    //        -> D --> C
    //   -> B --> C
    //        --> D
    //   -> C
    //   -> D --> C
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "dependencies": {
            "dragon-test-8-a": "1.0.0", "dragon-test-8-b": "1.0.0", "dragon-test-8-c": "1.0.0", "dragon-test-8-d": "1.0.0"
        } }),
        &[],
    );
    assert_eq!(walk(&env, "", &["dragon-test-8-a", "dragon-test-8-b"]), walk(&env, "", &["dragon-test-8-b"]));
    assert_eq!(walk(&env, "", &["dragon-test-8-a", "dragon-test-8-d"]), walk(&env, "", &["dragon-test-8-d"]));
}

#[test]
fn dragon_9_two_aliases_of_one_package_with_peers_are_one_copy() {
    // yarnpkg/berry#1352: `second` was deduped out of existence.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "dependencies": { "first": "npm:peer-deps@1.0.0", "second": "npm:peer-deps@1.0.0", "no-deps": "1.0.0" } }),
        &[],
    );
    assert!(walk(&env, "", &["first"]).is_some());
    assert_eq!(walk(&env, "", &["first"]), walk(&env, "", &["second"]));
    assert_eq!(id(&env, "", &["second", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn dragon_10_a_workspace_peer_on_the_workspace_that_depends_on_it() {
    // c -> b --> c (peer), c --> anything (peer, on no registry): c's b sees c itself.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"] }),
        &[
            ("packages/a", json!({ "name": "a", "devDependencies": { "b": "workspace:*" } })),
            (
                "packages/b",
                json!({ "name": "b", "peerDependencies": { "c": "*" }, "devDependencies": { "c": "workspace:*" } }),
            ),
            (
                "packages/c",
                json!({ "name": "c", "peerDependencies": { "anything": "*" }, "dependencies": { "b": "workspace:*" } }),
            ),
        ],
    );
    assert_eq!(walk(&env, "packages/c", &["b", "c"]), std::fs::canonicalize(env.path("packages/c")).ok());
}

#[test]
fn dragon_11_a_peer_named_for_a_package_the_root_aliases() {
    // . -> aliased (dragon-test-11-a) -> dragon-test-11-b --> dragon-test-11-a (peer)
    // yarnpkg/berry#3630: b's peer is the aliased package itself, under its own name. Yarn
    // expects this of its pnp and pnpm linkers (its hoisting linker cannot).
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "aliased": "npm:dragon-test-11-a@1.0.0" } }), &[]);
    let root = walk(&env, "", &["aliased"]);
    assert!(root.is_some());
    assert_eq!(walk(&env, "", &["aliased", "dragon-test-11-b", "dragon-test-11-a"]), root);
}

#[test]
fn dragon_12_a_workspace_with_peers_depending_on_a_package_and_its_alias() {
    let r = berry();
    let env = install(
        &r,
        json!({ "workspaces": ["pkg-a", "pkg-b"] }),
        &[
            ("pkg-a", json!({ "name": "pkg-a", "dependencies": { "pkg-b": "workspace:*" } })),
            (
                "pkg-b",
                json!({
                    "name": "pkg-b",
                    "dependencies": { "peer-deps": "1.0.0", "fake-peer-deps": "npm:peer-deps@1.0.0" },
                    "peerDependencies": { "whatever": "*" }
                }),
            ),
        ],
    );
    assert_eq!(id(&env, "pkg-a", &["pkg-b", "fake-peer-deps"]), "peer-deps@1.0.0");
    assert_eq!(walk(&env, "pkg-b", &["peer-deps"]), walk(&env, "pkg-b", &["fake-peer-deps"]));
}

#[test]
fn dragon_13_a_package_optional_in_one_workspace_and_required_in_another() {
    // Its build fails: the install fails, the other workspace's `optional` notwithstanding.
    // jpm runs a dependency's install script only once approved: `jpm approve` runs it.
    let r = berry();
    let env = install(
        &r,
        json!({ "workspaces": ["pkg-a", "pkg-b"] }),
        &[
            ("pkg-a", json!({ "name": "pkg-a", "optionalDependencies": { "no-deps-failing": "1.0.0" } })),
            ("pkg-b", json!({ "name": "pkg-b", "dependencies": { "no-deps-failing": "1.0.0" } })),
        ],
    );
    let out = fails(&env, &["approve", "no-deps-failing"]);
    assert!(out.contains("no-deps-failing@1.0.0 install failed"), "{out}");
    assert!(!out.contains("skipped optional"), "{out}");
}

#[test]
fn dragon_14_one_package_under_two_aliases_in_two_workspaces() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["pkg-a", "pkg-b"] }),
        &[
            ("pkg-a", json!({ "name": "a", "dependencies": { "alias-1": "npm:peer-deps@1.0.0", "no-deps": "1.0.0" } })),
            ("pkg-b", json!({ "name": "b", "dependencies": { "alias-2": "npm:peer-deps@1.0.0", "no-deps": "1.0.0" } })),
        ],
    );
    assert!(walk(&env, "pkg-a", &["alias-1"]).is_some());
    assert_eq!(walk(&env, "pkg-a", &["alias-1"]), walk(&env, "pkg-b", &["alias-2"]));
}

#[test]
fn dragon_15_one_package_under_two_aliases_in_one_workspace() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["pkg-a", "pkg-b"] }),
        &[
            ("pkg-a", json!({ "name": "a", "dependencies": { "alias-1": "npm:peer-deps@1.0.0", "no-deps": "1.0.0" } })),
            (
                "pkg-b",
                json!({ "name": "b", "dependencies": {
                    "alias-1": "npm:peer-deps@1.0.0", "alias-2": "npm:peer-deps@1.0.0", "no-deps": "1.0.0"
                } }),
            ),
        ],
    );
    let one = walk(&env, "pkg-a", &["alias-1"]);
    assert!(one.is_some());
    assert_eq!(walk(&env, "pkg-b", &["alias-1"]), one);
    assert_eq!(walk(&env, "pkg-b", &["alias-2"]), one);
}

// basic.test.js (its pnpm and node-modules linker runs)

#[test]
fn basic_installs_plain_scoped_aliased_fixed_and_ranged_dependencies() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": {
            "@types/no-deps": "1.0.0", "aliased": "npm:no-deps@1.0.0", "one-fixed-dep": "1.0.0", "one-range-dep": "1.0.0"
        } }),
        &[],
    );
    assert_eq!(id(&env, "", &["@types/no-deps"]), "@types/no-deps@1.0.0");
    assert_eq!(id(&env, "", &["aliased"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["one-range-dep", "no-deps"]), "no-deps@1.1.0");
}

#[test]
fn basic_installs_a_dependency_loop() {
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "dep-loop-entry": "1.0.0" } }), &[]);
    let entry = walk(&env, "", &["dep-loop-entry"]);
    assert!(entry.is_some());
    assert_eq!(walk(&env, "", &["dep-loop-entry", "dep-loop-exit", "dep-loop-entry"]), entry);
}

#[test]
fn basic_installs_from_archives_urls_and_directories() {
    // With the dependencies of each: the archive's, the URL's and the directory's no-deps.
    let r = berry();
    let env = Env::new(&r);
    let fixed = fixtures().into_iter().find(|p| p.name == "one-fixed-dep" && p.version == "1.0.0").unwrap();
    std::fs::create_dir_all(env.project().join("archives")).unwrap();
    std::fs::write(env.project().join("archives/one-fixed-dep.tgz"), fixed.tarball()).unwrap();
    env.write(
        "dir/package.json",
        r#"{ "name": "one-fixed-dep", "version": "1.0.0", "dependencies": { "no-deps": "1.0.0" } }"#,
    );
    env.manifest(json!({ "dependencies": {
        "from-archive": "file:./archives/one-fixed-dep.tgz",
        "from-url": format!("{}/one-fixed-dep/-/one-fixed-dep-1.0.0.tgz", r.url),
        "from-dir": "file:./dir",
        "linked": "link:./dir"
    } }));
    env.ok(&["install"]);
    for name in ["from-archive", "from-url", "from-dir"] {
        assert_eq!(id(&env, "", &[name]), "one-fixed-dep@1.0.0", "{name}");
        assert_eq!(id(&env, "", &[name, "no-deps"]), "no-deps@1.0.0", "{name}");
    }
    assert_eq!(id(&env, "", &["linked"]), "one-fixed-dep@1.0.0");
}

#[test]
fn basic_peers_resolve_from_the_top_level_from_a_dependency_and_two_levels_deep() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "peer-deps": "1.0.0", "no-deps": "1.0.0", "provides-peer-deps-1-0-0": "1.0.0", "peer-deps-lvl0": "1.0.0" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["peer-deps", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["provides-peer-deps-1-0-0", "peer-deps", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["peer-deps-lvl0", "peer-deps-lvl1", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["peer-deps-lvl0", "peer-deps-lvl1", "peer-deps-lvl2", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn basic_a_peer_wins_over_the_same_regular_dependency_it_falls_back_to() {
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "fallback-peer-deps": "1.0.0", "no-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["fallback-peer-deps", "no-deps"]), "no-deps@1.0.0");
    let env = install(&r, json!({ "dependencies": { "fallback-peer-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["fallback-peer-deps", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn basic_falls_back_to_the_dependency_when_the_parent_lacks_the_peer() {
    // . -> lib (file:) -> fallback-peer-deps --> no-deps (peer; its own dependency is 2.0.0)
    //             --> no-deps (peer, missing)
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "lib": "file:./lib" } }),
        &[(
            "lib",
            json!({ "name": "lib", "dependencies": { "fallback-peer-deps": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
        )],
    );
    assert_eq!(id(&env, "", &["lib", "fallback-peer-deps", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn basic_packages_require_themselves() {
    // By their own name under an alias too, as pnpm has it: the files are under that name.
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "various-requires": "1.0.0", "self-require-dep": "1.0.0", "vr": "npm:various-requires@1.0.0" } }),
        &[],
    );
    let own = walk(&env, "", &["various-requires"]);
    assert!(own.is_some());
    assert_eq!(walk(&env, "", &["various-requires", "various-requires"]), own);
    assert_eq!(id(&env, "", &["self-require-dep", "various-requires", "various-requires"]), "various-requires@1.0.0");
    assert_eq!(walk(&env, "", &["vr", "various-requires"]), walk(&env, "", &["vr"]));
}

#[test]
fn basic_a_dependency_on_another_version_of_itself() {
    // self-require-trap@1 depends on self-require-trap@2. Yarn has its own name be 2.0.0 from
    // inside; in pnpm's layout, jpm's too, the package's directory has that name, so pnpm links
    // no such dependency and the package requires itself (pnpm's rule; npm nests 2.0.0 in it).
    // Twice, as yarn found a link broken on the second install; and under an alias.
    let r = berry();
    for (dep, spec) in [("self-require-trap", "1.0.0"), ("aliased", "npm:self-require-trap@1.0.0")] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { dep: spec } }));
        for _ in 0..2 {
            env.ok(&["install"]);
            assert_eq!(id(&env, "", &[dep]), "self-require-trap@1.0.0");
            assert_eq!(id(&env, "", &[dep, "self-require-trap"]), "self-require-trap@1.0.0");
        }
    }
}

#[test]
fn basic_installs_a_portal() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "soft-link": "portal:./soft-link" } }),
        &[("soft-link", json!({ "name": "soft-link", "version": "1.0.0" }))],
    );
    assert_eq!(id(&env, "", &["soft-link"]), "soft-link@1.0.0");
}

// pnp.test.js: what holds for any linker (the rest checks the .pnp.cjs runtime)

#[test]
fn pnp_identical_packages_share_one_copy_of_a_dependency() {
    // Two directory copies of one-fixed-dep: their no-deps is one copy, the root's when it is
    // the same version (easy), another when it is not (complex).
    let r = berry();
    let fixed = json!({ "name": "one-fixed-dep", "version": "1.0.0", "dependencies": { "no-deps": "1.0.0" } });
    for (root, same) in [("1.0.0", true), ("2.0.0", false)] {
        let env = install(
            &r,
            json!({ "dependencies": { "one-fixed-dep-1": "file:./one", "one-fixed-dep-2": "file:./two", "no-deps": root } }),
            &[("one", fixed.clone()), ("two", fixed.clone())],
        );
        let one = walk(&env, "", &["one-fixed-dep-1", "no-deps"]);
        assert!(one.is_some());
        assert_eq!(walk(&env, "", &["one-fixed-dep-2", "no-deps"]), one);
        assert_eq!(walk(&env, "", &["no-deps"]) == one, same, "root no-deps {root}");
    }
}

#[test]
#[ignore = "known gap: jpm keeps one copy of each name@version, so a package's peers are one set; pnpm and yarn make a copy per set of peers"]
fn pnp_identical_packages_with_different_peers_are_different_copies() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "provides-peer-deps-1-0-0": "1.0.0", "provides-peer-deps-2-0-0": "1.0.0" } }),
        &[],
    );
    assert_ne!(
        walk(&env, "", &["provides-peer-deps-1-0-0", "peer-deps"]),
        walk(&env, "", &["provides-peer-deps-2-0-0", "peer-deps"])
    );
    assert_eq!(id(&env, "", &["provides-peer-deps-1-0-0", "peer-deps", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["provides-peer-deps-2-0-0", "peer-deps", "no-deps"]), "no-deps@2.0.0");
    assert_eq!(id(&env, "", &["provides-peer-deps-2-0-0", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn pnp_identical_packages_with_the_same_peers_are_one_copy() {
    let r = berry();
    // Simple: two parents with the same no-deps.
    let env = install(
        &r,
        json!({ "dependencies": { "provides-peer-deps-1-0-0": "1.0.0", "provides-peer-deps-1-0-0-too": "1.0.0" } }),
        &[],
    );
    let one = walk(&env, "", &["provides-peer-deps-1-0-0", "peer-deps"]);
    assert!(one.is_some());
    assert_eq!(walk(&env, "", &["provides-peer-deps-1-0-0-too", "peer-deps"]), one);
    // Complex: two parents that forward the root's no-deps as their own peer.
    let env = install(
        &r,
        json!({ "dependencies": { "forward-peer-deps": "1.0.0", "forward-peer-deps-too": "1.0.0", "no-deps": "1.0.0" } }),
        &[],
    );
    let one = walk(&env, "", &["forward-peer-deps", "peer-deps"]);
    assert!(one.is_some());
    assert_eq!(walk(&env, "", &["forward-peer-deps-too", "peer-deps"]), one);
    assert_eq!(id(&env, "", &["forward-peer-deps", "peer-deps", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn pnp_packages_with_similar_peers_but_other_names_stay_apart() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "peer-deps": "1.0.0", "peer-deps-too": "1.0.0", "no-deps": "1.0.0" } }),
        &[],
    );
    assert_ne!(walk(&env, "", &["peer-deps"]), walk(&env, "", &["peer-deps-too"]));
    assert_eq!(id(&env, "", &["peer-deps-too", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn pnp_a_missing_peer_is_installed() {
    // Yarn leaves it out and its runtime throws MISSING_PEER_DEPENDENCY, naming the ancestor
    // that broke the chain (broken-peer-deps). jpm installs a missing required peer, as npm and
    // pnpm do: the newest.
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "peer-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["peer-deps", "no-deps"]), "no-deps@2.0.0");
    let env = install(&r, json!({ "dependencies": { "broken-peer-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["broken-peer-deps", "peer-deps", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn pnp_a_peer_out_of_the_roots_range_links_the_roots() {
    // Yarn links the root's no-deps 2.0.0 to peer-deps-fixed (^1.0.0) with a warning (YN0060),
    // and so do pnpm and jpm: one copy of the peer, not a second one in its range.
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "peer-deps-fixed": "1.0.0", "no-deps": "1.0.0" } }), &[]);
    assert_eq!(walk(&env, "", &["peer-deps-fixed", "no-deps"]), walk(&env, "", &["no-deps"]));
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "peer-deps-fixed": "1.0.0", "no-deps": "2.0.0" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("unmet peer no-deps@^1.0.0 of peer-deps-fixed@1.0.0"), "{out}");
    assert_eq!(walk(&env, "", &["peer-deps-fixed", "no-deps"]), walk(&env, "", &["no-deps"]));
    assert_eq!(id(&env, "", &["no-deps"]), "no-deps@2.0.0");
}

// features/peerDependenciesMeta.test.ts

#[test]
fn meta_an_optional_peer_is_not_installed() {
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "optional-peer-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["optional-peer-deps", "no-deps"]), "missing");
}

#[test]
fn meta_a_mismatched_peer_below_the_root() {
    // The root's no-deps 1.1.0 is out of the range of mismatched-peer-deps-lvl1 (<=1.0.1) and
    // lvl2 (1.0.0). Yarn warns and links 1.1.0, and so do pnpm and jpm: one copy for all three.
    let r = berry();
    for (top, chain) in [
        ("mismatched-peer-deps-lvl1", &["mismatched-peer-deps-lvl1"][..]),
        ("mismatched-peer-deps-lvl0", &["mismatched-peer-deps-lvl0", "mismatched-peer-deps-lvl1"][..]),
    ] {
        let env = install(&r, json!({ "dependencies": { top: "1.0.0", "no-deps": "1.1.0" } }), &[]);
        let root = walk(&env, "", &["no-deps"]);
        let mut at = chain.to_vec();
        at.push("no-deps");
        assert_eq!(id(&env, "", &at), "no-deps@1.1.0", "{top}");
        assert_eq!(walk(&env, "", &at), root, "{top}");
        at.pop();
        at.extend(["mismatched-peer-deps-lvl2", "no-deps"]);
        assert_eq!(walk(&env, "", &at), root, "{top}");
        if top == "mismatched-peer-deps-lvl0" {
            assert_eq!(walk(&env, "", &[top, "no-deps"]), root);
        }
        assert!(env.lock()["packages"].get("no-deps@1.0.0").is_none(), "{top}");
    }
}

#[test]
fn meta_a_peer_named_only_in_its_meta_is_the_parents() {
    let r = berry();
    let env =
        install(&r, json!({ "dependencies": { "optional-peer-deps-implicit": "1.0.0", "no-deps": "1.0.0" } }), &[]);
    let root = walk(&env, "", &["no-deps"]);
    assert!(root.is_some());
    assert_eq!(walk(&env, "", &["optional-peer-deps-implicit", "no-deps"]), root);
}

#[test]
fn meta_a_dependency_wins_over_the_parents_types_package() {
    // Yarn adds @types/no-deps as an optional peer of whatever peers on no-deps; the package's
    // own @types/no-deps 2.0.0 must still win over the root's 1.0.0.
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "peer-deps-implicit-types-conflict": "1.0.0", "@types/no-deps": "1.0.0" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["@types/no-deps"]), "@types/no-deps@1.0.0");
    assert_eq!(id(&env, "", &["peer-deps-implicit-types-conflict", "@types/no-deps"]), "@types/no-deps@2.0.0");
}

#[test]
fn a_peer_of_a_child_settles_on_the_parents_version() {
    // hoisting-peer-check-*, a fixture with no test of its own: the parent's no-deps 2.0.0,
    // not the root's 1.0.0.
    let r = berry();
    let env =
        install(&r, json!({ "dependencies": { "hoisting-peer-check-parent": "1.0.0", "no-deps": "1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["hoisting-peer-check-parent", "hoisting-peer-check-child", "no-deps"]), "no-deps@2.0.0");
}

// node-modules.test.ts: the outcomes, not where its hoister puts things

#[test]
fn nm_a_workspace_named_like_a_dependency_is_linked_for_a_star() {
    // With enableTransparentWorkspaces off, yarn gives the root's no-deps `*` the registry's
    // 2.0.0. jpm links a workspace a range fits by name, as npm does, and `*` fits any
    // version, a prerelease too (npm's dep-valid).
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"], "dependencies": { "no-deps": "*" } }),
        &[
            (
                "packages/workspace",
                json!({ "name": "workspace", "version": "1.0.0", "dependencies": { "no-deps": "workspace:*" } }),
            ),
            ("packages/no-deps", json!({ "name": "no-deps", "version": "1.0.0-local" })),
        ],
    );
    assert_eq!(id(&env, "", &["no-deps"]), "no-deps@1.0.0-local");
    assert_eq!(id(&env, "packages/workspace", &["no-deps"]), "no-deps@1.0.0-local");
}

fn bin_target(env: &Env, name: &str) -> String {
    let bin = if cfg!(windows) { format!("node_modules/.bin/{name}.cmd") } else { format!("node_modules/.bin/{name}") };
    let path = env.path(&bin);
    match std::fs::read_link(&path) {
        Ok(to) => to.to_string_lossy().into_owned(),
        Err(_) => std::fs::read_to_string(&path).unwrap_or_default(),
    }
}

#[test]
fn nm_a_direct_dependencys_bins_win_over_a_transitive_ones() {
    // @fixture/native is has-bin-entries 2.0.0; has-bin-entries is one-dep-alias-bins, whose
    // @fixture/old is has-bin-entries 1.0.0 with the same bins.
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "@fixture/native": "npm:has-bin-entries@2.0.0", "has-bin-entries": "npm:one-dep-alias-bins@1.0.0" } }),
        &[],
    );
    let to = bin_target(&env, "has-bin-entries-with-relative-require");
    assert!(to.contains("has-bin-entries@2.0.0") || to.contains("@fixture"), "{to}");
    assert!(!to.contains("has-bin-entries@1.0.0"), "{to}");
}

#[test]
fn nm_aliases_in_the_root_and_a_workspace() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"], "dependencies": { "no-deps": "1.0.0", "no-deps2": "npm:no-deps@2.0.0" } }),
        &[(
            "packages/workspace",
            json!({ "name": "workspace", "version": "1.0.0", "dependencies": {
                "no-deps": "npm:no-deps-bins@1.0.0", "no-deps2": "npm:no-deps@2.0.0"
            } }),
        )],
    );
    assert_eq!(id(&env, "", &["no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["no-deps2"]), "no-deps@2.0.0");
    assert_eq!(walk(&env, "packages/workspace", &["no-deps2"]), walk(&env, "", &["no-deps2"]));
    assert_eq!(id(&env, "packages/workspace", &["no-deps"]), "no-deps-bins@1.0.0");
    // No second copy of an aliased package under it.
    assert!(!env.exists("node_modules/no-deps2/node_modules/no-deps"));
}

#[test]
fn nm_a_peer_on_the_parent_keeps_the_parents_version() {
    // . -> dep -> conflict@2 -> unhoistable --> conflict (peer)
    //   -> conflict@1
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "dependencies": { "dep": "file:./dep", "conflict": "file:./conflict1" } }),
        &[
            ("conflict1", json!({ "name": "conflict", "version": "1.0.0" })),
            (
                "conflict2",
                json!({ "name": "conflict", "version": "2.0.0", "dependencies": { "unhoistable": "file:../unhoistable" } }),
            ),
            ("dep", json!({ "name": "dep", "version": "1.0.0", "dependencies": { "conflict": "file:../conflict2" } })),
            (
                "unhoistable",
                json!({ "name": "unhoistable", "version": "1.0.0", "peerDependencies": { "conflict": "2.0.0" } }),
            ),
        ],
    );
    assert_eq!(id(&env, "", &["conflict"]), "conflict@1.0.0");
    assert_eq!(id(&env, "", &["dep", "conflict", "unhoistable", "conflict"]), "conflict@2.0.0");
}

#[test]
fn nm_removing_a_dependency_removes_its_bins() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "dependencies": { "dep1": "file:./dep1", "dep2": "file:./dep2" } }),
        &[
            ("dep1", json!({ "name": "dep1", "version": "1.0.0", "bin": "bin1.js" })),
            ("dep2", json!({ "name": "dep2", "version": "1.0.0", "bin": "bin2.js" })),
        ],
    );
    let bin = if cfg!(windows) { "node_modules/.bin/dep1.cmd" } else { "node_modules/.bin/dep1" };
    assert!(env.exists(bin));
    env.ok(&["remove", "dep1"]);
    assert!(!env.exists(bin));
}

#[test]
fn nm_transitive_peers_in_a_workspace_are_the_workspaces() {
    // . -> no-deps@1
    //   -> workspace -> peer-deps-lvl1 -> peer-deps-lvl2 --> no-deps
    //                                  --> no-deps
    //                -> no-deps@2
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["workspace"], "dependencies": { "no-deps": "1.0.0" } }),
        &[(
            "workspace",
            json!({ "name": "workspace", "version": "1.0.0", "dependencies": { "peer-deps-lvl1": "1.0.0", "no-deps": "2.0.0" } }),
        )],
    );
    assert_eq!(id(&env, "workspace", &["peer-deps-lvl1", "no-deps"]), "no-deps@2.0.0");
    assert_eq!(id(&env, "workspace", &["peer-deps-lvl1", "peer-deps-lvl2", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn nm_a_workspace_peer_is_the_depending_workspaces() {
    // . -> foo (workspace) -> bar (workspace) --> no-deps (peer)
    //                      -> no-deps@1
    //   -> no-deps@2
    // Yarn nests bar in foo as foo's own workspaces; npm and pnpm list every workspace at the
    // root, so foo/bar is listed there. bar's peer is foo's no-deps.
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["foo", "foo/bar"], "dependencies": { "no-deps": "2.0.0" } }),
        &[
            ("foo", json!({ "name": "foo", "dependencies": { "bar": "workspace:*", "no-deps": "1.0.0" } })),
            ("foo/bar", json!({ "name": "bar", "peerDependencies": { "no-deps": "*" } })),
        ],
    );
    assert_eq!(id(&env, "foo", &["bar", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn nm_add_repairs_an_interrupted_install() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["foo"] }),
        &[("foo", json!({ "name": "foo", "dependencies": { "has-bin-entries": "1.0.0" } }))],
    );
    let _ = std::fs::remove_dir_all(env.path("foo/node_modules/has-bin-entries"));
    let _ = std::fs::remove_file(env.path("foo/node_modules/has-bin-entries"));
    env.ok(&["add", "has-bin-entries@2.0.0"]);
    assert_eq!(id(&env, "", &["has-bin-entries"]), "has-bin-entries@2.0.0");
    assert!(env.exists("node_modules/has-bin-entries/index.js"));
    assert_eq!(id(&env, "foo", &["has-bin-entries"]), "has-bin-entries@1.0.0");
}

#[test]
fn nm_a_workspace_peer_with_a_dev_default_takes_the_default() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["foo"], "dependencies": { "has-bin-entries": "2.0.0" } }),
        &[(
            "foo",
            json!({ "name": "foo", "peerDependencies": { "has-bin-entries": "*" }, "devDependencies": { "has-bin-entries": "1.0.0" } }),
        )],
    );
    assert_eq!(id(&env, "foo", &["has-bin-entries"]), "has-bin-entries@1.0.0");
}

#[test]
fn nm_a_required_dependency_for_another_platform_fails() {
    // Yarn skips linking it. npm (EBADPLATFORM) and pnpm refuse a required one; an optional one
    // is left out.
    let r = berry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "native": "1.0.0" } }));
    let out = fails(&env, &["install"]);
    assert!(out.contains("EBADPLATFORM"), "{out}");
    let env = install(&r, json!({ "dependencies": { "optional-native": "1.0.0" } }), &[]);
    for name in ["native-bar-x64", "native-foo-x64", "native-foo-x86"] {
        assert_eq!(id(&env, "", &["optional-native", name]), "missing");
    }
}

#[test]
fn nm_each_workspace_gets_its_own_version() {
    // Yarn hoists the workspace's no-deps 2.0.0 over one-fixed-dep's 1.0.0 to the top, where
    // the root requires it without declaring it. jpm's root reaches only what it declares.
    let r = berry();
    let env = install(
        &r,
        json!({ "workspaces": ["ws1", "ws2"], "dependencies": { "one-fixed-dep": "1.0.0" } }),
        &[
            ("ws1", json!({ "name": "ws1", "dependencies": { "no-deps": "2.0.0" } })),
            ("ws2", json!({ "name": "ws2", "dependencies": { "has-bin-entries": "1.0.0" } })),
        ],
    );
    assert_eq!(id(&env, "ws1", &["no-deps"]), "no-deps@2.0.0");
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "ws2", &["has-bin-entries", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn nm_a_peer_the_parent_lacks_falls_back_to_the_dependency() {
    // . -> app -> lib --> no-deps (peer, and a dependency)
    //          --> no-deps (peer, missing)
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "app": "portal:./lib-1" } }),
        &[
            (
                "lib-2",
                json!({ "name": "lib", "dependencies": { "no-deps": "*" }, "peerDependencies": { "no-deps": "*" } }),
            ),
            (
                "lib-1",
                json!({ "name": "app", "dependencies": { "lib": "portal:../lib-2" }, "peerDependencies": { "no-deps": "*" } }),
            ),
        ],
    );
    assert_eq!(id(&env, "", &["app", "lib", "no-deps"]), "no-deps@2.0.0");
}

// features/resolutions.test.js

#[test]
fn resolutions_override_everywhere_under_a_parent_or_by_the_range() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "one-fixed-dep": "1.0.0" }, "resolutions": { "no-deps": "2.0.0" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@2.0.0");

    let env = install(
        &r,
        json!({ "dependencies": { "one-fixed-dep": "1.0.0", "one-range-dep": "1.0.0" }, "resolutions": { "one-range-dep/no-deps": "2.0.0" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.0");
    assert_eq!(id(&env, "", &["one-range-dep", "no-deps"]), "no-deps@2.0.0");

    // `no-deps@1.0.0`: only an edge asking for 1.0.0.
    let env = install(
        &r,
        json!({ "dependencies": { "one-fixed-dep": "1.0.0", "no-deps": "1.1.0" }, "resolutions": { "no-deps@1.0.0": "2.0.0" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["no-deps"]), "no-deps@1.1.0");
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn resolutions_under_a_parent_version() {
    let r = berry();
    let env = install(
        &r,
        json!({ "dependencies": { "one-fixed-dep": "1.0.0" }, "resolutions": { "one-fixed-dep@1.0.0/no-deps": "1.0.1" } }),
        &[],
    );
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.1");
    env.manifest(json!({ "dependencies": { "one-fixed-dep": "2.0.0" }, "resolutions": { "one-fixed-dep@1.0.0/no-deps": "1.0.1" } }));
    env.ok(&["install"]);
    assert_eq!(id(&env, "", &["one-fixed-dep"]), "one-fixed-dep@2.0.0");
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn resolutions_to_an_archive_and_back_but_never_into_the_project() {
    let r = berry();
    let env = Env::new(&r);
    env.write("my-package/package.json", r#"{ "name": "no-deps", "version": "42.0.0" }"#);
    env.write("no-deps-2/package.json", r#"{ "name": "no-deps", "version": "2.0.0" }"#);
    let two = fixtures().into_iter().find(|p| p.name == "no-deps" && p.version == "2.0.0").unwrap();
    std::fs::write(env.project().join("no-deps-2.0.0.tgz"), two.tarball()).unwrap();
    let to = "file:./no-deps-2.0.0.tgz";
    env.manifest(json!({ "dependencies": { "one-fixed-dep": "1.0.0" }, "resolutions": { "no-deps": to } }));
    env.ok(&["install"]);
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@2.0.0");
    std::fs::remove_dir_all(env.path("node_modules")).unwrap();
    env.ok(&["ci"]);
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@2.0.0");
    // Yarn links a portal or a directory in place of a registry package's dependency. A
    // registry package's entry may be shared by every project on the machine, so jpm links
    // nothing of one project into it: the override holds for the root and workspaces only,
    // with a note, and the dependency keeps its own range.
    for to in ["portal:./my-package", "file:./no-deps-2"] {
        env.manifest(json!({ "dependencies": { "one-fixed-dep": "1.0.0" }, "resolutions": { "no-deps": to } }));
        let out = env.ok(&["install"]);
        assert!(out.contains("overrides send no-deps to"), "{to}: {out}");
        assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.0", "{to}");
    }
    // The resolution taken out, the dependency's own range again.
    env.manifest(json!({ "dependencies": { "one-fixed-dep": "1.0.0" } }));
    env.ok(&["install"]);
    assert_eq!(id(&env, "", &["one-fixed-dep", "no-deps"]), "no-deps@1.0.0");
}

// protocols/npm.test.js and protocols/semver.test.js

#[test]
fn npm_renames_a_package() {
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "no-deps": "npm:one-fixed-dep@1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["no-deps"]), "one-fixed-dep@1.0.0");
    assert_eq!(id(&env, "", &["no-deps", "no-deps"]), "no-deps@1.0.0");
}

#[test]
fn semver_a_v_prefix_and_build_metadata() {
    // Yarn's `npm:v1.0.0` and `npm:1.0.0+123` (a range after `npm:`, no name) are its own: npm
    // reads them as aliases of packages named `v1.0.0` and `1.0.0+123`.
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "no-deps": "v1.0.0" } }), &[]);
    assert_eq!(id(&env, "", &["no-deps"]), "no-deps@1.0.0");
    // A version is looked up without its build metadata, as npm-pick-manifest does: the npm
    // registry takes it off on publish, so no packument has a `1.0.0+123` to find.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "no-deps-build-metadata": "1.0.0+123" } }));
    assert!(fails(&env, &["install"]).contains("ETARGET"));
}

#[test]
fn npm_fetches_a_tarball_at_an_unconventional_url() {
    let r = berry();
    for spec in ["1.0.0", "latest"] {
        let env = install(&r, json!({ "dependencies": { "unconventional-tarball": spec } }), &[]);
        assert_eq!(id(&env, "", &["unconventional-tarball"]), "unconventional-tarball@1.0.0", "{spec}");
        // Again from the lockfile, with nothing on disk.
        std::fs::remove_dir_all(env.path("node_modules")).unwrap();
        let _ = std::process::Command::new("chmod").args(["-R", "u+w"]).arg(env.store()).output();
        std::fs::remove_dir_all(env.store()).unwrap();
        env.ok(&["install"]);
        assert_eq!(id(&env, "", &["unconventional-tarball"]), "unconventional-tarball@1.0.0", "{spec}");
    }
    let env = Env::new(&r);
    env.manifest(json!({}));
    env.ok(&["add", "unconventional-tarball"]);
    assert_eq!(id(&env, "", &["unconventional-tarball"]), "unconventional-tarball@1.0.0");
    // A URL with a fragment, and one with a query.
    let tgz = fixtures().into_iter().find(|p| p.name == "unconventional-tarball").unwrap().tarball();
    let path = "/unconventional-tarball/tralala/unconventional-tarball-1.0.0.tgz";
    r.serve(path, tgz.clone());
    r.serve(&format!("{path}?auth=1234"), tgz);
    for suffix in ["#fragment", "?auth=1234"] {
        let url = format!("{}{path}{suffix}", r.url);
        let env = install(&r, json!({ "dependencies": { "unconventional-tarball": url } }), &[]);
        assert_eq!(id(&env, "", &["unconventional-tarball"]), "unconventional-tarball@1.0.0", "{suffix}");
    }
}

#[test]
fn npm_a_star_takes_a_prerelease_only_when_there_is_nothing_else() {
    let r = berry();
    let env = install(&r, json!({ "dependencies": { "prerelease-only": "*", "no-deps-tags": "*" } }), &[]);
    assert_eq!(id(&env, "", &["prerelease-only"]), "prerelease-only@1.0.0-rc.2");
    assert_eq!(id(&env, "", &["no-deps-tags"]), "no-deps-tags@1.0.0");
    env.ok(&["install", "--frozen-lockfile"]);
}

// workspace.test.ts and protocols/workspace.test.ts

#[test]
fn ws_a_workspace_is_not_requireable_unless_declared() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"] }),
        &[("packages/workspace-a", json!({ "name": "workspace-a", "version": "1.0.0" }))],
    );
    assert_eq!(id(&env, "", &["workspace-a"]), "missing");
}

#[test]
fn ws_workspaces_require_each_other() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"], "dependencies": { "workspace-a": "1.0.0", "workspace-b": "1.0.0" } }),
        &[
            (
                "packages/workspace-a",
                json!({ "name": "workspace-a", "version": "1.0.0", "dependencies": { "workspace-b": "1.0.0" } }),
            ),
            (
                "packages/workspace-b",
                json!({ "name": "workspace-b", "version": "1.0.0", "dependencies": { "workspace-a": "1.0.0" } }),
            ),
        ],
    );
    let real = |p: &str| std::fs::canonicalize(env.path(p)).ok();
    assert_eq!(walk(&env, "", &["workspace-a"]), real("packages/workspace-a"));
    assert_eq!(walk(&env, "", &["workspace-a", "workspace-b"]), real("packages/workspace-b"));
    assert_eq!(walk(&env, "", &["workspace-b", "workspace-a"]), real("packages/workspace-a"));
}

#[test]
fn ws_a_workspace_out_of_range_comes_from_the_registry() {
    let r = berry();
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["packages/*"], "dependencies": { "workspace": "1.0.0" } }),
        &[
            (
                "packages/workspace",
                json!({ "name": "workspace", "version": "1.0.0", "dependencies": { "no-deps": "2.0.0" } }),
            ),
            ("packages/no-deps", json!({ "name": "no-deps", "version": "1.0.0" })),
        ],
    );
    assert_eq!(id(&env, "", &["workspace", "no-deps"]), "no-deps@2.0.0");
}

#[test]
fn ws_the_workspace_protocols_forms() {
    let r = berry();
    // `workspace:^` and `workspace:~`, and `workspace:*` of a prerelease.
    let env = install(
        &r,
        json!({ "private": true, "workspaces": ["util", "config", "core", "components"] }),
        &[
            (
                "util",
                json!({ "name": "util", "private": true, "dependencies": { "config": "workspace:^", "components": "workspace:*" } }),
            ),
            ("core", json!({ "name": "core", "private": true, "dependencies": { "config": "workspace:~" } })),
            ("config", json!({ "name": "config", "version": "1.0.0" })),
            ("components", json!({ "name": "components", "version": "1.0.0-alpha.0" })),
        ],
    );
    let real = |p: &str| std::fs::canonicalize(env.path(p)).ok();
    assert_eq!(walk(&env, "util", &["config"]), real("config"));
    assert_eq!(walk(&env, "util", &["components"]), real("components"));
    assert_eq!(walk(&env, "core", &["config"]), real("config"));
    // A relative path, under the workspace's name or another. Yarn also takes one without the
    // `./` (`workspace:packages/foo`), from the project's root; pnpm's is relative to the package
    // and starts with `./` or `../`, which jpm reads.
    for spec in [json!({ "foo": "workspace:./packages/foo" }), json!({ "bar": "workspace:./packages/foo" })] {
        let name = spec.as_object().unwrap().keys().next().unwrap().clone();
        let env = install(
            &r,
            json!({ "workspaces": ["packages/*"], "dependencies": spec }),
            &[("packages/foo", json!({ "name": "foo" }))],
        );
        assert_eq!(walk(&env, "", &[&name]), std::fs::canonicalize(env.path("packages/foo")).ok(), "{spec}");
    }
    // Yarn refuses a path that holds no workspace. pnpm's `workspace:<path>` links the
    // directory as `link:` does, a workspace's build output that may not be built yet
    // (drizzle's `workspace:../drizzle-typebox/dist`), and so does jpm.
    let env = install(
        &r,
        json!({ "workspaces": ["packages/*"], "dependencies": { "foo": "workspace:./packages/foo/dist" } }),
        &[("packages/foo", json!({ "name": "foo" }))],
    );
    assert!(env.exists("node_modules/foo"));
}

// protocols/links.test.js

#[test]
fn link_the_target_as_it_is() {
    // A link reaches the target, manifest or not; the target's own dependencies are not
    // installed, and it reaches its container's.
    let r = berry();
    let env = Env::new(&r);
    env.write(
        "one-fixed-dep/package.json",
        r#"{ "name": "one-fixed-dep", "version": "1.0.0", "dependencies": { "no-deps": "1.0.0" } }"#,
    );
    env.write("data/data.json", r#"{ "data": 42 }"#);
    env.write("my-dir/index.js", "module.exports = require('no-deps');\n");
    env.manifest(json!({ "dependencies": {
        "one-fixed-dep": "link:./one-fixed-dep", "foo": "link:./data", "mine": "link:./my-dir", "no-deps": "2.0.0"
    } }));
    env.ok(&["install"]);
    assert_eq!(id(&env, "", &["one-fixed-dep"]), "one-fixed-dep@1.0.0");
    assert!(!env.exists("one-fixed-dep/node_modules/no-deps"));
    assert!(env.read("node_modules/foo/data.json").contains("42"));
    let mine = std::fs::canonicalize(env.path("node_modules/mine")).unwrap();
    assert_eq!(resolve(&env, &mine, "no-deps"), walk(&env, "", &["no-deps"]));
}

#[test]
fn link_to_the_project_itself_is_refused() {
    // Yarn installs `link:.` beside another dependency, a link from node_modules to the project
    // that holds it. jpm refuses a dependency on the project's own directory.
    let r = berry();
    for name in ["a-my-app", "z-my-app"] {
        let env = Env::new(&r);
        env.manifest(json!({ "name": "my-app", "dependencies": { name: "link:.", "no-deps": "1.0.0" } }));
        let out = fails(&env, &["install"]);
        assert!(out.contains("cannot depend on the project's own directory"), "{out}");
    }
}
