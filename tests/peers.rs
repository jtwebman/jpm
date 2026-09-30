//! Peer-dependent copies: a package installed once for each set of peers it resolves, as pnpm
//! and yarn install it. A monorepo whose workspaces are on two Reacts gets a shared library twice,
//! each bound to its workspace's React.

mod common;

use std::path::Path;

use common::{Env, Pkg, Registry, pkg};
use serde_json::{Value, json};

/// A package whose index.js exports what `require(dep)` gives inside it.
fn requiring(name: &str, version: &str, dep: &str, manifest: Value) -> Pkg {
    let mut p = pkg(name, version, manifest);
    p.files = vec![("index.js".into(), 0o644, format!("module.exports = require('{dep}')").into_bytes())];
    p
}

fn registry() -> Registry {
    Registry::start(vec![
        pkg("react", "17.0.2", json!({})),
        pkg("react", "18.2.0", json!({})),
        requiring(
            "ui-lib",
            "1.0.0",
            "react",
            json!({ "peerDependencies": { "react": ">=17" }, "bin": { "ui-cli": "cli.js" } }),
        )
        .file("cli.js", 0o755, "#!/usr/bin/env node\nconsole.log(require('react'))\n"),
        requiring("wrapper", "1.0.0", "ui-lib", json!({ "dependencies": { "ui-lib": "1.0.0" } })),
    ])
}

/// A root with workspaces at `packages/<name>`, each with these dependencies.
fn monorepo(env: &Env, root: Value, workspaces: &[(&str, Value)]) {
    let mut manifest = json!({ "name": "root", "private": true, "workspaces": ["packages/*"] });
    if let Some(deps) = root.as_object().filter(|d| !d.is_empty()) {
        manifest["dependencies"] = Value::Object(deps.clone());
    }
    env.manifest(manifest);
    for (name, deps) in workspaces {
        let m = json!({ "name": name, "version": "1.0.0", "dependencies": deps });
        env.write(&format!("packages/{name}/package.json"), &m.to_string());
    }
}

/// What Node's `require(name)` gives from a directory of the project.
fn node_require(env: &Env, from: &str, name: &str) -> String {
    let out = std::process::Command::new("node")
        .arg("-p")
        .arg(format!("require('{name}')"))
        .current_dir(env.path(from))
        .output()
        .expect("node");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn keys(lock: &Value, name: &str) -> Vec<String> {
    let prefix = format!("{name}@");
    lock["packages"].as_object().unwrap().keys().filter(|k| k.starts_with(&prefix)).cloned().collect()
}

fn two_reacts(env: &Env) {
    monorepo(
        env,
        json!({}),
        &[
            ("a", json!({ "react": "17.0.2", "ui-lib": "1.0.0" })),
            ("b", json!({ "react": "18.2.0", "ui-lib": "1.0.0" })),
        ],
    );
}

#[test]
fn a_library_shared_by_workspaces_on_two_reacts_is_two_copies() {
    let r = registry();
    for store in ["global-store=true", "global-store=false"] {
        let env = Env::new(&r);
        env.write(".npmrc", &format!("{store}\n"));
        two_reacts(&env);
        env.ok(&["install"]);
        let lock = env.lock();
        assert_eq!(keys(&lock, "ui-lib"), ["ui-lib@1.0.0(react@17.0.2)", "ui-lib@1.0.0(react@18.2.0)"], "{store}");
        assert_eq!(lock["workspaces"]["packages/a"]["dependencies"]["ui-lib"], "1.0.0(react@17.0.2)");
        assert_eq!(lock["packages"]["ui-lib@1.0.0(react@18.2.0)"]["dependencies"]["react"], "18.2.0");
        assert_eq!(node_require(&env, "packages/a", "ui-lib"), "react@17.0.2", "{store}");
        assert_eq!(node_require(&env, "packages/b", "ui-lib"), "react@18.2.0", "{store}");
        // Each workspace's bin runs its own copy.
        for (ws, react) in [("a", "react@17.0.2"), ("b", "react@18.2.0")] {
            let dir = env.path(&format!("packages/{ws}"));
            let out = env.command_in(&dir, &["exec", "ui-cli"]).output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && text.contains(react),
                "{store} {ws}: {text}{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(env.ok(&["install"]).contains("up to date"));
    }
}

#[test]
fn a_package_whose_dependency_takes_a_peer_from_above_is_copied_too() {
    // wrapper has no peers, but its ui-lib takes react from above wrapper: wrapper is a copy per
    // React as well.
    let r = registry();
    let env = Env::new(&r);
    monorepo(
        &env,
        json!({}),
        &[
            ("a", json!({ "react": "17.0.2", "wrapper": "1.0.0" })),
            ("b", json!({ "react": "18.2.0", "wrapper": "1.0.0" })),
        ],
    );
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(keys(&lock, "wrapper"), ["wrapper@1.0.0(react@17.0.2)", "wrapper@1.0.0(react@18.2.0)"]);
    assert_eq!(lock["packages"]["wrapper@1.0.0(react@17.0.2)"]["dependencies"]["ui-lib"], "1.0.0(react@17.0.2)");
    assert_eq!(node_require(&env, "packages/a", "wrapper"), "react@17.0.2");
    assert_eq!(node_require(&env, "packages/b", "wrapper"), "react@18.2.0");
}

#[test]
fn the_same_peers_are_one_copy() {
    let r = registry();
    let env = Env::new(&r);
    monorepo(
        &env,
        json!({ "react": "18.2.0", "ui-lib": "1.0.0" }),
        &[
            ("a", json!({ "react": "17.0.2", "ui-lib": "1.0.0" })),
            ("b", json!({ "react": "18.2.0", "ui-lib": "1.0.0" })),
            ("c", json!({ "react": "18.2.0", "wrapper": "1.0.0" })),
            // No React of its own: the root's, as pnpm resolves peers from the workspace root.
            ("d", json!({ "ui-lib": "1.0.0" })),
        ],
    );
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(keys(&lock, "ui-lib"), ["ui-lib@1.0.0(react@17.0.2)", "ui-lib@1.0.0(react@18.2.0)"]);
    // One copy of wrapper, so its key has no suffix.
    assert_eq!(keys(&lock, "wrapper"), ["wrapper@1.0.0"]);
    for top in [&lock["root"], &lock["workspaces"]["packages/b"], &lock["workspaces"]["packages/d"]] {
        assert_eq!(top["dependencies"]["ui-lib"], "1.0.0(react@18.2.0)");
    }
    assert_eq!(node_require(&env, "packages/d", "ui-lib"), "react@18.2.0");

    // One set of peers anywhere: the keys are as before copies.
    let env = Env::new(&r);
    monorepo(&env, json!({}), &[("a", json!({ "react": "18.2.0", "ui-lib": "1.0.0", "wrapper": "1.0.0" }))]);
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(keys(&lock, "ui-lib"), ["ui-lib@1.0.0"]);
    assert_eq!(lock["workspaces"]["packages/a"]["dependencies"]["ui-lib"], "1.0.0");
}

#[test]
fn the_lockfile_keeps_the_copies() {
    let r = registry();
    let env = Env::new(&r);
    two_reacts(&env);
    env.ok(&["install"]);
    let text = env.read("jpm.lock");
    assert!(text.contains("\npackage ui-lib@1.0.0(react@17.0.2)\n"), "{text}");
    // Resolved again from it, or from nothing, read again, installed from it: the same file,
    // and the same tree.
    env.ok(&["dedupe"]);
    assert_eq!(env.read("jpm.lock"), text);
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    env.ok(&["lock"]);
    assert_eq!(env.read("jpm.lock"), text);
    std::fs::remove_dir_all(env.path("node_modules")).unwrap();
    std::fs::remove_dir_all(env.path("packages/a/node_modules")).unwrap();
    env.ok(&["install", "--frozen-lockfile"]);
    assert_eq!(env.read("jpm.lock"), text);
    assert_eq!(node_require(&env, "packages/a", "ui-lib"), "react@17.0.2");
    assert_eq!(node_require(&env, "packages/b", "ui-lib"), "react@18.2.0");
}

#[test]
fn reads_a_lockfile_written_before_copies() {
    // What jpm wrote before copies: one ui-lib, with the one React it settled on.
    let r = registry();
    let env = Env::new(&r);
    two_reacts(&env);
    env.ok(&["install"]);
    let mut old = String::new();
    let mut skip = false;
    for line in env.read("jpm.lock").lines() {
        if line.starts_with("package ") {
            skip = line == "package ui-lib@1.0.0(react@17.0.2)";
        }
        if !skip && !line.starts_with("  subgraph ") && !line.starts_with("hash ") {
            old.push_str(&line.replace("(react@17.0.2)", "").replace("(react@18.2.0)", ""));
            old.push('\n');
        }
    }
    let old = old.replacen("jpm-lock 2\n", "jpm-lock 2\nhash 0\n", 1);
    assert!(old.contains("\npackage ui-lib@1.0.0\n") && !old.contains("(react"), "{old}");
    env.write("jpm.lock", &old);
    std::fs::remove_dir_all(env.path("node_modules")).unwrap();
    std::fs::remove_dir_all(env.path("packages/a/node_modules")).unwrap();
    // A key without a suffix is a package with one set of peers: installed as it says.
    env.ok(&["install", "--frozen-lockfile"]);
    assert_eq!(node_require(&env, "packages/a", "ui-lib"), "react@18.2.0");
    // It stands while package.json does; resolved again, it splits, the versions kept.
    env.ok(&["install"]);
    assert_eq!(keys(&env.lock(), "ui-lib"), ["ui-lib@1.0.0"]);
    env.ok(&["dedupe"]);
    assert_eq!(keys(&env.lock(), "ui-lib"), ["ui-lib@1.0.0(react@17.0.2)", "ui-lib@1.0.0(react@18.2.0)"]);
}

#[test]
fn a_long_peer_suffix_never_reaches_a_path() {
    // Windows has MAX_PATH and cmd.exe reads `(` in a shim: a copy's directory is its package,
    // version and a hash, however long its key.
    let long = |i: usize| format!("a-rather-long-package-name-to-peer-on-number-{i:02}");
    let mut pkgs = vec![];
    let mut peers = serde_json::Map::new();
    for i in 0..12 {
        pkgs.push(pkg(&long(i), "1.0.0", json!({})));
        pkgs.push(pkg(&long(i), "2.0.0", json!({})));
        peers.insert(long(i), json!("*"));
    }
    pkgs.push(pkg("wide", "1.0.0", json!({ "peerDependencies": peers, "bin": { "wide": "cli.js" } })).file(
        "cli.js",
        0o755,
        "#!/usr/bin/env node\nconsole.log('wide ran')\n",
    ));
    let r = Registry::start(pkgs);
    let env = Env::new(&r);
    env.write(".npmrc", "global-store=false\n");
    let deps = |v: &str| {
        let mut d = serde_json::Map::new();
        for i in 0..12 {
            d.insert(long(i), json!(v));
        }
        d.insert("wide".into(), json!("1.0.0"));
        Value::Object(d)
    };
    monorepo(&env, json!({}), &[("a", deps("1.0.0")), ("b", deps("2.0.0"))]);
    env.ok(&["install"]);
    let wide = keys(&env.lock(), "wide");
    assert_eq!(wide.len(), 2);
    assert!(wide.iter().all(|k| k.len() > 600), "{wide:?}");
    let entries: Vec<String> = std::fs::read_dir(env.path("node_modules/.jpm"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("wide@"))
        .collect();
    assert_eq!(entries.len(), 2, "{entries:?}");
    for e in &entries {
        assert!(e.len() <= "wide@1.0.0-".len() + 22 && !e.contains(['(', ')']), "{e}");
    }
    for ws in ["a", "b"] {
        // A cmd shim names its target; elsewhere the bin is a link to it.
        let shim = if cfg!(windows) {
            env.read(&format!("packages/{ws}/node_modules/.bin/wide.cmd"))
        } else {
            let link = std::fs::read_link(env.path(&format!("packages/{ws}/node_modules/.bin/wide"))).unwrap();
            link.to_string_lossy().into_owned()
        };
        assert!(!shim.contains('('), "{shim}");
        let out = env.command_in(Path::new(&env.path(&format!("packages/{ws}"))), &["exec", "wide"]).output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("wide ran"),
            "{ws}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A monorepo whose workspace `schema` is at `version`, with the registry's plugin (a peer on
/// schema) and wrap (which depends on plugin) at the root and in the workspace `app`.
fn schema_repo(env: &Env, version: &str) {
    monorepo(
        env,
        json!({ "plugin": "1.0.0", "wrap": "1.0.0", "schema": "workspace:*" }),
        &[("app", json!({ "wrap": "1.0.0", "schema": "workspace:*" }))],
    );
    let m = json!({ "name": "schema", "version": version });
    env.write("packages/schema/package.json", &m.to_string());
    env.write("packages/schema/index.js", &format!("module.exports = 'schema@{version}'"));
}

fn schema_registry() -> Registry {
    Registry::start(vec![
        requiring("plugin", "1.0.0", "schema", json!({ "peerDependencies": { "schema": "^1" } })),
        requiring("wrap", "1.0.0", "plugin", json!({ "dependencies": { "plugin": "1.0.0" } })),
    ])
}

/// Where a project's link leads, resolved.
fn real(env: &Env, rel: &str) -> std::path::PathBuf {
    std::fs::canonicalize(env.path(rel)).unwrap()
}

#[test]
fn a_registry_package_takes_its_peer_from_a_workspace() {
    // nuxt's root has @nuxt/cli, whose peer @nuxt/schema is the workspace packages/schema: pnpm
    // links the one to the other, `(@nuxt/schema@packages+schema)`, in its range or out of it.
    let r = schema_registry();
    for store in ["global-store=true", "global-store=false"] {
        for version in ["1.2.0", "2.0.0"] {
            let env = Env::new(&r);
            env.write(".npmrc", &format!("{store}\n"));
            schema_repo(&env, version);
            let out = env.ok(&["install"]);
            let unmet = format!("unmet peer schema@^1 of plugin@1.0.0: linked to the schema@{version} above it");
            assert_eq!(out.contains(&unmet), version == "2.0.0", "{store} {version}: {out}");
            let lock = env.lock();
            assert_eq!(lock["packages"]["plugin@1.0.0"]["dependencies"]["schema"], "link:packages/schema");
            let want = format!("schema@{version}");
            assert_eq!(node_require(&env, ".", "plugin"), want, "{store}");
            assert_eq!(node_require(&env, ".", "wrap"), want, "{store}");
            assert_eq!(node_require(&env, "packages/app", "wrap"), want, "{store}");
            // In the project, not the global store: another project's schema is another package.
            // So is wrap, which reaches it.
            let entries = real(&env, "node_modules/.jpm");
            for dep in ["plugin", "wrap"] {
                assert!(real(&env, &format!("node_modules/{dep}")).starts_with(&entries), "{store} {dep}");
            }
            assert!(env.ok(&["install"]).contains("up to date"), "{store} {version}");
            // Relinked, plugin's link to the workspace is already right: nothing is rebuilt.
            let _ = std::fs::remove_dir(env.path("node_modules/wrap"));
            let _ = std::fs::remove_file(env.path("node_modules/wrap"));
            let out = env.ok(&["install"]);
            assert!(!out.contains("repaired") && !out.contains("up to date"), "{store} {version}: {out}");
            assert_eq!(node_require(&env, ".", "wrap"), want, "{store}");

            // Read again, resolved again, installed from it: the same file and the same tree.
            let text = env.read("jpm.lock");
            env.ok(&["dedupe"]);
            assert_eq!(env.read("jpm.lock"), text);
            std::fs::remove_file(env.path("jpm.lock")).unwrap();
            env.ok(&["lock"]);
            assert_eq!(env.read("jpm.lock"), text);
            std::fs::remove_dir_all(env.path("node_modules")).unwrap();
            std::fs::remove_dir_all(env.path("packages/app/node_modules")).unwrap();
            env.ok(&["install", "--frozen-lockfile"]);
            assert_eq!(node_require(&env, "packages/app", "wrap"), want, "{store}");
            assert!(env.ok(&["install"]).contains("up to date"), "{store} {version}");
        }
    }
}

#[test]
fn a_copy_whose_peer_is_a_workspace_names_it_in_its_key() {
    let mut pkgs = vec![pkg("schema", "1.0.0", json!({}))];
    pkgs[0].files = vec![("index.js".into(), 0o644, b"module.exports = 'schema@1.0.0'".to_vec())];
    pkgs.push(requiring("plugin", "1.0.0", "schema", json!({ "peerDependencies": { "schema": "^1" } })));
    pkgs.push(requiring("wrap", "1.0.0", "plugin", json!({ "dependencies": { "plugin": "1.0.0" } })));
    let r = Registry::start(pkgs);
    for store in ["global-store=true", "global-store=false"] {
        let env = Env::new(&r);
        env.write(".npmrc", &format!("{store}\n"));
        schema_repo(&env, "2.0.0");
        // `other` takes schema from the registry: plugin is a copy for each schema.
        let m = json!({ "name": "other", "version": "1.0.0", "dependencies": { "wrap": "1.0.0", "schema": "1.0.0" } });
        env.write("packages/other/package.json", &m.to_string());
        env.ok(&["install"]);
        let lock = env.lock();
        assert_eq!(keys(&lock, "plugin"), ["plugin@1.0.0(schema@1.0.0)", "plugin@1.0.0(schema@link:packages/schema)"]);
        assert_eq!(node_require(&env, "packages/app", "wrap"), "schema@2.0.0", "{store}");
        assert_eq!(node_require(&env, "packages/other", "wrap"), "schema@1.0.0", "{store}");
        assert!(env.ok(&["install"]).contains("up to date"), "{store}");
        let text = env.read("jpm.lock");
        std::fs::remove_file(env.path("jpm.lock")).unwrap();
        env.ok(&["lock"]);
        assert_eq!(env.read("jpm.lock"), text);
    }
}

#[test]
fn a_package_links_a_directory_only_as_a_peer_on_a_workspace() {
    let r = schema_registry();
    let env = Env::new(&r);
    schema_repo(&env, "1.2.0");
    env.ok(&["install"]);
    let text = env.read("jpm.lock");
    let plugin = "package plugin@1.0.0\n";
    assert!(text.contains(plugin) && text.contains("  dep schema link:packages/schema\n"), "{text}");
    let refused = |edited: String, why: &str| {
        env.write("jpm.lock", &edited);
        let out = env.jpm(&["install", "--frozen-lockfile"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains(why), "{err}\n{edited}");
    };
    // wrap's own dependency, sent to the workspace by an edit.
    refused(
        text.replace("package wrap@1.0.0\n", "package wrap@1.0.0\n  dep schema link:packages/schema\n"),
        "packages[\"wrap@1.0.0\"].dependencies[\"schema\"] is link:packages/schema: a package links a directory only for a peer",
    );
    // plugin's peer, sent to a directory that is no workspace.
    let peer = "link:packages/schema
  peer schema ^1";
    for dir in ["link:packages/app", "link:../outside"] {
        refused(
            text.replace(peer, &peer.replace("link:packages/schema", dir)),
            "only for a peer, to the workspace of its name",
        );
    }
    env.write("jpm.lock", &text);
    env.ok(&["install", "--frozen-lockfile"]);

    // A registry package that declares a path dependency is refused, as before.
    for path in ["link:../x", "file:../x"] {
        let r = Registry::start(vec![pkg("bad", "1.0.0", json!({ "dependencies": { "x": path } }))]);
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "bad": "1.0.0" } }));
        let out = env.jpm(&["install"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains("only the root and workspaces may depend on a path"), "{err}");
    }
}

#[test]
fn a_pnpm_lock_whose_package_peers_on_a_workspace_installs() {
    // nuxt's pnpm-lock.yaml has `@nuxt/cli-nightly@…(@nuxt/schema@packages+schema)`. A lock with
    // workspaces is read for its versions, and the peer links to the workspace, as pnpm's did.
    let r = schema_registry();
    let env = Env::new(&r);
    schema_repo(&env, "1.2.0");
    env.write(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      plugin:
        specifier: 1.0.0
        version: 1.0.0(schema@packages+schema)
      schema:
        specifier: workspace:*
        version: link:packages/schema
      wrap:
        specifier: 1.0.0
        version: 1.0.0(schema@packages+schema)
  packages/app:
    dependencies:
      schema:
        specifier: workspace:*
        version: link:../schema
      wrap:
        specifier: 1.0.0
        version: 1.0.0(schema@packages+schema)
  packages/schema: {}
packages:
  plugin@1.0.0:
    resolution: {integrity: sha512-plugin}
    peerDependencies:
      schema: ^1
  wrap@1.0.0:
    resolution: {integrity: sha512-wrap}
snapshots:
  plugin@1.0.0(schema@packages+schema):
    dependencies:
      schema: link:packages/schema
  wrap@1.0.0(schema@packages+schema):
    dependencies:
      plugin: 1.0.0(schema@packages+schema)
",
    );
    let out = env.ok(&["install"]);
    assert!(out.contains("pnpm-lock.yaml has workspaces"), "{out}");
    assert_eq!(env.lock()["packages"]["plugin@1.0.0"]["dependencies"]["schema"], "link:packages/schema");
    assert_eq!(node_require(&env, "packages/app", "wrap"), "schema@1.2.0");
    assert!(env.ok(&["install"]).contains("up to date"));
}

/// gutenberg's shape: `prompts` and `inquirer`, which depends on it, both take an optional peer
/// the tree has at two versions, and a workspace reaches `prompts` with none in its scope.
fn optional_peer_registry() -> Registry {
    let soft = || json!({ "types-node": { "optional": true } });
    Registry::start(vec![
        pkg("types-node", "1.0.0", json!({})),
        pkg("types-node", "2.0.0", json!({})),
        pkg("prompts", "1.0.0", json!({ "peerDependencies": { "types-node": ">=1" }, "peerDependenciesMeta": soft() })),
        pkg(
            "inquirer",
            "1.0.0",
            json!({
                "dependencies": { "prompts": "^1.0.0" },
                "peerDependencies": { "types-node": ">=1" },
                "peerDependenciesMeta": soft(),
            }),
        ),
    ])
}

#[test]
fn a_lock_is_the_same_whatever_order_the_registry_answers_in() {
    let r = optional_peer_registry();
    let env = Env::new(&r);
    monorepo(
        &env,
        json!({}),
        &[
            ("bare", json!({ "prompts": "^1.0.0" })),
            ("cli", json!({ "inquirer": "^1.0.0" })),
            ("newer", json!({ "types-node": "2.0.0" })),
            ("rel", json!({ "prompts": "^1.0.0", "types-node": "1.0.0" })),
        ],
    );
    // Each run a fresh process (its maps ordered afresh) and a cold metadata cache, the
    // documents arriving in another order each time.
    let orders: [&[&str]; 4] = [&[], &["inquirer"], &["prompts", "types-node"], &["types-node", "inquirer"]];
    let mut first: Option<String> = None;
    for (i, slow) in orders.iter().cycle().take(12).enumerate() {
        r.slow_documents(slow, 100);
        let _ = std::fs::remove_dir_all(env.store().join("metadata"));
        let _ = std::fs::remove_file(env.path("jpm.lock"));
        env.ok(&["lock"]);
        let lock = env.read("jpm.lock");
        match &first {
            None => first = Some(lock),
            Some(f) => assert!(lock == *f, "run {i}, {slow:?} slow:\n{lock}\nnot\n{f}"),
        }
    }
    r.slow_documents(&[], 0);
    // An optional peer settles on what its parents have from the walk: rel's types-node, not the
    // 2.0.0 that inquirer, a parent too, was only wired to.
    let lock = env.lock();
    assert_eq!(lock["workspaces"]["packages/bare"]["dependencies"]["prompts"], "1.0.0");
    assert_eq!(lock["workspaces"]["packages/rel"]["dependencies"]["prompts"], "1.0.0");
    assert_eq!(lock["packages"]["prompts@1.0.0"]["optionalDependencies"]["types-node"], "1.0.0");
    assert_eq!(keys(&lock, "prompts"), ["prompts@1.0.0", "prompts@1.0.0(types-node@2.0.0)"]);
}
