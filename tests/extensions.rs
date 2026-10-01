//! End to end: packageExtensions from pnpm-workspace.yaml, package.json and .yarnrc.yml, fixing
//! what published packages forgot to declare.

mod common;

use common::{Env, Registry, pkg};
use serde_json::{Value, json};

fn registry() -> Registry {
    Registry::start(vec![
        // Requires helper and never says so; its next major does.
        pkg("forgetful", "1.0.0", json!({})).file("index.js", 0o644, "module.exports = require('helper')"),
        pkg("forgetful", "2.0.0", json!({ "dependencies": { "helper": "^1.0.0" } })),
        pkg("helper", "1.0.0", json!({})),
        pkg("helper", "1.1.0", json!({})),
        pkg("helper", "2.0.0", json!({})),
        pkg("extra", "1.0.0", json!({})),
        pkg("old-user", "1.0.0", json!({ "dependencies": { "forgetful": "1.0.0" } })),
        pkg("new-user", "1.0.0", json!({ "dependencies": { "forgetful": "2.0.0" } })),
        // Uses its host without a peer on it.
        pkg("plugin", "1.0.0", json!({})),
        pkg("host", "1.0.0", json!({})),
        pkg("host", "2.0.0", json!({})),
        // A required peer that should have been optional.
        pkg("soft", "1.0.0", json!({ "peerDependencies": { "host": "*" } })),
    ])
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "jpm {args:?} succeeded: {text}");
    text
}

fn dep(lock: &Value, key: &str, name: &str) -> Value {
    lock["packages"][key]["dependencies"][name].clone()
}

/// What `require(dep)` from inside the installed package `name` finds: its index.js.
fn seen_from(env: &Env, name: &str, dep: &str) -> String {
    env.read(&format!("node_modules/{name}/../{dep}/index.js"))
}

#[test]
fn adds_a_missing_dependency_from_each_place_extensions_are_written() {
    let r = registry();
    let root = json!({ "dependencies": { "forgetful": "1.0.0" } });
    let ext = json!({ "forgetful": { "dependencies": { "helper": "^1.0.0" } } });
    let yaml = "packageExtensions:\n  forgetful:\n    dependencies:\n      helper: ^1.0.0\n";
    let yarnrc = "nodeLinker: node-modules\npackageExtensions:\n  'forgetful@*':\n    dependencies:\n      helper: 'npm:^1.0.0'\n";
    // Selector, package.json, and the file beside it.
    type Case<'a> = (&'a str, Value, Option<(&'a str, &'a str)>);
    let cases: [Case; 3] = [
        ("forgetful", json!({ "dependencies": root["dependencies"], "pnpm": { "packageExtensions": ext } }), None),
        ("forgetful", root.clone(), Some(("pnpm-workspace.yaml", yaml))),
        ("forgetful@*", root.clone(), Some((".yarnrc.yml", yarnrc))),
    ];
    for (selector, manifest, file) in cases {
        let env = Env::new(&r);
        env.manifest(manifest);
        if let Some((file, text)) = file {
            env.write(file, text);
        }
        let out = env.ok(&["install"]);
        assert!(!out.contains("which jpm does not read"), "{out}");
        let lock = env.lock();
        assert_eq!(dep(&lock, "forgetful@1.0.0", "helper"), "1.1.0", "{selector}");
        assert_eq!(seen_from(&env, "forgetful", "helper"), "module.exports = 'helper@1.1.0'");
        let line = format!("  extension {selector} dependencies helper ^1.0.0\n");
        assert!(env.read("jpm.lock").contains(&line), "{}", env.read("jpm.lock"));
        assert_eq!(lock["root"]["packageExtensions"][selector]["dependencies"]["helper"], "^1.0.0");
        // A frozen install holds to them, and installs the same.
        std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
        env.ok(&["ci"]);
        assert_eq!(seen_from(&env, "forgetful", "helper"), "module.exports = 'helper@1.1.0'");
    }
}

#[test]
fn a_range_extends_only_the_versions_it_matches() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "old-user": "1.0.0", "new-user": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful@^1": { "dependencies": { "extra": "1.0.0" } } } }
    }));
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(dep(&lock, "forgetful@1.0.0", "extra"), "1.0.0");
    assert!(dep(&lock, "forgetful@2.0.0", "extra").is_null());
}

#[test]
fn what_a_package_declares_wins_over_an_extension() {
    // As pnpm merges them, `{ ...extension, ...manifest }`: forgetful@2 keeps its own ^1.0.0.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "old-user": "1.0.0", "new-user": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "helper": "2.0.0" } } } }
    }));
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(dep(&lock, "forgetful@1.0.0", "helper"), "2.0.0");
    assert_eq!(dep(&lock, "forgetful@2.0.0", "helper"), "1.1.0");
}

#[test]
fn several_extensions_of_a_package_apply_in_order() {
    // The first to name a dependency gives its range: pnpm-workspace.yaml's before .yarnrc.yml's.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "forgetful": "1.0.0" } }));
    env.write(
        "pnpm-workspace.yaml",
        "packageExtensions:\n  forgetful@1:\n    dependencies:\n      helper: 1.0.0\n  forgetful:\n    dependencies:\n      helper: 2.0.0\n      extra: 1.0.0\n",
    );
    env.write(".yarnrc.yml", "packageExtensions:\n  forgetful@*:\n    dependencies:\n      helper: ^1.1.0\n");
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(dep(&lock, "forgetful@1.0.0", "helper"), "1.0.0");
    assert_eq!(dep(&lock, "forgetful@1.0.0", "extra"), "1.0.0");
}

#[test]
fn reads_pnpm_workspace_yaml_in_place_of_package_json() {
    // pnpm 10 takes pnpm-workspace.yaml's setting in place of package.json's.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "forgetful": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "extra": "1.0.0" } } } }
    }));
    env.write("pnpm-workspace.yaml", "packageExtensions:\n  forgetful:\n    dependencies:\n      helper: 1.0.0\n");
    let out = env.ok(&["install"]);
    assert!(out.contains("pnpm-workspace.yaml's are read, as pnpm reads them"), "{out}");
    let lock = env.lock();
    assert_eq!(dep(&lock, "forgetful@1.0.0", "helper"), "1.0.0");
    assert!(dep(&lock, "forgetful@1.0.0", "extra").is_null());
}

#[test]
fn adds_a_peer() {
    let r = registry();
    let ext = json!({ "plugin": { "peerDependencies": { "host": "^1.0.0" } } });
    // The root's host is the one the plugin gets.
    let env = Env::new(&r);
    env.manifest(
        json!({ "dependencies": { "plugin": "1.0.0", "host": "1.0.0" }, "pnpm": { "packageExtensions": ext } }),
    );
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(lock["packages"]["plugin@1.0.0"]["peerDependencies"]["host"], "^1.0.0");
    assert_eq!(dep(&lock, "plugin@1.0.0", "host"), "1.0.0");
    assert_eq!(seen_from(&env, "plugin", "host"), "module.exports = 'host@1.0.0'");
    // With no host in the tree, a required peer is installed, in its range.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "plugin": "1.0.0" }, "pnpm": { "packageExtensions": ext } }));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "plugin@1.0.0", "host"), "1.0.0");
}

#[test]
fn makes_a_peer_optional() {
    let r = registry();
    // Without the extension soft's required peer is installed.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "soft": "1.0.0" } }));
    env.ok(&["install"]);
    assert!(env.lock()["packages"].get("host@2.0.0").is_some());
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "soft": "1.0.0" },
        "pnpm": { "packageExtensions": { "soft": { "peerDependenciesMeta": { "host": { "optional": true } } } } }
    }));
    let out = env.ok(&["install"]);
    let lock = env.lock();
    assert!(lock["packages"].as_object().unwrap().keys().all(|k| !k.starts_with("host@")), "{lock}");
    assert!(!out.contains("host"), "an optional peer missing is no warning: {out}");
    assert!(env.read("jpm.lock").contains("  extension soft peerDependenciesMeta host true\n"));
    // Where the tree has one, it is linked.
    env.manifest(json!({
        "dependencies": { "soft": "1.0.0", "host": "1.0.0" },
        "pnpm": { "packageExtensions": { "soft": { "peerDependenciesMeta": { "host": { "optional": true } } } } }
    }));
    env.ok(&["install"]);
    assert_eq!(seen_from(&env, "soft", "host"), "module.exports = 'host@1.0.0'");
}

#[test]
fn a_change_resolves_again_and_taking_it_out_goes_back() {
    let r = registry();
    let env = Env::new(&r);
    let plain = json!({ "dependencies": { "forgetful": "1.0.0" } });
    env.manifest(plain.clone());
    env.ok(&["install"]);
    let before = env.read("jpm.lock");
    assert!(!before.contains("extension"));
    let with = |range: &str| json!({ "dependencies": { "forgetful": "1.0.0" }, "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "helper": range } } } } });
    env.manifest(with("^1.0.0"));
    assert!(fails(&env, &["ci"]).contains("out of date"));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "forgetful@1.0.0", "helper"), "1.1.0");
    // Another range is another tree.
    env.manifest(with("2.0.0"));
    assert!(fails(&env, &["ci"]).contains("out of date"));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "forgetful@1.0.0", "helper"), "2.0.0");
    assert_eq!(seen_from(&env, "forgetful", "helper"), "module.exports = 'helper@2.0.0'");
    // The same again resolves nothing.
    let out = env.ok(&["install"]);
    assert!(!out.contains("wrote"), "{out}");
    // Gone: the lockfile is what it was, byte for byte.
    env.manifest(plain);
    env.ok(&["install"]);
    assert_eq!(env.read("jpm.lock"), before);
    assert!(!env.exists("node_modules/forgetful/../helper"));
    // In .yarnrc.yml, which the install's state reads too.
    env.write(".yarnrc.yml", "packageExtensions:\n  forgetful@*:\n    dependencies:\n      helper: 1.0.0\n");
    env.ok(&["install"]);
    assert_eq!(seen_from(&env, "forgetful", "helper"), "module.exports = 'helper@1.0.0'");
}

#[test]
fn extends_a_workspace_as_pnpm_extends_its_projects() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["app"] }));
    env.write("app/package.json", r#"{ "name": "app", "version": "1.0.0" }"#);
    env.write(
        "pnpm-workspace.yaml",
        "packages: [app]\npackageExtensions:\n  app@1:\n    dependencies:\n      helper: 1.0.0\n",
    );
    env.ok(&["install"]);
    assert_eq!(env.lock()["workspaces"]["app"]["dependencies"]["helper"], "1.0.0");
    assert_eq!(env.read("app/node_modules/helper/index.js"), "module.exports = 'helper@1.0.0'");
}

#[test]
fn says_which_extensions_change_nothing() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "new-user": "1.0.0" },
        "pnpm": { "packageExtensions": {
            "nothing-here": { "dependencies": { "helper": "1" } },
            "forgetful@2": { "dependencies": { "helper": "^1.0.0" } }
        } }
    }));
    let out = env.ok(&["install"]);
    assert!(out.contains("packageExtensions nothing-here: no package in the tree matches it"), "{out}");
    assert!(
        out.contains("packageExtensions forgetful@2: every package it matches declares what it adds already"),
        "{out}"
    );
    // What it cannot read is named, and left out.
    env.manifest(json!({
        "dependencies": { "new-user": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "helper": "file:../helper" }, "devDependencies": {} } } }
    }));
    let out = env.ok(&["install"]);
    assert!(out.contains("packageExtensions forgetful"), "{out}");
}

#[test]
fn an_extension_may_name_a_tarball_url_the_project_chose() {
    // As an override's: block-exotic-subdeps stops what a package brings in itself, not what the
    // project's own extensions give it.
    let r = registry();
    r.serve("/tb/helper-3.0.0.tgz", pkg("helper", "3.0.0", json!({})).tarball());
    let url = format!("{}/tb/helper-3.0.0.tgz", r.url);
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "forgetful": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "helper": url } } } }
    }));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "forgetful@1.0.0", "helper"), url.as_str());
    assert_eq!(seen_from(&env, "forgetful", "helper"), "module.exports = 'helper@3.0.0'");
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
}

#[test]
fn what_an_extension_adds_waits_out_the_release_age_and_its_scripts_wait_for_approval() {
    let r = Registry::start(vec![
        pkg("forgetful", "1.0.0", json!({})),
        pkg("helper", "1.0.0", json!({ "scripts": { "postinstall": "node -e 0" } })),
        pkg("helper", "1.1.0", json!({ "_published": "2999-01-01T00:00:00.000Z" })),
    ]);
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "forgetful": "1.0.0" },
        "pnpm": { "packageExtensions": { "forgetful": { "dependencies": { "helper": "^1.0.0" } } } }
    }));
    let out = env.command(&["install"]).env("npm_config_min_release_age", "1").output().unwrap();
    let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert_eq!(dep(&env.lock(), "forgetful@1.0.0", "helper"), "1.0.0", "1.1.0 is too new");
    assert!(text.contains("install scripts not run for helper@1.0.0"), "{text}");
}

#[test]
fn brings_over_a_pnpm_lockfile_resolved_under_the_same_extensions() {
    // pnpm records a checksum of its packageExtensions; this one is pnpm's own test's
    // (installing/deps-installer/test/install/packageExtensions.ts).
    let bar = pkg("@pnpm.e2e/bar", "100.1.0", json!({}));
    let positive = pkg("is-positive", "1.0.0", json!({}));
    let lock = |checksum: &str| {
        format!(
            "lockfileVersion: '9.0'\n\n{checksum}importers:\n\n  .:\n    dependencies:\n      is-positive:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  '@pnpm.e2e/bar@100.1.0':\n    resolution: {{integrity: {}}}\n\n  is-positive@1.0.0:\n    resolution: {{integrity: {}}}\n\nsnapshots:\n\n  '@pnpm.e2e/bar@100.1.0': {{}}\n\n  is-positive@1.0.0:\n    dependencies:\n      '@pnpm.e2e/bar': 100.1.0\n",
            common::sha512(&bar.tarball()),
            common::sha512(&positive.tarball()),
        )
    };
    let r = Registry::start(vec![bar.clone(), positive.clone(), pkg("@pnpm.e2e/bar", "100.2.0", json!({}))]);
    let yaml = "packageExtensions:\n  is-positive:\n    dependencies:\n      '@pnpm.e2e/bar': 100.1.0\n";
    let checksum = "packageExtensionsChecksum: sha256-HZEpjtRdr7gJfO0V6YoFDfxWmaw3anoE1/tQQbzas+E=\n\n";
    let project = |checksum: &str| {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "is-positive": "1.0.0" } }));
        env.write("pnpm-workspace.yaml", yaml);
        env.write("pnpm-lock.yaml", &lock(checksum));
        env
    };
    let env = project(checksum);
    env.ok(&["ci"]);
    let out = env.ok(&["install"]);
    assert!(out.contains("with the same versions"), "{out}");
    assert!(env.read("jpm.lock").contains("  extension is-positive dependencies @pnpm.e2e/bar 100.1.0\n"));
    // Written without them, or under others: resolved again, with them.
    for other in ["", "packageExtensionsChecksum: sha256-AAAA\n\n"] {
        let env = project(other);
        assert!(fails(&env, &["ci"]).contains("pnpm-lock.yaml is out of date with the packageExtensions"));
        let out = env.ok(&["install"]);
        assert!(out.contains("versions preferred"), "{out}");
        assert_eq!(dep(&env.lock(), "is-positive@1.0.0", "@pnpm.e2e/bar"), "100.1.0");
    }
    // A pnpm-lock.yaml with a checksum, for a project with none.
    let env = project(checksum);
    env.write("pnpm-workspace.yaml", "");
    assert!(fails(&env, &["ci"]).contains("out of date with the packageExtensions"));
}
