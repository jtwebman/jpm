//! End to end: overrides from every manager's field, and what else pnpm-workspace.yaml says.

mod common;

use common::{Env, Registry, pkg};
use serde_json::{Value, json};

fn registry() -> Registry {
    Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })),
        pkg("a", "1.1.0", json!({ "dependencies": { "b": "^1.1.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("b", "1.1.0", json!({})),
        pkg("b", "2.0.0", json!({})),
        pkg("c", "1.0.0", json!({ "dependencies": { "b": "^2.0.0" } })),
        pkg("host", "1.0.0", json!({})),
        pkg("host", "2.0.0", json!({})),
        pkg("plugin", "1.0.0", json!({ "peerDependencies": { "host": ">=1" } })),
    ])
}

fn integrity(name: &str, version: &str, manifest: Value) -> String {
    common::sha512(&pkg(name, version, manifest).tarball())
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "jpm {args:?} succeeded: {text}");
    text
}

/// The lockfile an install of `manifest` writes, with the files given beside package.json.
fn installed(r: &Registry, manifest: Value, files: &[(&str, &str)]) -> (Env, Value, String) {
    let env = Env::new(r);
    env.manifest(manifest);
    for (file, text) in files {
        env.write(file, text);
    }
    let out = env.ok(&["install"]);
    let lock = env.lock();
    (env, lock, out)
}

fn dep(lock: &Value, key: &str, name: &str) -> Value {
    lock["packages"][key]["dependencies"][name].clone()
}

#[test]
fn applies_every_override_form() {
    let r = registry();
    let both = json!({ "a": "1.1.0", "c": "1.0.0" });
    // npm: a name everywhere, a name in a range, one level of nesting and `$` references.
    let (env, lock, _) = installed(&r, json!({ "dependencies": { "a": "1.1.0" }, "overrides": { "b": "1.0.0" } }), &[]);
    assert_eq!(dep(&lock, "a@1.1.0", "b"), "1.0.0");
    assert!(env.read("jpm.lock").contains("  override npm b 1.0.0\n"));
    assert_eq!(lock["root"]["overrides"], json!([["npm", "b", "1.0.0"]]));
    let (_, lock, _) = installed(&r, json!({ "dependencies": both, "overrides": { "b@^1.1.0": "1.0.0" } }), &[]);
    assert_eq!((dep(&lock, "a@1.1.0", "b"), dep(&lock, "c@1.0.0", "b")), (json!("1.0.0"), json!("2.0.0")));
    let (_, lock, out) = installed(
        &r,
        json!({ "dependencies": { "a": "1.1.0", "c": "1.0.0", "b": "1.1.0" }, "overrides": { "c": { "b": "$b" }, "a": { "b": { "x": "1" } } } }),
        &[],
    );
    assert_eq!(dep(&lock, "c@1.0.0", "b"), "1.1.0");
    assert!(out.contains("overrides a > b > x: jpm applies it to every b's x"), "{out}");
    // yarn: a parent's dependency, or any.
    let (_, lock, _) = installed(&r, json!({ "dependencies": both, "resolutions": { "a/b": "1.0.0" } }), &[]);
    assert_eq!((dep(&lock, "a@1.1.0", "b"), dep(&lock, "c@1.0.0", "b")), (json!("1.0.0"), json!("2.0.0")));
    let (_, lock, _) = installed(&r, json!({ "dependencies": both, "resolutions": { "**/b": "1.0.0" } }), &[]);
    assert_eq!((dep(&lock, "a@1.1.0", "b"), dep(&lock, "c@1.0.0", "b")), (json!("1.0.0"), json!("1.0.0")));
    // pnpm: `-` takes an edge out; a parent's edge; a peer's range; pnpm-workspace.yaml.
    let (_, lock, _) =
        installed(&r, json!({ "dependencies": { "a": "1.1.0" }, "pnpm": { "overrides": { "a>b": "-" } } }), &[]);
    assert!(dep(&lock, "a@1.1.0", "b").is_null() && lock["packages"].get("b@1.1.0").is_none());
    let (_, lock, _) =
        installed(&r, json!({ "dependencies": both }), &[("pnpm-workspace.yaml", "overrides:\n  'c@1>b': 1.1.0\n")]);
    assert_eq!((dep(&lock, "a@1.1.0", "b"), dep(&lock, "c@1.0.0", "b")), (json!("1.1.0"), json!("1.1.0")));
    let (_, lock, _) = installed(
        &r,
        json!({ "dependencies": { "plugin": "1" }, "pnpm": { "overrides": { "plugin>host": "1.0.0" } } }),
        &[],
    );
    assert_eq!(dep(&lock, "plugin@1.0.0", "host"), "1.0.0", "not the newest host");
    // A value from the catalog.
    let yaml = "catalog:\n  b: 1.0.0\noverrides:\n  b: 'catalog:'\n";
    let (_, lock, _) = installed(&r, json!({ "dependencies": { "a": "1.1.0" } }), &[("pnpm-workspace.yaml", yaml)]);
    assert_eq!(dep(&lock, "a@1.1.0", "b"), "1.0.0");
    // The root's own edges too.
    let (env, lock, _) =
        installed(&r, json!({ "dependencies": { "b": "^1.0.0" }, "overrides": { "b": "2.0.0" } }), &[]);
    assert_eq!(lock["root"]["dependencies"]["b"], "2.0.0");
    assert!(env.read("node_modules/b/index.js").contains("b@2.0.0"));
}

#[test]
fn an_override_to_a_workspace_leaves_registry_packages_their_range() {
    // As vite and nuxt have it: a workspace overrides the registry package of its name. The
    // root and the workspaces link to it; a registry package keeps what it asked for.
    let r = registry();
    // A peer too: vitest's peer vite, in vite's own repository.
    let (env, lock, out) = installed(
        &r,
        json!({ "name": "root", "workspaces": ["b", "host"], "dependencies": { "a": "1.1.0", "b": "^1.0.0", "plugin": "1" } }),
        &[
            ("pnpm-workspace.yaml", "overrides:\n  b: 'workspace:*'\n  host: 'workspace:*'\n"),
            ("b/package.json", r#"{ "name": "b", "version": "1.5.0" }"#),
            ("host/package.json", r#"{ "name": "host", "version": "3.0.0" }"#),
        ],
    );
    assert_eq!(dep(&lock, "a@1.1.0", "b"), "1.1.0");
    assert!(env.read("node_modules/b/package.json").contains("1.5.0"), "the root links the workspace");
    assert!(out.contains("overrides send b to workspace:*"), "{out}");
    assert!(out.contains("overrides send host to workspace:*"), "{out}");
    assert!(dep(&lock, "plugin@1.0.0", "host").as_str().is_some_and(|v| v.starts_with("2.")), "{lock}");

    // A directory the same way, as nitro sends oxc-parser to a shim of its own.
    let (env, lock, out) = installed(
        &r,
        json!({ "name": "root", "dependencies": { "a": "1.1.0", "b": "^1.0.0" } }),
        &[
            ("pnpm-workspace.yaml", "overrides:\n  b: 'link:./shims/b'\n"),
            ("shims/b/package.json", r#"{ "name": "b", "version": "9.0.0" }"#),
        ],
    );
    assert_eq!(dep(&lock, "a@1.1.0", "b"), "1.1.0");
    assert!(env.read("node_modules/b/package.json").contains("9.0.0"), "the root links the shim");
    assert!(out.contains("overrides send b to link:./shims/b"), "{out}");
}

#[test]
fn an_override_change_makes_the_lockfile_stale() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "a@1.1.0", "b"), "1.1.0");
    env.manifest(json!({ "dependencies": { "a": "1.1.0" }, "resolutions": { "b": "1.0.0" } }));
    assert!(fails(&env, &["ci"]).contains("out of date"));
    // a@1.1.0 is still locked, but what it was locked with is not what the overrides say.
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "a@1.1.0", "b"), "1.0.0");
    // A frozen install from jpm.lock holds to them.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.0.0"));
    // And without them, the range picks again.
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    assert_eq!(dep(&env.lock(), "a@1.1.0", "b"), "1.1.0");
    assert!(!env.read("jpm.lock").contains("override"));
}

#[test]
fn brings_over_a_pnpm_lockfile_resolved_under_overrides() {
    let r = registry();
    // The file says which overrides it was resolved under.
    let lock = |overrides: &str| {
        format!(
            "lockfileVersion: '9.0'\n\noverrides:\n{overrides}\nimporters:\n\n  .:\n    dependencies:\n      a:\n        specifier: 1.1.0\n        version: 1.1.0\n\npackages:\n\n  a@1.1.0:\n    resolution: {{integrity: {}}}\n\n  b@1.0.0:\n    resolution: {{integrity: {}}}\n\nsnapshots:\n\n  a@1.1.0:\n    dependencies:\n      b: 1.0.0\n\n  b@1.0.0: {{}}\n",
            integrity("a", "1.1.0", json!({ "dependencies": { "b": "^1.1.0" } })),
            integrity("b", "1.0.0", json!({}))
        )
    };
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.write("pnpm-workspace.yaml", "overrides:\n  b: 1.0.0\n");
    env.write("pnpm-lock.yaml", &lock("  b: 1.0.0\n"));
    let out = env.ok(&["install"]);
    assert!(out.contains("with the same versions"), "{out}");
    assert!(env.read("jpm.lock").contains("  override pnpm b 1.0.0\n"));
    env.ok(&["ci"]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.write("pnpm-workspace.yaml", "overrides:\n  b: 1.0.0\n");
    env.write("pnpm-lock.yaml", &lock("  b: 1.1.0\n"));
    assert!(env.ok(&["install"]).contains("versions preferred"));
}

#[test]
fn a_frozen_yarn_install_honors_resolutions() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" }, "resolutions": { "b": "1.0.0" } }));
    // yarn keeps the range a asked for as the key, with the version the resolution forced.
    env.write(
        "yarn.lock",
        "# yarn lockfile v1\n\n\na@1.1.0:\n  version \"1.1.0\"\n  dependencies:\n    b \"^1.1.0\"\n\nb@1.0.0, b@^1.1.0:\n  version \"1.0.0\"\n",
    );
    env.ok(&["ci"]);
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.0.0"));
    let out = env.ok(&["install"]);
    assert!(out.contains("from yarn.lock"), "{out}");
    assert_eq!(dep(&env.lock(), "a@1.1.0", "b"), "1.0.0");
}

#[test]
fn says_what_it_does_not_read() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    env.write("pnpm-workspace.yaml", "minimumReleaseAge: 1440\npeerDependencyRules:\n  ignoreMissing: [x]\n");
    let out = env.ok(&["install"]);
    assert!(out.contains("pnpm-workspace.yaml sets minimumReleaseAge, which jpm does not read"), "{out}");
    assert!(!out.contains("peerDependencyRules"), "only settings that change the tree: {out}");
}

#[cfg(unix)]
#[test]
fn trusts_builds_pnpm_workspace_yaml_allows() {
    let bld = pkg("bld", "1.0.0", json!({ "scripts": { "postinstall": "echo run >> count.txt" } }));
    let r = Registry::start(vec![bld]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" } }));
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");
    // Trusted by pnpm-workspace.yaml alone: the version approved in jpm.lock runs.
    for yaml in ["allowBuilds:\n  bld: true\n", "onlyBuiltDependencies:\n  - bld\n"] {
        env.manifest(json!({ "dependencies": { "bld": "1.0.0" } }));
        env.write("pnpm-workspace.yaml", yaml);
        std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
        env.ok(&["install"]);
        assert_eq!(env.read("node_modules/bld/count.txt"), "run\n", "{yaml}");
    }
    // `false` takes the name out, whatever package.json says.
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "trustedDependencies": ["bld"] }));
    env.write("pnpm-workspace.yaml", "allowBuilds:\n  bld: false\n");
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    let out = env.ok(&["install"]);
    assert!(!env.exists("node_modules/bld/count.txt"));
    // And that is an answer: nothing waits for approval.
    assert!(!out.contains("install scripts not run"), "{out}");
}
