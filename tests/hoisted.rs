//! End to end: `node-linker=hoisted`, npm's layout of real directories.

mod common;

use common::{Env, Registry, pkg};
use serde_json::json;

fn registry() -> Registry {
    Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("b", "2.0.0", json!({})),
        pkg("cli", "1.0.0", json!({ "bin": { "hello": "bin/hello.js" } })).file(
            "bin/hello.js",
            0o755,
            "#!/bin/sh\necho hello-from-cli\n",
        ),
        pkg("electron", "1.0.0", json!({})),
        pkg(
            "bld",
            "1.0.0",
            json!({ "dependencies": { "b": "1.0.0" }, "scripts": { "postinstall": "echo run >> count.txt" } }),
        ),
    ])
}

fn real_dir(env: &Env, rel: &str) -> bool {
    std::fs::symlink_metadata(env.path(rel)).is_ok_and(|m| m.is_dir())
}

#[test]
fn lays_out_node_modules_as_npm_does() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "2.0.0", "cli": "1.0.0" } }));
    env.ok(&["install"]);
    // Real directories; a's b nested under it, where the root's b is another version.
    assert!(real_dir(&env, "node_modules/a") && real_dir(&env, "node_modules/b"));
    assert!(env.read("node_modules/b/index.js").contains("b@2.0.0"));
    assert!(env.read("node_modules/a/node_modules/b/index.js").contains("b@1.0.0"));
    assert!(!env.exists("node_modules/.jpm"), "no entries");
    let bin = if cfg!(windows) { "node_modules/.bin/hello.cmd" } else { "node_modules/.bin/hello" };
    assert!(env.exists(bin));
    assert!(env.ok(&["install"]).contains("up to date"));
    // `--verify` trusts nothing it finds: a file changed in place is put back.
    std::fs::remove_file(env.path("node_modules/b/index.js")).unwrap();
    std::fs::write(env.path("node_modules/b/index.js"), "changed").unwrap();
    env.ok(&["install", "--verify"]);
    assert!(env.read("node_modules/b/index.js").contains("b@2.0.0"));
    // A change moves only what it must; a dependency gone goes.
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "1.0.0" } }));
    env.ok(&["install"]);
    assert!(env.read("node_modules/b/index.js").contains("b@1.0.0"));
    assert!(!env.exists("node_modules/a/node_modules/b"), "a now finds the root's b");
    assert!(!env.exists("node_modules/cli") && !env.exists(bin));
    // From the lockfile alone.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
    assert!(real_dir(&env, "node_modules/a") && env.read("node_modules/b/index.js").contains("b@1.0.0"));
    // Back to jpm's own layout: the tree is laid out again.
    env.write(".npmrc", "node-linker=isolated\n");
    env.ok(&["install"]);
    assert!(env.exists("node_modules/.jpm") && !real_dir(&env, "node_modules/a"));
}

#[test]
fn links_every_workspace_at_the_root() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.manifest(json!({ "name": "root", "workspaces": ["w"], "dependencies": { "b": "2.0.0" } }));
    env.write("w/package.json", r#"{ "name": "w", "dependencies": { "a": "1.0.0", "b": "1.0.0" } }"#);
    env.ok(&["install"]);
    let real = |p: &str| std::fs::canonicalize(env.path(p)).unwrap();
    assert_eq!(real("node_modules/w"), real("w"));
    // The workspace's own b in its node_modules; a at the root, finding w's b first from w.
    assert!(env.read("w/node_modules/b/index.js").contains("b@1.0.0"));
    assert!(env.read("node_modules/b/index.js").contains("b@2.0.0"));
    assert!(real_dir(&env, "node_modules/a") || real_dir(&env, "w/node_modules/a"));
    assert!(env.ok(&["install"]).contains("up to date"));
}

#[test]
fn an_electron_app_is_hoisted_unless_set_otherwise() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "devDependencies": { "electron": "1.0.0" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("laying out node_modules as npm does: electron"), "{out}");
    assert!(real_dir(&env, "node_modules/a") && real_dir(&env, "node_modules/b"));
    env.write(".npmrc", "node-linker=isolated\n");
    env.ok(&["install"]);
    assert!(env.exists("node_modules/.jpm") && !real_dir(&env, "node_modules/a"));
}

#[cfg(unix)]
#[test]
fn runs_install_scripts_where_the_package_is() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "trustedDependencies": ["bld"] }));
    env.ok(&["install"]);
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");
    assert!(real_dir(&env, "node_modules/bld"));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n", "not again");
}

#[test]
fn patches_a_hoisted_package() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.write(
        "patches/b.patch",
        "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 'b@1.0.0'\n\\ No newline at end of file\n+module.exports = 'patched'\n\\ No newline at end of file\n",
    );
    env.manifest(json!({ "dependencies": { "b": "1.0.0" }, "patchedDependencies": { "b@1.0.0": "patches/b.patch" } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'patched'");
    // The store keeps b as published.
    let other = env.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("package.json"), r#"{ "dependencies": { "b": "1.0.0" } }"#).unwrap();
    std::fs::write(other.join(".npmrc"), "node-linker=hoisted\n").unwrap();
    assert!(env.command_in(&other, &["install"]).output().unwrap().status.success());
    assert_eq!(std::fs::read_to_string(other.join("node_modules/b/index.js")).unwrap(), "module.exports = 'b@1.0.0'");
}

#[test]
fn a_run_keeps_the_layout_the_last_install_chose() {
    // turbo runs each task with only the variables it is told to pass: a script's `jpm run`
    // may not see what chose the layout. It installs first only if the tree is not the last
    // install's, and keeps that install's layout.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "scripts": { "t": "echo ran" } }));
    let out = env.command(&["install"]).env("npm_config_node_linker", "hoisted").output().unwrap();
    assert!(out.status.success());
    assert!(real_dir(&env, "node_modules/a"));
    let out = env.ok(&["run", "t"]);
    assert!(!out.contains("installed"), "{out}");
    assert!(real_dir(&env, "node_modules/a"), "still hoisted");
}
