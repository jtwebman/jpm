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
fn verify_lays_out_again_only_what_changed() {
    // Each package placed is checked as the isolated layout checks an entry, and only one whose
    // files are not the store's is laid out again: on Windows, laying out all of cal.com's
    // 325,000 files again took longer than the install did.
    let r = registry();
    let env = Env::new(&r);
    env.write(
        ".npmrc",
        "node-linker=hoisted
",
    );
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "2.0.0", "cli": "1.0.0" } }));
    env.ok(&["install"]);
    std::fs::remove_file(env.path("node_modules/a/node_modules/b/index.js")).unwrap();
    let out = env.ok(&["install", "--verify"]);
    assert!(out.contains("1 entries (3 reused)"), "{out}");
    assert!(env.read("node_modules/a/node_modules/b/index.js").contains("b@1.0.0"));
    let out = env.ok(&["install", "--verify"]);
    assert!(out.contains("0 entries (4 reused)"), "{out}");
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

#[cfg(unix)]
#[test]
fn never_writes_through_a_link_out_of_the_project() {
    // A checkout can leave a link where a package was: nothing is placed or removed under it.
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "2.0.0" } }));
    env.ok(&["install"]);
    let outside = env.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::remove_dir_all(env.path("node_modules/a")).unwrap();
    std::os::unix::fs::symlink(&outside, env.path("node_modules/a")).unwrap();
    // The link goes, as a link; a's own directory and its b are made in its place.
    env.ok(&["install"]);
    assert!(real_dir(&env, "node_modules/a") && real_dir(&env, "node_modules/a/node_modules/b"));
    assert!(!outside.join("node_modules").exists());
}

#[cfg(unix)]
#[test]
fn never_keeps_a_link_where_a_package_was_placed() {
    // The previous install's state says node_modules/a is a@1.0.0; a link to elsewhere there is
    // not it: replaced with a's own files, the elsewhere left alone.
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "node-linker=hoisted\n");
    env.manifest(json!({ "dependencies": { "a": "1.0.0" } }));
    env.ok(&["install"]);
    let outside = env.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("index.js"), "evil").unwrap();
    std::fs::remove_dir_all(env.path("node_modules/a")).unwrap();
    std::os::unix::fs::symlink(&outside, env.path("node_modules/a")).unwrap();
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "cli": "1.0.0" } }));
    env.ok(&["install"]);
    assert!(real_dir(&env, "node_modules/a"));
    assert!(env.read("node_modules/a/index.js").contains("a@1.0.0"));
    assert_eq!(std::fs::read_to_string(outside.join("index.js")).unwrap(), "evil");
}
