//! End to end: pnpm's and bun's `patchedDependencies`, yarn's `patch:`, and `jpm patch`.

mod common;

use common::{Env, Registry, pkg};
use serde_json::json;

fn registry() -> Registry {
    Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("b", "2.0.0", json!({})),
    ])
}

/// A git diff of b's `index.js` (written with no newline at its end) to `to`.
fn diff(from: &str, to: &str) -> String {
    format!(
        "diff --git a/index.js b/index.js\nindex 1..2 100644\n--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n\
         -module.exports = '{from}'\n\\ No newline at end of file\n+module.exports = '{to}'\n\\ No newline at end of file\n"
    )
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "jpm {args:?} succeeded: {text}");
    text
}

#[test]
fn applies_a_pnpm_patch() {
    let r = registry();
    for global in ["1", "0"] {
        let env = Env::new(&r);
        let install = |args: &[&str]| {
            let out = env.command(args).env("JPM_GLOBAL_STORE", global).output().unwrap();
            let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            assert!(out.status.success(), "jpm {args:?} failed:\n{text}");
            text
        };
        env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "1.0.0" } }));
        env.write("patches/b@1.0.0.patch", &diff("b@1.0.0", "patched"));
        env.write("pnpm-workspace.yaml", "patchedDependencies:\n  b@1.0.0: patches/b@1.0.0.patch\n");
        install(&["install"]);
        assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'patched'");
        assert_eq!(env.read("node_modules/a/../b/index.js"), "module.exports = 'patched'", "a's b is the same copy");
        let lock = env.read("jpm.lock");
        let sha = lock.lines().find_map(|l| l.strip_prefix("  patch ")).unwrap_or_default();
        assert!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()), "{lock}");
        // Another project on the same store gets b as published: the patch went to a copy.
        let other = env.root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("package.json"), r#"{ "dependencies": { "b": "1.0.0" } }"#).unwrap();
        let out = env.command_in(&other, &["install"]).env("JPM_GLOBAL_STORE", global).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let clean = std::fs::read_to_string(other.join("node_modules/b/index.js")).unwrap();
        assert_eq!(clean, "module.exports = 'b@1.0.0'");
        assert!(install(&["install"]).contains("up to date"));
        // The patch file changes: the no-op check sees it, the lockfile and the copy follow.
        env.write("patches/b@1.0.0.patch", &diff("b@1.0.0", "again"));
        assert!(fails(&env, &["install", "--frozen-lockfile"]).contains("jpm.lock is out of date with the patches"));
        let out = install(&["install"]);
        assert!(!out.contains("up to date"), "{out}");
        assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'again'");
        assert_ne!(env.read("jpm.lock"), lock);
        install(&["ci"]);
        assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'again'");
        // Taken out: b as published, and no patch in the lockfile.
        env.write("pnpm-workspace.yaml", "\n");
        install(&["install"]);
        assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'b@1.0.0'");
        assert!(!env.read("jpm.lock").contains("patch"));
    }
}

#[test]
fn reads_patches_from_package_json() {
    let r = registry();
    let env = Env::new(&r);
    env.write("b.patch", &diff("b@1.0.0", "every b"));
    env.write("b2.patch", &diff("b@2.0.0", "b two"));
    // pnpm's bare name takes every version; a version's own patch comes first.
    let pnpm = json!({ "b": "b.patch", "b@2.0.0": "b2.patch" });
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "2.0.0" }, "pnpm": { "patchedDependencies": pnpm } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'b two'");
    assert_eq!(env.read("node_modules/a/../b/index.js"), "module.exports = 'every b'");
    let lock = env.lock();
    assert!(lock["packages"]["b@1.0.0"]["patch"].is_string() && lock["packages"]["b@2.0.0"]["patch"].is_string());
    assert_ne!(lock["packages"]["b@1.0.0"]["patch"], lock["packages"]["b@2.0.0"]["patch"]);
    // bun's field, a version to a patch.
    env.manifest(json!({ "dependencies": { "b": "2.0.0" }, "patchedDependencies": { "b@2.0.0": "b2.patch" } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'b two'");
    assert_eq!(env.lock()["packages"]["b@2.0.0"]["patch"], lock["packages"]["b@2.0.0"]["patch"]);
}

#[test]
fn refuses_patches_that_do_not_fit() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(
        json!({ "dependencies": { "b": "1.0.0" }, "pnpm": { "patchedDependencies": { "b@1.0.0": "b.patch" } } }),
    );
    // Written for another version: the context does not match.
    env.write("b.patch", &diff("b@9.9.9", "x"));
    let err = fails(&env, &["install"]);
    assert!(err.contains("b.patch does not apply to b@1.0.0: index.js: hunk #1 (@@ -1 +1 @@) does not apply"), "{err}");
    // Nothing in the tree to patch, as pnpm refuses too.
    env.manifest(
        json!({ "dependencies": { "b": "1.0.0" }, "pnpm": { "patchedDependencies": { "b@2.0.0": "b.patch" } } }),
    );
    assert!(fails(&env, &["install"]).contains("no package in the tree is patched by b@2.0.0 (b.patch)"));
    // A file that is not there.
    env.manifest(json!({ "dependencies": { "b": "1.0.0" }, "pnpm": { "patchedDependencies": { "b": "nope.patch" } } }));
    assert!(fails(&env, &["install"]).contains("cannot read the patch nope.patch"));
    // A path out of the package.
    env.manifest(json!({ "dependencies": { "b": "1.0.0" }, "pnpm": { "patchedDependencies": { "b": "b.patch" } } }));
    env.write("b.patch", "--- /dev/null\n+++ b/../../../../escaped.js\n@@ -0,0 +1 @@\n+x\n");
    assert!(fails(&env, &["install"]).contains("is not a path inside the package"));
    assert!(!env.root.join("escaped.js").exists() && !env.exists("escaped.js"));
}

#[cfg(unix)]
#[test]
fn patches_before_install_scripts_run() {
    let bld = pkg("bld", "1.0.0", json!({ "scripts": { "postinstall": "cat index.js > seen.txt" } }));
    let r = Registry::start(vec![bld]);
    let env = Env::new(&r);
    env.write("bld.patch", &diff("bld@1.0.0", "patched first").replace("b@", "bld@"));
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "patchedDependencies": { "bld@1.0.0": "bld.patch" } }));
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/seen.txt"), "module.exports = 'patched first'");
}

#[test]
fn brings_over_a_patched_pnpm_lockfile() {
    let r = registry();
    let integrity = common::sha512(&pkg("b", "1.0.0", json!({})).tarball());
    let lock = |path: &str| {
        format!(
            "lockfileVersion: '9.0'\n\npatchedDependencies:\n  b@1.0.0:\n    hash: 0123abcd\n    path: {path}\n\nimporters:\n\n  .:\n    dependencies:\n      b:\n        specifier: 1.0.0\n        version: 1.0.0(patch_hash=0123abcd)\n\npackages:\n\n  b@1.0.0:\n    resolution: {{integrity: {integrity}}}\n\nsnapshots:\n\n  b@1.0.0(patch_hash=0123abcd): {{}}\n"
        )
    };
    for (path, same) in [("patches/b.patch", true), ("patches/other.patch", false)] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
        env.write("pnpm-workspace.yaml", "patchedDependencies:\n  b@1.0.0: patches/b.patch\n");
        env.write("patches/b.patch", &diff("b@1.0.0", "from pnpm"));
        env.write("pnpm-lock.yaml", &lock(path));
        if same {
            env.ok(&["ci"]);
            assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'from pnpm'");
        } else {
            assert!(fails(&env, &["ci"]).contains("pnpm-lock.yaml is out of date with the patches"));
        }
        let out = env.ok(&["install"]);
        let said = if same { "with the same versions" } else { "out of date with the patches; resolving" };
        assert!(out.contains(said), "{out}");
        assert!(env.lock()["packages"]["b@1.0.0"]["patch"].is_string());
        assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'from pnpm'");
    }
}

#[test]
fn a_patch_changes_the_entries_above_it() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.0.0" } }));
    env.ok(&["install"]);
    let plain = std::fs::read_link(env.path("node_modules/a")).unwrap();
    env.write("b.patch", &diff("b@1.0.0", "patched"));
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "patchedDependencies": { "b@1.0.0": "b.patch" } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/a/../b/index.js"), "module.exports = 'patched'");
    // a's entry is another one: its key hashes what it reaches.
    assert_ne!(std::fs::read_link(env.path("node_modules/a")).unwrap(), plain);
    env.manifest(json!({ "dependencies": { "a": "1.0.0" } }));
    env.ok(&["install"]);
    assert_eq!(std::fs::read_link(env.path("node_modules/a")).unwrap(), plain);
    assert_eq!(env.read("node_modules/a/../b/index.js"), "module.exports = 'b@1.0.0'");
}

#[test]
fn applies_a_workspaces_yarn_patch_from_its_own_directory() {
    // backstage's and twenty's workspaces name patches: by a path from the workspace, or from
    // the root under `~/`.
    let r = registry();
    let env = Env::new(&r);
    env.write(".yarn/patches/b-npm-1.0.0-abc.patch", &diff("b@1.0.0", "from the workspace"));
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"] }));
    let dep = "patch:b@npm%3A1.0.0#../../.yarn/patches/b-npm-1.0.0-abc.patch";
    env.write("packages/w/package.json", &json!({ "name": "w", "dependencies": { "b": dep } }).to_string());
    env.ok(&["install"]);
    assert_eq!(env.read("packages/w/node_modules/b/index.js"), "module.exports = 'from the workspace'");
    let dep = "patch:b@npm%3A1.0.0#~/.yarn/patches/b-npm-1.0.0-abc.patch";
    env.write("packages/w/package.json", &json!({ "name": "w", "dependencies": { "b": dep } }).to_string());
    env.ok(&["install"]);
    assert_eq!(env.read("packages/w/node_modules/b/index.js"), "module.exports = 'from the workspace'");
}

#[test]
fn leaves_a_yarn_patch_nothing_takes_unused() {
    // cal.com's resolutions patch a version its tree no longer has: yarn leaves it unused.
    let r = registry();
    let env = Env::new(&r);
    env.write(".yarn/patches/b-npm-2.0.0-abc.patch", &diff("b@2.0.0", "yarn"));
    let stale = "patch:b@npm%3A2.0.0#./.yarn/patches/b-npm-2.0.0-abc.patch";
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "resolutions": { "b@^2.0.0": stale } }));
    let out = env.ok(&["install"]);
    assert!(
        out.contains("no package in the tree is patched by b@2.0.0") && out.contains("yarn leaves it unused"),
        "{out}"
    );
    // pnpm's is an error, as in pnpm.
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "pnpm": { "patchedDependencies": { "b@2.0.0": ".yarn/patches/b-npm-2.0.0-abc.patch" } } }));
    assert!(fails(&env, &["install"]).contains("no package in the tree is patched by b@2.0.0"));
    // Its file gone too (joplin's): yarn never reads it, and neither does jpm, until a package
    // takes it.
    let gone = "patch:b@npm%3A2.0.0#./.yarn/patches/gone.patch";
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "resolutions": { "b@^2.0.0": gone } }));
    assert!(env.ok(&["install"]).contains("yarn leaves it unused"));
    let gone = "patch:b@npm%3A1.0.0#./.yarn/patches/gone.patch";
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "resolutions": { "b@npm:1.0.0": gone } }));
    assert!(fails(&env, &["install"]).contains("cannot read the patch ./.yarn/patches/gone.patch"));
}

#[test]
fn applies_yarns_patch_protocol() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".yarn/patches/b-npm-1.0.0-abc.patch", &diff("b@1.0.0", "yarn"));
    // `yarn patch-commit -s`: a resolution to the patched source.
    let patched = "patch:b@npm%3A1.0.0#./.yarn/patches/b-npm-1.0.0-abc.patch";
    env.manifest(json!({ "dependencies": { "a": "1.0.0" }, "resolutions": { "b@npm:1.0.0": patched } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/a/../b/index.js"), "module.exports = 'yarn'");
    assert!(env.lock()["packages"]["b@1.0.0"]["patch"].is_string());
    // In place of a dependency's range, `~/` for the root, with yarn's parameters.
    let dep =
        "patch:b@npm%3A1.0.0#~/.yarn/patches/b-npm-1.0.0-abc.patch::version=1.0.0&hash=abc&locator=app%40workspace%3A.";
    env.manifest(json!({ "dependencies": { "b": dep } }));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'yarn'");
    assert!(env.read("jpm.lock").contains("  spec dependencies b 1.0.0\n"));
    // yarn.lock names the patched package by its patch: read for the version it gave.
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    let key = dep.replace("::version=1.0.0&hash=abc", "");
    let lock = format!("__metadata:\n  version: 8\n\n\"b@{key}\":\n  version: 1.0.0\n  resolution: \"b@{dep}\"\n");
    env.write("yarn.lock", &lock);
    env.ok(&["ci"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'yarn'");
    // yarn's builtin patches are for Plug'n'Play: the package as published.
    env.manifest(json!({ "dependencies": { "b": "patch:b@npm%3A^1.0.0#optional!builtin<compat/b>" } }));
    std::fs::remove_file(env.path("yarn.lock")).unwrap();
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'b@1.0.0'");
    assert!(!env.read("jpm.lock").contains("patch"));
}

#[test]
fn patch_and_patch_commit() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return; // patch-commit diffs with git
    }
    let r = Registry::start(vec![
        pkg("b", "1.0.0", json!({})),
        pkg("@s/c", "1.0.0", json!({})).file("lib/x.js", 0o644, "x\n"),
    ]);
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let out = env.ok(&["patch", "b"]);
    let edit = "node_modules/.jpm_patches/b@1.0.0";
    assert!(out.contains(&format!("jpm patch-commit {}", env.path(edit).display())), "{out}");
    assert_eq!(env.read(&format!("{edit}/index.js")), "module.exports = 'b@1.0.0'");
    assert!(fails(&env, &["patch", "b"]).contains("is already there"));
    env.write(&format!("{edit}/index.js"), "module.exports = 'edited'\n");
    env.write(&format!("{edit}/lib/new.js"), "new\n");
    let edit_dir = env.path(edit).display().to_string();
    let out = env.ok(&["patch-commit", &edit_dir]);
    assert!(out.contains("wrote patches/b@1.0.0.patch"), "{out}");
    let patch = env.read("patches/b@1.0.0.patch");
    assert!(patch.starts_with("diff --git a/index.js b/index.js\n"), "{patch}");
    assert!(patch.contains("diff --git a/lib/new.js b/lib/new.js\nnew file mode 100644\n"), "{patch}");
    let manifest: serde_json::Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert_eq!(manifest["pnpm"]["patchedDependencies"], json!({ "b@1.0.0": "patches/b@1.0.0.patch" }));
    assert_eq!(manifest["name"], "app");
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'edited'\n");
    assert_eq!(env.read("node_modules/b/lib/new.js"), "new\n");
    assert!(!env.exists(edit), "committed, the copy goes");
    // Again: from the patched package, into the same file.
    env.ok(&["patch", "b"]);
    assert_eq!(env.read(&format!("{edit}/index.js")), "module.exports = 'edited'\n");
    env.write(&format!("{edit}/index.js"), "module.exports = 'twice'\n");
    env.ok(&["patch-commit", &edit_dir]);
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'twice'\n");
    let manifest: serde_json::Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert_eq!(manifest["pnpm"]["patchedDependencies"], json!({ "b@1.0.0": "patches/b@1.0.0.patch" }));
    // A project that names its patches in pnpm-workspace.yaml gets the new one there; a scope's
    // `/` is `__` in the file name. --edit-dir puts the copy anywhere.
    env.write("pnpm-workspace.yaml", "patchedDependencies:\n  b@1.0.0: patches/b@1.0.0.patch\n");
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0", "@s/c": "1.0.0" } }));
    env.ok(&["install"]);
    let own = env.root.join("edit-c");
    env.ok(&["patch", "@s/c@1.0.0", "--edit-dir", &own.display().to_string()]);
    assert!(fails(&env, &["patch-commit", &own.display().to_string()]).contains("nothing to commit"));
    std::fs::write(own.join("lib/x.js"), "y\n").unwrap();
    env.ok(&["patch-commit", &own.display().to_string()]);
    let yaml = env.read("pnpm-workspace.yaml");
    assert_eq!(
        yaml,
        "patchedDependencies:\n  '@s/c@1.0.0': patches/@s__c@1.0.0.patch\n  b@1.0.0: patches/b@1.0.0.patch\n"
    );
    assert_eq!(env.read("node_modules/@s/c/lib/x.js"), "y\n");
    assert!(own.exists(), "a directory of the user's own stays");
    assert!(fails(&env, &["patch", "nope"]).contains("jpm.lock has no nope"));
}

fn has_git() -> bool {
    std::process::Command::new("git").arg("--version").output().is_ok()
}

/// A patch the project names outside itself, or through a link: refused before it is read, so
/// `jpm patch-commit` never writes there either.
#[test]
fn reads_patches_from_the_project_only() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let outside = env.root.join("home/.bashrc");
    std::fs::write(&outside, "--- a/x\n+++ b/SECRET=hunter2/../x\n").unwrap();
    let with = |path: &str| {
        env.manifest(json!({
            "name": "app", "dependencies": { "b": "1.0.0" },
            "pnpm": { "patchedDependencies": { "b@1.0.0": path } }
        }));
    };
    for path in [outside.display().to_string(), "../home/.bashrc".into(), "patches/../../home/.bashrc".into()] {
        with(&path);
        for args in [&["install"][..], &["patch", "b"]] {
            let err = fails(&env, args);
            assert!(err.contains("is not a path inside the project") && !err.contains("hunter2"), "{path}: {err}");
        }
    }
    // yarn's `patch:` names its file the same way.
    env.manifest(json!({ "dependencies": { "b": "patch:b@npm%3A1.0.0#../home/.bashrc" } }));
    assert!(fails(&env, &["install"]).contains("is not a path inside the project"));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, env.path("b.patch")).unwrap();
        with("b.patch");
        assert!(fails(&env, &["install"]).contains("is a link"));
    }
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "--- a/x\n+++ b/SECRET=hunter2/../x\n");
}

/// A package whose own package.json names another version, one a range reader would take for
/// its own: patch-commit goes by jpm.lock, and refuses the copy.
#[test]
fn patch_commit_goes_by_the_lock() {
    if !has_git() {
        return;
    }
    let evil = "1.0.0 || /../../../home/.bashrc.d/evil': x\\nonlyBuiltDependencies:\\n  - b\\n#";
    let b = pkg("b", "1.0.0", json!({})).file("package.json", 0o644, &format!(r#"{{"name":"b","version":"{evil}"}}"#));
    let r = Registry::start(vec![b]);
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.write("pnpm-workspace.yaml", "patchedDependencies:\n");
    env.ok(&["install"]);
    env.ok(&["patch", "b"]);
    let edit = "node_modules/.jpm_patches/b@1.0.0";
    env.write(&format!("{edit}/index.js"), "module.exports = 'edited'\n");
    let err = fails(&env, &["patch-commit", &env.path(edit).display().to_string()]);
    assert!(err.contains("where jpm.lock has b@1.0.0"), "{err}");
    assert!(!env.root.join("home/.bashrc.d").exists() && !env.exists("patches"));
    assert_eq!(env.read("pnpm-workspace.yaml"), "patchedDependencies:\n");
}

/// A name npm once allowed that would end a quoted YAML key: not written into the files.
#[test]
fn patch_commit_names_only_plain_names() {
    if !has_git() {
        return;
    }
    let r = Registry::start(vec![pkg("it's", "1.0.0", json!({}))]);
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "it's": "1.0.0" } }));
    env.write("pnpm-workspace.yaml", "patchedDependencies:\n");
    env.ok(&["install"]);
    env.ok(&["patch", "it's"]);
    let edit = "node_modules/.jpm_patches/it's@1.0.0";
    env.write(&format!("{edit}/index.js"), "module.exports = 'edited'\n");
    let err = fails(&env, &["patch-commit", &env.path(edit).display().to_string()]);
    assert!(err.contains("it's cannot be named in patchedDependencies"), "{err}");
    assert!(!env.exists("patches"));
    assert_eq!(env.read("pnpm-workspace.yaml"), "patchedDependencies:\n");
}

/// A checkout whose `patches` or `node_modules/.jpm_patches` is a link: nothing is written
/// through it.
#[cfg(unix)]
#[test]
fn patch_and_patch_commit_write_through_no_link() {
    if !has_git() {
        return;
    }
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let outside = env.root.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, env.path("patches")).unwrap();
    env.ok(&["patch", "b"]);
    let edit = "node_modules/.jpm_patches/b@1.0.0";
    env.write(&format!("{edit}/index.js"), "module.exports = 'edited'\n");
    let err = fails(&env, &["patch-commit", &env.path(edit).display().to_string()]);
    assert!(err.contains("is a link"), "{err}");
    std::fs::remove_file(env.path("patches")).unwrap();
    std::fs::remove_dir_all(env.path("node_modules/.jpm_patches")).unwrap();
    std::os::unix::fs::symlink(&outside, env.path("node_modules/.jpm_patches")).unwrap();
    assert!(fails(&env, &["patch", "b"]).contains("is a link"));
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing written outside the project");
}

/// Only the copy `jpm patch` made is removed after a commit, however the path to it is spelled.
#[test]
fn patch_commit_removes_only_its_own_copy() {
    if !has_git() {
        return;
    }
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let own = env.root.join("own");
    env.ok(&["patch", "b", "--edit-dir", &own.display().to_string()]);
    std::fs::write(own.join("index.js"), "module.exports = 'edited'\n").unwrap();
    std::fs::create_dir_all(env.path("node_modules/.jpm_patches")).unwrap();
    // Under .jpm_patches by its letters, the user's own directory by where it leads.
    let spelled = env.path("node_modules/.jpm_patches").join("../../../own");
    env.ok(&["patch-commit", &spelled.display().to_string()]);
    assert!(own.join("index.js").exists(), "a directory of the user's own stays");
    assert_eq!(env.read("node_modules/b/index.js"), "module.exports = 'edited'\n");
}

#[test]
fn patches_an_alias_by_the_package_it_installs() {
    // anthropic-sdk-typescript's `"tsc-multi": "npm:@stainless-api/tsc-multi@1.1.12"`, patched
    // as `@stainless-api/tsc-multi@1.1.12`, as pnpm matches it.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "t": "npm:b@1.0.0" } }));
    env.write("patches/b.patch", &diff("b@1.0.0", "patched"));
    env.write("pnpm-workspace.yaml", "patchedDependencies:\n  b@1.0.0: patches/b.patch\n");
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/t/index.js"), "module.exports = 'patched'");
    assert!(env.ok(&["install"]).contains("up to date"));
}
