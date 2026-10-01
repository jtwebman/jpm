//! End to end: what a package, a registry or the directories around a project can put in the
//! terminal and in the environment of the programs jpm starts.

mod common;

use common::{Env, Registry, pkg};
use serde_json::json;

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg(unix)]
fn have_node() -> bool {
    std::process::Command::new("node").arg("--version").output().is_ok()
}

/// b comes in through a, so a global-store install writes the hook.
fn hoisting_registry() -> Registry {
    Registry::start(vec![pkg("a", "1.1.0", json!({ "dependencies": { "b": "^1.1.0" } })), pkg("b", "1.1.0", json!({}))])
}

/// A package.json in `dir` depending on a, with one script `t`.
#[cfg(unix)]
fn project_at(dir: &std::path::Path, script: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let manifest = json!({ "dependencies": { "a": "1.1.0" }, "scripts": { "t": script } });
    std::fs::write(dir.join("package.json"), manifest.to_string()).unwrap();
}

#[test]
fn registry_text_reaches_the_terminal_escaped() {
    // OSC 52 sets the clipboard, OSC 0 the title: in a dependency's name and range.
    let r = Registry::start(vec![
        pkg("clip", "1.0.0", json!({ "dependencies": { "\u{1b}]52;c;cm0gLXJmIH4K\u{7}x": "1.0.0" } })),
        pkg("title", "1.0.0", json!({ "dependencies": { "b": "\u{1b}]0;PWNED\u{7}" } })),
        pkg("b", "1.0.0", json!({})),
    ]);
    let env = Env::new(&r);
    for name in ["clip", "title"] {
        env.manifest(json!({ "dependencies": { name: "1.0.0" } }));
        let out = env.jpm(&["install"]);
        let err = stderr(&out);
        assert!(!out.status.success() && err.contains("\\u{1b}]"), "{name}: {err:?}");
        assert!(!err.contains(['\u{1b}', '\u{7}']), "{name}: printed raw: {err:?}");
    }
    // resolve prints the tarball url and the start of the integrity as the registry has them.
    let doc = |name: &str, tarball: &str, integrity: &str| {
        let version =
            json!({ "name": name, "version": "1.0.0", "dist": { "tarball": tarball, "integrity": integrity } });
        let doc = json!({ "name": name, "dist-tags": { "latest": "1.0.0" }, "versions": { "1.0.0": version },
            "time": { "1.0.0": "2020-01-01T00:00:00Z" } });
        r.serve(&format!("/{name}"), doc.to_string().into_bytes());
    };
    doc("link", "http://e/\u{1b}]8;;http://evil\u{1b}\\x.tgz", "sha512-abc");
    let out = env.jpm(&["resolve", "link"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("http://e/\\u{1b}]8;;"), "{text:?} {}", stderr(&out));
    assert!(!text.contains('\u{1b}'), "printed raw: {text:?}");
    // A cut at 24 characters, not bytes: the 24th byte is inside the first two-byte one.
    doc("wide", "http://e/x.tgz", "sha512-aaaaaaaaaaaaaaaa\u{e9}\u{e9}\u{e9}\u{e9}");
    let out = env.jpm(&["resolve", "wide"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && text.contains("sha512-aaaaaaaaaaaaaaaa\u{e9}\u{2026}"),
        "{text:?} {}",
        stderr(&out)
    );
}

/// A project path with `"`, `\`, spaces, `--require` or a line break: Node still loads only the
/// hook, and starts.
#[cfg(unix)]
#[test]
fn node_options_hold_any_project_path() {
    if !have_node() {
        return;
    }
    let r = hoisting_registry();
    let env = Env::new(&r);
    let evil = env.root.join("evil.js");
    let pwned = env.root.join("PWNED");
    std::fs::write(&evil, format!("require('fs').writeFileSync({:?}, 'x')", pwned.display())).unwrap();
    for name in [
        format!("q\" --require {} \"x", evil.display()),
        format!("b\\\" --require {} x\\", evil.display()),
        "nl\n--require=/x a".to_string(),
    ] {
        let dir = env.project().join(&name);
        project_at(&dir, "node -e \"console.log('ran')\"");
        let out = env.command_in(&dir, &["run", "-s", "t"]).output().unwrap();
        assert!(dir.join("node_modules/.jpm/hoist.cjs").is_file(), "{name:?}: no hook written");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("ran"), "{name:?}: {text} {}", stderr(&out));
        assert!(!pwned.exists(), "{name:?}: evil.js ran");
    }
}

/// NODE_OPTIONS cannot spell a path that is not Unicode; a lossy spelling names no file and
/// stops every node. (APFS takes no such name.)
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn node_starts_under_a_project_path_that_is_not_unicode() {
    use std::os::unix::ffi::OsStrExt;
    if !have_node() {
        return;
    }
    let r = hoisting_registry();
    let env = Env::new(&r);
    let dir = env.project().join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
    project_at(&dir, "node -e \"console.log('ran')\"");
    let out = env.command_in(&dir, &["run", "-s", "t"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("ran"), "node did not start: {}", stderr(&out));
}

/// The hook runs in every node a script starts: only the project's own counts, never one in a
/// directory above it (anyone's, in /tmp). A workspace still gets its root's.
#[cfg(unix)]
#[test]
fn scripts_load_only_the_projects_own_hook() {
    if !have_node() {
        return;
    }
    let r = hoisting_registry();
    let env = Env::new(&r);
    let planted = env.root.join("node_modules/.jpm");
    std::fs::create_dir_all(&planted).unwrap();
    let marker = env.root.join("PLANTED");
    std::fs::write(planted.join("hoist.cjs"), format!("require('fs').writeFileSync({:?}, 'x')", marker.display()))
        .unwrap();
    std::fs::create_dir_all(env.root.join("node_modules/.bin")).unwrap();
    // No hook of its own: the project's entries are not in the global store.
    env.write(".npmrc", "global-store=false\n");
    env.manifest(json!({
        "dependencies": { "a": "1.1.0" },
        "scripts": { "t": "node -e \"console.log(process.env.NODE_OPTIONS + '|' + process.env.NODE_PATH)\"" }
    }));
    let out = env.ok(&["run", "-s", "t"]);
    assert!(!env.exists("node_modules/.jpm/hoist.cjs"));
    assert!(!marker.exists(), "a parent directory's hoist.cjs ran: {out}");
    assert!(!out.contains(&env.root.join("node_modules").display().to_string()), "{out}");
    // With the global store, a workspace's script gets the root's hook.
    env.write(".npmrc", "");
    env.manifest(json!({ "workspaces": ["w"], "dependencies": { "a": "1.1.0" } }));
    env.write("w/package.json", r#"{ "name": "w", "scripts": { "t": "node -p process.env.NODE_OPTIONS" } }"#);
    env.ok(&["install"]);
    let out = env.command_in(&env.project().join("w"), &["run", "-s", "t"]).output().unwrap();
    let hook = env.project().join("node_modules/.jpm/hoist.cjs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&hook.display().to_string()), "{text} {}", stderr(&out));
    assert!(!marker.exists());
}

/// `jpm` alone is install: where there is no package.json it fails and writes nothing.
#[test]
fn bare_jpm_writes_nothing_where_there_is_no_package_json() {
    let r = hoisting_registry();
    let env = Env::new(&r);
    let dir = env.root.join("empty");
    std::fs::create_dir_all(&dir).unwrap();
    let out = env.command_in(&dir, &[]).output().unwrap();
    assert!(!out.status.success() && stderr(&out).contains("ENOENT"), "{}", stderr(&out));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// npm's proxy settings and client key stay out of a dependency's scripts, and a proxy
/// variable reaches them without its user and password.
#[cfg(unix)]
#[test]
fn install_scripts_see_no_proxy_credentials_or_client_keys() {
    let script = "echo \"$npm_config_https_proxy|$npm_config_proxy|$npm_config_KEY|$HTTPS_PROXY|$https_proxy|$npm_config_noproxy\" > seen.txt";
    let r = Registry::start(vec![pkg("bld", "1.0.0", json!({ "scripts": { "postinstall": script } }))]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "trustedDependencies": ["bld"] }));
    env.ok(&["install"]);
    // Nothing listens on port 9; noproxy keeps jpm itself off it.
    let out = env
        .command(&["approve", "bld"])
        .env("npm_config_proxy", "http://user:SECRET@127.0.0.1:9")
        .env("npm_config_https_proxy", "http://user:SECRET@127.0.0.1:9")
        .env("npm_config_KEY", "-----BEGIN PRIVATE KEY-----SECRET")
        .env("HTTPS_PROXY", "http://user:SECRET@127.0.0.1:9")
        .env("https_proxy", "user:SECRET@127.0.0.1:9")
        .env("npm_config_noproxy", "127.0.0.1")
        .env("NO_PROXY", "127.0.0.1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(env.read("node_modules/bld/seen.txt"), "|||http://127.0.0.1:9|127.0.0.1:9|127.0.0.1\n");
}

/// Every file of every package in the store (indexes aside), with what it holds and whether it is
/// read-only.
#[cfg(windows)]
fn store_files(env: &Env) -> Vec<(std::path::PathBuf, Vec<u8>, bool)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>, bool)>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let meta = std::fs::symlink_metadata(e.path()).unwrap();
            if meta.is_dir() {
                walk(&e.path(), out);
            } else if meta.is_file() && !e.file_name().to_string_lossy().ends_with(".idx") {
                out.push((e.path(), std::fs::read(e.path()).unwrap(), meta.permissions().readonly()));
            }
        }
    }
    let mut out = Vec::new();
    walk(&env.store().join("v1/pkg"), &mut out);
    out.sort();
    out
}

/// The store's files are read-only on Windows as on unix, and a project's hardlinks with them: a
/// write through one fails and leaves the store's copy (every project's) as it was. What jpm
/// itself changes still works: a patch, `jpm patch` and `patch-commit`, and prune deleting what
/// no project uses.
#[cfg(windows)]
#[test]
fn a_write_through_a_project_link_cannot_change_the_store() {
    let r = Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "1.0.0" } })),
        pkg("b", "1.0.0", json!({})).file("lib/x.js", 0o644, "x\n"),
        pkg("gone", "1.0.0", json!({})),
    ]);
    let env = Env::new(&r);
    for global in ["false", "true"] {
        env.write(".npmrc", &format!("global-store={global}\n"));
        env.manifest(json!({ "name": "app", "dependencies": { "a": "1.0.0", "gone": "1.0.0" } }));
        env.ok(&["install"]);
        let before = store_files(&env);
        assert!(!before.is_empty() && before.iter().all(|(_, _, ro)| *ro), "{global}: every store file read-only");
        for rel in ["node_modules/a/index.js", "node_modules/a/../b/lib/x.js"] {
            let at = env.path(rel);
            assert!(std::fs::metadata(&at).unwrap().permissions().readonly(), "{rel}");
            assert!(std::fs::write(&at, "changed").is_err(), "{global}: wrote through {rel}");
            assert!(std::fs::OpenOptions::new().append(true).open(&at).is_err(), "{rel}");
        }
        assert_eq!(store_files(&env), before, "{global}: the store is as it was");

        // A package no longer wanted goes from the project and the store, read-only files and all.
        env.manifest(json!({ "name": "app", "dependencies": { "a": "1.0.0" } }));
        env.ok(&["install"]);
        env.ok(&["prune"]);
        let after = store_files(&env);
        assert!(!after.iter().any(|(_, data, _)| data == b"module.exports = 'gone@1.0.0'"), "{global}: pruned");
        assert!(after.iter().any(|(_, data, _)| data == b"x\n"), "{global}: b kept");
    }

    // `jpm patch` copies b out writable; the patch is installed; the store's b is untouched.
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return; // patch-commit diffs with git
    }
    env.write(".npmrc", "global-store=false\n");
    env.manifest(json!({ "name": "app", "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let before = store_files(&env);
    env.ok(&["patch", "b"]);
    let edit = "node_modules/.jpm_patches/b@1.0.0";
    std::fs::write(env.path(&format!("{edit}/lib/x.js")), "patched\n").unwrap();
    env.ok(&["patch-commit", &env.path(edit).display().to_string()]);
    assert_eq!(env.read("node_modules/b/lib/x.js"), "patched\n");
    assert_eq!(store_files(&env), before, "patching wrote nothing in the store");
    // Patched again from the patched package: its files replaced, not written through.
    env.ok(&["patch", "b"]);
    std::fs::write(env.path(&format!("{edit}/lib/x.js")), "twice\n").unwrap();
    env.ok(&["patch-commit", &env.path(edit).display().to_string()]);
    assert_eq!(env.read("node_modules/b/lib/x.js"), "twice\n");
    assert_eq!(store_files(&env), before);
}
