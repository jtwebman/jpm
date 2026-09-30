//! End to end: the jpm binary against a registry on localhost.

mod common;

use common::{Env, Registry, pkg};
use serde_json::json;

fn registry() -> Registry {
    Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })),
        pkg("a", "1.1.0", json!({ "dependencies": { "b": "^1.1.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("b", "1.1.0", json!({})),
        pkg("b", "2.0.0", json!({})),
        pkg("cli", "1.0.0", json!({ "bin": { "hello": "bin/hello.js" } })).file(
            "bin/hello.js",
            0o644,
            "#!/bin/sh\necho hello-from-cli\n",
        ),
        pkg("argv", "1.0.0", json!({ "bin": { "argv": "bin/argv.js" } })).file(
            "bin/argv.js",
            0o755,
            "#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)))\n",
        ),
        pkg("next", "1.0.0", json!({ "dependencies": { "b": "1.0.0" } })),
        pkg("host", "1.0.0", json!({})),
        pkg("host", "2.0.0", json!({})),
        pkg("plugin", "1.0.0", json!({ "peerDependencies": { "host": ">=1" } })),
        pkg("native", "1.0.0", json!({ "optionalDependencies": { "native-mars": "1.0.0", "native-any": "1.0.0" } })),
        pkg("native-mars", "1.0.0", json!({ "os": ["mars"] })),
        pkg("native-any", "1.0.0", json!({})),
        pkg("@scope/lib", "1.0.0", json!({ "dependencies": { "b": "2.0.0" } })),
        pkg("cyc-a", "1.0.0", json!({ "dependencies": { "cyc-b": "1.0.0" } })),
        pkg("cyc-b", "1.0.0", json!({ "dependencies": { "cyc-a": "1.0.0" } })),
    ])
}

#[test]
fn installs_an_isolated_tree() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "a": "^1.0.0", "@scope/lib": "1" }, "devDependencies": { "cli": "1" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("Installed"), "{out}");
    // Only direct deps at the top; each package sees exactly what it declared.
    assert!(env.exists("node_modules/a") && env.exists("node_modules/@scope/lib") && env.exists("node_modules/cli"));
    assert!(!env.exists("node_modules/b"), "b is not a direct dependency");
    assert!(env.read("node_modules/a/index.js").contains("a@1.1.0"));
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"), "a resolves its own b");
    assert!(env.read("node_modules/@scope/lib/../../b/index.js").contains("b@2.0.0"));
    let lock = env.lock();
    assert_eq!(lock["root"]["dependencies"]["a"], "1.1.0");
    assert!(lock["packages"]["a@1.1.0"]["dependencies"]["b"] == "1.1.0");
    assert!(lock["packages"]["a@1.1.0"].get("resolved").is_none(), "the registry's own url is derived");
    // A repeat is a no-op.
    let again = env.ok(&["install"]);
    assert!(again.contains("up to date"), "{again}");
}

#[test]
fn no_command_installs() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    let out = env.ok(&[]);
    assert!(out.contains("Installed"), "{out}");
    assert!(env.exists("node_modules/b"));
    // Flags without a command are install's.
    let out = env.ok(&["--frozen-lockfile"]);
    assert!(out.contains("up to date"), "{out}");
    env.manifest(json!({ "dependencies": { "b": "2.0.0" } }));
    let out = env.jpm(&["--frozen-lockfile"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("out of date"));
    let out = env.jpm(&["--lock"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--lock only applies to fetch"));
    for help in ["--help", "-h"] {
        let out = env.ok(&[help]);
        assert!(out.contains("Usage"), "{out}");
    }
}

#[test]
fn keeps_installed_versions_without_a_lockfile() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "^1.0.0", "b": "^1.0.0" } }));
    env.ok(&["install"]);
    r.publish(pkg("a", "1.2.0", json!({ "dependencies": { "b": "^1.1.0" } })));
    r.publish(pkg("b", "1.2.0", json!({})));
    let versions = |env: &Env| {
        let lock = env.lock();
        (lock["root"]["dependencies"]["a"].clone(), lock["root"]["dependencies"]["b"].clone())
    };
    // Deleting jpm.lock keeps what node_modules has, where the ranges allow it.
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    let out = env.ok(&["install"]);
    assert!(out.contains("versions in node_modules preferred"), "{out}");
    assert_eq!(versions(&env), (json!("1.1.0"), json!("1.1.0")));
    assert!(env.read("node_modules/a/index.js").contains("a@1.1.0"));
    // A range the installed version no longer satisfies is resolved again.
    env.manifest(json!({ "dependencies": { "a": "^1.0.0", "b": "^2.0.0" } }));
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    env.ok(&["install"]);
    assert_eq!(versions(&env), (json!("1.1.0"), json!("2.0.0")));
    assert!(env.read("node_modules/b/index.js").contains("b@2.0.0"));
    // `jpm lock` resolves afresh, as does an install with no node_modules.
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    env.ok(&["lock"]);
    assert_eq!(versions(&env).0, json!("1.2.0"));
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    std::fs::remove_dir_all(env.path("node_modules")).unwrap();
    env.ok(&["install"]);
    assert_eq!(versions(&env).0, json!("1.2.0"));
}

#[test]
fn links_bins_and_runs_scripts() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(
        json!({ "name": "app", "scripts": { "greet": "hello", "echo": "echo" }, "devDependencies": { "cli": "1" } }),
    );
    env.ok(&["install"]);
    assert!(env.exists("node_modules/.bin/hello"));
    if cfg!(unix) {
        let out = env.ok(&["run", "greet"]);
        assert!(out.contains("hello-from-cli"), "{out}");
        let out = env.ok(&["echo", "a b", "it's"]);
        assert!(out.contains("a b it's"), "{out}");
        let out = env.ok(&["exec", "hello"]);
        assert!(out.contains("hello-from-cli"), "{out}");
    }
    let out = env.jpm(&["run", "nope"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing script"));
}

#[test]
fn frozen_installs_need_a_current_lockfile() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    let out = env.jpm(&["ci"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is missing"));
    env.ok(&["install"]);
    env.ok(&["ci"]);
    env.manifest(json!({ "dependencies": { "b": "2.0.0" } }));
    let out = env.jpm(&["install", "--frozen-lockfile"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("out of date"));
}

#[test]
fn installs_offline_from_the_store() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.0.0" } }));
    env.ok(&["install"]);
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    let before = r.requests.load(std::sync::atomic::Ordering::Relaxed);
    env.ok(&["install", "--offline"]);
    assert_eq!(r.requests.load(std::sync::atomic::Ordering::Relaxed), before, "a warm install asks nothing");
    assert!(env.exists("node_modules/a/../b"));
}

#[test]
fn adds_and_removes() {
    let r = registry();
    let env = Env::new(&r);
    env.write("package.json", "{\n    \"name\": \"app\"\n}\n");
    env.ok(&["add", "b@^1", "--save-dev"]);
    env.ok(&["add", "a"]);
    let text = env.read("package.json");
    assert!(text.contains("    \"devDependencies\": {\n        \"b\": \"^1\"\n    }"), "{text}");
    assert!(text.contains("\"a\": \"^1.1.0\""), "{text}");
    assert!(env.exists("node_modules/a") && env.exists("node_modules/b"));
    env.ok(&["remove", "b"]);
    assert!(!env.read("package.json").contains("\"b\""));
    assert!(!env.exists("node_modules/b"));
    let out = env.jpm(&["remove", "nope"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("ENODEP"));
}

#[test]
fn settles_peers_against_the_tree() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "host": "1.0.0", "plugin": "1" } }));
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(lock["packages"]["plugin@1.0.0"]["dependencies"]["host"], "1.0.0", "the root's host, not the newest");
    assert!(env.read("node_modules/plugin/../host/index.js").contains("host@1.0.0"));
}

#[test]
fn consumers_missing_one_peer_share_a_version_that_fits_them_all() {
    // typescript-eslint caps typescript where ts-api-utils takes any: a copy each gave
    // ts-api-utils a typescript it could not load (unjs/upm#8).
    let r = Registry::start(vec![
        pkg("capped", "1.0.0", json!({ "peerDependencies": { "ts": ">=4.8.4 <6.1.0" } })),
        pkg("open", "1.0.0", json!({ "peerDependencies": { "ts": ">=4.8.4" } })),
        pkg("gap", "1.0.0", json!({ "peerDependencies": { "ts": ">=6.5.0" } })),
        pkg("ts", "5.9.0", json!({})),
        pkg("ts", "6.0.3", json!({})),
        pkg("ts", "7.0.2", json!({})),
    ]);
    let ts = |env: &Env, who: &str| env.lock()["packages"][who]["dependencies"]["ts"].clone();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "open": "^1", "capped": "^1" } }));
    env.ok(&["install"]);
    assert_eq!(ts(&env, "open@1.0.0"), "6.0.3");
    assert_eq!(ts(&env, "capped@1.0.0"), "6.0.3");
    assert!(env.lock()["packages"].get("ts@7.0.2").is_none());

    // No version fits both: each keeps its own.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "gap": "^1", "capped": "^1" } }));
    env.ok(&["install"]);
    assert_eq!(ts(&env, "gap@1.0.0"), "7.0.2");
    assert_eq!(ts(&env, "capped@1.0.0"), "6.0.3");

    // A dev-only consumer never narrows what a shipped one gets.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "open": "^1" }, "devDependencies": { "capped": "^1" } }));
    env.ok(&["install"]);
    assert_eq!(ts(&env, "open@1.0.0"), "7.0.2");
    assert_eq!(ts(&env, "capped@1.0.0"), "6.0.3");

    // A lock that gave them a copy each heals from what it has: the locked 6.0.3 fits both.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "open": "^1" }, "devDependencies": { "capped": "^1" } }));
    env.ok(&["install"]);
    env.manifest(json!({ "dependencies": { "open": "^1", "capped": "^1" } }));
    env.ok(&["install"]);
    assert_eq!(ts(&env, "open@1.0.0"), "6.0.3");
    assert_eq!(ts(&env, "capped@1.0.0"), "6.0.3");
}

#[test]
fn skips_other_platforms_builds() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "native": "1" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("skipped"), "{out}");
    let lock = env.lock();
    assert!(lock["packages"].get("native-mars@1.0.0").is_some(), "the lockfile keeps every platform");
    assert!(!env.exists("node_modules/native/../native-mars"));
    assert!(env.exists("node_modules/native/../native-any"));
}

#[test]
fn handles_cycles() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "cyc-a": "1" } }));
    env.ok(&["install"]);
    assert!(env.read("node_modules/cyc-a/../cyc-b/../cyc-a/index.js").contains("cyc-a"));
}

#[test]
fn links_workspaces() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"], "dependencies": { "one": "workspace:*" } }));
    env.write(
        "packages/one/package.json",
        r#"{ "name": "one", "version": "1.0.0", "dependencies": { "two": "^2", "b": "1.0.0" } }"#,
    );
    env.write(
        "packages/two/package.json",
        r#"{ "name": "two", "version": "2.0.0", "scripts": { "build": "echo built-two" } }"#,
    );
    env.ok(&["install"]);
    assert!(env.exists("node_modules/one"));
    assert!(env.exists("packages/one/node_modules/two"));
    assert!(env.exists("packages/one/node_modules/b"));
    let lock = env.lock();
    assert_eq!(lock["workspaces"]["packages/one"]["dependencies"]["two"], "link:packages/two");
    if cfg!(unix) {
        let out = env.ok(&["run", "--workspaces", "--if-present", "build"]);
        assert!(out.contains("built-two"), "{out}");
    }
}

#[test]
fn a_workspace_tree_is_up_to_date_until_a_workspace_changes() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "workspaces": ["packages/*"], "dependencies": { "a": "1.1.0" } }));
    env.write("packages/w/package.json", r#"{ "name": "w", "dependencies": { "cli": "1.0.0" } }"#);
    // Matched by the glob, but no workspace until it has a package.json.
    env.write("packages/u/index.js", "");
    env.ok(&["install"]);
    let bin =
        if cfg!(windows) { "packages/w/node_modules/.bin/hello.cmd" } else { "packages/w/node_modules/.bin/hello" };
    let up_to_date = || {
        let out = env.ok(&["install"]);
        out.contains("up to date") && out.contains("1 workspace")
    };
    // The state holds what the no-op checks without the graph: each workspace's links too.
    let state = env.read("node_modules/.jpm.json");
    assert!(state.contains("\"inputs\"") && state.contains("\"packages/w\""), "{state}");
    assert!(up_to_date());
    // A workspace's link or bin gone: linked again.
    // A symlink on unix, a junction (a directory) on Windows.
    let link = env.path("packages/w/node_modules/cli");
    std::fs::remove_dir(&link).or_else(|_| std::fs::remove_file(&link)).unwrap();
    assert!(!up_to_date());
    assert!(env.exists("packages/w/node_modules/cli"));
    std::fs::remove_file(env.path(bin)).unwrap();
    assert!(!up_to_date());
    assert!(env.exists(bin) && up_to_date());
    // A workspace's package.json edited: resolved again.
    env.write("packages/w/package.json", r#"{ "name": "w", "dependencies": { "cli": "1.0.0", "b": "1.0.0" } }"#);
    assert!(!up_to_date());
    assert!(env.read("packages/w/node_modules/b/index.js").contains("b@1.0.0"));
    // A directory the glob matched becomes a workspace, then goes.
    env.write("packages/u/package.json", r#"{ "name": "u", "dependencies": { "b": "2.0.0" } }"#);
    let out = env.ok(&["install"]);
    assert!(out.contains("2 workspaces") && !out.contains("up to date"), "{out}");
    assert!(env.read("packages/u/node_modules/b/index.js").contains("b@2.0.0"));
    std::fs::remove_dir_all(env.path("packages/u")).unwrap();
    assert!(!up_to_date());
    assert!(env.lock()["workspaces"].get("packages/u").is_none());
    assert!(up_to_date());
}

#[test]
fn links_the_root_listed_as_a_workspace() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({
        "name": "root", "version": "1.0.0", "workspaces": [".", "a", "play/**"],
        "bin": { "root-cli": "cli.js" }, "dependencies": { "b": "1.0.0" }
    }));
    env.write("cli.js", "#!/bin/sh\necho root\n");
    env.write("a/package.json", r#"{ "name": "a", "dependencies": { "root": "workspace:*" } }"#);
    // A fixture under its parent's name is left out while nothing links to that name.
    env.write("play/x/package.json", r#"{ "name": "x" }"#);
    env.write("play/x/dir/package.json", r#"{ "name": "x" }"#);
    let out = env.ok(&["install"]);
    assert!(out.contains("workspaces play/x and play/x/dir are both named x; jpm installs only play/x"), "{out}");
    // `../..` on unix, absolute as a junction: either way, the project itself.
    let real = |p: std::path::PathBuf| std::fs::canonicalize(p).unwrap();
    assert_eq!(real(env.project().join("a/node_modules/root")), real(env.project()));
    assert!(env.exists("a/node_modules/.bin/root-cli"));
    // Installed once, as the root.
    assert!(env.exists("node_modules/b") && !env.exists("node_modules/root") && !env.exists("play/x/dir/node_modules"));
    let lock = env.lock();
    assert_eq!(lock["workspaces"]["a"]["dependencies"]["root"], "link:.");
    assert_eq!(lock["workspaces"]["."]["name"], "root");
    assert!(env.ok(&["install"]).contains("up to date"));
    env.ok(&["ci"]);
    // Once something links to the name, which copy it means is ambiguous.
    env.write("a/package.json", r#"{ "name": "a", "dependencies": { "root": "workspace:*", "x": "*" } }"#);
    let out = env.jpm(&["install"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("a dependency on x could mean either"));
}

#[test]
fn names_the_dependency_forms_it_does_not_read() {
    let r = registry();
    let env = Env::new(&r);
    for (spec, says) in [
        ("catalog:", "x@catalog:, but no catalogs are defined here or above"),
        ("gist:11081aaa", r#""gist:" dependencies are not supported yet"#),
        ("portal:../dir", r#""portal:" dependencies are not supported yet"#),
    ] {
        env.manifest(json!({ "dependencies": { "x": spec } }));
        let out = env.jpm(&["install"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && err.contains(says), "{spec}: {err}");
    }
}

#[test]
fn installs_local_tarballs() {
    let r = registry();
    let env = Env::new(&r);
    let tgz = common::pkg("vendored", "3.0.0", json!({ "dependencies": { "b": "2" } })).tarball();
    std::fs::create_dir_all(env.project().join("vendor")).unwrap();
    std::fs::write(env.project().join("vendor/v.tgz"), &tgz).unwrap();
    env.manifest(json!({ "dependencies": { "vendored": "file:vendor/v.tgz" } }));
    env.ok(&["install"]);
    let lock = env.lock();
    let entry = &lock["packages"]["vendored@file:vendor/v.tgz"];
    assert_eq!(entry["version"], "3.0.0");
    assert_eq!(entry["integrity"], common::sha512(&tgz));
    assert!(env.read("node_modules/vendored/../b/index.js").contains("b@2.0.0"));
    env.ok(&["install", "--frozen-lockfile"]);
}

/// Unpacking holds a bounded part of a tarball in memory, however big its files or however
/// often it repeats a path: the old writer queue held every large body, and every repeat, whole.
#[cfg(target_os = "linux")]
#[test]
fn unpacks_big_and_repeated_files_in_bounded_memory() {
    use std::io::Write;
    let r = registry();
    let env = Env::new(&r);
    std::fs::create_dir_all(env.project().join("vendor")).unwrap();
    let file = env.project().join("vendor/big.tar");
    // Plain tar, written a chunk at a time (a child's peak counts what this process held when it
    // started it): 65 small files, past the ones written inline, the first 12 again at 8 MiB
    // each, and one 48 MiB file.
    let mut out = std::io::BufWriter::new(std::fs::File::create(&file).unwrap());
    let mut add = |path: &str, fill: u8, size: usize| {
        out.write_all(&common::tar_header(&format!("package/{path}"), 0o644, size)).unwrap();
        let chunk = [fill; 4096];
        for at in (0..size).step_by(chunk.len()) {
            out.write_all(&chunk[..chunk.len().min(size - at)]).unwrap();
        }
        out.write_all(&vec![0; size.div_ceil(512) * 512 - size]).unwrap();
    };
    let manifest = br#"{"name":"big","version":"1.0.0"}"#;
    add("package.json", b' ', manifest.len());
    for i in 0..65 {
        add(&format!("f{i}"), b's', 5);
    }
    for i in 0..12 {
        add(&format!("f{i}"), b'r', 8 << 20);
    }
    add("huge", b'h', 48 << 20);
    out.write_all(&[0; 1024]).unwrap();
    drop(out);
    // The manifest's bytes, over the blanks written for them.
    let mut tar = std::fs::OpenOptions::new().write(true).open(&file).unwrap();
    std::io::Seek::seek(&mut tar, std::io::SeekFrom::Start(512)).unwrap();
    tar.write_all(manifest).unwrap();
    drop(tar);
    env.manifest(json!({ "dependencies": { "big": "file:vendor/big.tar" } }));
    let mut c = env.command(&["install"]);
    let pid = c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap().id();
    // This child's own peak, not the test process's or another test's.
    let (mut status, mut usage) = (0, unsafe { std::mem::zeroed::<libc::rusage>() });
    // SAFETY: waits for the child just spawned, which nothing else waits for.
    assert_eq!(unsafe { libc::wait4(pid as libc::pid_t, &mut status, 0, &mut usage) }, pid as i32);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "install failed");
    let peak_mib = usage.ru_maxrss / 1024;
    assert!(peak_mib < 96, "unpacking 144 MiB peaked at {peak_mib} MiB");
    // The later entry for a repeated path wins, as tar has it.
    let f3 = std::fs::read(env.path("node_modules/big/f3")).unwrap();
    assert!(f3.len() == 8 << 20 && f3.iter().all(|b| *b == b'r'));
    assert_eq!(env.read("node_modules/big/f64"), "sssss");
    assert_eq!(std::fs::metadata(env.path("node_modules/big/huge")).unwrap().len(), 48 << 20);
}

#[test]
fn repairs_a_damaged_tree_under_verify() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let b = std::fs::canonicalize(env.project().join("node_modules/b")).unwrap();
    // A shared entry is sealed; damaging it takes lifting that first, as a user could.
    let _ = std::process::Command::new("chmod").arg("u+w").arg(&b).output();
    std::fs::remove_file(b.join("index.js")).unwrap();
    let out = env.ok(&["install", "--verify"]);
    assert!(out.contains("repaired"), "{out}");
    assert!(env.read("node_modules/b/index.js").contains("b@1.0.0"));
}

/// The entries built in a project's `.jpm`.
fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir.join("node_modules/.jpm"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && n != "node_modules" && n != "hoist.cjs") // the hidden hoist and its hook
        .collect();
    out.sort();
    out
}

fn link_of(dir: &std::path::Path, name: &str) -> String {
    std::fs::read_link(dir.join("node_modules").join(name)).unwrap().to_string_lossy().into_owned()
}

#[test]
fn shares_entries_through_the_global_store() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    let links = env.store().join("v1/links");
    let target = link_of(&env.project(), "a");
    // Built once in the store; the project links its direct deps straight there.
    assert!(entries(&env.project()).is_empty());
    assert!(std::path::Path::new(&target).starts_with(&links), "{target}");
    assert_eq!(std::fs::read_dir(&links).unwrap().count(), 2);
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));

    // A second project links to the same entries and builds none.
    let other = env.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::copy(env.project().join("package.json"), other.join("package.json")).unwrap();
    let out = env.command_in(&other, &["install"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("0 entries"), "{text}");
    assert_eq!(link_of(&other, "a"), target);

    // Off, the project builds its own entries; on again, it links back.
    env.ok(&["install", "--no-global-store"]);
    assert_eq!(entries(&env.project()).len(), 2);
    // Relative on unix, absolute as a junction: either way, into the project's own entries.
    let nm = env.project().join("node_modules");
    assert!(nm.join(link_of(&env.project(), "a")).starts_with(nm.join(".jpm")));
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));
    env.ok(&["install"]);
    assert_eq!(link_of(&env.project(), "a"), target);
    let again = env.ok(&["install"]);
    assert!(again.contains("up to date"), "{again}");
}

#[test]
fn keeps_entries_missing_an_optional_package_local() {
    let r = registry();
    r.publish(pkg(
        "nat",
        "1.0.0",
        json!({ "dependencies": { "b": "1.0.0" }, "optionalDependencies": { "native-any": "1.0.0" } }),
    ));
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "nat": "1" } }));
    env.ok(&["install"]);
    // Republished with other bytes, the locked package fails its integrity check and is skipped.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    let _ = std::process::Command::new("chmod").args(["-R", "u+w"]).arg(env.store()).output();
    std::fs::remove_dir_all(env.store()).unwrap();
    r.publish(pkg("native-any", "1.0.0", json!({})).file("extra.js", 0o644, "changed"));
    let out = env.ok(&["install"]);
    assert!(out.contains("skipped optional native-any"), "{out}");
    // nat lacks native-any, so its entry is the project's own; b is still shared.
    let list = entries(&env.project());
    assert!(list.len() == 1 && list[0].starts_with("nat@"), "{list:?}");
    assert!(!env.exists("node_modules/nat/../native-any"));
    assert!(env.read("node_modules/nat/../b/index.js").contains("b@1.0.0"));
}

fn pruned(env: &Env, dir: &std::path::Path) -> (u64, u64) {
    let out = env.command_in(dir, &["prune", "--json"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    (v["shared"]["removed"].as_u64().unwrap(), v["store"]["removed"].as_u64().unwrap())
}

#[test]
fn prunes_what_no_project_uses() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    let other = env.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("package.json"), r#"{ "dependencies": { "a": "1.1.0", "cli": "1" } }"#).unwrap();
    assert!(env.command_in(&other, &["install"]).status().unwrap().success());
    assert_eq!(pruned(&env, &env.project()), (0, 0), "both projects use everything");

    // Only what the removed project used alone goes; the other project still stands.
    std::fs::remove_dir_all(&other).unwrap();
    assert_eq!(pruned(&env, &env.project()), (1, 1));
    assert!(env.ok(&["install"]).contains("up to date"));
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));

    // A project the store does not know loses its entries, and its next install notices.
    std::fs::remove_dir_all(env.store().join("v1/projects")).unwrap();
    let third = env.root.join("third");
    std::fs::create_dir_all(&third).unwrap();
    std::fs::write(third.join("package.json"), r#"{ "dependencies": { "cli": "1" } }"#).unwrap();
    assert!(env.command_in(&third, &["install"]).status().unwrap().success());
    assert_eq!(pruned(&env, &third), (2, 2));
    let again = env.ok(&["install"]);
    assert!(!again.contains("up to date"), "{again}");
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));
}

#[cfg(unix)]
#[test]
fn never_builds_or_prunes_through_a_committed_symlink() {
    let r = registry();
    let env = Env::new(&r);
    // A repo can commit node_modules/.jpm, or node_modules itself, as a link to anywhere.
    let victim = env.root.join("victim");
    std::fs::create_dir_all(victim.join("precious@1.0.0-aaaaaaaaaaaaaaaaaaaaaa")).unwrap();
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    for link in ["node_modules/.jpm", "node_modules"] {
        let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
        let at = env.project().join(link);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &at).unwrap();
        env.write(
            "node_modules/.jpm.json",
            r#"{"version":1,"hash":"x","entries":[],"complete":true,"store":"/nowhere"}"#,
        );
        let out = env.jpm(&["install", "--no-global-store"]);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && text.contains("leads outside the project"), "{link}: {text}");
        env.ok(&["prune"]);
        assert!(victim.join("precious@1.0.0-aaaaaaaaaaaaaaaaaaaaaa").exists(), "{link}: prune emptied the target");
        std::fs::remove_file(&at).unwrap();
    }
}

/// Directories inside node_modules a checkout ships as symlinks out of the project: nothing is
/// linked there, and nothing there swept away.
#[cfg(unix)]
#[test]
fn never_links_or_sweeps_through_a_symlink_in_node_modules() {
    let r = Registry::start(vec![
        pkg("top", "1.0.0", json!({ "dependencies": { "b": "1.0.0", "@s/c": "1.0.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("@s/c", "1.0.0", json!({ "bin": { "c": "c.js" } })).file("c.js", 0o755, "#!/bin/sh\n"),
        pkg("tool", "1.0.0", json!({ "bin": { "tool": "t.js" } })).file("t.js", 0o755, "#!/bin/sh\n"),
    ]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "top": "1.0.0", "tool": "1.0.0" } }));
    let victim = env.root.join("victim");
    let plant = |at: &std::path::Path| {
        let _ = std::fs::remove_dir_all(&victim);
        std::fs::create_dir_all(&victim).unwrap();
        std::os::unix::fs::symlink("/", victim.join("keep")).unwrap();
        let _ = std::fs::remove_dir_all(at);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, at).unwrap();
    };
    let untouched = |what: &str| {
        let names: Vec<String> =
            std::fs::read_dir(&victim).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into()).collect();
        assert_eq!(names, ["keep"], "{what}: written or swept outside the project");
    };
    // The bins' directory, the hidden hoist, and a scope in the hoist.
    for rel in ["node_modules/.bin", "node_modules/.jpm/node_modules", "node_modules/.jpm/node_modules/@s"] {
        let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
        plant(&env.project().join(rel));
        let out = env.jpm(&["install"]);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && text.contains("leads outside the project"), "{rel}: {text}");
        untouched(rel);
    }
    // An entry's own node_modules, or its bins, in the project layout.
    for rel in ["node_modules", "node_modules/.bin"] {
        let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
        env.ok(&["install", "--no-global-store"]);
        let entries = env.project().join("node_modules/.jpm");
        let entry = std::fs::read_dir(&entries)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().starts_with("top@"));
        plant(&entry.unwrap().path().join(rel));
        std::fs::remove_file(env.project().join("node_modules/.jpm.json")).unwrap();
        let out = env.jpm(&["install", "--no-global-store"]);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && text.contains("leads outside the project"), "entry {rel}: {text}");
        untouched(rel);
    }
}

/// An install script's log and marker are new files: never written through a link left there.
#[cfg(unix)]
#[test]
fn writes_a_build_log_through_no_link() {
    let r = scripted();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "trustedDependencies": ["bld"] }));
    env.ok(&["install"]);
    env.ok(&["approve", "bld"]);
    let victim = env.root.join("victim.txt");
    std::fs::write(&victim, "precious").unwrap();
    let entries = env.project().join("node_modules/.jpm");
    let entry =
        std::fs::read_dir(&entries).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("bld@"));
    let entry = entry.unwrap().path();
    std::fs::remove_file(entry.join(".built")).unwrap();
    std::fs::remove_file(entry.join(".build.log")).unwrap();
    std::os::unix::fs::symlink(&victim, entry.join(".build.log")).unwrap();
    std::fs::remove_file(env.project().join("node_modules/.jpm.json")).unwrap();
    env.ok(&["install"]);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    assert!(entry.join(".built").is_file());
}

/// package.json names one tarball url, and an edited jpm.lock another in its place.
#[test]
fn a_lockfile_cannot_move_a_tarball_dependency_to_another_url() {
    let r = registry();
    let good = pkg("tb", "1.0.0", json!({})).file("which.js", 0o644, "good");
    let evil = pkg("tb", "1.0.0", json!({})).file("which.js", 0o644, "evil");
    r.serve("/good/tb.tgz", good.tarball());
    r.serve("/evil/tb.tgz", evil.tarball());
    let env = Env::new(&r);
    let (g, e) = (format!("{}/good/tb.tgz", r.url), format!("{}/evil/tb.tgz", r.url));
    env.manifest(json!({ "dependencies": { "tb": e } }));
    env.ok(&["install"]);
    env.manifest(json!({ "dependencies": { "tb": g } }));
    let lock = env.read("jpm.lock");
    env.write("jpm.lock", &lock.replace(&format!("spec dependencies tb {e}"), &format!("spec dependencies tb {g}")));
    let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
    let out = env.jpm(&["ci"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("which its specs do not name"), "{text}");
    assert!(!env.exists("node_modules/tb"));
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/tb/which.js"), "good");
}

#[test]
fn sends_tokens_only_where_they_belong() {
    let r = registry();
    let other = registry();
    let env = Env::new(&r);
    let host = |url: &str| url.trim_start_matches("http://").to_string();
    // The registry is plain http here, configured so: its own token goes to it. Another host's
    // token never does, and the scope on the other host gets only its own.
    env.write(
        ".npmrc",
        &format!(
            "//{}/:_authToken=MINE\n@s:registry={}\n//{}/npm/:_authToken=PATH-ONLY\n",
            host(&r.url),
            other.url,
            host(&other.url)
        ),
    );
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    let hits = r.hits.lock().unwrap().clone();
    assert!(hits.iter().any(|h| h.contains("authorization: Bearer MINE")), "{hits:?}");
    assert!(!hits.iter().any(|h| h.contains("PATH-ONLY")), "{hits:?}");
}

#[cfg(unix)]
#[test]
fn hands_npm_commands_only_to_the_system_npm() {
    use std::os::unix::fs::PermissionsExt;
    let r = registry();
    let env = Env::new(&r);
    let script = |path: &std::path::Path, body: &str| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // A dependency's (or the project's) npm must never see `login` or `publish`.
    let planted = env.root.join("planted");
    script(&env.project().join("node_modules/.bin/npm"), &format!("touch {}", planted.display()));
    env.manifest(json!({ "name": "app", "bin": { "npm": "evil.js" } }));
    let system = env.root.join("system-bin");
    script(&system.join("npm"), "echo system-npm \"$@\"");
    let path = format!("{}:/usr/bin:/bin", system.display());
    let out = env.command(&["whoami"]).env("PATH", &path).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("system-npm whoami"), "{out:?}");
    assert!(!planted.exists(), "a project npm ran");
    // Without one on PATH, jpm says so rather than installing npm from the project's registry.
    let out = env.command(&["whoami"]).env("PATH", "/usr/bin:/bin").output().unwrap();
    assert!(
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("npm is not on PATH") || which_npm(),
        "{out:?}"
    );
    assert!(!planted.exists());
}

#[cfg(unix)]
fn which_npm() -> bool {
    ["/usr/bin/npm", "/bin/npm"].iter().any(|p| std::path::Path::new(p).exists())
}

#[test]
fn brings_over_npm_lockfiles() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "a": "^1.0.0" } }));
    let integrity = |p: &str, v: &str, deps: serde_json::Value| common::sha512(&common::pkg(p, v, deps).tarball());
    env.write(
        "package-lock.json",
        &serde_json::to_string_pretty(&json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "dependencies": { "a": "^1.0.0" } },
                "node_modules/a": { "version": "1.0.0", "resolved": format!("{}/a/-/a-1.0.0.tgz", r.url), "integrity": integrity("a", "1.0.0", json!({ "dependencies": { "b": "^1.0.0" } })), "dependencies": { "b": "^1.0.0" } },
                "node_modules/b": { "version": "1.0.0", "resolved": format!("{}/b/-/b-1.0.0.tgz", r.url), "integrity": integrity("b", "1.0.0", json!({})) }
            }
        }))
        .unwrap(),
    );
    // CI reads it as it is and writes nothing.
    env.ok(&["ci"]);
    assert!(!env.exists("jpm.lock"));
    assert!(env.read("node_modules/a/index.js").contains("a@1.0.0"), "the locked version, not the newest");
    // An install brings it over: same versions, now in jpm.lock.
    let out = env.ok(&["install"]);
    assert!(out.contains("from package-lock.json"), "{out}");
    let lock = env.lock();
    assert!(lock["packages"].get("a@1.0.0").is_some() && lock["packages"].get("b@1.0.0").is_some());
    assert!(env.exists("package-lock.json"), "the old file is left alone");
    // And jpm.lock is what a later edit works on.
    env.ok(&["add", "cli"]);
    assert!(env.lock()["packages"].get("a@1.0.0").is_some(), "the edit keeps the brought-over versions");
}

/// b@^1.0.0 at 1.0.0 for the root and 1.1.0 for a: a resolve would put both on 1.1.0.
const YARN_V1: &str = "# yarn lockfile v1\n\n\na@1.1.0:\n  version \"1.1.0\"\n  dependencies:\n    b \"^1.1.0\"\n\nb@^1.0.0:\n  version \"1.0.0\"\n\nb@^1.1.0:\n  version \"1.1.0\"\n";
const YARN_BERRY: &str = "__metadata:\n  version: 8\n\n\"a@npm:1.1.0\":\n  version: 1.1.0\n  resolution: \"a@npm:1.1.0\"\n  dependencies:\n    b: \"npm:^1.1.0\"\n\n\"b@npm:^1.0.0\":\n  version: 1.0.0\n\n\"b@npm:^1.1.0\":\n  version: 1.1.0\n";

#[test]
fn brings_over_yarn_lockfiles() {
    let r = registry();
    for text in [YARN_V1, YARN_BERRY] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "a": "1.1.0", "b": "^1.0.0" } }));
        env.write("yarn.lock", text);
        // CI installs yarn's versions and writes nothing.
        env.ok(&["ci"]);
        assert!(!env.exists("jpm.lock"));
        assert!(env.read("node_modules/b/index.js").contains("b@1.0.0"), "yarn's b, where 1.1.0 is newer");
        assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));
        // An install brings it over, each range as yarn resolved it.
        let out = env.ok(&["install"]);
        assert!(out.contains("from yarn.lock"), "{out}");
        let lock = env.lock();
        assert_eq!(lock["root"]["dependencies"]["b"], "1.0.0");
        assert_eq!(lock["packages"]["a@1.1.0"]["dependencies"]["b"], "1.1.0");
    }
}

#[test]
fn resolves_an_out_of_date_yarn_lockfile() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0", "b": "^1.0.0", "host": "^1.0.0" } }));
    env.write("yarn.lock", YARN_V1);
    let out = env.jpm(&["ci"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("yarn.lock is out of date"), "{text}");
    let out = env.ok(&["install"]);
    assert!(out.contains("versions preferred"), "{out}");
    let lock = env.lock();
    assert_eq!(lock["root"]["dependencies"]["b"], "1.0.0", "yarn's versions still count");
    assert_eq!(lock["root"]["dependencies"]["host"], "1.0.0");
}

#[test]
fn resolves_an_out_of_date_lockfile_with_its_versions() {
    let r = registry();
    let env = Env::new(&r);
    // package.json moved on (a new dependency) since pnpm wrote this; its versions still count.
    env.manifest(json!({ "dependencies": { "b": "^1.0.0", "host": "^1.0.0" } }));
    env.write(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      b:\n        specifier: ^1.0.0\n        version: 1.0.0\npackages:\n  b@1.0.0:\n    resolution: {integrity: sha512-x}\nsnapshots:\n  b@1.0.0: {}\n",
    );
    let out = env.ok(&["install"]);
    assert!(out.contains("versions preferred"), "{out}");
    let lock = env.lock();
    assert_eq!(lock["root"]["dependencies"]["b"], "1.0.0", "pnpm's b, where 1.1.0 is newer");
    assert_eq!(lock["root"]["dependencies"]["host"], "1.0.0");
}

#[test]
fn resolves_and_prints_json() {
    let r = registry();
    let env = Env::new(&r);
    let out = env.jpm(&["resolve", "b@^1", "--json"]);
    assert!(out.status.success());
    let list: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(list[0]["version"], "1.1.0");
    let out = env.jpm(&["resolve", "nope"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("E404"));
}

#[test]
fn prunes_and_dedupes() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.0.0", "b": "^1.0.0" } }));
    env.ok(&["install"]);
    env.ok(&["dedupe"]);
    env.ok(&["prune"]);
    assert!(env.exists("node_modules/a"));
}

#[test]
fn production_skips_dev_packages() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" }, "devDependencies": { "cli": "1" } }));
    env.ok(&["install", "--production"]);
    assert!(env.exists("node_modules/b") && !env.exists("node_modules/cli"));
}

#[test]
fn rejects_bad_usage() {
    let r = registry();
    let env = Env::new(&r);
    assert_eq!(env.jpm(&["--nope"]).status.code(), Some(2));
    assert_eq!(env.jpm(&["add"]).status.code(), Some(2));
    assert_eq!(env.jpm(&["install", "--dev"]).status.code(), Some(2));
    assert!(env.ok(&["--help"]).contains("Usage"));
}

/// A package with an install script: it counts its runs and records what token it could see.
#[cfg(unix)]
fn bld(version: &str) -> common::Pkg {
    pkg(
        "bld",
        version,
        json!({
            "dependencies": { "dep": "1.0.0" },
            "scripts": { "postinstall": "echo run >> count.txt; echo \"[$NPM_TOKEN$npm_config__authToken]\" > token.txt" }
        }),
    )
}

/// Packages with install scripts, and ones whose scripts fail.
#[cfg(unix)]
fn scripted() -> Registry {
    let fails = |name: &str| pkg(name, "1.0.0", json!({ "scripts": { "install": "echo broken >&2; exit 3" } }));
    Registry::start(vec![
        bld("1.0.0"),
        bld("1.1.0"),
        pkg("dep", "1.0.0", json!({})),
        fails("fails"),
        fails("optfails"),
        pkg("host", "1.0.0", json!({ "optionalDependencies": { "optfails": "1.0.0" } })),
    ])
}

#[cfg(unix)]
#[test]
fn runs_install_scripts_only_when_approved() {
    let r = scripted();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" } }));
    // Not approved: nothing runs, and the install says what did not.
    let out = env.ok(&["install"]);
    assert!(out.contains("install scripts not run for bld@1.0.0"), "{out}");
    assert!(!env.exists("node_modules/bld/count.txt"));
    assert!(env.read("jpm.lock").contains("  scripts\n"));
    // Trusted by name alone is not enough: the version must be approved.
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" }, "trustedDependencies": ["bld"] }));
    env.ok(&["install"]);
    assert!(!env.exists("node_modules/bld/count.txt"));
    assert!(env.ok(&["approve"]).contains("waiting for approval: bld@1.0.0"));

    // Approved: it runs once, in a writable copy of its own, with no npm credentials.
    let out = env.command(&["approve", "bld"]).env("NPM_TOKEN", "SECRET").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("approved bld@1.0.0"), "{text}");
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");
    assert_eq!(env.read("node_modules/bld/token.txt"), "[]\n");
    assert!(env.read("jpm.lock").contains("  build\n"));
    assert!(env.read("package.json").contains("\"trustedDependencies\""));
    let real = std::fs::canonicalize(env.project().join("node_modules/bld")).unwrap();
    assert!(real.starts_with(std::fs::canonicalize(env.project()).unwrap()), "built in the project: {real:?}");
    env.ok(&["install"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n", "not again");
    // Another edit resolves again: the approval stays with the version.
    let out = env.ok(&["add", "dep@1.0.0"]);
    assert!(!out.contains("not run"), "{out}");
    assert!(env.read("jpm.lock").contains("  build\n"));
    env.ok(&["dedupe"]);
    assert!(env.read("jpm.lock").contains("  build\n"), "dedupe keeps the approval");
    // CI installs the approved scripts from the lockfile as it is.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");

    // A new version waits for its own approval.
    let out = env.ok(&["add", "bld@1.1.0"]);
    assert!(out.contains("install scripts not run for bld@1.1.0"), "{out}");
    assert!(!env.exists("node_modules/bld/count.txt"));
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");

    // --ignore-scripts runs nothing, approved or not.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["install", "--ignore-scripts"]);
    assert!(!env.exists("node_modules/bld/count.txt"));
}

#[cfg(unix)]
#[test]
fn stops_on_a_failing_install_script() {
    let r = scripted();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "fails": "1.0.0", "host": "1.0.0" } }));
    env.ok(&["install"]);
    // An optional package's failure is a warning; a required one's stops the install.
    let out = env.jpm(&["approve", "optfails"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("skipped optional optfails@1.0.0 install failed"));
    let out = env.jpm(&["approve", "fails"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("fails@1.0.0 install failed") && text.contains("broken"), "{text}");
    assert!(env.jpm(&["approve", "dep"]).status.code() != Some(0), "a package with no scripts cannot be approved");
}

#[cfg(unix)]
#[test]
fn runs_the_projects_own_lifecycle_scripts() {
    let r = scripted();
    let env = Env::new(&r);
    env.manifest(json!({
        "dependencies": { "dep": "1.0.0" },
        "scripts": { "preinstall": "echo pre >> order.txt", "postinstall": "echo post >> order.txt", "prepare": "echo prepare >> order.txt" }
    }));
    env.ok(&["install"]);
    assert_eq!(env.read("order.txt"), "pre\npost\nprepare\n");
    env.ok(&["install"]);
    assert_eq!(env.read("order.txt"), "pre\npost\nprepare\n", "a no-op install runs nothing");
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["install", "--ignore-scripts"]);
    assert_eq!(env.read("order.txt"), "pre\npost\nprepare\n");
}

#[cfg(unix)]
#[test]
fn finds_install_scripts_bun_lock_leaves_out() {
    let r = scripted();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "dependencies": { "bld": "1.0.0" } }));
    let integrity = |p: common::Pkg| common::sha512(&p.tarball());
    // bun.lock names no install scripts: they are read from the packages themselves.
    env.write(
        "bun.lock",
        &format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {{ \"\": {{ \"name\": \"app\", \"dependencies\": {{ \"bld\": \"1.0.0\" }} }} }},\n  \"packages\": {{\n    \"bld\": [\"bld@1.0.0\", \"\", {{ \"dependencies\": {{ \"dep\": \"1.0.0\" }} }}, \"{}\"],\n    \"dep\": [\"dep@1.0.0\", \"\", {{}}, \"{}\"],\n  }}\n}}\n",
            integrity(bld("1.0.0")),
            integrity(pkg("dep", "1.0.0", json!({})))
        ),
    );
    let out = env.ok(&["install"]);
    assert!(out.contains("from bun.lock") && out.contains("install scripts not run for bld@1.0.0"), "{out}");
    let lock = env.read("jpm.lock");
    assert!(lock.contains("package bld@1.0.0") && lock.contains("  scripts\n"), "{lock}");
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");
}

#[test]
fn an_alias_never_takes_another_packages_place() {
    // `b` declares `real` as an alias for `evil` at the version `a`'s real `real` has: each
    // must get its own package.
    let r = Registry::start(vec![
        pkg("real", "1.0.0", json!({})),
        pkg("evil", "1.0.0", json!({})),
        pkg("a", "1.0.0", json!({ "dependencies": { "real": "1.0.0" } })),
        pkg("b", "1.0.0", json!({ "dependencies": { "real": "npm:evil@1.0.0" } })),
    ]);
    // jpm keeps one package per name and version, so the tree is refused rather than letting
    // either stand in for the other.
    for order in [["a", "b"], ["b", "a"]] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { order[0]: "1.0.0", order[1]: "1.0.0" } }));
        let out = env.jpm(&["install"]);
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && text.contains("real@1.0.0 is two different packages"), "{order:?}: {text}");
        assert!(!env.exists("node_modules/a"), "{order:?}: nothing is linked");
    }
    // An alias under a name nothing else uses is fine.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "b": "1.0.0" } }));
    env.ok(&["install"]);
    assert!(env.read("node_modules/b/../real/index.js").contains("evil@1.0.0"));
}

#[cfg(unix)]
#[test]
fn approvals_hold_only_for_the_registrys_own_package() {
    let r = scripted();
    r.publish(pkg("evil", "1.0.0", json!({ "scripts": { "postinstall": "touch pwned.txt" } })));
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "1.0.0" } }));
    env.ok(&["approve", "bld"]);
    assert_eq!(env.read("node_modules/bld/count.txt"), "run\n");
    // A lockfile edit keeps the approval but points the package at another tarball, integrity
    // and all: it installs, and its scripts do not run.
    let evil =
        common::sha512(&pkg("evil", "1.0.0", json!({ "scripts": { "postinstall": "touch pwned.txt" } })).tarball());
    let lock = env.read("jpm.lock");
    let at = lock.find("package bld@1.0.0\n").unwrap();
    let end = lock[at..].find("\npackage ").map_or(lock.len(), |i| at + i + 1);
    let entry = format!(
        "package bld@1.0.0\n  resolved {}/evil/-/evil-1.0.0.tgz\n  integrity {evil}\n  dep dep 1.0.0\n  scripts\n  build\n",
        r.url
    );
    env.write("jpm.lock", &format!("{}{entry}{}", &lock[..at], &lock[end..]));
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    let out = env.ok(&["install"]);
    assert!(out.contains("tarball is not the registry's"), "{out}");
    assert!(!env.exists("node_modules/bld/pwned.txt"), "the substituted package's script ran");

    // An alias wearing a trusted name is not the package the name says.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "bld": "npm:evil@1.0.0" }, "trustedDependencies": ["bld"] }));
    env.ok(&["install"]);
    let out = env.jpm(&["approve", "bld"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("not the registry"), "{text}");
    assert!(!env.exists("node_modules/bld/pwned.txt"));
}

#[cfg(unix)]
#[test]
fn seals_shared_entries() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    // Nothing one project runs may change what another links to: not a file, and not the
    // directories that hold them.
    let a = std::fs::canonicalize(env.project().join("node_modules/a")).unwrap();
    assert!(a.starts_with(std::fs::canonicalize(env.store()).unwrap()), "{a:?}");
    let root = unsafe { libc_geteuid() } == 0;
    if !root {
        assert!(std::fs::write(a.join("planted.js"), "x").is_err(), "a file was added to a shared entry");
        assert!(std::fs::remove_file(a.join("index.js")).is_err(), "a file was removed from a shared entry");
        assert!(std::fs::write(a.join("index.js"), "x").is_err());
    }
    // Pruning still removes a sealed entry.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    let out = env.ok(&["prune", "--json"]);
    assert!(out.contains("\"shared\""), "{out}");
    let links = env.store().join("v1/links");
    assert_eq!(
        std::fs::read_dir(&links)
            .unwrap()
            .filter(|e| !e.as_ref().unwrap().file_name().to_string_lossy().starts_with('.'))
            .count(),
        0
    );
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

#[test]
fn reads_what_it_can_of_a_peer_range() {
    let r = Registry::start(vec![
        pkg("host", "1.0.0", json!({})),
        pkg("anim", "1.0.0", json!({ "peerDependencies": { "host": ">=1.0.0 || insiders || >=4.0.0-alpha.20" } })),
        pkg("odd", "1.0.0", json!({ "peerDependencies": { "host": "insiders || nightly" } })),
    ]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "anim": "1.0.0", "odd": "1.0.0", "host": "^1.0.0" } }));
    let out = env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(lock["packages"]["anim@1.0.0"]["dependencies"]["host"], "1.0.0", "the alternatives that are ranges");
    // No alternative is a range: nothing matches, and that is a warning.
    assert!(out.contains("host@insiders || nightly"), "{out}");
    assert!(lock["packages"]["odd@1.0.0"]["dependencies"]["host"].is_null());
}

#[test]
fn pins_come_from_kept_packuments_without_asking() {
    let fresh = json!({ "_published": "2999-01-01T00:00:00.000Z" });
    let r = Registry::start(vec![
        pkg("a", "1.0.0", json!({ "dependencies": { "b": "1.0.0" } })),
        pkg("b", "1.0.0", json!({})),
        pkg("fresh", "1.0.0", fresh),
    ]);
    let env = Env::new(&r);
    // Ranges keep the packuments; a's pin on b may be asked for by its route.
    env.manifest(json!({ "dependencies": { "a": "^1.0.0", "fresh": "^1.0.0" } }));
    env.ok(&["lock"]);
    // Pinned now: a@1.0.0's own route was never asked for, and its packument answers.
    env.manifest(json!({ "dependencies": { "a": "1.0.0" } }));
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    let asked = r.hits.lock().unwrap().len();
    env.ok(&["lock", "--prefer-offline"]);
    let hits = r.hits.lock().unwrap()[asked..].to_vec();
    assert!(hits.is_empty(), "{hits:?}");
    assert!(env.lock()["packages"].get("a@1.0.0").is_some());
    // A pin the release age cuts from the kept packument is still asked for by its route,
    // which the cutoff does not apply to.
    env.manifest(json!({ "dependencies": { "fresh": "1.0.0" } }));
    std::fs::remove_file(env.path("jpm.lock")).unwrap();
    let out = env.command(&["lock", "--prefer-offline"]).env("npm_config_min_release_age", "1").output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(env.lock()["packages"].get("fresh@1.0.0").is_some());
}

#[test]
fn keeps_new_versions_an_imported_lockfile_names() {
    let fresh = json!({ "_published": "2999-01-01T00:00:00.000Z" });
    let r = Registry::start(vec![pkg("b", "1.0.0", json!({})), pkg("@s/fresh", "1.0.0", fresh.clone())]);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "@s/fresh": "^1.0.0", "b": "^1.0.0" } }));
    let aged = |args: &[&str]| env.command(args).env("npm_config_min_release_age", "1").output().unwrap();
    let out = aged(&["lock"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("min-release-age"), "nothing names it yet: {text}");
    // package-lock.json predates b, so it is resolved again, keeping the version it names.
    let tgz = common::pkg("@s/fresh", "1.0.0", fresh).tarball();
    env.write(
        "package-lock.json",
        &serde_json::to_string_pretty(&json!({
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "@s/fresh": "^1.0.0" } },
                "node_modules/@s/fresh": { "version": "1.0.0", "resolved": format!("{}/@s/fresh/-/fresh-1.0.0.tgz", r.url), "integrity": common::sha512(&tgz) }
            }
        }))
        .unwrap(),
    );
    let out = aged(&["lock"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && text.contains("versions preferred"), "{text}");
    assert!(env.lock()["packages"].get("@s/fresh@1.0.0").is_some());
}

#[test]
fn legacy_peer_deps_links_only_peers_the_tree_has() {
    let r = registry();
    let env = Env::new(&r);
    env.write(".npmrc", "legacy-peer-deps=true\n");
    env.manifest(json!({ "dependencies": { "plugin": "1" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("unmet peer host@>=1"), "{out}");
    assert!(env.lock()["packages"].get("host@2.0.0").is_none(), "no peer is added");
    env.manifest(json!({ "dependencies": { "plugin": "1", "host": "1.0.0" } }));
    env.ok(&["install"]);
    assert_eq!(env.lock()["packages"]["plugin@1.0.0"]["dependencies"]["host"], "1.0.0", "the tree's host");
    // The flag says the same.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "plugin": "1" } }));
    env.ok(&["install", "--legacy-peer-deps"]);
    assert!(env.lock()["packages"].get("host@2.0.0").is_none());
}

#[test]
fn yarn_1_lockfiles_install_no_peers() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "plugin": "1" } }));
    // yarn 1 never installs peers, so its file names no host.
    env.write("yarn.lock", "# yarn lockfile v1\n\n\nplugin@1:\n  version \"1.0.0\"\n");
    env.ok(&["ci"]);
    assert!(env.exists("node_modules/plugin") && !env.exists("node_modules/plugin/../host"));
    let out = env.ok(&["install"]);
    assert!(out.contains("with the same versions"), "{out}");
    assert!(env.lock()["packages"].get("host@2.0.0").is_none());
}

#[test]
fn skips_a_dev_dependency_for_another_platform() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"] }));
    let core = |group: &str| {
        // native, which ships, has native-mars as an optional dependency: that is not a need.
        let text = json!({ "name": "core", "version": "1.0.0", "dependencies": { "native": "1" }, group: { "native-mars": "1.0.0", "b": "1.0.0" } });
        env.write("packages/core/package.json", &text.to_string());
    };
    core("devDependencies");
    let out = env.ok(&["install"]);
    assert!(out.contains("native-mars@1.0.0"), "{out}");
    assert!(env.lock()["packages"].get("native-mars@1.0.0").is_some(), "the lockfile keeps every platform");
    assert!(env.exists("packages/core/node_modules/b") && !env.exists("packages/core/node_modules/native-mars"));
    // One that ships cannot be left out; the error says who needs it.
    core("dependencies");
    let out = env.jpm(&["install"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("EBADPLATFORM") && text.contains("packages/core"), "{text}");
}

#[test]
fn installs_a_workspace_versioned_latest() {
    let r = registry();
    let env = Env::new(&r);
    // puppeteer's private test package: npm installs it, as 0.0.0 here.
    env.manifest(json!({ "name": "root", "workspaces": ["test"], "dependencies": { "t": "workspace:*" } }));
    env.write(
        "test/package.json",
        r#"{ "name": "t", "version": "latest", "private": true, "dependencies": { "b": "1.0.0" } }"#,
    );
    env.ok(&["install"]);
    assert!(env.exists("node_modules/t") && env.exists("test/node_modules/b"));
}

#[test]
fn passes_arguments_through_scripts_and_shims() {
    // The bin is a node script; the rest of the suite needs no node.
    if std::process::Command::new("node").arg("--version").output().is_err() {
        eprintln!("skipped: no node on PATH");
        return;
    }
    let r = registry();
    let env = Env::new(&r);
    // The script names a bin: on Windows a .cmd shim, whose %* reads the arguments again, so
    // an unescaped `&` would start a second command.
    env.manifest(json!({ "scripts": { "show": "argv" }, "dependencies": { "argv": "1" } }));
    env.ok(&["install"]);
    let args = ["a b", "x&y", "|pipe", "<in>", "50%", "^caret", "q\"uote", "(p)", "!b!", ""];
    for how in [&["run", "-s", "show"][..], &["exec", "-s", "argv"][..]] {
        let mut argv: Vec<&str> = how.to_vec();
        argv.extend(args);
        let out = env.jpm(&argv);
        let text = String::from_utf8_lossy(&out.stdout);
        let got: serde_json::Value = serde_json::from_str(text.trim().lines().last().unwrap_or(""))
            .unwrap_or_else(|_| panic!("{how:?}: {text}{}", String::from_utf8_lossy(&out.stderr)));
        assert_eq!(got, json!(args), "{how:?}");
    }
}

#[test]
fn reads_pnpm_workspaces_and_catalogs() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "dependencies": { "one": "workspace:*", "a": "catalog:" } }));
    // As people write it: comments, and a list no deeper than its key.
    env.write(
        "pnpm-workspace.yaml",
        "# the workspaces\npackages:\n- 'packages/*' # all of them\n\ncatalog:\n  a: 1.0.0\ncatalogs:\n  next:\n    'b': ^2 # newest\n",
    );
    env.write(
        "packages/one/package.json",
        r#"{ "name": "one", "version": "1.0.0", "dependencies": { "b": "catalog:next" } }"#,
    );
    env.ok(&["install"]);
    assert!(env.read("node_modules/a/index.js").contains("a@1.0.0"));
    assert!(env.read("packages/one/node_modules/b/index.js").contains("b@2.0.0"));
    assert!(env.exists("node_modules/one"));

    // The catalog moves; the install follows it.
    let yaml = std::fs::read_to_string(env.project().join("pnpm-workspace.yaml")).unwrap();
    env.write("pnpm-workspace.yaml", &yaml.replace("a: 1.0.0", "a: 1.1.0"));
    env.ok(&["install"]);
    assert!(env.read("node_modules/a/index.js").contains("a@1.1.0"));

    // A name the catalog does not have is an error that says so.
    env.write(
        "packages/one/package.json",
        r#"{ "name": "one", "version": "1.0.0", "dependencies": { "c": "catalog:" } }"#,
    );
    let out = env.jpm(&["install"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("catalog default"), "{text}");
}

#[test]
fn reads_catalogs_from_yarnrc_after_plugins() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "dependencies": { "a": "catalog:" } }));
    env.write(
        ".yarnrc.yml",
        "nodeLinker: node-modules\nplugins:\n  - path: .yarn/plugins/x.cjs\n    spec: \"x\"\ncatalog:\n  a: 1.0.0\n",
    );
    env.ok(&["install"]);
    assert!(env.read("node_modules/a/index.js").contains("a@1.0.0"));

    // A file it cannot read is named, not taken for one with no catalogs.
    env.write(".yarnrc.yml", "catalog:\n  a: 1.0.0\n    b: 1\n");
    let out = env.jpm(&["install"]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains(".yarnrc.yml"), "{text}");
}

#[test]
fn reads_catalogs_from_package_json() {
    let r = registry();
    let env = Env::new(&r);
    // bun's spelling, under workspaces.
    env.manifest(json!({
        "name": "root",
        "workspaces": { "packages": ["packages/*"], "catalog": { "b": "1.1.0" } },
        "dependencies": { "one": "workspace:*" }
    }));
    env.write(
        "packages/one/package.json",
        r#"{ "name": "one", "version": "1.0.0", "dependencies": { "b": "catalog:" } }"#,
    );
    env.ok(&["install"]);
    assert!(env.read("packages/one/node_modules/b/index.js").contains("b@1.1.0"));
}

#[test]
fn hoists_one_of_every_package_for_undeclared_imports() {
    let r = registry();
    let env = Env::new(&r);
    // b@1.1.0 through a, b@2.0.0 through @scope/lib; b is not a root dependency.
    env.manifest(json!({ "dependencies": { "a": "1.1.0", "@scope/lib": "1" } }));
    env.ok(&["install", "--no-global-store"]);
    assert!(env.read("node_modules/.jpm/node_modules/b/index.js").contains("b@2.0.0"), "the highest");
    assert!(!env.exists("node_modules/.jpm/node_modules/@scope/lib"), "the root links its own");
    assert!(!env.exists("node_modules/b"), "the hoist is not the root's node_modules");
    // A name the root links stays out: Node finds the root's own version next. The hoist
    // follows the tree.
    env.manifest(json!({ "dependencies": { "a": "1.1.0", "@scope/lib": "1", "b": "1.0.0" } }));
    env.ok(&["install", "--no-global-store"]);
    assert!(!env.exists("node_modules/.jpm/node_modules/b"));
    env.manifest(json!({ "dependencies": { "@scope/lib": "1" } }));
    env.ok(&["install", "--no-global-store"]);
    assert!(!env.exists("node_modules/.jpm/node_modules/a"), "gone with its package");
    // Prune drops the unused entries and keeps the hoist.
    env.ok(&["prune"]);
    assert!(!entries(&env.project()).iter().any(|e| e.starts_with("a@")));
    assert!(env.read("node_modules/.jpm/node_modules/b/index.js").contains("b@2.0.0"));
    // A tree without its hoist (deleted, or installed before there was one) is not up to date.
    std::fs::remove_dir_all(env.path("node_modules/.jpm/node_modules")).unwrap();
    env.ok(&["install", "--no-global-store"]);
    assert!(env.read("node_modules/.jpm/node_modules/b/index.js").contains("b@2.0.0"));
    // Entries in the global store resolve from the store: the hook points Node at the hoist.
    env.ok(&["install"]);
    assert!(env.read("node_modules/.jpm/node_modules/b/index.js").contains("b@2.0.0"));
    assert!(env.exists("node_modules/.jpm/hoist.cjs"));
    env.ok(&["install", "--no-global-store"]);
    assert!(!env.exists("node_modules/.jpm/hoist.cjs"), "Node finds the hoist itself");
}

#[test]
fn packages_in_the_global_store_find_undeclared_imports_under_run_and_exec() {
    if std::process::Command::new("node").arg("--version").output().is_err() {
        eprintln!("skipped: no node on PATH");
        return;
    }
    // Neither `uses` (require) nor `esm` (import) declares b; a brings it into the hoist.
    let bin = |name: &str, body: &str| {
        let module = if name == "esm" { "module" } else { "commonjs" };
        pkg(name, "1.0.0", json!({ "type": module, "bin": { name: "main.js" } })).file(
            "main.js",
            0o755,
            &format!("#!/usr/bin/env node\n{body}\n"),
        )
    };
    let r = Registry::start(vec![
        pkg("a", "1.1.0", json!({ "dependencies": { "b": "^1.1.0" } })),
        pkg("b", "1.1.0", json!({})),
        pkg("c", "1.0.0", json!({})),
        bin("uses", "console.log('cjs ' + require('b') + ' ' + require('c'))"),
        bin("esm", "import b from 'b';\nimport c from 'c';\nconsole.log('esm ' + b + ' ' + c)"),
    ]);
    let env = Env::new(&r);
    // c is the root's own: Node reaches it past the hoist, as it does in the project layout.
    env.manifest(json!({
        "scripts": { "both": "uses && esm", "env": "node -p process.env.NODE_OPTIONS+process.env.NODE_PATH" },
        "dependencies": { "a": "1.1.0", "c": "1.0.0", "uses": "1.0.0", "esm": "1.0.0" }
    }));
    let want = "cjs b@1.1.0 c@1.0.0\nesm b@1.1.0 c@1.0.0";
    // The import hook needs Node 22.15's module.registerHooks; older Node gets require only.
    let probe = std::process::Command::new("node").args(["-p", "typeof require('module').registerHooks"]).output();
    let hooks = probe.is_ok_and(|o| o.stdout.starts_with(b"function"));
    for flag in [None, Some("--no-global-store")] {
        env.ok(&["install"].into_iter().chain(flag).collect::<Vec<_>>());
        let global = flag.is_none();
        assert_eq!(link_of(&env.project(), "uses").contains("v1"), global);
        if global && !hooks {
            let out = env.ok(&["exec", "uses"]);
            assert!(out.contains("cjs b@1.1.0 c@1.0.0"), "{out}");
            continue;
        }
        assert!(env.ok(&["run", "-s", "both"]).contains(want), "{flag:?}");
        let out = env.ok(&["exec", "uses"]) + &env.ok(&["exec", "esm"]);
        assert!(out.contains(want), "{flag:?}: {out}");
    }
    // The user's own NODE_OPTIONS and NODE_PATH stay, first.
    env.ok(&["install"]);
    let mine = env.path("mine");
    let out = env
        .command(&["run", "-s", "env"])
        .env("NODE_OPTIONS", "--no-deprecation")
        .env("NODE_PATH", &mine)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let hoist = env.project().join("node_modules").join(".jpm").join("node_modules");
    let sep = if cfg!(windows) { ';' } else { ':' };
    assert!(text.starts_with("--no-deprecation --require "), "{text}");
    assert!(text.contains(&format!("{}{sep}{}", mine.display(), hoist.display())), "{text}");
}

#[test]
fn the_hoist_never_hides_what_the_root_links() {
    // Node looks in the hoist before the root's node_modules, so a registry `b` there would
    // stand in for the root's workspace `b` in every undeclared import.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "workspaces": ["b"], "dependencies": { "b": "workspace:*", "a": "1.1.0" } }));
    env.write("b/package.json", r#"{ "name": "b", "version": "9.0.0" }"#);
    env.ok(&["install", "--no-global-store"]);
    assert!(env.exists("node_modules/.jpm/node_modules"));
    assert!(!env.exists("node_modules/.jpm/node_modules/b"), "the root's b is the workspace");
}

#[test]
fn builds_in_the_project_for_frameworks_that_need_it() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "next": "1.0.0" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("building packages in the project") && out.contains("next"), "{out}");
    assert_eq!(entries(&env.project()).len(), 2, "next and b, in the project");
    assert!(env.exists("node_modules/.jpm/node_modules/b"), "with the hidden hoist");
    // An explicit setting still wins.
    let out = env.command(&["install"]).env("JPM_GLOBAL_STORE", "1").output().unwrap();
    assert!(out.status.success());
    assert!(link_of(&env.project(), "next").contains("v1"), "{}", link_of(&env.project(), "next"));
}

#[test]
fn finds_the_framework_in_workspaces_and_edits() {
    let r = registry();
    let env = Env::new(&r);
    // In a workspace, not the root.
    env.manifest(json!({ "workspaces": ["w"], "dependencies": { "a": "1.1.0" } }));
    env.write("w/package.json", r#"{ "name": "w", "dependencies": { "next": "1.0.0" } }"#);
    let out = env.ok(&["install"]);
    assert!(out.contains("building packages in the project"), "{out}");
    // Relative on unix, absolute as a junction: either way, into the project's own entries.
    let local = |env: &Env, name: &str| {
        let nm = env.project().join("node_modules");
        nm.join(link_of(&env.project(), name)).starts_with(nm.join(".jpm"))
    };
    assert!(local(&env, "a"), "{}", link_of(&env.project(), "a"));
    // Added and removed: the edited package.json decides, not the one read before the edit.
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "a": "1.1.0" } }));
    env.ok(&["install"]);
    assert!(link_of(&env.project(), "a").contains("v1"), "{}", link_of(&env.project(), "a"));
    let out = env.ok(&["add", "next@1.0.0"]);
    assert!(out.contains("building packages in the project"), "{out}");
    assert!(local(&env, "next"), "{}", link_of(&env.project(), "next"));
    env.ok(&["remove", "next"]);
    assert!(link_of(&env.project(), "a").contains("v1"), "{}", link_of(&env.project(), "a"));
}

#[test]
fn links_while_downloads_are_under_way() {
    let r = registry();
    r.slow_tarballs(300);
    let env = Env::new(&r);
    // Entries, dependency links and bins, each built as its packages arrive.
    env.manifest(json!({ "dependencies": { "a": "1.1.0", "@scope/lib": "1", "cli": "1" } }));
    env.ok(&["install", "--no-global-store"]);
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));
    assert!(env.read("node_modules/@scope/lib/../../b/index.js").contains("b@2.0.0"));
    assert!(env.exists(if cfg!(windows) { "node_modules/.bin/hello.cmd" } else { "node_modules/.bin/hello" }));
    if cfg!(windows) {
        // A shim written before its target arrived would not know to run sh.
        assert!(env.read("node_modules/.bin/hello.cmd").contains("\"sh\""));
    }
    // And again into the global store, from a store that already has every package.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["install"]);
    assert!(env.read("node_modules/a/../b/index.js").contains("b@1.1.0"));
}

#[test]
fn fetches_a_locked_tree_into_a_cold_store_once() {
    let mut pkgs: Vec<common::Pkg> = (0..40).map(|i| pkg(&format!("p{i:02}"), "1.0.0", json!({}))).collect();
    pkgs.push(pkg(
        "native",
        "1.0.0",
        json!({ "optionalDependencies": { "native-mars": "1.0.0", "native-any": "1.0.0" } }),
    ));
    pkgs.push(pkg("native-mars", "1.0.0", json!({ "os": ["mars"] })));
    pkgs.push(pkg("native-any", "1.0.0", json!({})));
    // Where the store keeps p01: its index file.
    let digest =
        common::sha512(&pkgs[1].tarball())["sha512-".len()..].replace('+', "-").replace('/', "_").replace('=', "");
    let p01 = format!("v1/pkg/{}/sha512-{}.idx", &digest[..2], &digest[2..]);
    let r = Registry::start(pkgs);
    let env = Env::new(&r);
    let mut deps: serde_json::Map<String, serde_json::Value> =
        (0..40).map(|i| (format!("p{i:02}"), json!("1.0.0"))).collect();
    deps.insert("native".into(), json!("1.0.0"));
    env.manifest(json!({ "dependencies": deps }));
    env.ok(&["lock"]);
    // native-any's download fails: an optional package, skipped each time.
    r.serve("/native-any/-/native-any-1.0.0.tgz", b"not a tarball".to_vec());
    let asked = || r.hits.lock().unwrap().len();
    let tarballs = |from: usize| -> Vec<String> {
        r.hits.lock().unwrap()[from..]
            .iter()
            .filter(|h| h.contains("/-/") && !h.contains("native-any"))
            .cloned()
            .collect()
    };
    for (n, layout) in ["--global-store", "--no-global-store"].into_iter().enumerate() {
        let store = env.root.join(format!("cold{n}"));
        let install = |from: usize| {
            let _ = std::fs::remove_dir_all(env.project().join("node_modules"));
            let out = env.ok(&["install", layout, "--store", store.to_str().unwrap()]);
            assert!(out.contains("skipped optional native-any@1.0.0"), "{out}");
            assert!(env.read("node_modules/p01/index.js").contains("p01@1.0.0"));
            tarballs(from)
        };
        // From jpm.lock into an empty store: each package this platform installs, once.
        let mut got = install(asked());
        let all = got.len();
        got.sort();
        got.dedup();
        assert_eq!((got.len(), all), (41, 41), "{got:?}");
        assert!(!got.iter().any(|h| h.contains("native-mars")));
        // Warm: nothing.
        assert_eq!(install(asked()), Vec::<String>::new());
        // A store that lost one package fetches that one.
        std::fs::remove_file(store.join(&p01)).unwrap();
        let got = install(asked());
        assert!(got.iter().all(|h| h.starts_with("/p01/")), "{got:?}");
    }
}

#[test]
fn drops_an_optional_package_that_fails_while_linking() {
    let r = registry();
    // native-any's tarball is not what the registry's integrity says: its download fails.
    r.serve("/native-any/-/native-any-1.0.0.tgz", b"not a tarball".to_vec());
    r.slow_tarballs(200);
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "native": "1.0.0", "a": "1.1.0" } }));
    // The project layout settles optional packages as they arrive.
    let out = env.ok(&["install", "--no-global-store"]);
    assert!(out.contains("skipped optional native-any@1.0.0"), "{out}");
    assert!(env.exists("node_modules/native") && env.read("node_modules/a/index.js").contains("a@1.1.0"));
    // Nothing links to what did not arrive: not the entry, not the hidden hoist.
    assert!(!env.exists("node_modules/native/../native-any"));
    assert!(!env.exists("node_modules/.jpm/node_modules/native-any"));
    assert!(!entries(&env.project()).iter().any(|e| e.starts_with("native-any@")));
    // Incomplete, so the next install tries again rather than calling it up to date.
    let again = env.ok(&["install", "--no-global-store"]);
    assert!(!again.contains("up to date"), "{again}");
}

#[test]
fn shows_progress_only_on_a_terminal() {
    let r = registry();
    r.slow_tarballs(300);
    let manifest = json!({ "dependencies": { "a": "1.1.0", "@scope/lib": "1" } });
    // Piped, as here: no progress, however long the install takes.
    let env = Env::new(&r);
    env.manifest(manifest.clone());
    let out = env.command(&["install"]).env_remove("CI").env("TERM", "xterm").output().unwrap();
    assert!(out.status.success());
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!text.contains('\x1b') && text.contains("Installed"), "{text:?}");
    // On a terminal: a pseudo-terminal from util-linux's `script`, where there is one.
    if !cfg!(target_os = "linux") || std::process::Command::new("script").arg("-V").output().is_err() {
        return;
    }
    // `line` runs in a shell on the terminal; what the terminal showed, and whether it succeeded.
    let on_a_terminal = |line: &str, ci: bool| {
        let env = Env::new(&r);
        env.manifest(manifest.clone());
        let mut c = std::process::Command::new("script");
        c.args(["-qec", &line.replace("jpm", env!("CARGO_BIN_EXE_jpm")), "/dev/null"]);
        for (k, v) in env.command(&[]).get_envs() {
            if let Some(v) = v {
                c.env(k, v);
            }
        }
        c.current_dir(env.project()).env_remove("CI").env("TERM", "xterm").env("WT_SESSION", "1");
        if ci {
            c.env("CI", "true");
        }
        let out = c.output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let (ok, text) = on_a_terminal("jpm install", false);
    assert!(ok && text.contains("\rjpm: ") && text.contains("fetched"), "a progress line: {text:?}");
    assert!(text.contains("\x1b]9;4;"), "the terminal's progress report: {text:?}");
    // Both taken off before the summary.
    let summary = text.find("Installed").unwrap();
    assert!(text[..summary].ends_with("\r\x1b[K\x1b]9;4;0\x1b\\"), "{text:?}");
    for (line, ci) in
        [("jpm install", true), ("jpm install --silent", false), ("jpm --json", false), ("jpm --no-progress", false)]
    {
        let (ok, text) = on_a_terminal(line, ci);
        assert!(ok && !text.contains("\x1b]9;4") && !text.contains("\rjpm: "), "{line} ci={ci}: {text:?}");
    }
    // Ctrl+C, once the line is up, takes it and the report off, and still ends jpm.
    r.slow_tarballs(3000);
    let (ok, text) = on_a_terminal("timeout -s INT 0.5 jpm install", false);
    assert!(!ok && text.contains("\rjpm: "), "{text:?}");
    assert!(text.ends_with("\r\x1b[K\x1b]9;4;0\x1b\\"), "{text:?}");
}
