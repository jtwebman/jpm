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
            "#!/usr/bin/env node
console.log(JSON.stringify(process.argv.slice(2)))
",
        ),
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
        ("github:watson/ci-info#v1", "git dependencies are not supported yet: github:watson/ci-info#v1"),
        ("file:../dir", "directory dependencies are not supported yet: file:../dir"),
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
        .filter(|n| !n.starts_with('.'))
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
