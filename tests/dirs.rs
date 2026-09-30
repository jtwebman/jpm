//! End to end: directory dependencies, `link:` and `file:`.

mod common;

use std::path::{Component, Path, PathBuf};

use common::{Env, Registry, pkg};
use serde_json::json;

fn registry() -> Registry {
    Registry::start(vec![
        pkg("a", "1.0.0", json!({})),
        pkg("b", "1.0.0", json!({})),
        pkg("b", "2.0.0", json!({})),
        pkg("host", "1.0.0", json!({})),
    ])
}

/// `..` taken off by the letters, as a link's target is followed.
fn clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// The link `name` in `dir`'s node_modules leads to `to`: relative on unix, so the project can
/// move, and absolute as a junction on Windows.
fn leads(dir: &Path, name: &str, to: &Path) {
    let nm = dir.join("node_modules");
    let link = std::fs::read_link(nm.join(name)).unwrap();
    assert!(cfg!(windows) || link.is_relative(), "{}", link.display());
    assert_eq!(clean(&nm.join(&link)), clean(to), "{name} in {}", dir.display());
}

fn write_at(dir: &Path, rel: &str, text: &str) {
    let file = dir.join(rel);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, text).unwrap();
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn installs_a_file_directory_as_a_workspace() {
    let r = registry();
    let env = Env::new(&r);
    // Named `lib` by the dependency, whatever its own package.json says.
    env.write(
        "libs/lib/package.json",
        r#"{ "name": "own-name", "version": "2.0.0", "bin": { "lib-cli": "cli.js" },
             "dependencies": { "b": "1.0.0", "inner": "file:../inner" } }"#,
    );
    env.write("libs/lib/cli.js", "#!/bin/sh\necho lib\n");
    env.write("libs/inner/package.json", r#"{ "name": "inner", "dependencies": { "host": "1.0.0" } }"#);
    env.manifest(json!({ "name": "app", "dependencies": { "lib": "file:./libs/lib" } }));
    env.ok(&["install"]);
    leads(&env.project(), "lib", &env.project().join("libs/lib"));
    assert!(env.exists("node_modules/.bin/lib-cli"));
    // Its dependencies install in its own node_modules, a nested file: directory's too.
    assert!(env.read("libs/lib/node_modules/b/index.js").contains("b@1.0.0"));
    leads(&env.project().join("libs/lib"), "inner", &env.project().join("libs/inner"));
    assert!(env.read("libs/inner/node_modules/host/index.js").contains("host@1.0.0"));
    let lock = env.lock();
    assert_eq!(lock["root"]["dependencies"]["lib"], "link:libs/lib");
    assert_eq!(lock["workspaces"]["libs/lib"]["name"], "lib");
    assert_eq!(lock["workspaces"]["libs/lib"]["version"], "2.0.0");
    assert_eq!(lock["workspaces"]["libs/lib"]["dependencies"]["inner"], "link:libs/inner");
    assert!(env.ok(&["install"]).contains("up to date"));
    env.ok(&["ci"]);
    // Its package.json is read on every install: a change there makes the lockfile stale.
    env.write(
        "libs/lib/package.json",
        r#"{ "name": "own-name", "version": "2.0.0", "dependencies": { "b": "2.0.0", "inner": "file:../inner" } }"#,
    );
    let out = env.jpm(&["ci"]);
    assert!(!out.status.success() && stderr(&out).contains("out of date"), "{}", stderr(&out));
    env.ok(&["install"]);
    assert!(env.read("libs/lib/node_modules/b/index.js").contains("b@2.0.0"));
    assert!(!env.exists("node_modules/.bin/lib-cli"), "its bin went with it");
    // jpm.lock alone installs it again.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    std::fs::remove_dir_all(env.project().join("libs/lib/node_modules")).unwrap();
    env.ok(&["ci"]);
    assert!(env.read("node_modules/lib/node_modules/b/index.js").contains("b@2.0.0"));
    // A file: directory with no package.json is an error that names it.
    env.manifest(json!({ "dependencies": { "nope": "file:libs/nope" } }));
    let out = env.jpm(&["install"]);
    assert!(stderr(&out).contains("nope@file:libs/nope"), "{}", stderr(&out));
}

#[test]
fn installs_a_yarn_portal_as_a_file_directory() {
    // storybook's scripts workspace takes its local eslint rules by `portal:`.
    let r = registry();
    let env = Env::new(&r);
    env.write("rules/package.json", r#"{ "name": "rules", "version": "1.0.0", "dependencies": { "b": "1.0.0" } }"#);
    env.manifest(json!({ "name": "app", "dependencies": { "rules": "portal:./rules" } }));
    env.ok(&["install"]);
    leads(&env.project(), "rules", &env.project().join("rules"));
    assert!(env.read("rules/node_modules/b/index.js").contains("b@1.0.0"));
    assert_eq!(env.lock()["root"]["dependencies"]["rules"], "link:rules");
}

#[test]
fn links_a_workspace_protocol_path() {
    // drizzle's integration tests take a workspace's build output by `workspace:../x/dist`.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app", "workspaces": ["tests", "typebox"] }));
    env.write("typebox/package.json", r#"{ "name": "typebox", "version": "1.0.0" }"#);
    env.write("typebox/dist/package.json", r#"{ "name": "typebox", "version": "1.0.0", "main": "index.js" }"#);
    env.write(
        "tests/package.json",
        r#"{ "name": "tests", "dependencies": { "typebox": "workspace:../typebox/dist" } }"#,
    );
    env.ok(&["install"]);
    leads(&env.project().join("tests"), "typebox", &env.project().join("typebox/dist"));
    assert!(env.ok(&["install"]).contains("up to date"));
    env.ok(&["ci"]);
}

#[test]
fn takes_names_the_registry_would_not() {
    // babel links its scripts' helpers as `$repo-utils`; an alias's own name is the project's
    // to pick. Only what the directory, the lockfile or Windows cannot hold is refused.
    let r = registry();
    r.publish(pkg("b", "2.0.0-alpha1a", json!({})));
    let env = Env::new(&r);
    env.write("scripts/repo-utils/package.json", r#"{ "name": "$repo-utils", "private": true }"#);
    env.manifest(
        json!({ "name": "app", "dependencies": { "$repo-utils": "link:./scripts/repo-utils", "my$b": "npm:b@1.0.0", "💩": "npm:b@1.0.0", "💩pre": "npm:b@2.0.0-alpha1a" } }),
    );
    env.ok(&["install"]);
    leads(&env.project(), "$repo-utils", &env.project().join("scripts/repo-utils"));
    assert!(env.read("node_modules/my$b/index.js").contains("b@1.0.0"));
    assert!(env.read("node_modules/💩/index.js").contains("b@1.0.0"));
    assert!(env.read("node_modules/💩pre/index.js").contains("b@2.0.0-alpha1a"));
    assert!(env.read("jpm.lock").contains("package 💩pre@npm:b@2.0.0-alpha1a\n"));
    assert!(env.ok(&["install"]).contains("up to date"));
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
    assert!(env.read("node_modules/my$b/index.js").contains("b@1.0.0"));
    env.manifest(json!({ "dependencies": { "a:b": "npm:b@1.0.0" } }));
    assert!(stderr(&env.jpm(&["install"])).contains("Invalid package name \"a:b\""));
}

#[test]
fn links_a_directory_outside_the_project_without_writing_there() {
    let r = registry();
    let env = Env::new(&r);
    let sibling = env.root.join("sibling");
    write_at(
        &sibling,
        "package.json",
        r#"{ "name": "sib", "version": "1.2.3", "bin": "cli.js", "dependencies": { "b": "1" } }"#,
    );
    write_at(&sibling, "cli.js", "#!/bin/sh\necho sib\n");
    env.manifest(json!({ "dependencies": { "sib": "file:../sibling" } }));
    let out = env.ok(&["install"]);
    assert!(out.contains("file:../sibling is outside the project"), "{out}");
    leads(&env.project(), "sib", &sibling);
    assert!(env.exists("node_modules/.bin/sib"));
    assert!(!sibling.join("node_modules").exists(), "nothing is written outside the project");
    let lock = env.lock();
    assert_eq!(lock["root"]["dependencies"]["sib"], "link:../sibling");
    let entry = &lock["packages"]["sib@link:../sibling"];
    assert_eq!(entry["version"], "1.2.3");
    assert!(entry.get("dependencies").is_none(), "{entry}");
    assert!(env.read("jpm.lock").contains("package sib@link:../sibling\n  version 1.2.3\n  bin sib cli.js\n"));
    assert!(env.ok(&["install"]).contains("up to date"));
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["ci"]);
    leads(&env.project(), "sib", &sibling);
    assert!(!sibling.join("node_modules").exists());
}

#[test]
fn links_link_directories_as_they_are() {
    let r = registry();
    let env = Env::new(&r);
    // link: installs nothing for the directory, inside the project or out.
    env.write(
        "tools/t/package.json",
        r#"{ "name": "t", "version": "1.0.0", "bin": { "tool": "t.js" }, "dependencies": { "b": "1" } }"#,
    );
    env.write("tools/t/t.js", "#!/bin/sh\necho tool\n");
    env.write("packages/w/package.json", r#"{ "name": "w", "dependencies": { "t2": "link:../../tools/t" } }"#);
    env.manifest(json!({
        "workspaces": ["packages/*"],
        "devDependencies": { "t": "link:tools/t", "gone": "link:./missing" }
    }));
    env.ok(&["install"]);
    leads(&env.project(), "t", &env.project().join("tools/t"));
    leads(&env.project().join("packages/w"), "t2", &env.project().join("tools/t"));
    assert!(env.exists("node_modules/.bin/tool") && env.exists("packages/w/node_modules/.bin/tool"));
    assert!(!env.exists("tools/t/node_modules"), "its dependencies are its own");
    // A missing directory is linked all the same, as pnpm does.
    leads(&env.project(), "gone", &env.project().join("missing"));
    let lock = env.lock();
    assert_eq!(lock["packages"]["t@link:tools/t"]["version"], "1.0.0");
    assert_eq!(lock["packages"]["t2@link:tools/t"]["bin"]["tool"], "t.js");
    assert_eq!(lock["packages"]["gone@link:missing"]["version"], "0.0.0");
    env.ok(&["install", "--frozen-lockfile"]);
    // A lockfile edit cannot point a name at another directory than package.json says.
    let text = env.read("jpm.lock");
    env.write(
        "jpm.lock",
        &text
            .replace("dep t link:tools/t", "dep t link:missing")
            .replace("package t@link:tools/t", "package t@link:missing"),
    );
    let out = env.jpm(&["ci"]);
    assert!(stderr(&out).contains("which its specs do not name"), "{}", stderr(&out));
    env.write("jpm.lock", &text);
    // A registry package may not depend on a path.
    r.publish(pkg("bad", "1.0.0", json!({ "dependencies": { "x": "link:../x" } })));
    env.manifest(json!({ "dependencies": { "bad": "1.0.0" } }));
    let out = env.jpm(&["install"]);
    assert!(stderr(&out).contains("only the root and workspaces may depend on a path"), "{}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn never_installs_through_a_symlink_out_of_the_project() {
    let r = registry();
    let env = Env::new(&r);
    // Inside by its path, outside by where it leads: its node_modules would be written there.
    let outside = env.root.join("outside");
    write_at(&outside, "x/package.json", r#"{ "name": "x", "dependencies": { "b": "1" } }"#);
    std::os::unix::fs::symlink(&outside, env.project().join("libs")).unwrap();
    env.manifest(json!({ "dependencies": { "x": "file:libs/x" } }));
    let out = env.jpm(&["install"]);
    assert!(!out.status.success() && stderr(&out).contains("leads outside the project"), "{}", stderr(&out));
    assert!(!outside.join("x/node_modules").exists());
}

#[test]
fn adds_a_directory_by_its_path() {
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "app" }));
    env.write("libs/x/package.json", r#"{ "name": "x-lib", "version": "1.0.0" }"#);
    env.ok(&["add", "./libs/x"]);
    env.ok(&["add", "y@link:libs/x"]);
    let text = env.read("package.json");
    assert!(text.contains(r#""x-lib": "file:libs/x""#) && text.contains(r#""y": "link:libs/x""#), "{text}");
    leads(&env.project(), "x-lib", &env.project().join("libs/x"));
    leads(&env.project(), "y", &env.project().join("libs/x"));
}

#[test]
fn installs_file_directories_that_share_a_name() {
    let r = registry();
    let env = Env::new(&r);
    // SvelteKit's test apps: each has a `server-side-dep` directory of its own, one name.
    env.manifest(json!({ "name": "root", "workspaces": ["apps/*"] }));
    for (app, b) in [("one", "1.0.0"), ("two", "2.0.0")] {
        env.write(
            &format!("apps/{app}/package.json"),
            &format!(r#"{{ "name": "{app}", "dependencies": {{ "dep": "file:dep" }} }}"#),
        );
        env.write(
            &format!("apps/{app}/dep/package.json"),
            &format!(r#"{{ "name": "dep", "version": "1.0.0", "dependencies": {{ "b": "{b}" }} }}"#),
        );
    }
    env.ok(&["install"]);
    // Each app links its own directory, and each directory installs its own dependencies.
    for (app, b) in [("one", "b@1.0.0"), ("two", "b@2.0.0")] {
        let dir = env.project().join("apps").join(app);
        leads(&dir, "dep", &dir.join("dep"));
        assert!(env.read(&format!("apps/{app}/dep/node_modules/b/index.js")).contains(b), "{app}");
    }
    let lock = env.lock();
    assert_eq!(lock["workspaces"]["apps/one/dep"]["name"], "dep");
    assert_eq!(lock["workspaces"]["apps/two/dep"]["name"], "dep");
    // The lockfile it wrote reads back: up to date, and enough for a frozen install.
    assert!(env.ok(&["install"]).contains("up to date"));
    env.ok(&["ci"]);
}

#[test]
fn a_lockfile_cannot_swap_directories_that_share_a_name() {
    let r = registry();
    let env = Env::new(&r);
    // Two `file:` directories named `dep`, and a workspace named `dep` the root takes by name.
    env.manifest(json!({ "name": "root", "workspaces": ["apps/*"], "dependencies": { "dep": "workspace:*" } }));
    env.write("apps/three/package.json", r#"{ "name": "dep", "version": "1.0.0" }"#);
    for app in ["one", "two"] {
        env.write(
            &format!("apps/{app}/package.json"),
            &format!(r#"{{ "name": "{app}", "dependencies": {{ "dep": "file:dep" }} }}"#),
        );
        env.write(&format!("apps/{app}/dep/package.json"), r#"{ "name": "dep", "version": "1.0.0" }"#);
    }
    env.ok(&["install"]);
    leads(&env.project(), "dep", &env.project().join("apps/three"));
    let lock = env.read("jpm.lock");
    // Each edit points a name at another directory named alike; none reads.
    for (from, to) in [
        ("dep dep link:apps/one/dep", "dep dep link:apps/two/dep"),
        ("dep dep link:apps/three", "dep dep link:apps/one/dep"),
    ] {
        let edited = lock.replacen(from, to, 1);
        assert_ne!(edited, lock, "{from}");
        env.write("jpm.lock", &edited);
        let out = env.jpm(&["ci"]);
        assert!(
            !out.status.success() && stderr(&out).contains("which its specs do not name"),
            "{to}: {}",
            stderr(&out)
        );
    }
    env.write("jpm.lock", &lock);
    env.ok(&["ci"]);
}

#[test]
fn a_tree_with_a_directory_and_an_alias_installs_once() {
    // A `file:` directory inside the project is read on every install, so the no-op is the
    // linker's: nuxt's `@nuxt/cli: npm:@nuxt/cli-nightly@…` beside its fixtures' directories
    // was linked again every time, and every entry with a bin rebuilt on Windows.
    let r = Registry::start(vec![
        pkg("tool", "1.0.0", json!({ "bin": { "tool": "cli.js" } })).file("cli.js", 0o755, "#!/usr/bin/env node\n"),
        pkg("user", "1.0.0", json!({ "dependencies": { "tool": "1.0.0" } })),
    ]);
    let env = Env::new(&r);
    // Entries in the project, which a relink checks one by one.
    env.write(
        ".npmrc",
        "global-store=false
",
    );
    env.write("fixture/package.json", r#"{ "name": "fixture", "version": "1.0.0" }"#);
    env.manifest(json!({ "dependencies": { "cli": "npm:user@1.0.0", "fixture": "file:fixture" } }));
    env.ok(&["install"]);
    assert!(env.ok(&["install"]).contains("up to date"));
    // Relinked, with every entry already right: none is rebuilt.
    std::fs::remove_dir_all(env.path("node_modules/cli")).ok();
    let _ = std::fs::remove_file(env.path("node_modules/cli"));
    let out = env.ok(&["install"]);
    assert!(!out.contains("repaired") && !out.contains("up to date"), "{out}");
    assert!(env.ok(&["install"]).contains("up to date"));
}

/// `host` depends on itself, on a directory it ships (which depends on another it ships, and on
/// itself), and on one its publish left out.
fn inner_registry() -> Registry {
    Registry::start(vec![
        pkg("b", "1.0.0", json!({})),
        pkg("b", "2.0.0", json!({})),
        pkg(
            "host",
            "1.0.0",
            json!({ "dependencies": { "host": "link:.", "local": "file:./local", "gone": "link:packages/f", "b": "1.0.0" } }),
        )
        .file(
            "local/package.json",
            0o644,
            r#"{ "name": "@x/local", "version": "1.2.0", "bin": { "local-cli": "cli.js" },
                 "dependencies": { "b": "2.0.0", "other": "file:../other", "local": "link:." } }"#,
        )
        .file("local/cli.js", 0o755, "#!/usr/bin/env node\n")
        .file("other/package.json", 0o644, r#"{ "name": "other", "version": "0.1.0" }"#),
    ])
}

#[test]
fn a_registry_package_links_directories_inside_itself() {
    let r = inner_registry();
    for flags in [&["install"][..], &["install", "--no-global-store"]] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "host": "1.0.0" } }));
        let out = env.ok(flags);
        assert!(
            out.contains("host@1.0.0 depends on gone@link:packages/f, which is not in its tarball; left out"),
            "{out}"
        );
        assert!(!env.exists("node_modules/host/../gone"));
        // The directory it ships is a package of its own beside it: that subtree's files, and
        // its own dependencies, not the host's.
        assert!(env.read("node_modules/host/../local/package.json").contains("\"@x/local\""));
        assert!(env.exists("node_modules/host/../local/cli.js") && !env.exists("node_modules/host/../local/local"));
        assert!(env.exists("node_modules/host/local/package.json"), "the host keeps its files");
        assert!(env.read("node_modules/host/../b/package.json").contains("\"1.0.0\""));
        assert!(env.read("node_modules/host/../local/../b/package.json").contains("\"2.0.0\""));
        assert!(env.read("node_modules/host/../local/../other/package.json").contains("\"other\""));
        assert!(
            env.exists("node_modules/host/../.bin/local-cli") || env.exists("node_modules/host/../.bin/local-cli.cmd")
        );
        let lock = env.lock();
        let local = &lock["packages"]["local@path:host@1.0.0/local"];
        assert_eq!(local["version"], "1.2.0");
        assert_eq!(local["integrity"], lock["packages"]["host@1.0.0"]["integrity"]);
        assert_eq!(local["dependencies"]["other"], "path:host@1.0.0/other");
        assert_eq!(lock["packages"]["host@1.0.0"]["dependencies"]["local"], "path:host@1.0.0/local");
        assert!(lock["packages"]["host@1.0.0"]["dependencies"].get("host").is_none(), "no edge to itself");
        assert!(local["dependencies"].get("local").is_none());
        // The lockfile installs the same tree again, and is written back byte for byte.
        let text = env.read("jpm.lock");
        std::fs::remove_dir_all(env.path("node_modules")).unwrap();
        env.ok(&[&["ci"][..], &flags[1..]].concat());
        assert!(env.read("node_modules/host/../local/../b/package.json").contains("\"2.0.0\""));
        env.ok(flags);
        assert_eq!(env.read("jpm.lock"), text);
        // An edit cannot link a directory from another package's tarball, nor from the project.
        let refused = |edited: String, why: &str| {
            env.write("jpm.lock", &edited);
            let out = env.jpm(&["install", "--frozen-lockfile"]);
            assert!(!out.status.success() && stderr(&out).contains(why), "{}\n{edited}", stderr(&out));
        };
        refused(text.replace("path:host@1.0.0/local", "path:b@1.0.0/local"), "only inside its own tarball");
        refused(
            text.replace("  dep host 1.0.0\n", "  dep host 1.0.0\n  dep local path:host@1.0.0/local\n").replace(
                "  spec dependencies host 1.0.0\n",
                "  spec dependencies host 1.0.0\n  spec dependencies local 1\n",
            ),
            "only the package that ships it links it",
        );
        refused(
            text.replace("path:host@1.0.0/local", "path:host@1.0.0/../local"),
            "not a directory inside a registry package",
        );
        env.write("jpm.lock", &text);
        env.ok(&["install", "--frozen-lockfile"]);
    }
}

#[test]
fn a_registry_package_path_out_of_itself_is_refused() {
    let paths = [
        "link:../x",
        "file:../../x",
        "file:sub/../../x",
        "../x",
        "file:/etc/x",
        "/etc/x",
        "file:~/x",
        "file:C:/x",
        r"C:\x",
        r"link:\\host\share",
        "file:%2e%2e/x",
        "link:sub%2fx",
    ];
    let r = Registry::start(
        paths
            .iter()
            .enumerate()
            .map(|(i, p)| pkg(&format!("bad{i}"), "1.0.0", json!({ "dependencies": { "x": p } })))
            .collect(),
    );
    let env = Env::new(&r);
    for (i, path) in paths.iter().enumerate() {
        env.manifest(json!({ "dependencies": { format!("bad{i}"): "1.0.0" } }));
        let out = env.jpm(&["install"]);
        let want = format!("{path} is not a relative path inside the package");
        assert!(!out.status.success() && stderr(&out).contains(&want), "{path}: {}", stderr(&out));
    }
}
