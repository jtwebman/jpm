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
