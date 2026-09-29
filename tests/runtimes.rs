//! End to end: runtimes as dependencies (`runtime:`, `devEngines.runtime`), from a fake Node
//! release site on the test registry. Each fake `node` is a shell script printing its version,
//! so these run on unix only.
#![cfg(unix)]

mod common;

use common::{Env, Registry, b64, gzip, tar};
use serde_json::{Value, json};

/// This machine as Node names its downloads.
fn platform() -> String {
    let os = if cfg!(target_os = "macos") { "darwin" } else { std::env::consts::OS };
    let cpu = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{cpu}")
}

fn sha256(data: &[u8]) -> Vec<u8> {
    jpm_crypto::hash::digest(jpm_crypto::hash::Alg::Sha256, data).as_ref().to_vec()
}

fn node_archive(version: &str, plat: &str) -> Vec<u8> {
    let script = format!("#!/bin/sh\necho v{version}\n").into_bytes();
    gzip(&tar(&[(format!("node-v{version}-{plat}/bin/node"), 0o755, script)]))
}

/// Node releases under `/dist`: `index.json`, and per version `SHASUMS256.txt` and this
/// platform's archive (a musl one too, whichever libc the machine has).
fn serve_node(r: &Registry, releases: &[(&str, Option<&str>)]) {
    let index: Vec<Value> = releases.iter().map(|(v, lts)| json!({ "version": format!("v{v}"), "lts": lts })).collect();
    r.serve("/dist/index.json", serde_json::to_vec(&index).unwrap());
    for (v, _) in releases {
        let mut sums = String::new();
        for plat in [platform(), format!("{}-musl", platform())] {
            let file = format!("node-v{v}-{plat}.tar.gz");
            let bytes = node_archive(v, &plat);
            let hex: String = sha256(&bytes).iter().map(|b| format!("{b:02x}")).collect();
            sums.push_str(&format!("{hex}  {file}\n"));
            r.serve(&format!("/dist/v{v}/{file}"), bytes);
        }
        sums.push_str(&format!("{}  win-x64/node.exe\n", "ab".repeat(32)));
        r.serve(&format!("/dist/v{v}/SHASUMS256.txt"), sums.into_bytes());
    }
}

fn setup(releases: &[(&str, Option<&str>)]) -> (Registry, Env) {
    let r = Registry::start(Vec::new());
    serve_node(&r, releases);
    let env = Env::new(&r);
    env.write(".npmrc", &format!("node-mirror:release={}/dist/\n", r.url));
    (r, env)
}

/// PATH without any directory that has a `node`: only the runtime jpm links can answer.
fn path_without_node() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(std::env::split_paths(&path).filter(|d| !d.join("node").exists())).unwrap()
}

/// `jpm run <script>` in `dir` with no system node, its output trimmed.
fn run_in(env: &Env, dir: &std::path::Path, script: &str) -> String {
    let out = env.command_in(dir, &["run", "--silent", script]).env("PATH", path_without_node()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(out.status.success(), "run {script} failed: {text}{}", String::from_utf8_lossy(&out.stderr));
    text
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success(), "jpm {args:?} succeeded: {text}");
    text
}

const RELEASES: [(&str, Option<&str>); 4] =
    [("24.1.0", None), ("22.12.0", Some("Jod")), ("22.11.0", Some("Jod")), ("20.18.1", Some("Iron"))];

#[test]
fn installs_the_node_a_range_names() {
    let (_r, env) = setup(&RELEASES);
    env.manifest(json!({ "devDependencies": { "node": "runtime:22" }, "scripts": { "v": "node --version" } }));
    env.ok(&["install"]);
    let lock = env.read("jpm.lock");
    assert!(lock.contains("spec devDependencies node runtime:22\n  dep node runtime:22.12.0\n"), "{lock}");
    assert!(lock.contains("package node@runtime:22.12.0\n  version 22.12.0\n"), "{lock}");
    let variant = format!("  variant {} sha256-", platform());
    assert!(lock.contains(&variant) && lock.contains("variant win32-x64 sha256-"), "{lock}");
    assert!(env.exists("node_modules/.bin/node") && env.exists("node_modules/node"));
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    // The same inputs: a no-op, which never asks the release site.
    let json: Value = serde_json::from_slice(&env.jpm(&["install", "--json"]).stdout).unwrap();
    assert_eq!(json["upToDate"], true);
    // Without node_modules, the lockfile's version is what installs, whatever is newer.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["install", "--frozen-lockfile"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    // `--production` leaves a dev runtime out.
    env.ok(&["install", "--production"]);
    assert!(!env.exists("node_modules/.bin/node"));
}

#[test]
fn a_new_range_makes_the_lockfile_stale() {
    let (_r, env) = setup(&RELEASES);
    env.manifest(json!({ "dependencies": { "node": "runtime:^22.11.0" }, "scripts": { "v": "node --version" } }));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    // A range the locked version still meets keeps it.
    env.manifest(json!({ "dependencies": { "node": "runtime:>=22" }, "scripts": { "v": "node --version" } }));
    assert!(fails(&env, &["install", "--frozen-lockfile"]).contains("out of date"));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    // One it does not moves to the newest that fits; so does `lts` once the range reads so.
    env.manifest(json!({ "dependencies": { "node": "runtime:20" }, "scripts": { "v": "node --version" } }));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v20.18.1");
    env.manifest(json!({ "dependencies": { "node": "runtime:lts" }, "scripts": { "v": "node --version" } }));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    assert!(!env.read("jpm.lock").contains("runtime:20.18.1"));
}

#[test]
fn each_workspace_gets_its_own_node_or_the_roots() {
    let (_r, env) = setup(&RELEASES);
    let script = json!({ "v": "node --version" });
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"], "devDependencies": { "node": "runtime:24" } }));
    let ws = |name: &str, extra: Value| {
        let mut m = json!({ "name": name, "version": "1.0.0", "scripts": script });
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        env.write(&format!("packages/{name}/package.json"), &m.to_string());
    };
    ws("old", json!({ "devDependencies": { "node": "runtime:20" } }));
    // pnpm's own spelling, which `pnpm add -D node@runtime:22` writes.
    ws("jod", json!({ "devEngines": { "runtime": { "name": "node", "version": "22.11.0", "onFail": "download" } } }));
    ws("plain", json!({}));
    env.ok(&["install"]);
    let dir = |name: &str| env.project().join("packages").join(name);
    assert_eq!(run_in(&env, &dir("old"), "v"), "v20.18.1");
    assert_eq!(run_in(&env, &dir("jod"), "v"), "v22.11.0");
    assert_eq!(run_in(&env, &dir("plain"), "v"), "v24.1.0", "a workspace without one uses the root's");
    let lock = env.read("jpm.lock");
    for v in ["24.1.0", "22.11.0", "20.18.1"] {
        assert!(lock.contains(&format!("package node@runtime:{v}\n")), "{lock}");
    }
    assert!(env.ok(&["install"]).contains("up to date"));
}

#[test]
fn refuses_a_build_whose_bytes_changed() {
    let (r, env) = setup(&RELEASES);
    env.manifest(json!({ "devDependencies": { "node": "runtime:20" } }));
    env.ok(&["lock"]);
    // The site now serves other bytes under the locked name: the store's first download fails.
    r.serve(&format!("/dist/v20.18.1/node-v20.18.1-{}.tar.gz", platform()), node_archive("6.6.6", &platform()));
    r.serve(&format!("/dist/v20.18.1/node-v20.18.1-{}-musl.tar.gz", platform()), node_archive("6.6.6", &platform()));
    let err = fails(&env, &["install"]);
    assert!(err.contains("EINTEGRITY") || err.contains("Integrity check failed"), "{err}");
    assert!(!env.exists("node_modules/.bin/node"));
}

#[test]
fn prune_keeps_a_runtime_in_use_and_drops_it_after() {
    let (_r, env) = setup(&RELEASES);
    env.manifest(json!({ "devDependencies": { "node": "runtime:20" } }));
    env.ok(&["install"]);
    let stored = |v: &str| {
        let text = env.read("jpm.lock");
        let at = text.find(&format!("package node@runtime:{v}")).unwrap();
        let line = text[at..].lines().find(|l| l.starts_with(&format!("  variant {} ", platform()))).unwrap();
        let sri = line.split(' ').nth(4).unwrap().strip_prefix("sha256-").unwrap().to_string();
        let raw: Vec<u8> = common_b64_decode(&sri);
        let safe = b64(&raw).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
        env.store().join("v1/pkg").join(&safe[..2]).join(format!("sha256-{}", &safe[2..]))
    };
    let dir = stored("20.18.1");
    assert!(dir.join("bin/node").is_file(), "{}", dir.display());
    env.ok(&["prune"]);
    assert!(dir.is_dir(), "a runtime the project uses stays");
    env.manifest(json!({ "devDependencies": { "node": "runtime:22" } }));
    env.ok(&["install"]);
    env.ok(&["prune"]);
    assert!(!dir.exists(), "one no project uses goes");
    assert!(stored("22.12.0").is_dir());
}

fn common_b64_decode(text: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.bytes().take_while(|c| *c != b'=') {
        acc = (acc << 6) | T.iter().position(|t| *t == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[test]
fn dev_engines_downloads_or_only_checks() {
    let (_r, env) = setup(&RELEASES);
    let engines = |on_fail: &str| {
        json!({ "devEngines": { "runtime": [
            { "name": "node", "version": "^24", "onFail": on_fail },
            { "name": "deno", "version": "^2", "onFail": "ignore" }
        ] }, "scripts": { "v": "node --version" } })
    };
    // Only a check: the system's node (JPM_NODE_VERSION stands in for it) is outside the range.
    env.manifest(engines("warn"));
    let out = env.ok(&["install"]);
    assert!(out.contains("package.json devEngines.runtime wants node ^24, and the node on PATH is 22.0.0"), "{out}");
    assert!(!out.contains("deno"), "{out}");
    assert!(!env.exists("node_modules/.bin/node") && !env.read("jpm.lock").contains("runtime:"));
    env.manifest(engines("error"));
    assert!(env.ok(&["install"]).contains("wants node ^24"), "error is a warning too");
    env.manifest(engines("download"));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "v"), "v24.1.0");
    assert!(env.read("jpm.lock").contains("spec devDependencies node runtime:^24"));
}

#[test]
fn add_writes_the_runtime_where_pnpm_does() {
    let (_r, env) = setup(&RELEASES);
    env.manifest(json!({ "name": "app" }));
    env.ok(&["add", "--dev", "node@runtime:22"]);
    let m: Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert_eq!(m["devEngines"]["runtime"], json!({ "name": "node", "version": "22", "onFail": "download" }));
    assert!(m.get("devDependencies").is_none(), "{m}");
    assert!(env.exists("node_modules/.bin/node"));
    // No range: the newest, with a caret. A second runtime makes the field a list.
    env.ok(&["add", "--dev", "node@runtime:"]);
    let m: Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert_eq!(m["devEngines"]["runtime"]["version"], "^24.1.0");
    env.ok(&["add", "node@runtime:20", "--exact"]);
    let m: Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert_eq!(m["engines"]["runtime"], json!({ "name": "node", "version": "20.18.1", "onFail": "download" }));
    assert!(m.get("devEngines").is_none(), "one place per name: {m}");
    env.ok(&["remove", "node"]);
    let m: Value = serde_json::from_str(&env.read("package.json")).unwrap();
    assert!(m.get("engines").is_none(), "{m}");
    assert!(!env.exists("node_modules/.bin/node"));
    assert!(fails(&env, &["add", "npm@runtime:10"]).contains("node, bun and deno"));
}

#[test]
fn the_mirror_can_come_from_the_environment() {
    let (r, env) = setup(&[("22.12.0", Some("Jod"))]);
    env.write(".npmrc", "");
    env.manifest(json!({ "devDependencies": { "node": "runtime:22" }, "scripts": { "v": "node --version" } }));
    let out = env.command(&["install"]).env("NODEJS_ORG_MIRROR", format!("{}/dist", r.url)).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(run_in(&env, &env.project(), "v"), "v22.12.0");
    // No network needed once locked and stored: offline works.
    std::fs::remove_dir_all(env.project().join("node_modules")).unwrap();
    env.ok(&["install", "--offline"]);
}

/// `bun` and `deno` on the registry, each version listing a platform package per libc for this
/// machine (and a `-baseline` build jpm skips), whose binary is a script printing its version.
fn bun_and_deno() -> Vec<common::Pkg> {
    let (os, cpu) = platform().split_once('-').map(|(o, c)| (o.to_string(), c.to_string())).unwrap();
    let mut out = Vec::new();
    for (name, scope, versions, bin) in
        [("bun", "@oven/bun", ["1.2.0", "1.3.0"], "bin/bun"), ("deno", "@deno/deno", ["2.3.0", "2.4.0"], "deno")]
    {
        for v in versions {
            let mut optional = serde_json::Map::new();
            for libc in ["glibc", "musl"] {
                for suffix in ["", "-baseline"] {
                    let platform = format!("{scope}-{os}-{cpu}-{libc}{suffix}");
                    optional.insert(platform.clone(), json!(v));
                    let script = format!("#!/bin/sh\necho {name} {v}{suffix}\n");
                    let manifest = json!({ "os": [os], "cpu": [cpu], "libc": [libc] });
                    out.push(common::pkg(&platform, v, manifest).file(bin, 0o755, &script));
                }
            }
            out.push(common::pkg(name, v, json!({ "optionalDependencies": optional, "bin": { name: "cli.js" } })));
        }
    }
    out
}

#[test]
fn installs_bun_and_deno_from_their_platform_packages() {
    let r = Registry::start(bun_and_deno());
    let env = Env::new(&r);
    env.manifest(json!({
        "devDependencies": { "bun": "runtime:~1.2.0" },
        "devEngines": { "runtime": { "name": "deno", "version": "^2", "onFail": "download" } },
        "scripts": { "b": "bun", "d": "deno" }
    }));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "b"), "bun 1.2.0");
    assert_eq!(run_in(&env, &env.project(), "d"), "deno 2.4.0");
    let lock = env.read("jpm.lock");
    let variant = format!("  variant {} sha512-", platform());
    assert!(lock.contains("package bun@runtime:1.2.0\n") && lock.contains("package deno@runtime:2.4.0\n"), "{lock}");
    assert!(lock.contains(&variant) && lock.contains(&format!("@oven/bun-{}-glibc\n", platform())), "{lock}");
    assert!(lock.contains("-musl sha512-") && !lock.contains("baseline"), "{lock}");
    assert!(env.ok(&["install"]).contains("up to date"));
    env.manifest(json!({ "devDependencies": { "bun": "runtime:1" }, "scripts": { "b": "bun" } }));
    env.ok(&["install"]);
    assert_eq!(run_in(&env, &env.project(), "b"), "bun 1.2.0", "the locked version still fits");
    assert!(!env.exists("node_modules/.bin/deno"));
}
