//! Install scripts. A dependency's `preinstall`, `install` and `postinstall` run only when
//! package.json trusts its name and jpm.lock approves its version (`jpm approve`), in a copy of
//! the package with npm credentials taken out of the environment. The project's own lifecycle
//! scripts run as npm runs them, once the tree is linked.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::graph::Resolution;
use crate::json::Value;
use crate::project::RootManifest;
use crate::{run, ui};

const INSTALL: [&str; 3] = ["preinstall", "install", "postinstall"];
const LIFECYCLE: [&str; 6] = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"];

/// The names package.json trusts with install scripts: bun's `trustedDependencies`, and pnpm's
/// `pnpm.onlyBuiltDependencies`.
pub fn trusted(m: &RootManifest) -> HashSet<String> {
    let names = |v: Option<&Value>| {
        v.and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let mut out: HashSet<String> = names(m.doc.get("trustedDependencies")).into_iter().collect();
    out.extend(names(m.doc.get("pnpm").and_then(|p| p.get("onlyBuiltDependencies"))));
    out
}

/// The packages whose scripts run: approved in jpm.lock and trusted by name.
pub fn chosen(res: &Resolution, trusted: &HashSet<String>) -> HashSet<String> {
    res.packages
        .iter()
        .filter(|(_, p)| p.build && p.local.is_none() && trusted.contains(&p.name))
        .map(|(id, _)| id.clone())
        .collect()
}

/// Packages with install scripts that do not run, as `name@version`, for the install to say so.
pub fn skipped(res: &Resolution, chosen: &HashSet<String>, installed: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out: Vec<String> = res
        .packages
        .iter()
        .filter(|(id, p)| p.scripts && !chosen.contains(*id) && installed(id))
        .map(|(_, p)| format!("{}@{}", p.name, p.version))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Run the chosen packages' install scripts, each package's dependencies first, in its entry
/// under `node_modules/.jpm` (`keys` names them). A package whose scripts ran is marked, so a
/// later install does not run them again. The number that ran.
pub fn run_packages(dir: &Path, res: &Resolution, keys: &HashMap<String, String>) -> Result<usize> {
    let entries = dir.join("node_modules").join(".jpm");
    let mut ran = 0;
    'packages: for id in order(res, keys) {
        let (p, root) = (&res.packages[id], entries.join(&keys[id]));
        let marker = root.join(".built");
        // Not installed (an optional package the store lacked), or built already.
        if !root.is_dir() || marker.exists() {
            continue;
        }
        let pkg_dir = root.join("node_modules").join(&p.name);
        let file = pkg_dir.join("package.json");
        let scripts = read_scripts(&file);
        let mut events: Vec<(&str, String)> =
            INSTALL.iter().filter_map(|e| scripts.get(*e).map(|line| (*e, line.clone()))).collect();
        // npm's default for a native addon with no script of its own.
        if !events.iter().any(|(e, _)| *e != "postinstall") && pkg_dir.join("binding.gyp").is_file() {
            let at = events.iter().position(|(e, _)| *e == "postinstall").unwrap_or(events.len());
            events.insert(at, ("install", "node-gyp rebuild".into()));
        }
        for (event, line) in &events {
            let mut command = run::shell(line, &pkg_dir, &run::bin_dirs(&pkg_dir));
            run::script_env(&mut command, &file, event, line, &p.name, &p.version);
            without_credentials(&mut command);
            // Output goes to a log beside the package: shown only when the script fails.
            let log = root.join(".build.log");
            let file = fs::File::create(&log).map_err(|e| Error::io(&e, format!("cannot write {}", log.display())))?;
            let err = file.try_clone().map_err(|e| Error::io(&e, "cannot share the build log"))?;
            command.stdin(std::process::Stdio::null()).stdout(file).stderr(err);
            let status = command.status().map_err(|e| Error::io(&e, "cannot start the shell"))?;
            if status.success() {
                continue;
            }
            let text = fs::read_to_string(&log).unwrap_or_default();
            let tail: Vec<&str> = text.lines().rev().take(40).collect();
            let tail: String = tail.into_iter().rev().map(|l| format!("\n  {l}")).collect();
            let why = format!("{}@{} {event} failed ({status}){tail}", p.name, p.version);
            if p.optional {
                ui::warn(&format!("skipped optional {why}"));
                continue 'packages;
            }
            return Err(Error::new("EBUILD", why));
        }
        fs::write(&marker, "").map_err(|e| Error::io(&e, format!("cannot write {}", marker.display())))?;
        ui::info(&format!("built {}@{}", p.name, p.version));
        ran += 1;
    }
    Ok(ran)
}

/// The project's lifecycle scripts (`preinstall` to `postprepare`), the root first, then each
/// workspace, each in its own directory. Their output is shown: it is the project's own code.
pub fn run_lifecycle(tops: &[(&Path, &RootManifest)]) -> Result<()> {
    for (dir, m) in tops {
        let scripts = m.doc.get("scripts").and_then(Value::as_object);
        for event in LIFECYCLE {
            let Some(line) = scripts.and_then(|s| s.get(event)).and_then(Value::as_str) else { continue };
            let (name, version) = (m.name.as_deref().unwrap_or(""), m.version.as_deref().unwrap_or(""));
            ui::info(&format!("> {event}: {line}"));
            let mut command = run::shell(line, dir, &run::bin_dirs(dir));
            run::script_env(&mut command, &dir.join("package.json"), event, line, name, version);
            let code = run::wait(&mut command)?;
            if code != 0 {
                return Err(Error::new("ESCRIPT", format!("{event} in {} exited with code {code}", dir.display())));
            }
        }
    }
    Ok(())
}

/// The chosen packages, each after the chosen packages it reaches: a script may use what a
/// dependency's built.
fn order<'a>(res: &'a Resolution, keys: &'a HashMap<String, String>) -> Vec<&'a String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut ids: Vec<&String> = keys.keys().collect();
    ids.sort();
    for id in ids {
        visit(res, keys, id, &mut seen, &mut out);
    }
    out
}

fn visit<'a>(
    res: &'a Resolution,
    keys: &'a HashMap<String, String>,
    id: &'a String,
    seen: &mut HashSet<&'a String>,
    out: &mut Vec<&'a String>,
) {
    let Some((id, p)) = res.packages.get_key_value(id) else { return };
    if !seen.insert(id) {
        return;
    }
    for (name, version) in p.dependencies.iter().chain(&p.optional_dependencies) {
        if let Some((dep, _)) = res.packages.get_key_value(&format!("{name}@{version}")) {
            visit(res, keys, dep, seen, out);
        }
    }
    if keys.contains_key(id) {
        out.push(id);
    }
}

/// `scripts` of a package.json; anything unreadable is none.
fn read_scripts(file: &Path) -> HashMap<String, String> {
    let text = fs::read_to_string(file).unwrap_or_default();
    let doc = crate::json::parse(&text).ok();
    let scripts = doc.as_ref().and_then(|d| d.get("scripts")).and_then(Value::as_object);
    scripts.into_iter().flatten().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect()
}

/// A dependency's scripts are someone else's code: no npm token or password reaches them.
fn without_credentials(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy().to_ascii_lowercase();
        let secret = ["auth", "token", "password"].iter().any(|s| k.contains(s));
        if k == "npm_token" || k == "node_auth_token" || (k.starts_with("npm_config_") && secret) {
            command.env_remove(&key);
        }
    }
}
