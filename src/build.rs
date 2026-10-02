//! Install scripts. A dependency's `preinstall`, `install` and `postinstall` (and a git one's
//! `prepare`) run only when package.json trusts its name and jpm.lock approves its version
//! (`jpm approve`), in a copy of the package with npm credentials taken out of the environment.
//! The project's own lifecycle scripts run as npm runs them, once the tree is linked.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::graph::Resolution;
use crate::json::Value;
use crate::project::RootManifest;
use crate::rules::Rules;
use crate::{run, spec, ui};

const INSTALL: [&str; 3] = ["preinstall", "install", "postinstall"];
const LIFECYCLE: [&str; 6] = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"];

/// The names the project trusts with install scripts: bun's `trustedDependencies`, pnpm's
/// `pnpm.onlyBuiltDependencies`, and pnpm-workspace.yaml's `onlyBuiltDependencies` and
/// `allowBuilds`, where a `false` takes a name out.
pub fn trusted(m: &RootManifest, rules: &Rules) -> HashSet<String> {
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
    for (name, allowed) in &rules.builds {
        if *allowed {
            out.insert(name.clone());
        } else {
            out.remove(name);
        }
    }
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

/// Whether the project itself names `id`, a package that is not the registry's (a git, tarball
/// or `file:` package): a top depends on its source directly, or an override of the root's
/// names it. A directory inside another package's tarball never is: its name is whatever that
/// package's author gave it, and approving a trusted name must not approve it.
pub fn named_by_project(res: &Resolution, id: &str) -> bool {
    let Some(p) = res.packages.get(id) else { return false };
    if p.within().is_some() {
        return false;
    }
    let Some((name, source)) = crate::graph::split_key(crate::graph::split_peers(id).0) else { return false };
    let tops = std::iter::once(&res.root.dependencies).chain(
        res.packages.values().filter(|p| p.local.is_some()).flat_map(|p| [&p.dependencies, &p.optional_dependencies]),
    );
    let mut edges = tops.flat_map(|deps| deps.iter());
    edges.any(|(n, v)| n == name && crate::graph::edge_base(n, v) == source)
        || res.root.overrides.iter().any(|o| {
            o.name == name
                && o.value
                    .as_deref()
                    .is_some_and(|v| spec::parse_dep(name, v).is_ok_and(|s| spec::names_source(&s, "", source)))
        })
}

/// Packages with install scripts that do not run, as `name@version`, for the install to say so.
/// A directory inside another package's tarball says which: its name and version are only what
/// that package's author wrote.
pub fn skipped(res: &Resolution, chosen: &HashSet<String>, installed: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out: Vec<String> = res
        .packages
        .iter()
        .filter(|(id, p)| p.scripts && !chosen.contains(*id) && installed(id))
        .map(|(_, p)| match p.within() {
            Some((parent, at)) => format!("{}@{} (the directory {at} inside {parent})", p.name, p.version),
            None => format!("{}@{}", p.name, p.version),
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Whether a package as unpacked in the store has what `run_packages` runs: an install script,
/// a binding.gyp, or a git package's `prepare`. The registry's `hasInstallScript` can say so of
/// a tarball with none (fsevents 2, on every Mac).
pub fn ships_install_scripts(p: &crate::graph::Package, dir: &Path, index: &crate::store::Index) -> bool {
    let scripts = read_scripts(&dir.join(index.stored("package.json")));
    let git = p.source.as_deref().is_some_and(spec::is_git);
    INSTALL.iter().any(|e| scripts.contains_key(*e))
        || (git && scripts.contains_key("prepare"))
        || index.files.iter().any(|f| f.path == "binding.gyp")
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
        let pkg_dir = root.join("node_modules").join(p.dir_name());
        let file = pkg_dir.join("package.json");
        let scripts = read_scripts(&file);
        let mut events: Vec<(&str, String)> =
            INSTALL.iter().filter_map(|e| scripts.get(*e).map(|line| (*e, line.clone()))).collect();
        // npm's default for a native addon with no script of its own.
        if !events.iter().any(|(e, _)| *e != "postinstall") && pkg_dir.join("binding.gyp").is_file() {
            let at = events.iter().position(|(e, _)| *e == "postinstall").unwrap_or(events.len());
            events.insert(at, ("install", "node-gyp rebuild".into()));
        }
        // A git package's `prepare` builds what a registry tarball would ship built, so it runs
        // first. Its devDependencies are not installed for it.
        if let Some(line) = scripts.get("prepare").filter(|_| p.source.as_deref().is_some_and(spec::is_git)) {
            events.insert(0, ("prepare", line.clone()));
        }
        for (event, line) in &events {
            let mut command = run::shell(line, &pkg_dir, &run::bin_dirs(&pkg_dir), dir);
            run::script_env(&mut command, &file, event, line, &p.name, &p.version);
            without_credentials(&mut command);
            // Output goes to a log beside the package: shown only when the script fails.
            let log = root.join(".build.log");
            let file = fresh(&log).map_err(|e| Error::io(&e, format!("cannot write {}", log.display())))?;
            let err = file.try_clone().map_err(|e| Error::io(&e, "cannot share the build log"))?;
            command.stdin(std::process::Stdio::null()).stdout(file).stderr(err);
            let status = command.status().map_err(|e| Error::io(&e, "cannot start the shell"))?;
            if status.success() {
                continue;
            }
            let text = fs::read_to_string(&log).unwrap_or_default();
            let cut = (text.len().saturating_sub(2000)..text.len()).find(|&i| text.is_char_boundary(i));
            let tail = &text[cut.unwrap_or(text.len())..];
            let why =
                format!("{}@{} {event} failed ({status}); the end of {}:\n{tail}", p.name, p.version, log.display());
            if p.optional {
                ui::warn(&format!("skipped optional {why}"));
                continue 'packages;
            }
            return Err(Error::new("EBUILD", why));
        }
        fresh(&marker).map_err(|e| Error::io(&e, format!("cannot write {}", marker.display())))?;
        ui::info(&format!("built {}@{}", p.name, p.version));
        ran += 1;
    }
    Ok(ran)
}

/// A new empty file at `path`, never written through a link a checkout left there.
fn fresh(path: &Path) -> std::io::Result<fs::File> {
    let _ = fs::remove_file(path);
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

/// The project's lifecycle scripts (`preinstall` to `postprepare`), the root first, then each
/// workspace, each in its own directory. Their output is shown: it is the project's own code.
/// `workspace_prepare`: a workspace's `prepare` runs too, as npm and pnpm run it; yarn runs only
/// the root's (gatsby's create-gatsby would build before what it needs is built).
pub fn run_lifecycle(tops: &[(&Path, &RootManifest)], workspace_prepare: bool) -> Result<()> {
    let Some(&(root, _)) = tops.first() else { return Ok(()) };
    for (i, (dir, m)) in tops.iter().enumerate() {
        let scripts = m.doc.get("scripts").and_then(Value::as_object);
        let prepare = i == 0 || workspace_prepare;
        for event in LIFECYCLE.iter().filter(|e| prepare || !e.ends_with("prepare")) {
            let Some(line) = scripts.and_then(|s| s.get(event)).and_then(Value::as_str) else { continue };
            let (name, version) = (m.name.as_deref().unwrap_or(""), m.version.as_deref().unwrap_or(""));
            ui::info(&format!("> {event}: {line}"));
            let mut command = run::shell(line, dir, &run::bin_dirs(dir), root);
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
    for id in res.packages.keys().filter(|id| keys.contains_key(*id)) {
        visit(res, keys, id, &mut seen, &mut out);
    }
    out
}

fn visit<'a>(
    res: &'a Resolution,
    keys: &'a HashMap<String, String>,
    id: &'a String,
    seen: &mut HashSet<&'a str>,
    out: &mut Vec<&'a String>,
) {
    let Some((id, p)) = res.packages.get_key_value(id) else { return };
    if !seen.insert(id.as_str()) {
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

/// A dependency's scripts are someone else's code: no npm, yarn or bun token or password, npm
/// proxy setting or client key reaches them through the environment, and a proxy variable's
/// user and password are taken out of it. Hygiene, not a sandbox: a script can still read the
/// user's files, .npmrc among them.
fn without_credentials(command: &mut Command) {
    for (key, value) in std::env::vars_os() {
        let k = key.as_encoded_bytes();
        let has = |word: &[u8]| k.windows(word.len()).any(|w| w.eq_ignore_ascii_case(word));
        let npm = k.len() > 11 && k[..11].eq_ignore_ascii_case(b"npm_config_");
        let setting = |names: &[&str]| {
            let rest = String::from_utf8_lossy(&k[11.min(k.len())..]).replace('-', "_");
            names.iter().any(|n| rest.eq_ignore_ascii_case(n))
        };
        let named = [&b"NPM_TOKEN"[..], b"NODE_AUTH_TOKEN", b"YARN_NPM_AUTH_TOKEN", b"BUN_AUTH_TOKEN"];
        if named.iter().any(|n| k.eq_ignore_ascii_case(n))
            || (npm && (has(b"auth") || has(b"token") || has(b"password")))
            || (npm && setting(&["proxy", "https_proxy", "http_proxy", "key", "cert", "certfile", "keyfile"]))
        {
            command.env_remove(&key);
        } else if [&b"HTTPS_PROXY"[..], b"HTTP_PROXY", b"ALL_PROXY"].iter().any(|n| k.eq_ignore_ascii_case(n)) {
            match value.to_str().map(without_userinfo) {
                Some(Some(bare)) => command.env(&key, bare),
                Some(None) => command,
                None => command.env_remove(&key),
            };
        }
    }
}

/// A proxy url without its `user:password@`; `None` when it has none.
fn without_userinfo(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://").map_or(("", url), |(s, r)| (s, r));
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let at = authority.rfind('@')?;
    let host = &rest[at + 1..];
    Some(if scheme.is_empty() { host.to_string() } else { format!("{scheme}://{host}") })
}

#[cfg(test)]
mod tests {
    #[test]
    fn takes_the_user_out_of_a_proxy_url() {
        let bare = |u: &str| super::without_userinfo(u);
        assert_eq!(bare("http://u:p%40ss@proxy:8080/x").as_deref(), Some("http://proxy:8080/x"));
        assert_eq!(bare("u@corp:p@proxy:3128").as_deref(), Some("proxy:3128"));
        assert_eq!(bare("http://proxy:8080/a@b"), None, "an @ past the host is the path's");
        assert_eq!(bare("proxy:8080"), None);
    }
}
