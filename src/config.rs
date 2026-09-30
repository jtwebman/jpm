//! `.npmrc`: where packages come from and what to send to get them. The global file, the user
//! file over it, the project file over that, `npm_config_*` over all three, then the flags.
//! Only what jpm uses is read; npm ignores keys it does not know, and so does this. The project's
//! file comes with the repository, so it cannot weaken what the others check: TLS, proxies,
//! signature checks and the release cutoff are the user's to set (`restrict_project`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::manifest::parse_date;
use crate::registry::{INSECURE, registry_base};
use crate::util::{from_base64, now_ms, to_base64};

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The registry, trailing slashes off.
    pub registry: String,
    /// `@scope` -> its registry.
    pub scopes: BTreeMap<String, String>,
    /// `//host/path/` -> the `authorization` header for every request under it.
    pub auth: BTreeMap<String, String>,
    pub save_exact: bool,
    /// The release cutoff in epoch ms, or `None` when it is off.
    pub before: Option<i64>,
    pub release_age_exclude: Vec<String>,
    pub offline: bool,
    pub prefer_offline: bool,
    /// `global-store`: build package entries once, in the store, for every project to link to.
    pub global_store: Option<bool>,
    /// `ignore-scripts`: run no install or lifecycle scripts.
    pub ignore_scripts: bool,
    /// pnpm's `block-exotic-subdeps`: only the root and workspaces may take a package from a git
    /// repository or a tarball url. On unless the user says `false` (a project's .npmrc cannot).
    pub block_exotic_subdeps: bool,
    /// `legacy-peer-deps`: install no peers; link one only to what the tree already has.
    pub legacy_peer_deps: bool,
    /// `cafile`: a PEM file of certificates to trust in place of Mozilla's roots.
    pub cafile: Option<PathBuf>,
    /// `ca`: the same as PEM text, `\n` for its line breaks; `ca[]=` once per certificate.
    pub ca: Option<String>,
    /// `strict-ssl=false`: take any certificate. The one way to turn the checks off.
    pub insecure_tls: bool,
    /// `proxy`, `https-proxy` and `noproxy`, over the environment's.
    pub proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub noproxy: Option<String>,
    /// `node-mirror:release` (pnpm's), else `NODEJS_ORG_MIRROR`: where Node runtimes come from.
    pub node_mirror: Option<String>,
    /// `verify-node-signature`: check a Node release's SHASUMS256.txt against Node's release
    /// keys. On unless `false`.
    pub verify_node_signature: bool,
}

/// What the command line says, over every file.
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub registry: Option<String>,
    pub min_release_age: Option<f64>,
    pub before: Option<String>,
    pub min_release_age_exclude: Option<Vec<String>>,
    pub offline: Option<bool>,
    pub prefer_offline: Option<bool>,
    pub global_store: Option<bool>,
    pub legacy_peer_deps: Option<bool>,
    pub verify_node_signature: Option<bool>,
    pub block_exotic_subdeps: Option<bool>,
}

type Layer = BTreeMap<String, String>;

const AUTH_FIELDS: [&str; 4] = ["_authtoken", "_auth", "username", "_password"];
const DAY: i64 = 86_400_000;

/// A file's `key=value` lines as npm's ini reads them. A credential with no url is refused: it
/// would go to whichever registry wins, and a cloned project's `.npmrc` can name one.
pub fn parse_npmrc(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Layer> {
    let mut out = Layer::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';', '[']) {
            continue;
        }
        let (written, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line, "true"),
        };
        let key = normalize_key(written);
        let quoted = value.len() > 1
            && ((value.starts_with('"') && value.ends_with('"')) || (value.starts_with('\'') && value.ends_with('\'')));
        let mut value = if quoted {
            value[1..value.len() - 1].to_string()
        } else {
            let end = value.find([';', '#']).unwrap_or(value.len());
            value[..end].trim_end().to_string()
        };
        if AUTH_FIELDS.contains(&key.as_str()) && !value.is_empty() {
            return Err(Error::new(
                "ECONFIG",
                format!("{written} in .npmrc must be keyed by its registry: //host/path/:{written}"),
            ));
        }
        value = expand_env(&value, env);
        if let Some(list) = key.strip_suffix("[]") {
            let joined = match out.get(list) {
                Some(have) if !have.is_empty() && !value.is_empty() => format!("{have},{value}"),
                Some(have) if !have.is_empty() => have.clone(),
                _ => value,
            };
            out.insert(list.to_string(), joined);
        } else {
            out.insert(key, value);
        }
    }
    Ok(out)
}

/// `${VAR}` as npm reads it: `${VAR?}` is empty when unset where `${VAR}` stays as written,
/// and a backslash before the `$` keeps it literal.
fn expand_env(value: &str, env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        let slashes = rest[..at].bytes().rev().take_while(|b| *b == b'\\').count();
        let Some(close) = rest[at..].find('}') else { break };
        let inner = &rest[at + 2..at + close];
        let (name, opt) = match inner.strip_suffix('?') {
            Some(n) => (n, true),
            None => (inner, false),
        };
        let valid = !name.is_empty() && !name.contains(['$', '{', '}', '?']);
        out.push_str(&rest[..at - slashes]);
        let whole = &rest[at..=at + close];
        if !valid {
            out.push_str(&rest[at - slashes..=at + close]);
        } else if slashes % 2 == 1 {
            out.push_str(&"\\".repeat((slashes - 1) / 2));
            out.push_str(whole);
        } else {
            out.push_str(&"\\".repeat(slashes / 2));
            match env(name) {
                Some(v) => out.push_str(&v),
                None if opt => {}
                None => out.push_str(&format!("${{{name}}}")),
            }
        }
        rest = &rest[at + close + 1..];
    }
    out.push_str(rest);
    out
}

/// `npm_config_save_exact=true` is `save-exact=true`; `JPM_REGISTRY` stands in for a
/// `npm_config_registry` npm did not set.
pub fn env_config(vars: impl Iterator<Item = (String, String)>) -> Layer {
    let mut out = Layer::new();
    let mut ours = None;
    for (name, value) in vars {
        if name == "JPM_REGISTRY" && !value.is_empty() {
            ours = Some(value.clone());
        }
        let Some(key) = name.get(..11).filter(|p| p.eq_ignore_ascii_case("npm_config_")).map(|_| &name[11..]) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let key = if key.starts_with("//") { key.to_string() } else { dashes(key) };
        let key = normalize_key(&key);
        if !AUTH_FIELDS.contains(&key.as_str()) {
            out.insert(key, value);
        }
    }
    if let Some(r) = ours {
        out.entry("registry".into()).or_insert(r);
    }
    out
}

/// `save_exact` -> `save-exact`, but a leading underscore stays (`_authToken`).
fn dashes(key: &str) -> String {
    key.char_indices().map(|(i, c)| if c == '_' && i > 0 { '-' } else { c }).collect()
}

/// Case only matters in a url.
fn normalize_key(key: &str) -> String {
    if !key.starts_with("//") {
        return key.to_ascii_lowercase();
    }
    match key.rfind(':') {
        Some(c) => format!("{}{}", &key[..c], key[c..].to_ascii_lowercase()),
        None => key.to_string(),
    }
}

/// The config the layers add up to, the last layer winning per key.
pub fn to_config(layers: &[Layer], registry: Option<&str>) -> Result<Config> {
    let mut merged = Layer::new();
    for layer in layers {
        for (k, v) in layer {
            if !v.is_empty() {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    let base = registry_base(registry.filter(|r| !r.is_empty()).or(merged.get("registry").map(String::as_str)));
    let mut scopes = BTreeMap::new();
    let mut fields: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (key, value) in &merged {
        if key.starts_with('@') && key.ends_with(":registry") {
            scopes.insert(key[..key.len() - 9].to_string(), registry_base(Some(value)));
        } else if key.starts_with("//")
            && let Some(c) = key.rfind(':')
        {
            fields.entry(key[..c].to_string()).or_default().insert(key[c + 1..].to_string(), value.clone());
        }
    }
    let mut auth = BTreeMap::new();
    for (dart, found) in &fields {
        if let Some(header) = authorization(found) {
            auth.insert(dart.clone(), header);
        }
    }
    // A credential goes over plain http only to a host whose registry is configured as http:
    // a lockfile or packument naming an http url must not expose an https registry's token.
    for url in std::iter::once(&base).chain(scopes.values()) {
        if url.starts_with("http://")
            && let Some(host) = host_of(url)
        {
            auth.insert(format!("{INSECURE}{host}"), String::new());
        }
    }
    let exclude: Vec<String> = merged
        .get("min-release-age-exclude")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    // `null` and `false` are npm's ways to write "not set".
    let set = |key: &str| merged.get(key).filter(|v| !matches!(v.as_str(), "null" | "false")).cloned();
    let mut dedup = Vec::new();
    for e in exclude {
        if !dedup.contains(&e) {
            dedup.push(e);
        }
    }
    Ok(Config {
        registry: base,
        scopes,
        auth,
        save_exact: merged.get("save-exact").is_some_and(|v| v == "true"),
        before: cutoff(layers)?,
        release_age_exclude: dedup,
        offline: merged.get("offline").is_some_and(|v| v == "true"),
        prefer_offline: merged.get("prefer-offline").is_some_and(|v| v == "true"),
        global_store: merged.get("global-store").map(|v| v == "true"),
        // Any layer can turn scripts off and none can turn them back on: a cloned repo's .npmrc
        // must not undo the user's own `ignore-scripts=true`.
        ignore_scripts: layers.iter().any(|l| l.get("ignore-scripts").is_some_and(|v| v == "true")),
        // On, as in pnpm 10.26 and later; the project's own `false` is taken out before this.
        block_exotic_subdeps: merged.get("block-exotic-subdeps").is_none_or(|v| v != "false"),
        legacy_peer_deps: merged.get("legacy-peer-deps").is_some_and(|v| v == "true"),
        cafile: set("cafile").map(PathBuf::from),
        // npm's ini reads `\n` in a quoted value as a line break.
        ca: set("ca").map(|v| v.replace("\\n", "\n")),
        insecure_tls: merged.get("strict-ssl").is_some_and(|v| v == "false"),
        proxy: set("proxy"),
        https_proxy: set("https-proxy"),
        noproxy: set("noproxy"),
        node_mirror: set("node-mirror:release")
            .or_else(|| std::env::var("NODEJS_ORG_MIRROR").ok().filter(|m| !m.is_empty())),
        verify_node_signature: merged.get("verify-node-signature").is_none_or(|v| v != "false"),
    })
}

/// A layer's `before` beats its own `min-release-age`, and a higher layer beats a lower one.
fn cutoff(layers: &[Layer]) -> Result<Option<i64>> {
    let mut before = Some(now_ms() - DAY);
    for layer in layers {
        if let Some(b) = layer.get("before").filter(|b| !b.is_empty()) {
            before = Some(parse_date(b).ok_or_else(|| Error::new("ECONFIG", format!("before={b} is not a date")))?);
        } else if let Some(age) = layer.get("min-release-age").filter(|a| !a.is_empty()) {
            let days: f64 = age
                .trim()
                .parse()
                .ok()
                .filter(|d: &f64| *d >= 0.0)
                .ok_or_else(|| Error::new("ECONFIG", format!("min-release-age={age} is not a number of days")))?;
            before = if days == 0.0 { None } else { Some(now_ms() - (days * DAY as f64) as i64) };
        }
    }
    Ok(before)
}

fn authorization(fields: &BTreeMap<String, String>) -> Option<String> {
    if let Some(t) = fields.get("_authtoken") {
        return Some(format!("Bearer {t}"));
    }
    if let Some(a) = fields.get("_auth") {
        return Some(format!("Basic {a}"));
    }
    let (user, pass) = (fields.get("username")?, fields.get("_password")?);
    let pass = String::from_utf8_lossy(&from_base64(pass)).into_owned();
    Some(format!("Basic {}", to_base64(format!("{user}:{pass}").as_bytes())))
}

/// `//host/` for a url.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| format!("//{host}/"))
}

pub fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// The config a project runs under.
pub fn read_config(dir: &Path, flags: &Flags) -> Result<Config> {
    let env = |name: &str| std::env::var(name).ok();
    let from_env = env_config(std::env::vars());
    let home = home();
    let path = |p: &str| match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(p),
    };
    let user_file = from_env.get("userconfig").map_or_else(|| home.join(".npmrc"), |p| path(p));
    let user = parse_npmrc(&read(&user_file), &env)?;
    let global_file = match from_env.get("globalconfig").or(user.get("globalconfig")) {
        Some(p) => path(p),
        None => global_file(from_env.get("prefix").or(user.get("prefix")).map(|p| path(p))),
    };
    let global = parse_npmrc(&read(&global_file), &env)?;
    let project_file = dir.join(".npmrc");
    let mut project = parse_npmrc(&read(&project_file), &env)?;
    // The user's own file, when the project is the home directory, is the user's to say.
    if project_file != user_file && project_file != global_file {
        let dropped = restrict_project(&mut project, &[global.clone(), user.clone()])?;
        if !dropped.is_empty() {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                crate::ui::warn(&format!(
                    "{} sets {}, which only ~/.npmrc, the global npmrc, npm_config_* or a flag may set; ignored",
                    project_file.display(),
                    dropped.join(", ")
                ));
            });
        }
    }
    let mut cli = Layer::new();
    if let Some(age) = flags.min_release_age {
        cli.insert("min-release-age".into(), age.to_string());
    }
    if let Some(b) = &flags.before {
        cli.insert("before".into(), b.clone());
    }
    if let Some(list) = &flags.min_release_age_exclude {
        cli.insert("min-release-age-exclude".into(), list.join(","));
    }
    if let Some(o) = flags.offline {
        cli.insert("offline".into(), o.to_string());
    }
    if let Some(o) = flags.prefer_offline {
        cli.insert("prefer-offline".into(), o.to_string());
    }
    if let Some(g) = flags.global_store {
        cli.insert("global-store".into(), g.to_string());
    }
    if let Some(l) = flags.legacy_peer_deps {
        cli.insert("legacy-peer-deps".into(), l.to_string());
    }
    if let Some(b) = flags.block_exotic_subdeps {
        cli.insert("block-exotic-subdeps".into(), b.to_string());
    }
    if let Some(v) = flags.verify_node_signature {
        cli.insert("verify-node-signature".into(), v.to_string());
    }
    let mut config = to_config(&[global, user, project, from_env, cli], flags.registry.as_deref())?;
    // A relative cafile is from where jpm runs, as npm takes it.
    config.cafile = config.cafile.map(|f| path(&f.to_string_lossy()));
    crate::http::configure(&config)?;
    crate::runtime::configure(config.node_mirror.as_deref(), config.verify_node_signature);
    Ok(config)
}

/// What a project's .npmrc may not set: a cloned repository could route every request, and the
/// user's tokens with it, through a proxy of its choosing and have jpm trust its certificate.
const USER_ONLY: [&str; 5] = ["ca", "cafile", "proxy", "https-proxy", "http-proxy"];

/// Take out of a project's layer what would weaken the checks the layers `below` it (global,
/// user) make: the settings above, `strict-ssl=false`, `block-exotic-subdeps=false`,
/// `verify-node-signature=false`, and a release cutoff laxer than theirs. The keys taken out, as written.
fn restrict_project(project: &mut Layer, below: &[Layer]) -> Result<Vec<String>> {
    let mut dropped = Vec::new();
    let mut take_out = |project: &mut Layer, key: &str, when: &dyn Fn(&str) -> bool| {
        if project.remove(key).is_some_and(|v| when(&v)) {
            dropped.push(key.to_string());
        }
    };
    for key in USER_ONLY {
        take_out(project, key, &|v| !matches!(v, "" | "null" | "false"));
    }
    take_out(project, "strict-ssl", &|v| v == "false");
    if project.get("block-exotic-subdeps").is_some_and(|v| v == "false") {
        take_out(project, "block-exotic-subdeps", &|_| true);
    }
    if project.get("verify-node-signature").is_some_and(|v| v == "false") {
        take_out(project, "verify-node-signature", &|_| true);
    }
    let theirs = cutoff(below)?;
    let with = cutoff(&[below, std::slice::from_ref(project)].concat())?;
    // A second's slack: `min-release-age` is counted from now, read twice.
    if theirs.is_some_and(|t| with.is_none_or(|w| w > t + 1000)) {
        for key in ["min-release-age", "before"] {
            take_out(project, key, &|_| true);
        }
    }
    Ok(dropped)
}

/// npm's global file is `<prefix>/etc/npmrc`, the prefix being where node is installed.
fn global_file(prefix: Option<PathBuf>) -> PathBuf {
    let prefix = prefix.or_else(|| std::env::var_os("PREFIX").map(PathBuf::from)).or_else(|| {
        let node = crate::run::which("node")?;
        if cfg!(windows) {
            node.parent().map(Path::to_path_buf)
        } else {
            node.parent()?.parent().map(Path::to_path_buf)
        }
    });
    prefix.unwrap_or_default().join("etc").join("npmrc")
}

/// Unreadable is absent, as with npm.
fn read(file: &Path) -> String {
    std::fs::read_to_string(file).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn parses_ini() {
        let env = |n: &str| (n == "TOKEN").then(|| "abc".to_string());
        let layer = parse_npmrc(
            "registry = https://r.test/ ; comment\n# c\n//r.test/:_authToken=${TOKEN}\nx=\"a;b\"\nlist[]=a\nlist[]=b\nopt=${NOPE?}x\nlit=\\${TOKEN}",
            &env,
        )
        .unwrap();
        assert_eq!(layer["registry"], "https://r.test/");
        assert_eq!(layer["//r.test/:_authtoken"], "abc");
        assert_eq!(layer["x"], "a;b");
        assert_eq!(layer["list"], "a,b");
        assert_eq!(layer["opt"], "x");
        assert_eq!(layer["lit"], "${TOKEN}");
    }

    #[test]
    fn refuses_bare_credentials() {
        assert_eq!(parse_npmrc("_authToken=x", &no_env).unwrap_err().code, "ECONFIG");
    }

    #[test]
    fn builds_auth_and_scopes() {
        let layer = parse_npmrc(
            "registry=https://r.test/npm/\n@s:registry=https://s.test\n//r.test/npm/:_authToken=t\n//s.test/:username=u\n//s.test/:_password=cA==",
            &no_env,
        )
        .unwrap();
        let config = to_config(&[layer], None).unwrap();
        assert_eq!(config.registry, "https://r.test/npm");
        assert_eq!(config.scopes["@s"], "https://s.test");
        assert_eq!(config.auth["//r.test/npm/"], "Bearer t");
        // A path-scoped token stays on its path, as npm keeps it.
        assert!(!config.auth.contains_key("//r.test/"));
        assert_eq!(config.auth["//s.test/"], format!("Basic {}", to_base64(b"u:p")));
    }

    #[test]
    fn ignore_scripts_only_turns_on() {
        let on: Layer = [("ignore-scripts".into(), "true".into())].into();
        let off: Layer = [("ignore-scripts".into(), "false".into())].into();
        assert!(to_config(&[on.clone(), off.clone()], None).unwrap().ignore_scripts, "a later layer cannot undo it");
        assert!(to_config(&[off.clone(), on], None).unwrap().ignore_scripts);
        assert!(!to_config(&[off], None).unwrap().ignore_scripts);
    }

    #[test]
    fn block_exotic_subdeps_is_on_unless_the_user_turns_it_off() {
        let on: Layer = [("block-exotic-subdeps".into(), "true".into())].into();
        let off: Layer = [("block-exotic-subdeps".into(), "false".into())].into();
        assert!(to_config(&[], None).unwrap().block_exotic_subdeps, "on by default");
        assert!(!to_config(std::slice::from_ref(&off), None).unwrap().block_exotic_subdeps);
        assert!(!to_config(&[on.clone(), off.clone()], None).unwrap().block_exotic_subdeps, "a later layer wins");
        assert!(to_config(&[off.clone(), on], None).unwrap().block_exotic_subdeps);
        // Not the project's own file: its `false` is taken out.
        let mut project = off;
        assert_eq!(restrict_project(&mut project, &[]).unwrap(), ["block-exotic-subdeps"]);
        assert!(to_config(&[project], None).unwrap().block_exotic_subdeps);
    }

    #[test]
    fn release_age_layers() {
        let off: Layer = [("min-release-age".into(), "0".into())].into();
        assert_eq!(to_config(std::slice::from_ref(&off), None).unwrap().before, None);
        let date: Layer = [("before".into(), "2020-01-01".into())].into();
        assert_eq!(to_config(&[off, date], None).unwrap().before, parse_date("2020-01-01"));
        assert!(to_config(&[], None).unwrap().before.is_some());
    }

    #[test]
    fn reads_tls_and_proxy_settings() {
        let config = |rc: &str| to_config(&[parse_npmrc(rc, &no_env).unwrap()], None).unwrap();
        let none = config("");
        assert!(!none.insecure_tls, "certificates are checked unless asked otherwise");
        assert!(none.ca.is_none() && none.cafile.is_none() && none.proxy.is_none() && none.noproxy.is_none());
        let c = config(
            "cafile=/etc/corp.pem\nca=\"-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\"\nstrict-ssl=false\nproxy=http://p.test:1\nhttps-proxy=http://u:p@s.test:2\nnoproxy=a.test,b.test",
        );
        assert_eq!(c.cafile.as_deref(), Some(Path::new("/etc/corp.pem")));
        assert_eq!(c.ca.as_deref(), Some("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        assert!(c.insecure_tls);
        assert_eq!(c.proxy.as_deref(), Some("http://p.test:1"));
        assert_eq!(c.https_proxy.as_deref(), Some("http://u:p@s.test:2"));
        assert_eq!(c.noproxy.as_deref(), Some("a.test,b.test"));
        // Lists, and npm's spellings of "not set".
        let c = config("ca[]=\"x\\ny\"\nca[]=z\nnoproxy[]=a.test\nnoproxy[]=b.test\nproxy=false\nhttps-proxy=null");
        assert_eq!(c.ca.as_deref(), Some("x\ny,z"));
        assert_eq!(c.noproxy.as_deref(), Some("a.test,b.test"));
        assert!(c.proxy.is_none() && c.https_proxy.is_none());
        assert!(!config("strict-ssl=true").insecure_tls);
        // A later layer turns the checks back on; the environment's spelling works too.
        let off = parse_npmrc("strict-ssl=false", &no_env).unwrap();
        let on = env_config([("npm_config_strict_ssl".to_string(), "true".to_string())].into_iter());
        assert!(!to_config(&[off.clone(), on], None).unwrap().insecure_tls);
        let env = env_config([("npm_config_https_proxy".to_string(), "http://e.test".to_string())].into_iter());
        let c = to_config(&[off, env], None).unwrap();
        assert!(c.insecure_tls);
        assert_eq!(c.https_proxy.as_deref(), Some("http://e.test"));
    }

    #[test]
    fn a_project_npmrc_cannot_weaken_checks() {
        let restricted = |rc: &str, user: &str| {
            let mut project = parse_npmrc(rc, &no_env).unwrap();
            let dropped = restrict_project(&mut project, &[parse_npmrc(user, &no_env).unwrap()]).unwrap();
            (project, dropped)
        };
        let (left, dropped) = restricted(
            "strict-ssl=false\nca=x\ncafile=/c.pem\nproxy=http://p\nhttps-proxy=http://p\nhttp-proxy=http://p\nblock-exotic-subdeps=false\nverify-node-signature=false\nmin-release-age=0\nregistry=https://r.test\n@s:registry=https://s.test\nnoproxy=a.test\nnode-mirror:release=https://m.test",
            "",
        );
        assert_eq!(
            dropped,
            [
                "ca",
                "cafile",
                "proxy",
                "https-proxy",
                "http-proxy",
                "strict-ssl",
                "block-exotic-subdeps",
                "verify-node-signature",
                "min-release-age"
            ]
        );
        let kept: Vec<&str> = left.keys().map(String::as_str).collect();
        assert_eq!(kept, ["@s:registry", "node-mirror:release", "noproxy", "registry"]);
        // What only makes the checks stricter stays, and says nothing.
        let (left, dropped) =
            restricted("strict-ssl=true\nverify-node-signature=true\nmin-release-age=3\nproxy=false", "");
        assert!(dropped.is_empty(), "{dropped:?}");
        assert_eq!(to_config(&[left], None).unwrap().before.unwrap() / DAY, (now_ms() - 3 * DAY) / DAY);
        // A cutoff laxer than the user's goes, a date past it too; the user's own 0 leaves it be.
        assert_eq!(restricted("min-release-age=1", "min-release-age=7").1, ["min-release-age"]);
        assert_eq!(restricted("before=2999-01-01", "").1, ["before"]);
        assert!(restricted("min-release-age=0", "min-release-age=0").1.is_empty());
        assert!(restricted("before=2000-01-01", "").1.is_empty());
    }

    #[test]
    fn reads_env() {
        let layer = env_config(
            [("npm_config_save_exact".to_string(), "true".to_string()), ("NPM_CONFIG__authToken".into(), "x".into())]
                .into_iter(),
        );
        assert_eq!(layer.get("save-exact").map(String::as_str), Some("true"));
        assert!(!layer.contains_key("_authtoken"));
    }
}
