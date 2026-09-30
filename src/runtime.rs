//! Runtimes as dependencies, as pnpm has them: `"node": "runtime:22"` in a dependency group, or
//! `devEngines.runtime` (`engines.runtime`) with `onFail: "download"`, installs that Node.js,
//! Bun or Deno as the package `node` (`bun`, `deno`), its binary linked into `.bin`. The range
//! is resolved once to the newest version it allows and locked with every platform's build, so a
//! lockfile made on Linux installs on macOS or Windows without asking the network which bytes to
//! trust.
//!
//! Node comes from nodejs.org (`node-mirror:release` in .npmrc or `NODEJS_ORG_MIRROR` name a
//! mirror), each file checked against the release's `SHASUMS256.txt`: the `.tar.gz` on Linux and
//! macOS, the bare `node.exe` on Windows (jpm reads no zip). As pnpm does, jpm first checks that
//! file's signature, `SHASUMS256.txt.sig`, against Node's release keys (`pgp.rs`), unless
//! `verify-node-signature=false` says not to. Bun and Deno come from their npm
//! platform packages (`@oven/bun-linux-x64`, `@deno/darwin-arm64`), through the registry like
//! any other package.

use std::sync::OnceLock;

use crate::bin::Bins;
use crate::error::{Error, Result};
use crate::graph::Package;
use crate::json::Value;
use crate::registry::{Registry, tarball_url};
use crate::semver;
use crate::sys::Platform;
use crate::util::{from_hex, to_base64};

pub const NAMES: [&str; 3] = ["node", "bun", "deno"];
pub const PROTOCOL: &str = "runtime:";
const NODE_DIST: &str = "https://nodejs.org/download/release";
/// Musl builds before Node 26 are only here.
const UNOFFICIAL: &str = "https://unofficial-builds.nodejs.org/download/release";
/// Node's release keys, one file per key fingerprint. `JPM_NODE_KEYS_URL` replaces it, for tests.
const RELEASE_KEYS: &str = "https://raw.githubusercontent.com/nodejs/release-keys/HEAD/keys";

/// One platform's build: `platform` is `<os>-<cpu>`, `-musl` added for a musl build, in Node's
/// spelling. `file` is where it is: for Node a file under the release's directory on the mirror
/// (or a whole url), for Bun and Deno the npm package that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    pub platform: String,
    pub integrity: String,
    pub file: String,
}

static MIRROR: OnceLock<String> = OnceLock::new();
static VERIFY: OnceLock<bool> = OnceLock::new();

/// Where Node releases come from, and whether their signatures are checked; set once from the
/// config.
pub fn configure(mirror: Option<&str>, verify: bool) {
    let _ = MIRROR.set(mirror.map_or(NODE_DIST, |m| m.trim_end_matches('/')).to_string());
    let _ = VERIFY.set(verify);
}

fn mirror() -> &'static str {
    MIRROR.get().map_or(NODE_DIST, String::as_str)
}

/// Whether `range` in `name`'s entry is a runtime: `runtime:` on node, bun or deno.
pub fn is_runtime(name: &str, range: &str) -> bool {
    range.starts_with(PROTOCOL) && NAMES.contains(&name)
}

/// This machine's variant name.
pub fn platform_key(p: &Platform) -> String {
    let musl = p.os == "linux" && p.libc.as_deref() == Some("musl");
    format!("{}-{}{}", p.os, p.cpu, if musl { "-musl" } else { "" })
}

/// The build for `p`. Arm64 macOS and Windows run x64 builds too (Rosetta, Windows' emulation),
/// for versions that have no arm64 one.
pub fn pick<'a>(variants: &'a [Variant], p: &Platform) -> Option<&'a Variant> {
    let key = platform_key(p);
    let found = variants.iter().find(|v| v.platform == key);
    let emulated = matches!(p.os.as_str(), "darwin" | "win32") && p.cpu == "arm64";
    found.or_else(|| emulated.then(|| variants.iter().find(|v| v.platform == format!("{}-x64", p.os))).flatten())
}

/// The bins a runtime links, as pnpm does: its binary alone.
pub fn bins(name: &str, os: &str) -> Bins {
    let win = os == "win32";
    let target = match name {
        "node" if win => "node.exe",
        "node" => "bin/node",
        "bun" if win => "bin/bun.exe",
        "bun" => "bin/bun",
        "deno" if win => "deno.exe",
        _ => "deno",
    };
    Bins::from([(name.to_string(), target.to_string())])
}

/// Fill in what installs here: this platform's integrity, url and bins. With no build for this
/// platform the package is marked as not running on it, so the platform filter says so.
pub fn apply(p: &mut Package, base_for: &dyn Fn(&str) -> String) {
    let here = Platform::current();
    let Some(v) = p.runtime.as_deref().and_then(|all| pick(all, &here)).cloned() else {
        p.os = Some(vec![format!("!{}", here.os)]);
        return;
    };
    p.resolved = if p.name != "node" {
        tarball_url(&base_for(&v.file), &v.file, &p.version)
    } else if v.file.starts_with("https://") || v.file.starts_with("http://") {
        v.file.clone()
    } else {
        format!("{}/v{}/{}", mirror(), p.version, v.file)
    };
    p.integrity = v.integrity;
    p.bin = bins(&p.name, &here.os);
}

/// The package a runtime range resolves to: the newest version it allows, or `pinned` (a
/// version already locked or preferred), with every platform's build.
pub fn resolve(name: &str, range: &str, pinned: Option<&str>, registry: &Registry) -> Result<Package> {
    let (version, variants) = match name {
        "node" => node(range, pinned, registry)?,
        _ => from_npm(name, range, pinned, registry)?,
    };
    if variants.is_empty() {
        return Err(Error::new("ENOVERSIONS", format!("{name}@{version} has no builds jpm can install")));
    }
    let mut p = Package {
        name: name.to_string(),
        source: Some(format!("{PROTOCOL}{version}")),
        version,
        runtime: Some(variants),
        ..Package::default()
    };
    apply(&mut p, &|n| registry.base_for(n).to_string());
    Ok(p)
}

fn fetch(registry: &Registry, url: &str) -> Result<Vec<u8>> {
    if registry.offline() {
        return Err(Error::new("EOFFLINE", format!("offline: cannot read {url}")));
    }
    let r = crate::http::get(url, &[], registry.auth())?;
    match r.status {
        200 => Ok(r.body),
        404 => Err(Error::new("E404", format!("{url} returned 404"))),
        s => Err(Error::new("ENETWORK", format!("{url} returned {s}"))),
    }
}

fn download(registry: &Registry, url: &str) -> Result<String> {
    String::from_utf8(fetch(registry, url)?).map_err(|_| Error::new("ENETWORK", format!("{url} is not text")))
}

/// A release's `SHASUMS256.txt` (`text`, from `url`) must be signed by one of Node's release
/// keys. The key comes from nodejs/release-keys once, and is kept in the store's metadata.
fn check_signature(registry: &Registry, version: &str, url: &str, text: &str) -> Result<()> {
    let refused = |why: &str| {
        Error::new("ESIGNATURE", format!("Node.js {version}: {url} is not signed by a Node.js release key: {why}"))
    };
    let sig = match fetch(registry, &format!("{url}.sig")) {
        Err(e) if e.code == "E404" => {
            return Err(Error::new(
                "ESIGNATURE",
                format!(
                    "Node.js {version}: {url}.sig is missing, and jpm checks the signature of every Node.js release. \
                     For a mirror that publishes none, set verify-node-signature=false in .npmrc \
                     (or pass --no-verify-node-signature)"
                ),
            ));
        }
        other => other?,
    };
    let key = crate::pgp::signer(&sig).map_err(|e| refused(&e))?;
    let name = crate::pgp::hex(&key);
    let kept = registry.metadata_dir().map(|d| d.join("_node_keys").join(format!("{name}.asc")));
    if let Some(armored) = kept.as_ref().and_then(|f| std::fs::read(f).ok())
        && crate::pgp::verify(text.as_bytes(), &sig, &key, &armored).is_ok()
    {
        return Ok(());
    }
    let base = std::env::var("JPM_NODE_KEYS_URL").unwrap_or_else(|_| RELEASE_KEYS.to_string());
    let armored = fetch(registry, &format!("{base}/{name}.asc"))
        .map_err(|e| e.context(format_args!("Node.js {version}: cannot read release key {name}")))?;
    crate::pgp::verify(text.as_bytes(), &sig, &key, &armored).map_err(refused)?;
    if let Some(file) = kept
        && file.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok())
    {
        let _ = crate::util::write_atomic(&file, &armored);
    }
    Ok(())
}

fn node(range: &str, pinned: Option<&str>, registry: &Registry) -> Result<(String, Vec<Variant>)> {
    let exact = semver::parse(range).filter(|v| v.pre.is_empty()).map(|v| v.text);
    let version = match pinned.map(str::to_string).or(exact) {
        Some(v) => v,
        None => {
            let url = format!("{}/index.json", mirror());
            let index = crate::json::parse(&download(registry, &url)?).map_err(|e| e.context(&url))?;
            pick_node(&index, range)?
        }
    };
    let url = format!("{}/v{version}/SHASUMS256.txt", mirror());
    let text = download(registry, &url)?;
    if *VERIFY.get().unwrap_or(&true) {
        check_signature(registry, &version, &url, &text)?;
    }
    let mut variants = node_variants(&text, &version, "");
    // nodejs.org's releases have unofficial musl builds beside them, for the platforms theirs lack.
    // Their list is signed by no release key: it is trusted as far as its TLS download, as pnpm
    // trusts it.
    if mirror() == NODE_DIST {
        let base = format!("{UNOFFICIAL}/v{version}/");
        if let Ok(text) = download(registry, &format!("{base}SHASUMS256.txt")) {
            let more = node_variants(&text, &version, &base).into_iter().filter(|v| v.platform.ends_with("-musl"));
            let more: Vec<Variant> = more.filter(|m| !variants.iter().any(|v| v.platform == m.platform)).collect();
            variants.extend(more);
        }
    }
    let variants = by_platform(variants);
    Ok((version, variants))
}

/// The newest release `range` allows, from the mirror's `index.json`: a semver range, `lts`
/// (or an LTS line's codename, `jod`), or `latest`. Prereleases and nightlies are never picked.
pub fn pick_node(index: &Value, range: &str) -> Result<String> {
    let releases: Vec<(&str, Option<&str>)> = index
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let v = r.get("version")?.as_str()?;
            Some((v.strip_prefix('v').unwrap_or(v), r.get("lts").and_then(Value::as_str)))
        })
        .collect();
    let wanted = range.trim().to_ascii_lowercase();
    let newest = |keep: &dyn Fn(Option<&str>) -> bool| {
        let list = releases.iter().filter(|(_, lts)| keep(*lts)).map(|(v, _)| *v);
        semver::max_satisfying(list, "*").map(str::to_string)
    };
    let found = match wanted.as_str() {
        "" | "*" | "latest" | "current" => newest(&|_| true),
        "lts" | "lts/*" => newest(&|lts| lts.is_some()),
        w if w.contains('/') || w.starts_with("rc") || w.starts_with("nightly") => {
            return Err(Error::new(
                "EINVALIDSPEC",
                format!("runtime:{range}: jpm installs only released Node versions"),
            ));
        }
        w if !semver::valid_range(w) => newest(&|lts| lts.is_some_and(|l| l.eq_ignore_ascii_case(w))),
        w => semver::max_satisfying(releases.iter().map(|(v, _)| *v), w).map(str::to_string),
    };
    found.ok_or_else(|| Error::new("ETARGET", format!("no Node.js release matches runtime:{range}")))
}

/// Each build a `SHASUMS256.txt` lists that jpm installs: `node-v<V>-<os>-<cpu>.tar.gz` and
/// `win-<cpu>/node.exe`, with `base` before the file when it is not on the mirror.
pub fn node_variants(text: &str, version: &str, base: &str) -> Vec<Variant> {
    let prefix = format!("node-v{version}-");
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((hex, file)) = line.trim().split_once(char::is_whitespace) else { continue };
        let file = file.trim().trim_start_matches('*');
        let Some(digest) = from_hex(hex).filter(|d| d.len() == 32) else { continue };
        let platform = match file.strip_prefix("win-").and_then(|f| f.strip_suffix("/node.exe")) {
            Some(cpu) => format!("win32-{}", node_cpu(cpu)),
            None => {
                let Some(name) = file.strip_prefix(&prefix).and_then(|f| f.strip_suffix(".tar.gz")) else { continue };
                let (name, musl) = name.strip_suffix("-musl").map_or((name, ""), |n| (n, "-musl"));
                let Some((os, cpu)) = name.split_once('-').filter(|(os, _)| matches!(*os, "linux" | "darwin" | "aix"))
                else {
                    continue;
                };
                format!("{os}-{}{musl}", node_cpu(cpu))
            }
        };
        out.push(Variant {
            platform,
            integrity: format!("sha256-{}", to_base64(&digest)),
            file: format!("{base}{file}"),
        });
    }
    out
}

/// Node's download names to `process.arch`.
fn node_cpu(cpu: &str) -> &str {
    match cpu {
        "armv7l" => "arm",
        "ppc64le" => "ppc64",
        "x86" => "ia32",
        other => other,
    }
}

/// Bun or Deno: the version from the npm package `bun` (`deno`), whose optional dependencies
/// are one package per platform, each read for where it runs and its integrity.
fn from_npm(name: &str, range: &str, pinned: Option<&str>, registry: &Registry) -> Result<(String, Vec<Variant>)> {
    let spec = crate::spec::parse_dep(name, if range.is_empty() { "latest" } else { range })?;
    let m = registry.pick(&spec, pinned, pinned.is_some())?;
    // `-baseline` builds are for CPUs without AVX2, the same platform as the default build.
    let platforms: Vec<(String, String)> = m
        .optional_dependencies
        .iter()
        .filter(|(n, _)| n.starts_with('@') && !n.contains("-baseline") && !n.contains("-profile"))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let read = crate::pool::map(crate::pool::network_threads(), platforms, |(pkg, v)| {
        let full = registry.manifest(&pkg, &v)?;
        let first = |l: &Option<Vec<String>>| l.as_ref().and_then(|l| l.first().cloned()).unwrap_or_default();
        let musl = full.libc.as_ref().is_some_and(|l| l.iter().any(|c| c == "musl"));
        let platform = format!("{}-{}{}", first(&full.os), first(&full.cpu), if musl { "-musl" } else { "" });
        Ok::<_, Error>(Variant { platform, integrity: full.integrity()?, file: pkg })
    });
    let mut variants = read.into_iter().collect::<Result<Vec<_>>>()?;
    variants.retain(|v| !v.platform.starts_with('-') && !v.platform.contains("--"));
    let variants = by_platform(variants);
    Ok((m.version.clone(), variants))
}

/// In platform order, one build per platform: the lockfile's order.
fn by_platform(mut variants: Vec<Variant>) -> Vec<Variant> {
    variants.sort_unstable_by(|a, b| a.platform.cmp(&b.platform));
    variants.dedup_by(|a, b| a.platform == b.platform);
    variants
}

/// Another lockfile's builds of the runtime `p`, as `(url, integrity)`: one that is also among
/// `p`'s, by its file name, must be the same bytes. (pnpm's Windows Node, and its Bun and Deno,
/// are other archives, and are not compared.)
pub fn check_builds(p: &Package, builds: &[(String, String)], file: &str) -> Result<()> {
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    for (url, integrity) in builds {
        let Some(v) = p.runtime.iter().flatten().find(|v| base(&v.file) == base(url)) else { continue };
        let same = |a: &str, b: &str| {
            let (a, b) = (crate::integrity::Integrity::parse(a), crate::integrity::Integrity::parse(b));
            a.is_ok_and(|a| b.is_ok_and(|b| a == b))
        };
        if !same(&v.integrity, integrity) {
            return Err(Error::new(
                "EINTEGRITY",
                format!("{file} has {url} as {integrity}, and the release lists {}", v.integrity),
            ));
        }
    }
    Ok(())
}

/// The version a system binary reports, for a `devEngines.runtime` that is only checked. Node's
/// is the one `engines.node` is checked against (`JPM_NODE_VERSION` can stand in for it).
fn system_version(name: &str) -> Option<String> {
    if name == "node" {
        return crate::registry::node_version().map(|v| v.text.clone());
    }
    let exe = crate::run::which(name)?;
    let out = std::process::Command::new(exe).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split_whitespace().find_map(|w| semver::parse(w).map(|v| v.text))
}

/// `devEngines.runtime` or `engines.runtime` that does not download: a warning when the system's
/// runtime is missing or outside the range. jpm never fails the install over it.
pub fn check_system(name: &str, range: &str, file: &str) -> Option<String> {
    let range = if range.trim().is_empty() { "*" } else { range };
    if !semver::valid_range(range) {
        return None;
    }
    match system_version(name) {
        None => Some(format!("{file} wants {name} {range}, and there is no {name} on PATH")),
        Some(v) if !semver::satisfies(&v, range) => {
            Some(format!("{file} wants {name} {range}, and the {name} on PATH is {v}"))
        }
        Some(_) => None,
    }
}

/// A lockfile's variant, checked before any of it is used: a platform name, an integrity jpm
/// reads, and a file that is a path inside the release (or an https url), or a package name.
pub fn check_variant(name: &str, v: &Variant) -> std::result::Result<(), String> {
    let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !plain(&v.platform) {
        return Err(format!("variant {:?} is not a platform", v.platform));
    }
    crate::integrity::Integrity::parse(&v.integrity).map_err(|e| e.message)?;
    let ok = match name {
        "node" => v.file.starts_with("https://") || crate::tar::plain(&v.file),
        _ => v.file.starts_with('@') && crate::spec::check_name(&v.file, &v.file).is_ok(),
    };
    if !ok || v.file.bytes().any(|b| b <= b' ' || b == b'"') {
        return Err(format!("variant {} names {:?}, which is not where a {name} build is", v.platform, v.file));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = r#"[
      {"version":"v24.1.0","lts":false},
      {"version":"v23.0.0-rc.1","lts":false},
      {"version":"v22.12.0","lts":"Jod"},
      {"version":"v22.11.0","lts":"Jod"},
      {"version":"v20.18.1","lts":"Iron"}
    ]"#;

    #[test]
    fn picks_the_newest_release_a_range_allows() {
        let index = crate::json::parse(INDEX).unwrap();
        for (range, want) in [
            ("22", "22.12.0"),
            ("^22.0.0", "22.12.0"),
            ("~22.11.0", "22.11.0"),
            ("20 || 22", "22.12.0"),
            (">=23", "24.1.0"),
            ("", "24.1.0"),
            ("latest", "24.1.0"),
            ("lts", "22.12.0"),
            ("iron", "20.18.1"),
            ("Jod", "22.12.0"),
        ] {
            assert_eq!(pick_node(&index, range).unwrap(), want, "{range}");
        }
        assert_eq!(pick_node(&index, "25").unwrap_err().code, "ETARGET");
        assert_eq!(pick_node(&index, "rc/23").unwrap_err().code, "EINVALIDSPEC");
        assert_eq!(pick_node(&index, "nightly").unwrap_err().code, "EINVALIDSPEC");
    }

    #[test]
    fn reads_the_builds_a_shasums_file_lists() {
        let text = "\
dLsPOoAw  bad-hex.tar.gz
74bb0f3a80307c52942dc3ed84517b8f54386770 short.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-linux-x64.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-linux-x64.tar.xz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-linux-armv7l.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-linux-x64-musl.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-darwin-arm64.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-win-x64.zip
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0-headers.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v22.0.0.tar.gz
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  win-x64/node.exe
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  win-x64/node.lib
74bb0f3a80307c529421c3ed84517b8f543867709f41e53cd73df99e6442af4d  node-v21.0.0-linux-arm64.tar.gz
";
        let found: Vec<(String, String)> =
            node_variants(text, "22.0.0", "").into_iter().map(|v| (v.platform, v.file)).collect();
        let want = [
            ("linux-x64", "node-v22.0.0-linux-x64.tar.gz"),
            ("linux-arm", "node-v22.0.0-linux-armv7l.tar.gz"),
            ("linux-x64-musl", "node-v22.0.0-linux-x64-musl.tar.gz"),
            ("darwin-arm64", "node-v22.0.0-darwin-arm64.tar.gz"),
            ("win32-x64", "win-x64/node.exe"),
        ];
        assert_eq!(found, want.map(|(a, b)| (a.to_string(), b.to_string())));
        let v = &node_variants(text, "22.0.0", "https://x/")[0];
        assert_eq!(v.integrity, "sha256-dLsPOoAwfFKUIcPthFF7j1Q4Z3CfQeU81z35nmRCr00=");
        assert_eq!(v.file, "https://x/node-v22.0.0-linux-x64.tar.gz");
    }

    #[test]
    fn picks_this_platforms_build() {
        let v = |p: &str| Variant { platform: p.into(), integrity: String::new(), file: p.into() };
        let all = [v("darwin-x64"), v("linux-x64"), v("linux-x64-musl"), v("win32-x64")];
        let at = |os: &str, cpu: &str, libc: Option<&str>| {
            let p = Platform { os: os.into(), cpu: cpu.into(), libc: libc.map(str::to_string) };
            pick(&all, &p).map(|v| v.platform.clone())
        };
        assert_eq!(at("linux", "x64", Some("glibc")).as_deref(), Some("linux-x64"));
        assert_eq!(at("linux", "x64", None).as_deref(), Some("linux-x64"));
        assert_eq!(at("linux", "x64", Some("musl")).as_deref(), Some("linux-x64-musl"));
        assert_eq!(at("linux", "arm64", Some("glibc")), None);
        // Rosetta and Windows on arm run the x64 build when there is no arm64 one.
        assert_eq!(at("darwin", "arm64", None).as_deref(), Some("darwin-x64"));
        assert_eq!(at("win32", "arm64", None).as_deref(), Some("win32-x64"));
    }

    #[test]
    fn refuses_a_hostile_variant() {
        let sha = "sha256-dLsPOoAwfFKUIcPthFF7j1Q4Z3CfQeU81z35nmRCr00=";
        let v = |platform: &str, integrity: &str, file: &str| Variant {
            platform: platform.into(),
            integrity: integrity.into(),
            file: file.into(),
        };
        assert!(check_variant("node", &v("linux-x64", sha, "node-v1.0.0-linux-x64.tar.gz")).is_ok());
        assert!(check_variant("node", &v("win32-x64", sha, "win-x64/node.exe")).is_ok());
        assert!(check_variant("node", &v("linux-x64-musl", sha, "https://h/x.tar.gz")).is_ok());
        assert!(check_variant("bun", &v("linux-x64", sha, "@oven/bun-linux-x64")).is_ok());
        assert!(check_variant("node", &v("linux-x64", sha, "../../x")).is_err());
        assert!(check_variant("node", &v("linux-x64", sha, "/etc/passwd")).is_err());
        assert!(check_variant("node", &v("Linux X64", sha, "a.tar.gz")).is_err());
        assert!(check_variant("node", &v("linux-x64", "md5-x", "a.tar.gz")).is_err());
        assert!(check_variant("bun", &v("linux-x64", sha, "bun")).is_err());
        assert!(check_variant("deno", &v("linux-x64", sha, "@deno/../x")).is_err());
    }
}
