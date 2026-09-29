//! Dependency specs, as `npm-package-arg` reads them: versions, ranges, tags, `npm:` aliases,
//! `workspace:` ranges, tarballs and directories.

use crate::error::{Error, Result};
use crate::semver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Version,
    Range,
    Tag,
    /// Never asks the registry: `fetch_spec` is the range a workspace's version must satisfy.
    Workspace,
    /// `fetch_spec` is an http(s) url as given, or `file:` and a clean relative `/` path.
    Tarball,
    /// `fetch_spec` is `link:` or `file:` and a clean relative `/` path, which may start with
    /// `../`: a directory, linked where it is.
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub raw: String,
    /// The name the dependency is installed under.
    pub name: String,
    /// The registry package to ask for: differs from `name` for an alias.
    pub fetch_name: String,
    pub kind: Kind,
    pub fetch_spec: String,
}

const TARBALL_EXT: [&str; 3] = [".tgz", ".tar.gz", ".tar"];

fn is_url(s: &str) -> bool {
    let lower = s.get(..8).unwrap_or(s).to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn ends_as_tarball(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    TARBALL_EXT.iter().any(|ext| lower.ends_with(ext))
}

/// A CLI argument that names no package, only where one is (a url, a `file:`, `link:`, `./` or
/// `../` path, or a file name ending as a tarball does), as its spec's `fetch_spec`.
pub fn bare_source(arg: &str) -> Result<Option<String>> {
    let pathish = arg.starts_with("file:")
        || arg.starts_with("link:")
        || arg.starts_with("./")
        || arg.starts_with("../")
        || arg.starts_with(".\\")
        || arg.starts_with("..\\");
    if is_url(arg) || pathish {
        return path(arg, arg);
    }
    if !arg.contains('@') && ends_as_tarball(arg) {
        return path(&format!("file:{arg}"), arg);
    }
    Ok(None)
}

/// Where a tarball or directory spec points, as a lockfile spells it: a url as given, a path
/// joined onto `base`, the root-relative directory of the package.json that declared it.
pub fn source_at(fetch_spec: &str, base: &str) -> String {
    for protocol in ["file:", "link:"] {
        if let Some(path) = fetch_spec.strip_prefix(protocol) {
            return format!("{protocol}{}", join_path(base, path));
        }
    }
    fetch_spec.to_string()
}

/// A CLI argument such as `foo@^1.2`, `@scope/foo@latest` or `foo@npm:bar@^1`.
pub fn parse_spec(arg: &str) -> Result<Spec> {
    let (name, spec) = split_at(arg);
    build(name, spec, arg)
}

/// A package.json entry, already split.
pub fn parse_dep(name: &str, spec: &str) -> Result<Spec> {
    let raw = if spec.is_empty() { name.to_string() } else { format!("{name}@{spec}") };
    build(name, spec, &raw)
}

/// `@scope/foo` -> `@scope%2ffoo`, the registry path form, after checking the name.
pub fn escape_name(name: &str) -> Result<String> {
    check_name(name, name)?;
    Ok(name.replacen('/', "%2f", 1))
}

/// Split `name@spec` on the `@` that is not a scope marker.
fn split_at(arg: &str) -> (&str, &str) {
    match arg.get(1..).and_then(|s| s.find('@')) {
        Some(i) => (&arg[..=i], &arg[i + 2..]),
        None => (arg, ""),
    }
}

fn build(name: &str, spec: &str, raw: &str) -> Result<Spec> {
    check_name(name, raw)?;
    let mut fetch_name = name.to_string();
    let mut s = spec.trim().to_string();
    unsupported(&s, raw)?;
    let source = path(&s, raw)?;
    let mut local = false;
    if let Some(rest) = s.strip_prefix("workspace:") {
        local = true;
        let (n, r) = workspace(name, rest, raw)?;
        fetch_name = n;
        s = r;
    } else if let Some(rest) = s.strip_prefix("npm:") {
        // `name@npm:pkg@range` installs the registry package `pkg` under `name`.
        let (n, r) = split_at(rest);
        check_name(n, raw)?;
        fetch_name = n.to_string();
        s = r.trim().to_string();
        if s.starts_with("npm:") || s.starts_with("workspace:") {
            return Err(invalid(format!("Invalid alias of package \"{raw}\": an alias cannot point at an alias")));
        }
    }
    let make = |kind, fetch_spec: String| Spec {
        raw: raw.to_string(),
        name: name.to_string(),
        fetch_name: fetch_name.clone(),
        kind,
        fetch_spec,
    };
    if let Some(source) = source {
        let dir = source.starts_with("link:") || source.starts_with("file:") && !ends_as_tarball(&source);
        return Ok(make(if dir { Kind::Directory } else { Kind::Tarball }, source));
    }
    if local {
        return Ok(make(Kind::Workspace, s));
    }
    if s.is_empty() || s == "*" {
        return Ok(make(Kind::Range, "*".into()));
    }
    if semver::valid_range(&s) {
        let kind = if semver::parse(&s).is_some() { Kind::Version } else { Kind::Range };
        return Ok(make(kind, s));
    }
    if !url_safe(&s) {
        return Err(invalid(format!("Invalid tag \"{s}\" of package \"{raw}\": tags must be url-safe")));
    }
    Ok(make(Kind::Tag, s))
}

/// The forms other managers read that jpm does not yet, refused by name rather than as a bad tag.
fn unsupported(s: &str, raw: &str) -> Result<()> {
    const PROTOCOLS: [&str; 5] = ["patch:", "portal:", "catalog:", "jsr:", "exec:"];
    const GIT: [&str; 10] = [
        "git:",
        "git+https:",
        "git+http:",
        "git+ssh:",
        "git+file:",
        "git@",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ];
    let lower = s.to_ascii_lowercase();
    if let Some(p) = PROTOCOLS.iter().find(|p| lower.starts_with(*p)) {
        return Err(invalid(format!("\"{p}\" dependencies are not supported yet (in package \"{raw}\")")));
    }
    // `user/repo` is github shorthand, with an optional `#ref`.
    let repo = s.split('#').next().unwrap_or(s);
    let shorthand = repo.split_once('/').is_some_and(|(user, name)| {
        let ok = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
        ok(user) && ok(name) && !user.starts_with(['.', '-'])
    });
    if shorthand || GIT.iter().any(|p| lower.starts_with(p)) {
        return Err(invalid(format!("git dependencies are not supported yet: {s} (in package \"{raw}\")")));
    }
    Ok(())
}

/// A tarball's or a directory's `fetch_spec`, or `None` when `s` is neither: a url, or a path
/// relative to package.json. `file:` (or a bare `./` path) ending as a tarball does is a
/// tarball; any other is a directory, as every `link:` is.
fn path(s: &str, raw: &str) -> Result<Option<String>> {
    if is_url(s) {
        if !valid_url(s) {
            return Err(invalid(format!("Invalid url \"{s}\" of package \"{raw}\"")));
        }
        return Ok(Some(s.to_string()));
    }
    let (protocol, path) = if let Some(p) = s.strip_prefix("file:") {
        ("file:", p)
    } else if let Some(p) = s.strip_prefix("link:") {
        ("link:", p)
    } else if ["/", "\\", "./", ".\\", "../", "..\\", "~/", "~\\"].iter().any(|p| s.starts_with(p)) {
        ("file:", s)
    } else {
        return Ok(None);
    };
    let clean = path.replace('\\', "/");
    let joined = join_path("", &clean);
    // Checked once normalized: `./C:/x` joins to `C:/x`. A `:` is a drive or a stream on Windows.
    if clean.starts_with('/') || clean.starts_with('~') || joined.contains(':') {
        return Err(invalid(format!("Invalid path \"{path}\" of package \"{raw}\": give it relative to package.json")));
    }
    if protocol == "link:" && ends_as_tarball(&joined) {
        return Err(invalid(format!("Invalid path \"{path}\" of package \"{raw}\": link: names a directory")));
    }
    Ok(Some(format!("{protocol}{joined}")))
}

fn valid_url(s: &str) -> bool {
    let rest = s.split_once("://").map_or("", |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !s.contains(char::is_whitespace)
}

/// `path` under `base`, both `/`-separated, `.` and empty segments dropped and `..` taking one
/// off where there is one to take.
pub fn join_path(base: &str, path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in base.split('/').chain(path.split('/')) {
        match part {
            "" | "." => {}
            ".." if out.last().is_some_and(|l| *l != "..") => {
                out.pop();
            }
            _ => out.push(part),
        }
    }
    out.join("/")
}

/// pnpm's `workspace:` protocol: `*`, `^`, `~` or nothing take any version; a range one that
/// fits; `<pkg>@<range>` names another workspace.
fn workspace(name: &str, rest: &str, raw: &str) -> Result<(String, String)> {
    let mut fetch_name = name.to_string();
    let mut s = rest.trim().to_string();
    if s.get(1..).is_some_and(|t| t.contains('@')) {
        let (n, r) = split_at(&s);
        check_name(n, raw)?;
        fetch_name = n.to_string();
        s = r.trim().to_string();
    }
    if s.is_empty() || s == "^" || s == "~" {
        s = "*".into();
    }
    if !semver::valid_range(&s) {
        let why = if s.starts_with('.') || s.starts_with('/') {
            "a workspace is named, not given by path"
        } else {
            "not a range"
        };
        return Err(invalid(format!("Invalid workspace spec \"{rest}\" of package \"{raw}\": {why}")));
    }
    Ok((fetch_name, s))
}

/// What `encodeURIComponent` leaves alone.
fn url_safe(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b))
}

pub fn check_name(name: &str, raw: &str) -> Result<()> {
    let bad = |why: &str| Err(invalid(format!("Invalid package name \"{name}\" of package \"{raw}\": {why}")));
    if name.is_empty() {
        return bad("name is empty");
    }
    if name.starts_with('.') || name.starts_with('_') {
        return bad("name starts with . or _");
    }
    if name.starts_with('-') {
        return bad("name starts with a hyphen");
    }
    if name == "node_modules" || name == "favicon.ico" {
        return bad("name is reserved");
    }
    let (scope, pkg) = match name.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((s, p)) if !s.is_empty() && !s.contains('/') => (Some(s), p),
            _ => return bad("name is malformed"),
        },
        None => (None, name),
    };
    if pkg.is_empty() || pkg.contains('/') {
        return bad("name is malformed");
    }
    if scope.is_some_and(|s| !url_safe(s)) {
        return bad("scope has url-unsafe characters");
    }
    if !url_safe(pkg) {
        return bad("name has url-unsafe characters");
    }
    if pkg == "." || pkg == ".." {
        return bad("name is a path segment");
    }
    Ok(())
}

fn invalid(message: String) -> Error {
    Error::new("EINVALIDSPEC", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_kinds() {
        let s = parse_spec("foo@^1.2").unwrap();
        assert_eq!((s.name.as_str(), s.kind, s.fetch_spec.as_str()), ("foo", Kind::Range, "^1.2"));
        let s = parse_spec("@scope/foo@latest").unwrap();
        assert_eq!((s.name.as_str(), s.kind), ("@scope/foo", Kind::Tag));
        let s = parse_spec("foo").unwrap();
        assert_eq!((s.kind, s.fetch_spec.as_str()), (Kind::Range, "*"));
        let s = parse_spec("foo@1.2.3").unwrap();
        assert_eq!(s.kind, Kind::Version);
        let s = parse_spec("sw@npm:string-width@^4").unwrap();
        assert_eq!((s.name.as_str(), s.fetch_name.as_str(), s.fetch_spec.as_str()), ("sw", "string-width", "^4"));
        let s = parse_dep("a", "workspace:^").unwrap();
        assert_eq!((s.kind, s.fetch_spec.as_str()), (Kind::Workspace, "*"));
        let s = parse_dep("a", "workspace:b@^1").unwrap();
        assert_eq!(s.fetch_name, "b");
    }

    #[test]
    fn reads_tarballs() {
        let s = parse_dep("lib", "file:./vendor/../vendor/lib-1.0.0.tgz").unwrap();
        assert_eq!((s.kind, s.fetch_spec.as_str()), (Kind::Tarball, "file:vendor/lib-1.0.0.tgz"));
        let s = parse_dep("lib", "https://example.com/lib.tgz").unwrap();
        assert_eq!(s.kind, Kind::Tarball);
        assert!(parse_dep("lib", "file:/abs/lib.tgz").is_err());
        for drive in ["file:C:/x.tgz", "file:./C:/x.tgz", "./x/../C:\\x.tgz", "file:c:x.tgz", "file:a:s.tgz"] {
            assert!(parse_dep("lib", drive).is_err(), "{drive}");
        }
        assert_eq!(bare_source("lib-1.0.0.tgz").unwrap().as_deref(), Some("file:lib-1.0.0.tgz"));
        assert_eq!(bare_source("vue@^3").unwrap(), None);
        assert_eq!(source_at("file:../x.tgz", "packages/a"), "file:packages/x.tgz");
    }

    #[test]
    fn reads_directories() {
        let dir = |spec: &str| parse_dep("d", spec).map(|s| (s.kind, s.fetch_spec));
        let is = |spec: &str, want: &str| assert_eq!(dir(spec).unwrap(), (Kind::Directory, want.to_string()), "{spec}");
        is("file:../dir", "file:../dir");
        is("./dir", "file:dir");
        is("../a/./b/../c", "file:../a/c");
        is("file:.", "file:");
        is("link:../../x/", "link:../../x");
        is("link:x\\y", "link:x/y");
        // A tarball by its name, and a path that leaves package.json's side are not directories.
        assert_eq!(dir("./x.tgz").unwrap().0, Kind::Tarball);
        for bad in ["link:/abs", "link:~/x", "link:C:/x", "link:./c:x", "file:/abs/dir", "link:x.tgz", "link:a:b"] {
            assert!(dir(bad).is_err(), "{bad}");
        }
        assert_eq!(bare_source("link:../x").unwrap().as_deref(), Some("link:../x"));
        assert_eq!(bare_source("./libs/x").unwrap().as_deref(), Some("file:libs/x"));
        assert_eq!(source_at("link:../../x", "packages/a"), "link:x");
        assert_eq!(source_at("file:../../../x", "packages/a"), "file:../x");
    }

    #[test]
    fn refuses_bad_names() {
        for bad in ["", ".x", "_x", "-x", "node_modules", "@/x", "a/b", "@s/", "a b", "@s/.."] {
            assert!(parse_dep(bad, "1").is_err(), "{bad:?}");
        }
        assert!(parse_dep("foo", "not a tag").is_err());
        assert!(parse_dep("foo", "not/a tag").unwrap_err().message.starts_with("Invalid tag"));
    }

    #[test]
    fn names_the_forms_it_does_not_read() {
        let msg = |spec: &str| parse_dep("x", spec).unwrap_err().message;
        assert_eq!(msg("catalog:"), r#""catalog:" dependencies are not supported yet (in package "x@catalog:")"#);
        for spec in ["patch:x@1#p.patch", "portal:../x", "catalog:react18", "jsr:@std/fs@1", "exec:./gen.js"] {
            let prefix = &spec[..=spec.find(':').unwrap()];
            assert!(msg(spec).starts_with(&format!("\"{prefix}\" dependencies are not supported yet")), "{spec}");
        }
        assert_eq!(
            msg("github:watson/ci-info#v1"),
            r#"git dependencies are not supported yet: github:watson/ci-info#v1 (in package "x@github:watson/ci-info#v1")"#
        );
        let git = [
            "watson/ci-info",
            "watson/ci-info#semver:^3",
            "git+https://github.com/a/b.git",
            "git+ssh://git@github.com/a/b",
            "git://github.com/a/b",
            "git@github.com:a/b.git",
        ];
        for spec in git {
            assert!(msg(spec).starts_with("git dependencies are not supported yet"), "{spec}");
        }
        // Still read as before.
        for spec in ["npm:y@1", "workspace:*", "https://example.com/y.tgz", "file:y.tgz", "latest", "^1"] {
            assert!(parse_dep("x", spec).is_ok(), "{spec}");
        }
        assert_eq!(escape_name("@a/b").unwrap(), "@a%2fb");
    }
}
