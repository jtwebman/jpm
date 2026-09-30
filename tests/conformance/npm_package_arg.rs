//! npm-package-arg's own test cases (tests/conformance/npm-package-arg, see its README), read
//! as jpm reads a spec: a CLI argument as `jpm add` does, an `npa.resolve(name, spec)` as a
//! package.json entry. What jpm has of npa's result is compared: the kind, the name, the
//! registry name and range of an alias, where a path or url points, and a repository's url and
//! ref. Paths are npa's posix ones, joined onto its `where`. Built into jpm's own tests from
//! src/spec.rs.

use super::*;
use serde_json::Value;

const FILES: [(&str, &str); 8] = [
    ("basic", include_str!("npm-package-arg/basic.json")),
    ("github", include_str!("npm-package-arg/github.json")),
    ("gitlab", include_str!("npm-package-arg/gitlab.json")),
    ("bitbucket", include_str!("npm-package-arg/bitbucket.json")),
    ("invalid-url", include_str!("npm-package-arg/invalid-url.json")),
    ("posix", include_str!("npm-package-arg/posix.json")),
    ("realize-package-specifier", include_str!("npm-package-arg/realize-package-specifier.json")),
    ("windows", include_str!("npm-package-arg/windows.json")),
];

const ABSOLUTE: &str = "jpm takes a path only relative to package.json: jpm.lock reads the same on every machine";
const HOME: &str = "a home directory differs per machine: jpm takes a path only relative to package.json";
const NO_PATH: &str = "an ssh url with a port and no path names no repository";
const SUBDIR: &str = "a directory inside a repository (#path:) is not supported yet, and said so";
const SPACED: &str = "a ref with spaces is none git can hold: refused before asking the remote";

/// Where jpm reads a spec otherwise than npm does on purpose: the input, and why. Each is one
/// jpm refuses.
const DIFFERENT: &[(&str, &str)] = &[
    ("/path/to/foo", ABSOLUTE),
    ("/path/to/foo.tar", ABSOLUTE),
    ("/path/to/foo.tgz", ABSOLUTE),
    ("/path/to/package.tar.gz", ABSOLUTE),
    ("/path/to/package.tgz", ABSOLUTE),
    ("/path/to/package.tar", ABSOLUTE),
    ("/path/to/package.tarXgz", ABSOLUTE),
    ("/path/to/package.tar_gz", ABSOLUTE),
    ("/test%dir", ABSOLUTE),
    ("file:/test%dir", ABSOLUTE),
    ("file:/~path/to/foo", ABSOLUTE),
    ("file:/.path/to/foo", ABSOLUTE),
    ("file:///path/to/foo", ABSOLUTE),
    ("file:/path/to/foo", ABSOLUTE),
    ("file://path/to/foo", ABSOLUTE),
    ("file:////path/to/foo", ABSOLUTE),
    (r"C:\x\y\z", ABSOLUTE),
    (r"foo@C:\x\y\z", ABSOLUTE),
    (r"foo@file:///C:\x\y\z", ABSOLUTE),
    (r"foo@file://C:\x\y\z", ABSOLUTE),
    (r"file:///C:\x\y\z", ABSOLUTE),
    (r"file://C:\x\y\z", ABSOLUTE),
    ("foo@/foo/bar/baz", ABSOLUTE),
    (r"foo@git+file://C:\x\y\z", "a repository url with a backslash is refused, and this one names an absolute path"),
    ("file:~/path/to/foo", HOME),
    ("file:/~/path/to/foo", HOME),
    ("git+ssh://mydomain.com:1234#1.2.3", NO_PATH),
    ("git@github.com:12345", NO_PATH),
    ("git@github.com:12345/", NO_PATH),
    (
        "git+ssh://username:password@mydomain.com:1234/hey#1.2.3",
        "a password would be written to jpm.lock: ssh keys or git's credential helper hold it",
    ),
    ("git+file://path/to/repo#1.2.3", "git+file:// with a host: git clones only a local path, so jpm takes none"),
    ("git+http://foo.com/bar", "jpm fetches a repository over https, not in the clear"),
    ("user/foo#path:dist", SUBDIR),
    ("user/foo#1234::path:dist", SUBDIR),
    ("user..blerg--/..foo-js# . . . . . some . tags / / /", SPACED),
    ("gitlab:user..blerg--/..foo-js# . . . . . some . tags / / /", SPACED),
    ("bitbucket:user..blerg--/..foo-js# . . . . . some . tags / / /", SPACED),
];

/// What jpm made of a row's input.
struct Read {
    name: Option<String>,
    fetch_name: Option<String>,
    kind: Kind,
    fetch_spec: String,
}

fn input(row: &Value) -> String {
    match row["arg"].as_str() {
        Some(arg) => arg.to_string(),
        None => format!("resolve({}, {})", row["name"], row["spec"]),
    }
}

fn read(row: &Value) -> Result<Read> {
    if let Some(arg) = row["arg"].as_str() {
        // As `jpm add` reads it: a source that names no package first, then `name@spec`.
        if let Some(source) = bare_source(arg)? {
            let kind = if is_git(&source) { Kind::Git } else { parse_dep("x", &source)?.kind };
            return Ok(Read { name: None, fetch_name: None, kind, fetch_spec: source });
        }
        let s = parse_spec(arg)?;
        return Ok(Read { name: Some(s.name), fetch_name: Some(s.fetch_name), kind: s.kind, fetch_spec: s.fetch_spec });
    }
    // npa.resolve(null, spec) reads a spec with no name; a package.json entry always has one.
    let name = row["name"].as_str();
    let s = parse_dep(name.unwrap_or("x"), row["spec"].as_str().unwrap_or(""))?;
    Ok(Read { name: name.map(|_| s.name), fetch_name: Some(s.fetch_name), kind: s.kind, fetch_spec: s.fetch_spec })
}

/// npa's type as a jpm kind, and whether a tarball is a url.
fn kind_of(t: &str) -> Option<(Kind, bool)> {
    Some(match t {
        "version" => (Kind::Version, false),
        "range" => (Kind::Range, false),
        "tag" => (Kind::Tag, false),
        "git" => (Kind::Git, false),
        "directory" => (Kind::Directory, false),
        "file" => (Kind::Tarball, false),
        "remote" => (Kind::Tarball, true),
        _ => return None,
    })
}

/// `/`-joined and cleaned, from the root: how npa's posix `path.resolve` spells a path.
fn absolute(base: &str, path: &str) -> String {
    format!("/{}", join_path(&base.replace('\\', "/"), path))
}

/// A repository url with what does not change the repository taken off: `git+`, ssh's
/// scp-like `host:path` spelled as a url, and `.git` and case on a hosted repository.
fn repo(url: &str) -> String {
    let url = url.strip_prefix("git+").unwrap_or(url);
    let url = if url.contains("://") { url.to_string() } else { format!("ssh://{url}") };
    let (scheme, rest) = url.split_once("://").unwrap_or(("", &url));
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (userhost, after) = authority.rsplit_once(':').filter(|(h, _)| !h.ends_with(']')).unwrap_or((authority, ""));
    let (authority, path) = if scheme == "ssh" && !after.is_empty() && !after.bytes().all(|b| b.is_ascii_digit()) {
        (userhost.to_string(), if path.is_empty() { after.to_string() } else { format!("{after}/{path}") })
    } else {
        (authority.to_string(), path.to_string())
    };
    let host = authority.rsplit_once('@').map_or(authority.as_str(), |(_, h)| h);
    if HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h.domain)) {
        let path = path.trim_end_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        return format!("{scheme}://{}/{path}", authority.to_ascii_lowercase());
    }
    format!("{scheme}://{authority}/{path}")
}

/// How jpm's reading of a row differs from npa's, one line per field.
fn differences(row: &Value) -> Vec<String> {
    let got = read(row);
    if !row["throws"].is_null() {
        return match got {
            Ok(r) => vec![format!("npa refuses it; jpm reads {:?} {}", r.kind, r.fetch_spec)],
            Err(_) => vec![],
        };
    }
    let r = match got {
        Ok(r) => r,
        Err(e) => return vec![format!("jpm refuses it: {}", e.message)],
    };
    let want = &row["expect"];
    let mut out = Vec::new();
    let mut differ = |field: &str, npa: &dyn std::fmt::Debug, jpm: &dyn std::fmt::Debug| {
        out.push(format!("{field}: npa {npa:?}, jpm {jpm:?}"));
    };
    if let Some(name) = want.get("name").filter(|n| n.is_null() || n.is_string())
        && name.as_str() != r.name.as_deref()
    {
        differ("name", name, &r.name);
    }
    if let Some(escaped) = want.get("escapedName").filter(|n| n.is_null() || n.is_string()) {
        let jpm = r.name.as_deref().map(|n| escape_name(n).unwrap_or_default());
        if escaped.as_str() != jpm.as_deref() {
            differ("escapedName", escaped, &jpm);
        }
    }
    // An alias is what it points at, under its own name.
    let (target, alias) = match want["type"].as_str() {
        Some("alias") => (&want["subSpec"], true),
        _ => (want, false),
    };
    if alias {
        if target["name"].as_str() != r.fetch_name.as_deref() {
            differ("subSpec.name", &target["name"], &r.fetch_name);
        }
    } else if r.name.is_some() && r.fetch_name != r.name {
        differ("alias", &Value::Null, &r.fetch_name);
    }
    if let Some(t) = target["type"].as_str() {
        match kind_of(t) {
            Some((kind, url)) if kind == r.kind && (kind != Kind::Tarball || url == is_url(&r.fetch_spec)) => {}
            _ => differ("type", &t, &r.kind),
        }
    }
    let where_ = row["where"].as_str().or(want["where"].as_str());
    match (&target["fetchSpec"], r.kind) {
        (Value::String(npa), Kind::Directory | Kind::Tarball) if !is_url(&r.fetch_spec) => {
            let path = r.fetch_spec.split_once(':').map_or("", |p| p.1);
            match where_ {
                Some(base) if absolute(base, path) == *npa => {}
                Some(base) => differ("fetchSpec", npa, &absolute(base, path)),
                None => differ("fetchSpec", npa, &r.fetch_spec),
            }
        }
        (Value::String(npa), Kind::Git) => {
            let (url, _) = r.fetch_spec.split_once('#').unwrap_or((&r.fetch_spec, ""));
            if repo(npa) != repo(url) {
                differ("fetchSpec", npa, &url);
            }
        }
        (Value::String(npa), _) if *npa != r.fetch_spec => differ("fetchSpec", npa, &r.fetch_spec),
        _ => {}
    }
    if r.kind == Kind::Git {
        let (url, git_ref) = r.fetch_spec.split_once('#').unwrap_or((&r.fetch_spec, ""));
        let range = git_ref.strip_prefix("semver:");
        let committish = Some(git_ref).filter(|c| range.is_none() && !c.is_empty());
        if let Some(npa) = want.get("gitCommittish").filter(|c| c.as_str() != committish) {
            differ("gitCommittish", npa, &committish);
        }
        if let Some(npa) = want.get("gitRange").filter(|c| c.as_str() != range) {
            differ("gitRange", npa, &range);
        }
        if let Some(npa) = want.get("gitSubdir").filter(|c| !c.is_null()) {
            differ("gitSubdir", npa, &None::<&str>);
        }
        if let Some(t) = want["hosted"]["type"].as_str() {
            let host = HOSTS.iter().find(|h| h.prefix.strip_suffix(':') == Some(t)).map(|h| h.domain);
            if !host.is_some_and(|h| repo(url).contains(&format!("{h}/"))) {
                differ("hosted.type", &t, &url);
            }
        }
    }
    out
}

#[test]
fn reads_specs_as_npm_package_arg_does() {
    let mut rows = 0;
    let mut wrong = Vec::new();
    let mut unused: Vec<&str> = DIFFERENT.iter().map(|(i, _)| *i).collect();
    for (file, text) in FILES {
        let table: Vec<Value> = serde_json::from_str(text).unwrap();
        for row in &table {
            rows += 1;
            let arg = input(row);
            let diff = differences(row);
            if DIFFERENT.iter().any(|(i, _)| *i == arg) {
                unused.retain(|i| *i != arg);
                if read(row).is_ok() {
                    wrong.push(format!("{file}: {arg}\n    jpm reads it now; npa: {}", row["expect"]));
                }
                continue;
            }
            if !diff.is_empty() {
                wrong.push(format!("{file}: {arg}\n    {}", diff.join("\n    ")));
            }
        }
    }
    assert!(rows > 150, "{rows} rows");
    assert!(wrong.is_empty(), "{} of {rows} read otherwise than npm does:\n{}", wrong.len(), wrong.join("\n"));
    assert!(unused.is_empty(), "no such row: {unused:?}");
}
