//! hosted-git-info's cases (tests/conformance/hosted-git-info, see its README) against how jpm
//! reads a dependency spec. Where hosted-git-info reads a hosted repository, jpm must read a git
//! dependency on the same host, repository and ref, however it spells the url it fetches.
//! Where it reads none, jpm must not read one on a hosted host either (npm may still read a
//! plain git url or a tarball there). Built into jpm's own tests from src/spec.rs.

use super::{Kind, parse_dep};
use serde_json::Value;

const FILES: [&str; 6] = ["github", "gitlab", "bitbucket", "sourcehut", "gist", "invalid"];

const DOMAINS: [(&str, &str); 5] = [
    ("github", "github.com"),
    ("gitlab", "gitlab.com"),
    ("bitbucket", "bitbucket.org"),
    ("sourcehut", "git.sr.ht"),
    ("gist", "gist.github.com"),
];

/// The differences jpm keeps, each with why. A rule excuses a case it matches only when jpm
/// reads that case as described, and every rule must excuse at least one case.
const DELIBERATE: [(&str, &str); 5] = [
    ("credentials", "a user or token in an https or git:// url would be written to jpm.lock; jpm refuses it"),
    ("gist", "`gist:` is refused as unsupported, and a gist's url is read as any git url or tarball url"),
    ("space", "git refuses a ref with whitespace, so jpm refuses it when package.json is read"),
    ("bitbucket git://", "a hosted repository is fetched over https however it is written"),
    (
        "colon",
        "no git ref holds a `:`: npm-package-arg reads `key:value` after `#` as an option and skips one it does not know, so npm and jpm take the default branch",
    ),
];

/// Host, repository path (no `.git`) and ref of a git `fetch_spec`. Over ssh the host is
/// `user@host` unless the user is `git`, the one npm reaches a hosted host as.
fn repository(fetch_spec: &str) -> (String, String, String) {
    let (url, committish) = fetch_spec.split_once('#').unwrap_or((fetch_spec, ""));
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (user, host) = authority.rsplit_once('@').unwrap_or(("", authority));
    let (host, path) = match host.split_once(':') {
        // scp-like: `host:path`, the path running on past any `/`.
        Some((h, p)) if !p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, if path.is_empty() { p.to_string() } else { format!("{p}/{path}") })
        }
        Some((h, _)) => (h, path.to_string()),
        None => (host, path.to_string()),
    };
    let host = host.to_ascii_lowercase();
    let host = if scheme == "git+ssh" && user != "git" { format!("{user}@{host}") } else { host };
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    (host, path.to_string(), committish.to_string())
}

#[test]
fn reads_hosted_git_urls_as_hosted_git_info_does() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/conformance/hosted-git-info");
    let mut excused = [0; DELIBERATE.len()];
    let (mut ran, mut failures) = (0, Vec::new());
    for file in FILES {
        let text = std::fs::read_to_string(format!("{dir}/{file}.json")).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        for case in doc["cases"].as_array().unwrap() {
            ran += 1;
            let input = case["input"].as_str().unwrap();
            let want = case["expect"].as_object().map(|e| {
                let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
                let domain = DOMAINS.iter().find(|(t, _)| *t == s("type")).unwrap().1;
                let path = if e["user"].is_null() { s("project") } else { format!("{}/{}", s("user"), s("project")) };
                (domain.to_string(), path, s("committish"), !e["auth"].is_null())
            });
            let got = parse_dep("x", input);
            let read = match &got {
                Ok(s) if s.kind == Kind::Git => Some(repository(&s.fetch_spec)),
                _ => None,
            };
            let hosted = |r: &(String, String, String)| DOMAINS.iter().any(|(_, d)| *d == r.0);
            let agrees = match (&want, &read) {
                (Some((domain, path, committish, _)), Some((h, p, c))) => {
                    h == domain && p == path && c.eq_ignore_ascii_case(committish)
                }
                (Some(_), None) => false,
                (None, read) => !read.as_ref().is_some_and(hosted),
            };
            if agrees {
                continue;
            }
            let refused = got.is_err();
            let rule = match &want {
                Some((.., true)) if refused => Some(0),
                _ if file == "gist" => Some(1),
                Some((_, _, c, _)) if refused && c.contains(char::is_whitespace) => Some(2),
                None if input.starts_with("git://bitbucket.org/") => Some(3),
                Some((d, p, c, _))
                    if c.contains(':') && read.as_ref().is_some_and(|r| (&r.0, &r.1, r.2.as_str()) == (d, p, "")) =>
                {
                    Some(4)
                }
                _ => None,
            };
            match rule {
                Some(r) => excused[r] += 1,
                None => failures.push(format!(
                    "{file}.json {input:?}: npm reads {want:?}, jpm {}",
                    match &got {
                        Ok(s) => format!("{:?} {}", s.kind, s.fetch_spec),
                        Err(e) => format!("refuses it: {}", e.message),
                    }
                )),
            }
        }
    }
    for ((name, why), n) in DELIBERATE.iter().zip(excused) {
        eprintln!("{n} cases differ as jpm means them to ({name}: {why})");
        assert!(n > 0, "the {name} rule excuses nothing: remove it");
    }
    assert!(ran > 600, "only {ran} cases");
    assert!(failures.is_empty(), "{} of {ran} cases:\n{}", failures.len(), failures.join("\n"));
}
