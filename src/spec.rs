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
    /// `fetch_spec` is a repository url as a lockfile spells it, `#`, and a ref (see `git`).
    Git,
    /// `runtime:<range>` on node, bun or deno: `fetch_spec` is the range (see `runtime`).
    Runtime,
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

/// A CLI argument that names no package, only where one is (a git repository, a url, a `file:`,
/// `link:`, `./` or `../` path, or a file name ending as a tarball does), as its spec's
/// `fetch_spec`.
pub fn bare_source(arg: &str) -> Result<Option<String>> {
    if let Some(repo) = git(arg, arg)? {
        return Ok(Some(repo));
    }
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
    Ok(match name.strip_prefix('@').and_then(|n| n.split_once('/')) {
        Some((scope, pkg)) => format!("@{}%2f{}", encode_segment(scope), encode_segment(pkg)),
        None => encode_segment(name),
    })
}

/// Split `name@spec` on the `@` that is not a scope marker.
fn split_at(arg: &str) -> (&str, &str) {
    match crate::graph::name_end(arg) {
        Some(at) => (&arg[..at], &arg[at + 1..]),
        None => (arg, ""),
    }
}

fn build(name: &str, spec: &str, raw: &str) -> Result<Spec> {
    check_name(name, raw)?;
    let mut fetch_name = name.to_string();
    let mut s = spec.trim().to_string();
    // The root's and workspaces' `patch:` ranges are read before this (`rules`); a builtin one
    // is only its range. A published package's names a file in its own repository, which its
    // tarball does not carry (@yarnpkg/core's got): nothing can apply it, so the version it
    // patches is installed as it is.
    if let Some((range, patch)) = crate::patch::yarn(name, &s) {
        if patch.is_some() {
            static TOLD: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
            let mut told = TOLD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !told.contains(&s) {
                told.push(s.clone());
                crate::ui::warn(&format!(
                    "a dependency on {raw} names a yarn patch only its own repository has; {name} is installed without it"
                ));
            }
        }
        return build(name, &range, raw);
    }
    if s.starts_with("patch:") {
        return Err(invalid(format!("not a patch: range jpm reads, one inside another (in package \"{name}\")")));
    }
    // jsr's packages from its npm registry, as pnpm reads them: `jsr:@s/n@r` (or `jsr:r` under
    // the jsr name) is `npm:@jsr/s__n@r`, from npm.jsr.io unless `@jsr:registry` says otherwise.
    if let Some(rest) = s.strip_prefix("jsr:") {
        let (jsr, range) = if rest.starts_with('@') { split_at(rest) } else { (name, rest) };
        let npm = jsr
            .strip_prefix('@')
            .and_then(|b| b.split_once('/'))
            .map(|(scope, n)| format!("@jsr/{scope}__{n}"))
            .ok_or_else(|| invalid(format!("\"{raw}\" names no jsr package (@scope/name)")))?;
        let range = if range.trim().is_empty() { "*" } else { range.trim() };
        return build(name, &format!("npm:{npm}@{range}"), raw);
    }
    unsupported(&s, raw)?;
    if let Some(range) = s.strip_prefix(crate::runtime::PROTOCOL) {
        if !crate::runtime::NAMES.contains(&name) {
            return Err(invalid(format!("\"runtime:\" is for node, bun and deno, not \"{raw}\"")));
        }
        let range = range.trim().to_string();
        return Ok(Spec {
            raw: raw.to_string(),
            name: name.into(),
            fetch_name: name.into(),
            kind: Kind::Runtime,
            fetch_spec: range,
        });
    }
    // pnpm's `workspace:<path>` links the directory there, as `link:` does (drizzle's
    // `workspace:../drizzle-typebox/dist`, a workspace's build output).
    if let Some(dir) = s.strip_prefix("workspace:").filter(|p| p.starts_with("./") || p.starts_with("../")) {
        return build(name, &format!("link:{dir}"), raw);
    }
    let repo = git(&s, raw)?;
    let source = if repo.is_some() { None } else { path(&s, raw)? };
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
    if let Some(repo) = repo {
        return Ok(make(Kind::Git, repo));
    }
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
        // `2.0.0-Beata🎉` was meant as a version: say why it is not one.
        if s.trim_start_matches(['v', '=']).starts_with(|c: char| c.is_ascii_digit()) {
            return Err(invalid(format!(
                "Invalid version \"{s}\" of package \"{raw}\": not semver (a prerelease or build takes only \
                 letters, digits and `-`, in `.`-separated parts), nor a tag (tags are url-safe)"
            )));
        }
        return Err(invalid(format!("Invalid tag \"{s}\" of package \"{raw}\": tags must be url-safe")));
    }
    Ok(make(Kind::Tag, s))
}

/// The forms other managers read that jpm does not yet, refused by name rather than as a bad tag.
fn unsupported(s: &str, raw: &str) -> Result<()> {
    const PROTOCOLS: [&str; 3] = ["catalog:", "exec:", "gist:"];
    let lower = s.to_ascii_lowercase();
    if let Some(p) = PROTOCOLS.iter().find(|p| lower.starts_with(*p)) {
        return Err(invalid(format!("\"{p}\" dependencies are not supported yet (in package \"{raw}\")")));
    }
    Ok(())
}

/// A host whose repositories npm reads in every spelling (hosted-git-info's hosts, but gist):
/// `<prefix>user/repo`, its https page, and its https, git:// and ssh urls.
pub struct Host {
    pub prefix: &'static str,
    pub domain: &'static str,
    /// `ssh://` is read as `git+ssh://`, as npm reads it for all but sourcehut.
    ssh: bool,
}

pub const HOSTS: [Host; 4] = [
    Host { prefix: "github:", domain: "github.com", ssh: true },
    Host { prefix: "gitlab:", domain: "gitlab.com", ssh: true },
    Host { prefix: "bitbucket:", domain: "bitbucket.org", ssh: true },
    Host { prefix: "sourcehut:", domain: "git.sr.ht", ssh: false },
];

impl Host {
    /// The host `host` names, `www.` or not.
    fn named(host: &str) -> Option<&'static Host> {
        let www = host.get(..4).is_some_and(|w| w.eq_ignore_ascii_case("www."));
        let bare = if www { &host[4..] } else { host };
        HOSTS.iter().find(|h| bare.eq_ignore_ascii_case(h.domain))
    }

    /// The host of a url after its scheme (`[user@]host[:port or path][/path]`).
    fn over(rest: &str) -> Option<&'static Host> {
        let authority = rest.split('/').next().unwrap_or(rest);
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        Host::named(host.split(':').next().unwrap_or(host))
    }

    /// The repository a url's path names, `.git` and a trailing `/` dropped: `user/repo`, a
    /// gitlab group's `group/sub/repo`, sourcehut's `~user/repo`.
    fn repo(&self, path: &str) -> Option<String> {
        let path = path.trim_end_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        let (owner, name) = path.rsplit_once('/')?;
        let mut owner = owner.split('/');
        let first = owner.next().unwrap_or_default();
        let chars = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
        let lead = |p: &str| chars(p) && !p.starts_with(['.', '-']);
        let user = if self.domain == "git.sr.ht" { first.strip_prefix('~').is_some_and(lead) } else { lead(first) };
        // Only gitlab has groups within groups.
        let groups = if self.domain == "gitlab.com" { owner.all(lead) } else { owner.next().is_none() };
        (user && groups && chars(name) && name != "." && name != "..").then(|| path.to_string())
    }

    /// The url jpm fetches `repo` from, and a lockfile names it by: sourcehut serves no
    /// repository at `.git`.
    fn https(&self, repo: &str) -> String {
        let git = if self.domain == "git.sr.ht" { "" } else { ".git" };
        format!("git+https://{}/{repo}{git}", self.domain)
    }
}

/// A git spec's `fetch_spec`, or `None` when `s` is not one: the repository as a lockfile spells
/// it, `#`, and the ref as written. A hosted repository over https or `git://` (`github:u/r`,
/// `u/r`, `git+https://github.com/u/r`) is always the host's own https url (`Host::https`),
/// and over ssh always reached as `git@`, as npm does; any other url keeps its spelling, the
/// scheme lowercased. The ref is empty for the default branch, a commit, a branch or tag, or
/// `semver:<range>` over the tags. Nothing here reaches git as an option: a url, host or user
/// starting with `-` is refused, and so are credentials in a url that is not ssh, which would
/// end up in jpm.lock.
fn git(s: &str, raw: &str) -> Result<Option<String>> {
    let (repo, mut committish) = s.split_once('#').unwrap_or((s, ""));
    let lower = repo.to_ascii_lowercase();
    let bad = |why: &str| Err(invalid(format!("Invalid git spec \"{s}\" of package \"{raw}\": {why}")));
    let github = &HOSTS[0];
    // `u/r` is github's, but `u/r/` a directory and `u/r.tgz` a tarball, as npm reads them.
    let bare = !lower.contains(':') && !repo.ends_with('/') && !ends_as_tarball(repo) && github.repo(repo).is_some();
    let short = HOSTS.iter().find(|h| lower.starts_with(h.prefix)).map(|h| (h, &repo[h.prefix.len()..]));
    let short = short.or_else(|| bare.then_some((github, repo)));
    let url = if let Some((host, path)) = short {
        // npm drops a user or password written before the repository (`github:user@u/r`).
        let path = path.split_once('@').filter(|(auth, _)| !auth.contains('/')).map_or(path, |(_, p)| p);
        let Some(path) = host.repo(path) else { return bad("give the repository as user/repo") };
        host.https(&path)
    } else if let Some(url) = scp(repo) {
        url
    } else if lower.starts_with("git+http://") {
        return bad("fetch it over https");
    } else if ["git+https://", "git+ssh://", "git://", "git+file://"].iter().any(|p| lower.starts_with(p)) {
        let at = lower.find("://").unwrap_or(0) + 3;
        format!("{}{}", &lower[..at], &repo[at..])
    } else if lower.starts_with("ssh://") && Host::over(&repo[6..]).is_some_and(|h| h.ssh) {
        format!("git+ssh://{}", &repo[6..])
    } else if let Some((url, tree)) = hosted_page(repo) {
        committish = tree.unwrap_or(committish);
        url
    } else {
        return Ok(None);
    };
    let at = url.find("://").unwrap_or(0) + 3;
    let (scheme, rest) = (&url[..at], &url[at..]);
    let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
    let (user, host) = authority.rsplit_once('@').unwrap_or(("", authority));
    // `host:path` is ssh's scp-like form; `host:22` a port. An IPv6 host is `[...]`.
    let (host, after) = match host.strip_prefix('[').and_then(|h| h.split_once(']')) {
        Some((v6, rest)) if rest.is_empty() || rest.starts_with(':') => {
            (&host[..v6.len() + 2], rest.get(1..).unwrap_or(""))
        }
        Some(_) => return bad("not a repository host"),
        None => host.split_once(':').unwrap_or((host, "")),
    };
    let scp = scheme == "git+ssh://" && !after.is_empty() && !after.bytes().all(|b| b.is_ascii_digit());
    let host_at = if user.is_empty() { 0 } else { user.len() + 1 };
    let path = if scp { &rest[host_at + host.len() + 1..] } else { rest.split_once('/').map_or("", |p| p.1) };
    let file = scheme == "git+file://";
    // `x::address` is git's syntax for a transport helper (`ext::`, `fd::`): never a repository.
    let unbracketed = if host.starts_with('[') { url.replacen(host, "", 1) } else { url.clone() };
    if url.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'\\')
        || unbracketed.contains("::")
        || path.is_empty()
        || path.starts_with('-')
    {
        return bad("not a repository url");
    }
    let named = |h: &str| {
        !h.is_empty() && !h.starts_with('-') && h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
    };
    let v6 = |h: &str| {
        let inner = h.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        inner.is_some_and(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_hexdigit() || b":.".contains(&b)))
    };
    // `c:path` is a drive letter to git on Windows: a repository on the disk, not over ssh.
    let drive = scp && host.len() == 1;
    let bad_host = if file { !host.is_empty() } else { !named(host) && !v6(host) };
    let hosted = Host::named(host);
    let ssh = scheme == "git+ssh://";
    // A hosted repository's ssh user is `git`: npm drops any other, and any password.
    let user = if hosted.is_some() && ssh { "git" } else { user };
    if user.starts_with('-') || drive || bad_host {
        return bad("not a repository host");
    }
    if !user.is_empty() && (!ssh || user.contains(':')) {
        return bad("credentials belong in git's credential helper or ssh, not package.json");
    }
    // A hosted repository over https or git:// is the host's own https url, however written.
    let url = match hosted {
        Some(h) if ssh => format!("git+ssh://git@{}{}", h.domain, &rest[host_at + host.len()..]),
        Some(h) if scheme == "git+https://" || scheme == "git://" => h.repo(path).map_or(url, |p| h.https(&p)),
        _ => url,
    };
    let committish = match committish.strip_prefix("semver:") {
        Some(range) if !semver::valid_range(range) => return bad("not a semver range"),
        Some(_) => committish.to_string(),
        None if committish.starts_with('-') || committish.bytes().any(|b| !b.is_ascii_graphic()) => {
            return bad("not a ref");
        }
        None if is_commit(committish) => committish.to_ascii_lowercase(),
        None => committish.to_string(),
    };
    Ok(Some(format!("{url}#{committish}")))
}

/// ssh's scp-like `user@host:path` as a `git+ssh://` url: as `git@` to any host, as any user
/// (which npm drops) to a hosted one.
fn scp(repo: &str) -> Option<String> {
    let git = repo.get(..4).is_some_and(|g| g.eq_ignore_ascii_case("git@"));
    let (auth, rest) = repo.rsplit_once('@')?;
    let at = rest.split_once(':').and_then(|(host, path)| Host::named(host)?.repo(path));
    let hosted = !auth.contains('/') && at.is_some();
    (git || hosted).then(|| format!("git+ssh://{repo}"))
}

/// `https://github.com/u/r`, a hosted repository's page, as a `git+https://` url, with the ref
/// of github's `…/tree/<ref>`: npm reads it as the repository (as hosted-git-info does), and
/// downloading it as a tarball gets an HTML page. Only a repository's top, or its tree at a
/// ref: `…/archive/v1.tar.gz` and other paths are still urls to download.
fn hosted_page(repo: &str) -> Option<(String, Option<&str>)> {
    let lower = repo.to_ascii_lowercase();
    let rest = lower.strip_prefix("https://").or_else(|| lower.strip_prefix("http://"))?;
    let rest = &repo[repo.len() - rest.len()..];
    let host = Host::over(rest)?;
    let (authority, path) = rest.split_once('/')?;
    // npm reads the one segment after `tree/` as the ref, so a ref with a `/` is not read.
    let tree =
        path.split_once("/tree/").filter(|(_, r)| host.domain == "github.com" && !r.is_empty() && !r.contains('/'));
    let (path, tree) = tree.map_or((path, None), |(p, r)| (p, Some(r)));
    (!ends_as_tarball(path) && host.repo(path).is_some()).then(|| (format!("git+https://{authority}/{path}"), tree))
}

/// A full commit id: 40 hex digits, or 64 for a SHA-256 repository.
pub fn is_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a lockfile's `version` (a url, a `file:` tarball, a repository at a commit) is the
/// source `s` names, as read from the package.json in the directory `base`: the same url or
/// file, or the same repository, at the commit `s` pins when it pins one.
pub fn names_source(s: &Spec, base: &str, version: &str) -> bool {
    match s.kind {
        Kind::Tarball => source_at(&s.fetch_spec, base) == version,
        Kind::Git => {
            let (url, want) = s.fetch_spec.split_once('#').unwrap_or((&s.fetch_spec, ""));
            let (locked, commit) = version.split_once('#').unwrap_or((version, ""));
            url == locked && is_commit(commit) && (!is_commit(want) || want == commit)
        }
        _ => false,
    }
}

/// A git source (`git+https://…#…`, `git://…#…`), as a lockfile key's tail or a `fetch_spec`.
pub fn is_git(source: &str) -> bool {
    source.starts_with("git+") || source.starts_with("git://")
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
    } else if let Some(p) = s.strip_prefix("portal:") {
        // yarn's: the directory linked and its dependencies installed, as `file:` has it.
        ("file:", p)
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
    if crate::graph::name_end(&s).is_some() {
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

/// A name jpm can hold. npm's naming rules are the registry's: a name it does not hold is not
/// found there. What jpm refuses is what would do harm here, for any name, an alias's own
/// included (`"my$tool": "npm:real@1"`, babel's `$repo-utils`): a name is a directory under
/// `node_modules`, a token in jpm.lock, and, percent-encoded, part of a registry url.
pub fn check_name(name: &str, raw: &str) -> Result<()> {
    let bad = |why: &str| Err(invalid(format!("Invalid package name \"{name}\" of package \"{raw}\": {why}")));
    if name.is_empty() {
        return bad("name is empty");
    }
    if name.len() > 214 {
        return bad("name is longer than 214 characters");
    }
    let (scope, pkg) = match name.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((s, p)) if !s.is_empty() => (Some(s), p),
            _ => return bad("name is malformed"),
        },
        None => (None, name),
    };
    for part in scope.into_iter().chain([pkg]) {
        if part.is_empty() || part.contains('/') {
            return bad("name is malformed");
        }
        // `.`, `..`, and `.bin` or `.jpm` beside the packages in node_modules.
        if part.starts_with('.') {
            return bad("name starts with a dot");
        }
        // A second `@` would move where name@version splits; the rest a path, the lockfile's
        // lines or Windows cannot hold.
        if part.chars().any(|c| c.is_control() || c.is_whitespace() || "@\\:<>\"|?*".contains(c)) {
            return bad("name has a character a directory or jpm.lock cannot hold");
        }
        if part.chars().any(hides) {
            return bad("name has a character that hides what it reads as");
        }
        // Windows drops a trailing dot or space, and keeps these names for devices.
        if part.ends_with('.') || device(part) {
            return bad("name is not a directory Windows can make");
        }
    }
    if pkg == "node_modules" {
        return bad("name is reserved");
    }
    Ok(())
}

/// Whether a name may hold `c` (within a part; `/` and a scope's `@` are the name's shape).
pub fn name_char(c: char) -> bool {
    !(c.is_control() || c.is_whitespace() || "/@\\:<>\"|?*".contains(c) || hides(c))
}

/// Emoji and other letters are fine; what makes a name read as another is not: bidi overrides
/// and marks, zero-width spaces, a byte-order mark (the zero-width joiner of an emoji sequence
/// stays).
pub fn hides(c: char) -> bool {
    matches!(c, '\u{200B}' | '\u{200C}' | '\u{200E}' | '\u{200F}' | '\u{2060}' | '\u{FEFF}')
        || ('\u{202A}'..='\u{202E}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// A Windows device name, whatever follows a dot: `CON`, `nul.js`, `COM1`.
fn device(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

/// A name part as a url path segment: what `encodeURIComponent` leaves alone kept, the rest
/// percent-encoded byte by byte.
pub fn encode_segment(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for b in part.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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
        // What a directory, jpm.lock or Windows cannot hold, or would read as something else.
        for bad in [
            "a\u{202E}b",
            "a\u{200B}b",
            "\u{FEFF}a",
            "",
            ".x",
            ".bin",
            "..",
            "node_modules",
            "@/x",
            "a/b",
            "@s/",
            "a b",
            "@s/..",
            "a@b",
            "@s/a@b",
            "a:b",
            "a\\b",
            "a\"b",
            "a|b",
            "a*",
            "x.",
            "CON",
            "nul.js",
            "@s/com1",
            "a\tb",
        ] {
            assert!(parse_dep(bad, "1").is_err(), "{bad:?}");
        }
        // The registry's own rules are not jpm's: babel's `$repo-utils`, an alias's own name.
        for good in [
            "$repo-utils",
            "my$tool",
            "_x",
            "-x",
            "JSONStream",
            "@s/$x",
            "com10",
            "a~b",
            "a%b",
            "\u{1F4A9}",
            "\u{1F468}\u{200D}\u{1F469}",
        ] {
            assert!(parse_dep(good, "1").is_ok(), "{good:?}");
        }
        assert_eq!(escape_name("$repo-utils").unwrap(), "%24repo-utils");
        assert_eq!(escape_name("\u{1F4A9}").unwrap(), "%F0%9F%92%A9");
        // Split by character: a name that begins with an emoji is not cut inside it.
        assert_eq!(crate::graph::split_key("\u{1F4A9}@1.0.0"), Some(("\u{1F4A9}", "1.0.0")));
        assert_eq!(parse_spec("\u{1F4A9}@^1").unwrap().fetch_spec, "^1");
        // A prerelease after it stays whole, an exact version, below its release.
        assert_eq!(crate::graph::split_key("\u{1F4A9}@1.0.0-alpha1a"), Some(("\u{1F4A9}", "1.0.0-alpha1a")));
        let pre = parse_spec("\u{1F4A9}@1.0.0-alpha1a").unwrap();
        assert_eq!((pre.kind, pre.fetch_spec.as_str()), (Kind::Version, "1.0.0-alpha1a"));
        assert!(semver::parse("1.0.0-alpha1a") < semver::parse("1.0.0"));
        assert!(!semver::satisfies("1.0.0-alpha1a", "^1.0.0") && semver::satisfies("1.0.0-alpha1a", "^1.0.0-alpha"));
        // Not semver, and no tag either: said as a version.
        for bad in ["2.0.0-Beata\u{1F389}", "2.0.0.-Beata\u{1F389}"] {
            assert!(parse_dep("mypackage", bad).unwrap_err().message.starts_with("Invalid version"), "{bad}");
        }
        assert_eq!(parse_dep("mypackage", "2.0.0-Beata").unwrap().kind, Kind::Version);
        let alias = crate::graph::split_key("\u{1F4A9}@npm:@s/x@1.0.0-alpha1a").unwrap();
        assert_eq!(crate::graph::split_alias(alias.1), Some(("@s/x", "1.0.0-alpha1a")));
        assert_eq!(escape_name("@s/a%b").unwrap(), "@s%2fa%25b");
        assert_eq!(
            crate::registry::tarball_url("https://r.test", "@s/$x", "1.0.0"),
            "https://r.test/@s/%24x/-/%24x-1.0.0.tgz"
        );
        assert!(parse_dep("foo", "not a tag").is_err());
        assert!(parse_dep("foo", "not/a tag").unwrap_err().message.starts_with("Invalid tag"));
    }

    const C: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn reads_git_specs() {
        let git = |spec: &str| {
            let s = parse_dep("x", spec).unwrap_or_else(|e| panic!("{spec}: {}", e.message));
            assert_eq!(s.kind, Kind::Git, "{spec}");
            s.fetch_spec
        };
        // Every spelling of a hosted repository over https is one url, the ref kept as written.
        let hub = "git+https://github.com/u/r.git#";
        for spec in [
            "github:u/r",
            "u/r",
            "u/r.git",
            "git+https://github.com/u/r",
            "git+https://github.com/u/r.git",
            "git+https://GitHub.com/u/r/",
            "git://github.com/u/r.git",
            "GIT+HTTPS://github.com/u/r",
            // A repository's page, as npm reads it (formik's vscode-textmate).
            "https://github.com/u/r",
            "https://github.com/u/r.git",
            "http://GitHub.com/u/r/",
        ] {
            assert_eq!(git(spec), hub, "{spec}");
        }
        assert_eq!(git("https://github.com/u/r#v1.2.3"), format!("{hub}v1.2.3"));
        assert_eq!(git("https://gitlab.com/g/p"), "git+https://gitlab.com/g/p.git#");
        // Anything below a repository's top is still a url to download.
        for url in [
            "https://github.com/u/r/archive/v1.tar.gz",
            "https://codeload.github.com/u/r/tar.gz/main",
            "https://github.com/u",
        ] {
            assert_ne!(parse_dep("x", url).map(|s| s.kind).ok(), Some(Kind::Git), "{url}");
        }
        assert_eq!(git("u/r#v1.2.3"), format!("{hub}v1.2.3"));
        assert_eq!(git("u/r#feature/x"), format!("{hub}feature/x"));
        assert_eq!(git("github:u/r#semver:^1.2 || ^2"), format!("{hub}semver:^1.2 || ^2"));
        assert_eq!(git(&format!("u/r#{}", C.to_uppercase())), format!("{hub}{C}"), "a commit is lowercase");
        assert_eq!(git("gitlab:g/p#main"), "git+https://gitlab.com/g/p.git#main");
        assert_eq!(git("bitbucket:t/p"), "git+https://bitbucket.org/t/p.git#");
        // hosted-git-info's spellings (tests/conformance/hosted-git-info), as npm reads them.
        assert_eq!(git("github:user:pass@u/r"), hub, "npm drops the user");
        assert_eq!(git("https://www.github.com/u/r"), hub);
        assert_eq!(git("https://github.com/u/r/tree/dev"), format!("{hub}dev"));
        assert_eq!(git("gitlab:g/sub/p#x"), "git+https://gitlab.com/g/sub/p.git#x");
        assert_eq!(git("https://gitlab.com/g/sub/p"), "git+https://gitlab.com/g/sub/p.git#");
        assert_eq!(git("sourcehut:~u/r"), "git+https://git.sr.ht/~u/r#");
        assert_eq!(git("https://git.sr.ht/~u/r.git#x"), "git+https://git.sr.ht/~u/r#x");
        // A hosted host is reached over ssh as `git`, whatever user or password is written.
        assert_eq!(git("user:pass@github.com:u/r"), "git+ssh://git@github.com:u/r#");
        assert_eq!(git("git+ssh://github.com:u/r"), "git+ssh://git@github.com:u/r#");
        assert_eq!(git("ssh://me@GitLab.com/g/p.git"), "git+ssh://git@gitlab.com/g/p.git#");
        assert_eq!(git("git@git.sr.ht:~u/r"), "git+ssh://git@git.sr.ht:~u/r#");
        for other in [
            "u/r/",
            "https://github.com/u/r/tree/a/b",
            "https://gitlab.com/g/-/p",
            "https://bitbucket.org/u/r/get/v1.tar.gz",
            "ssh://git.sr.ht/~u/r",
            "ssh://host/r",
            "me@host:r",
        ] {
            assert_ne!(parse_dep("x", other).map(|s| s.kind).ok(), Some(Kind::Git), "{other}");
        }
        // Over ssh it stays ssh: its keys are how a private repository is reached.
        assert_eq!(git("git+ssh://git@github.com/u/r.git"), "git+ssh://git@github.com/u/r.git#");
        assert_eq!(git("git@github.com:u/r.git#dev"), "git+ssh://git@github.com:u/r.git#dev");
        assert_eq!(git("git+ssh://git@host:2222/p/r.git"), "git+ssh://git@host:2222/p/r.git#");
        assert_eq!(git("git+https://example.com/a/b/c.git#x"), "git+https://example.com/a/b/c.git#x");
        assert_eq!(git("git://example.com/r"), "git://example.com/r#");
        assert_eq!(git("git+file:///srv/r.git"), "git+file:///srv/r.git#");
        assert_eq!(git("git+ssh://git@[::1]:r.git"), "git+ssh://git@[::1]:r.git#");
        assert_eq!(git("git+https://[fe80::1]:8443/r.git"), "git+https://[fe80::1]:8443/r.git#");
        assert!(is_git(&git("u/r")) && is_commit(C) && !is_commit(&C[..39]));
        // A bare CLI argument names one too.
        assert_eq!(bare_source("u/r").unwrap().as_deref(), Some(hub));
        assert_eq!(bare_source("@s/p").unwrap(), None);
        // A path or a tarball name is not github shorthand.
        assert_eq!(parse_dep("x", "./u/r").unwrap().kind, Kind::Directory);
        assert!(parse_dep("x", "vendor/x.tgz").is_err());
    }

    #[test]
    fn refuses_git_specs_that_would_reach_git_as_options() {
        for bad in [
            "git+https://-oProxyCommand=touch%20x/r",
            "git+ssh://-oProxyCommand=touch%20x/r",
            "git+ssh://git@-oProxyCommand=x:r",
            "git@-oProxyCommand=x:r",
            "git+ssh://-git@host/r",
            "git+ssh://git@host:--upload-pack=touch x",
            "git+ssh://git@host:-u/r",
            "git+https://host/r#--upload-pack=touch",
            "u/r#-x",
            "git+https:// host/r",
            "git+https://host",
            "git+https://host/",
            "git+https://host/r\\x",
            "git+https://user:token@github.com/u/r",
            "git+https://token@host/r",
            "git://user@host/r",
            "git+ssh://user:pass@host/r",
            "git+http://github.com/u/r",
            "git+file://host/r",
            "github:u",
            "github:u/r/x",
            "github:../r",
            "u/r#semver:not a range",
            "u/r#a b",
            // A transport helper, however it is dressed: git would run it.
            "git+ssh://ext::./x:r",
            "git+ssh://git@ext::sh:r",
            "git+ssh://fd::3:r",
            "git+https://host/a::b",
            // A drive letter, which git on Windows reads as a path on the disk.
            "git+ssh://c:foo/r",
            "git+ssh://host%2f:r",
            "git+https://ho_st/r",
            "git+https://[::1]x/r",
            "git+https://[]/r",
        ] {
            assert!(parse_dep("x", bad).is_err(), "{bad}");
        }
        // Not git at all, and so never handed to it: ext:: and file:: transports, bare urls.
        for other in ["ext::sh -c touch% /tmp/x", "file::/etc", "--upload-pack=x"] {
            assert!(parse_dep("x", other).map_or(true, |s| s.kind != Kind::Git), "{other}");
        }
    }

    #[test]
    fn names_the_forms_it_does_not_read() {
        let msg = |spec: &str| parse_dep("x", spec).unwrap_err().message;
        assert_eq!(msg("catalog:"), r#""catalog:" dependencies are not supported yet (in package "x@catalog:")"#);
        for spec in ["catalog:react18", "exec:./gen.js", "gist:11081aaa"] {
            let prefix = &spec[..=spec.find(':').unwrap()];
            assert!(msg(spec).starts_with(&format!("\"{prefix}\" dependencies are not supported yet")), "{spec}");
        }
        // jsr's npm registry, as pnpm maps it.
        let jsr = |name: &str, spec: &str| parse_dep(name, spec).map(|s| (s.fetch_name, s.fetch_spec));
        assert_eq!(jsr("fs", "jsr:@std/fs@^1").unwrap(), ("@jsr/std__fs".into(), "^1".into()));
        assert_eq!(jsr("@deno/doc", "jsr:^0.181.0").unwrap(), ("@jsr/deno__doc".into(), "^0.181.0".into()));
        assert_eq!(jsr("@std/fs", "jsr:").unwrap(), ("@jsr/std__fs".into(), "*".into()));
        assert!(jsr("fs", "jsr:^1").is_err());
        // A published package's patch lives in its own repository: the version, unpatched.
        assert_eq!(parse_dep("x", "patch:x@npm%3A1.2.3#~/.yarn/patches/x.patch").unwrap().fetch_spec, "1.2.3");
        assert_eq!(parse_dep("x", "patch:x@npm%3A^1#optional!builtin<compat/x>").unwrap().fetch_spec, "^1");
        // yarn's portal: a directory, installed as `file:` has one.
        let portal = parse_dep("x", "portal:./tools/x").unwrap();
        assert_eq!((portal.kind, portal.fetch_spec.as_str()), (Kind::Directory, "file:tools/x"));
        // pnpm's `workspace:<path>`: the directory, linked.
        let at = parse_dep("x", "workspace:../x/dist").unwrap();
        assert_eq!((at.kind, at.fetch_spec.as_str()), (Kind::Directory, "link:../x/dist"));
        // Still read as before.
        for spec in ["npm:y@1", "workspace:*", "https://example.com/y.tgz", "file:y.tgz", "latest", "^1"] {
            assert!(parse_dep("x", spec).is_ok(), "{spec}");
        }
        assert_eq!(escape_name("@a/b").unwrap(), "@a%2fb");
    }
}

#[cfg(test)]
#[path = "../tests/conformance/hosted_git_info.rs"]
mod hosted_git_info;
