//! Git dependencies: a ref resolved to a commit with `git ls-remote`, and a commit's files
//! unpacked from the host's archive (github, gists, gitlab, bitbucket and sourcehut over https,
//! through jpm's own http client and with no registry credentials) or from `git archive` of a
//! shallow fetch.
//!
//! git runs with only https, ssh and git:// allowed (no transport helper such as `ext::`, and no
//! `file://`), with every url after `--`, and with the repository variables of whatever git
//! called jpm taken out. It runs in an empty directory of jpm's own, below which it looks for no
//! repository, so no repository's config (the project's, or one a checkout carries) is read.
//! It asks for credentials only on a terminal, and only for a repository the project's own
//! package.json names: for one a dependency names, git, its credential manager and ssh ask
//! nothing. A url or ref is checked when the spec is read (`spec::git`) and again here; only a
//! commit id and a url reach git's command line.

use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::error::{Error, Result};
use crate::store::{Index, extract, remove_tree};
use crate::util::temp_suffix;
use crate::{http, semver, spec};

/// The repositories the project's own package.json files name (see `named_by_project`).
static NAMED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// A repository the project named itself, by its `fetch_spec`: git may ask the terminal for it.
pub fn named_by_project(fetch_spec: &str) {
    NAMED.lock().unwrap_or_else(PoisonError::into_inner).insert(split(fetch_spec).0.to_string());
}

fn may_ask(url: &str) -> bool {
    std::io::stdin().is_terminal() && NAMED.lock().unwrap_or_else(PoisonError::into_inner).contains(url)
}

/// For tests only: `file://` repositories, which a package.json must never reach.
const ALLOW_FILE: &str = "JPM_GIT_ALLOW_FILE";

/// `<url>#<ref>` split at the `#` every git `fetch_spec` and source has.
pub fn split(source: &str) -> (&str, &str) {
    source.split_once('#').unwrap_or((source, ""))
}

/// `<url>#<ref>` as `<url>#<commit>`: a commit as it is, anything else asked of the remote, from
/// an empty directory made under `tmp`.
pub fn resolve(fetch_spec: &str, offline: bool, tmp: &Path) -> Result<String> {
    let (url, committish) = split(fetch_spec);
    if spec::is_commit(committish) {
        return Ok(fetch_spec.to_string());
    }
    if offline {
        return Err(Error::new("EOFFLINE", format!("offline: {fetch_spec} needs git ls-remote")));
    }
    let empty = tmp.join(temp_suffix());
    std::fs::create_dir_all(&empty).map_err(|e| Error::io(&e, format!("cannot create {}", empty.display())))?;
    let mut ls = git(&empty, url);
    ls.args(["ls-remote", "--", &remote(url)?, "HEAD", "refs/heads/*", "refs/tags/*"]);
    let listing = run(&mut ls, fetch_spec);
    let _ = std::fs::remove_dir(&empty);
    let listing = listing?;
    match pick(&listing, committish) {
        Some(commit) => Ok(format!("{url}#{commit}")),
        None if committish.len() >= 7 && committish.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let commit = abbreviated(url, committish, tmp, fetch_spec).map_err(|e| {
                Error::new("EGIT", format!("{fetch_spec}: no branch, tag or commit {committish}: {}", e.message))
            })?;
            Ok(format!("{url}#{commit}"))
        }
        None => Err(Error::new("EGIT", format!("{fetch_spec}: no branch, tag or version matches {committish:?}"))),
    }
}

/// The commit an abbreviated id names (parcel's `#b8a4fa94`), as npm takes one: the branches'
/// and tags' commits fetched into an empty directory, without their trees or files, and the id
/// looked up among them. `short` is hex, never an option.
fn abbreviated(url: &str, short: &str, tmp: &Path, what: &str) -> Result<String> {
    let work = tmp.join(temp_suffix());
    std::fs::create_dir_all(&work).map_err(|e| Error::io(&e, format!("cannot create {}", work.display())))?;
    let found = (|| {
        // Bare: no branch is checked out, so git lets the fetch write every one (`main` too).
        run(git(&work, url).args(["init", "-q", "--bare"]), what)?;
        let refs = ["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];
        run(git(&work, url).args(["fetch", "-q", "--filter=tree:0", "--", &remote(url)?]).args(refs), what)?;
        run(git(&work, url).args(["rev-parse", "--verify", "--quiet", &format!("{short}^{{commit}}")]), what)
    })();
    remove_tree(&work);
    let id = found?.trim().to_ascii_lowercase();
    if spec::is_commit(&id) { Ok(id) } else { Err(Error::new("EGIT", format!("{short} is not a commit there"))) }
}

/// The commit `committish` names in `git ls-remote` output: HEAD for none, the highest tag in a
/// `semver:` range, else a branch, a tag or a full ref by that name. A tag's own commit is its
/// peeled (`^{}`) line.
fn pick(listing: &str, committish: &str) -> Option<String> {
    let refs: Vec<(&str, &str)> =
        listing.lines().filter_map(|l| l.split_once('\t')).filter(|(id, _)| spec::is_commit(id)).collect();
    let find = |name: &str| refs.iter().find(|(_, r)| *r == name).map(|(id, _)| id.to_ascii_lowercase());
    let tag = |t: &str| find(&format!("refs/tags/{t}^{{}}")).or_else(|| find(&format!("refs/tags/{t}")));
    if committish.is_empty() {
        return find("HEAD");
    }
    if let Some(range) = committish.strip_prefix("semver:") {
        let tags = refs.iter().filter_map(|(_, r)| r.strip_prefix("refs/tags/")).filter(|t| !t.ends_with("^{}"));
        return tag(semver::max_satisfying(tags, range)?);
    }
    find(&format!("refs/heads/{committish}")).or_else(|| tag(committish)).or_else(|| find(committish))
}

/// Unpack the files of `<url>#<commit>` into `dest`, with `work` for a clone to use.
pub fn fetch(source: &str, work: &Path, dest: &Path) -> Result<Index> {
    let (url, commit) = split(source);
    if !spec::is_commit(commit) {
        return Err(Error::new("EGIT", format!("{source} is not locked to a commit")));
    }
    if let Some(archive) = archive_url(url, commit) {
        // No credentials: a registry's token is never a git host's business.
        match http::open(&archive, &BTreeMap::new()) {
            Ok((mut body, _)) => return extract(&mut *body, dest, false).map_err(|e| e.context(source)),
            // Private, or not there: git may have credentials for it.
            Err(e) if e.code == "E404" => {}
            Err(e) => return Err(e),
        }
    }
    let cloned = clone(url, commit, work, dest, source);
    remove_tree(work);
    cloned
}

/// A shallow fetch of the one commit into `work`, then `git archive` of it into our tar reader,
/// which keeps regular files only. A server that will not serve a commit by id is fetched whole.
fn clone(url: &str, commit: &str, work: &Path, dest: &Path, source: &str) -> Result<Index> {
    let remote = remote(url)?;
    std::fs::create_dir_all(work).map_err(|e| Error::io(&e, format!("cannot create {}", work.display())))?;
    // Bare: no branch is checked out, so git lets the fetch write every one (`main` too).
    run(git(work, url).args(["init", "-q", "--bare"]), source)?;
    let fetch = |shallow: &[&str], refs: &[&str]| {
        let mut c = git(work, url);
        c.args(["fetch", "-q"]).args(shallow).args(["--", &remote]).args(refs);
        run(&mut c, source)
    };
    if fetch(&["--depth", "1"], &[commit]).is_err() {
        fetch(&[], &["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"])?;
    }
    // The tree as committed: no line endings converted for this machine.
    let mut archive = git(work, url);
    archive.args(["-c", "core.autocrlf=false", "archive", "--format=tar", "--prefix=package/", commit]);
    let mut child = archive.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| missing(&e, source))?;
    let mut out = child.stdout.take().ok_or_else(|| Error::new("EGIT", "no output"))?;
    let index = extract(&mut out, dest, false);
    drop(out); // should the reader stop early, a closed pipe ends git too
    let status = child.wait().map_err(|e| missing(&e, source))?;
    if !status.success() {
        return Err(Error::new("EGIT", format!("git archive of {source} failed ({status})")));
    }
    index.map_err(|e| e.context(source))
}

/// The host's archive of a commit, for a hosted repository over https.
fn archive_url(url: &str, commit: &str) -> Option<String> {
    let (host, path) = url.strip_prefix("git+https://")?.split_once('/')?;
    match (host, path.strip_suffix(".git")) {
        ("github.com" | "gist.github.com", Some(path)) => {
            let base =
                crate::util::test_hook("JPM_CODELOAD_URL").unwrap_or_else(|| "https://codeload.github.com".into());
            let path = if host == "github.com" { path.to_string() } else { format!("gist/{path}") };
            Some(format!("{base}/{path}/tar.gz/{commit}"))
        }
        // The repository's name is the last part: it may sit in a group within a group.
        ("gitlab.com", Some(path)) => {
            let repo = path.rsplit_once('/')?.1;
            Some(format!("https://gitlab.com/{path}/-/archive/{commit}/{repo}-{commit}.tar.gz"))
        }
        ("bitbucket.org", Some(path)) => Some(format!("https://bitbucket.org/{path}/get/{commit}.tar.gz")),
        // sourcehut's repository url has no `.git`.
        ("git.sr.ht", None) => Some(format!("https://git.sr.ht/{path}/archive/{commit}.tar.gz")),
        _ => None,
    }
}

/// The url as git takes it: `git+` dropped, and ssh's scp-like form (`git+ssh://git@host:path`)
/// given as git spells it (`git@host:path`), since `ssh://host:path` would read `path` as a port.
/// Never a transport helper (`<name>::<address>`) or a drive (`c:path`), whatever a lockfile says.
fn remote(url: &str) -> Result<String> {
    let url = url.strip_prefix("git+").unwrap_or(url);
    if url.starts_with("file://") && crate::util::test_hook(ALLOW_FILE).is_none() {
        return Err(Error::new("EGIT", format!("{url}: jpm does not fetch file:// repositories")));
    }
    let mut out = url;
    if let Some(rest) = url.strip_prefix("ssh://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let port = authority.rsplit_once(':').map(|(_, p)| p);
        if port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit())) {
            out = rest;
        }
    }
    // git reads `<scheme chars>::` as a helper to run, and `<letter>:` as a path on Windows.
    let lead = out.find(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c))).unwrap_or(out.len());
    let drive = lead == 1 && out[1..].starts_with(':');
    if out.starts_with('-') || out[lead..].starts_with("::") || drive {
        return Err(Error::new("EGIT", format!("{url} is not a repository url")));
    }
    Ok(out.to_string())
}

/// git for the repository `url` (see `plain`), asking nothing unless the project named it.
fn git(cwd: &Path, url: &str) -> Command {
    let mut c = plain(cwd);
    if !may_ask(url) {
        c.env("GIT_TERMINAL_PROMPT", "0");
        // Empty: no askpass program either (an editor's, or SSH_ASKPASS), and ssh's never.
        c.env("GIT_ASKPASS", "").env("SSH_ASKPASS_REQUIRE", "never");
        // Git Credential Manager, Git for Windows' default helper, asks in a window of its own:
        // a private or mistyped repository would otherwise open a sign-in window (or wait on
        // one in CI) for an install nobody is watching.
        c.env("GCM_INTERACTIVE", "never");
        // ssh asks on the terminal itself (a passphrase, an unknown host's key): batch mode,
        // unless the user runs ssh a way of their own.
        if url.starts_with("git+ssh://") && !own_ssh(cwd) {
            c.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
        }
    }
    c
}

/// Whether the user says how git runs ssh: `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand`.
fn own_ssh(cwd: &Path) -> bool {
    static OWN: OnceLock<bool> = OnceLock::new();
    *OWN.get_or_init(|| {
        let set = |v: &str| std::env::var_os(v).is_some_and(|v| !v.is_empty());
        let config = || {
            let out = plain(cwd).args(["config", "--get", "core.sshCommand"]).output();
            out.is_ok_and(|o| o.status.success() && !o.stdout.trim_ascii().is_empty())
        };
        set("GIT_SSH_COMMAND") || set("GIT_SSH") || config()
    })
}

/// git in `cwd`, an empty directory (or a repository) of jpm's own, looking for no repository
/// above it: one around the project, or a bare one a checkout carries, would have its config
/// read, and `core.sshCommand` and the like run commands.
fn plain(cwd: &Path) -> Command {
    let mut c = Command::new("git");
    let protocols = if crate::util::test_hook(ALLOW_FILE).is_some() { "https:ssh:git:file" } else { "https:ssh:git" };
    c.env("GIT_ALLOW_PROTOCOL", protocols).stdin(Stdio::null()).current_dir(cwd);
    let above = cwd.parent().and_then(|p| std::path::absolute(p).ok()).unwrap_or_default();
    c.env("GIT_CEILING_DIRECTORIES", above);
    // Set when jpm runs from a git hook: they would point every command at that repository.
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
    ] {
        c.env_remove(var);
    }
    c
}

/// `git diff --no-index` of the directories `a` and `b` in `dir`, as a patch names its files:
/// `a/<path>` and `b/<path>`. No renames, and nothing from the user's config that changes the text.
pub fn diff(dir: &Path) -> Result<Vec<u8>> {
    let mut c = plain(dir);
    c.args(["-c", "core.quotepath=false", "diff", "--no-index", "--no-color", "--no-ext-diff"]);
    c.args(["--no-textconv", "--no-renames", "--no-prefix", "a", "b"]);
    let out = c.stderr(Stdio::piped()).output().map_err(|e| missing(&e, "patch-commit"))?;
    // 1 says the directories differ.
    if !matches!(out.status.code(), Some(0 | 1)) {
        return Err(Error::new("EGIT", format!("git diff failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    // A new or deleted file's header names one directory twice: `diff --git b/x b/x`.
    let mut text = Vec::with_capacity(out.stdout.len());
    for line in out.stdout.split_inclusive(|&b| b == b'\n') {
        let mut line = line.to_vec();
        let n = line.len().saturating_sub(12);
        if line.starts_with(b"diff --git ") && line.ends_with(b"\n") && n % 2 == 1 {
            let q = usize::from(line[11] == b'"');
            line[11 + q] = b'a';
            line[11 + n / 2 + 1 + q] = b'b';
        }
        text.extend_from_slice(&line);
    }
    Ok(text)
}

/// Run git to the end: its output, or its error's last lines.
fn run(c: &mut Command, what: &str) -> Result<String> {
    let out = crate::pool::blocking(|| c.stderr(Stdio::piped()).output()).map_err(|e| missing(&e, what))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    let tail: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let tail = tail[tail.len().saturating_sub(3)..].join("; ");
    Err(Error::new("EGIT", format!("git failed for {what}: {tail}")))
}

fn missing(e: &std::io::Error, what: &str) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        return Error::new("ENOGIT", format!("git is not installed, and {what} needs it"));
    }
    Error::io(e, format!("cannot run git for {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const C: &str = "3333333333333333333333333333333333333333";

    #[test]
    fn never_asks_in_a_window_when_nobody_can_answer() {
        let at = std::env::temp_dir().join("jpm-git-test").join("empty");
        let check = |url: &str| {
            let c = git(&at, url);
            let env = |name: &str| c.get_envs().find(|(k, _)| *k == name).and_then(|(_, v)| v).map(|v| v.to_owned());
            // Wherever git may not prompt on a terminal, nothing else may ask either.
            assert_eq!(env("GIT_TERMINAL_PROMPT").is_some(), env("GCM_INTERACTIVE").is_some());
            assert_eq!(env("GIT_TERMINAL_PROMPT").is_some(), env("GIT_ASKPASS").is_some());
            if env("GIT_TERMINAL_PROMPT").is_some() {
                assert_eq!(env("GCM_INTERACTIVE").as_deref(), Some(std::ffi::OsStr::new("never")));
                assert_eq!(env("GIT_ASKPASS").as_deref(), Some(std::ffi::OsStr::new("")));
            }
            // In jpm's own directory, looking for no repository above it.
            assert_eq!(c.get_current_dir(), Some(at.as_path()));
            let above = env("GIT_CEILING_DIRECTORIES").unwrap_or_default();
            assert!(std::path::Path::new(&above).is_absolute() && at.starts_with(&above), "{above:?}");
            env("GIT_TERMINAL_PROMPT").is_some()
        };
        // A repository no package.json of the project names asks nothing, terminal or not.
        assert!(check("git+https://example.com/dependency/named.git"));
        named_by_project("git+https://example.com/project/named.git#main");
        assert_eq!(check("git+https://example.com/project/named.git"), !std::io::stdin().is_terminal());
    }

    #[test]
    fn picks_a_commit_from_ls_remote() {
        let listing = format!(
            "{A}\tHEAD\n{A}\trefs/heads/main\n{B}\trefs/heads/dev\n{C}\trefs/tags/v1.0.0\n\
             {B}\trefs/tags/v1.2.0\n{A}\trefs/tags/v1.2.0^{{}}\n{C}\trefs/tags/2.0.0\nnoise\n"
        );
        let pick = |c: &str| pick(&listing, c);
        assert_eq!(pick("").as_deref(), Some(A));
        assert_eq!(pick("dev").as_deref(), Some(B));
        assert_eq!(pick("v1.0.0").as_deref(), Some(C));
        assert_eq!(pick("v1.2.0").as_deref(), Some(A), "an annotated tag is its commit");
        assert_eq!(pick("semver:^1").as_deref(), Some(A));
        assert_eq!(pick("semver:>=2").as_deref(), Some(C));
        assert_eq!(pick("refs/heads/dev").as_deref(), Some(B));
        assert_eq!(pick("semver:^3"), None);
        assert_eq!(pick("nope"), None);
    }

    #[test]
    fn gives_git_a_url_it_reads() {
        assert_eq!(remote("git+https://h/a/b.git").unwrap(), "https://h/a/b.git");
        assert_eq!(remote("git+ssh://git@h:a/b.git").unwrap(), "git@h:a/b.git");
        assert_eq!(remote("git+ssh://git@h:22/a/b.git").unwrap(), "ssh://git@h:22/a/b.git");
        assert_eq!(remote("git://h/a/b").unwrap(), "git://h/a/b");
        assert!(remote("git+-oProxyCommand=x").is_err());
        // What a lockfile could say that the spec reader refuses: a transport helper, a drive.
        for bad in ["git+ssh://ext::sh:r", "git+ssh://fd::3:r", "git+ssh://c:foo/r", "git+ssh://-o:x"] {
            assert!(remote(bad).is_err(), "{bad}");
        }
        assert_eq!(remote("git+ssh://git@[::1]:r.git").unwrap(), "git@[::1]:r.git");
        if crate::util::test_hook(ALLOW_FILE).is_none() {
            assert!(remote("git+file:///tmp/x").is_err());
        }
        let c = "0123456789012345678901234567890123456789";
        assert_eq!(
            archive_url("git+https://github.com/u/r.git", c).filter(|_| std::env::var_os("JPM_CODELOAD_URL").is_none()),
            Some(format!("https://codeload.github.com/u/r/tar.gz/{c}"))
        );
        assert_eq!(
            archive_url("git+https://gitlab.com/u/r.git", c).unwrap(),
            format!("https://gitlab.com/u/r/-/archive/{c}/r-{c}.tar.gz")
        );
        assert_eq!(
            archive_url("git+https://bitbucket.org/u/r.git", c).unwrap(),
            format!("https://bitbucket.org/u/r/get/{c}.tar.gz")
        );
        assert_eq!(
            archive_url("git+https://gitlab.com/g/sub/r.git", c).unwrap(),
            format!("https://gitlab.com/g/sub/r/-/archive/{c}/r-{c}.tar.gz")
        );
        assert_eq!(
            archive_url("git+https://git.sr.ht/~u/r", c).unwrap(),
            format!("https://git.sr.ht/~u/r/archive/{c}.tar.gz")
        );
        assert_eq!(
            archive_url("git+https://gist.github.com/0a1b.git", c)
                .filter(|_| std::env::var_os("JPM_CODELOAD_URL").is_none()),
            Some(format!("https://codeload.github.com/gist/0a1b/tar.gz/{c}"))
        );
        assert_eq!(archive_url("git+ssh://git@github.com/u/r.git", c), None);
        assert_eq!(archive_url("git+https://example.com/u/r.git", c), None);
    }
}
