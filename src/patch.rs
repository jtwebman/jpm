//! Patches: pnpm's and bun's `patchedDependencies`. A patch is a git-style unified diff, applied
//! to a package's files as its entry is built. The entry's key holds the patch's hash, so a
//! patched copy never shares a directory with the clean one.
//!
//! The diff is applied as `git apply` would: every context line must match exactly (a hunk may
//! sit a few lines from where it says), new files, deleted files, renames and mode changes are
//! read from git's headers, and no path may leave the package.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::semver;

/// The most a patch file may hold.
const MAX_PATCH: u64 = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub name: String,
    /// An exact version or a range; `None` for every version.
    pub range: Option<String>,
    /// The diff, as package.json or pnpm-workspace.yaml gives it: relative to the project root.
    pub path: String,
    /// sha256 of the file, in hex.
    pub hash: String,
    /// The diff itself: what is hashed is what is applied.
    pub text: Vec<u8>,
}

impl Patch {
    /// The key it is listed under: `name`, `name@version` or `name@range`.
    pub fn selector(&self) -> String {
        match &self.range {
            Some(r) => format!("{}@{r}", self.name),
            None => self.name.clone(),
        }
    }

    /// Read the diff `path` names in `dir`: a file of the project's own, through no link.
    pub fn read(dir: &Path, name: String, range: Option<String>, path: &str) -> Result<Self> {
        let fail = |why: String| Error::new("EPATCH", format!("cannot read the patch {path}: {why}"));
        let file = project_path(dir, path).map_err(fail)?;
        let meta = fs::symlink_metadata(&file).map_err(|e| fail(e.to_string()))?;
        if !meta.is_file() {
            return Err(fail("not a file".into()));
        }
        let mut text = Vec::new();
        fs::File::open(&file)
            .and_then(|f| f.take(MAX_PATCH + 1).read_to_end(&mut text))
            .map_err(|e| fail(e.to_string()))?;
        if text.len() as u64 > MAX_PATCH {
            return Err(fail(format!("larger than {} MiB", MAX_PATCH >> 20)));
        }
        Ok(Self { name, range, path: path.to_string(), hash: crate::util::sha256_hex(&text), text })
    }
}

/// `rel`, a path the project names (a patch, where `jpm patch` works), under `dir`: relative,
/// inside it (`./` in front is allowed), and through no link that is there now.
pub fn project_path(dir: &Path, rel: &str) -> std::result::Result<PathBuf, String> {
    let mut plain = rel;
    while let Some(r) = plain.strip_prefix("./") {
        plain = r;
    }
    if !crate::tar::plain(plain) {
        return Err(format!("{rel} is not a path inside the project"));
    }
    let mut at = dir.to_path_buf();
    for part in plain.split('/') {
        at.push(part);
        if fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!("{} is a link", at.display()));
        }
    }
    Ok(at)
}

/// yarn's `patch:<source>#<path>[::<params>]` in place of `dep`'s range, its source url-encoded
/// (`x@npm%3A1.2.3`): the range it stands for, and the patch as a `patchedDependencies` key and
/// path (`~/` is the project root). yarn's builtin patches (`optional!builtin<compat/…>`) only
/// matter under Plug'n'Play: the range, and no patch.
pub fn yarn(dep: &str, value: &str) -> Option<(String, Option<(String, String)>)> {
    let (source, path) = value.strip_prefix("patch:")?.split_once('#')?;
    let mut bytes = Vec::with_capacity(source.len());
    let mut rest = source.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        let hex = tail.get(..2).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match hex.filter(|_| b == b'%') {
            Some(h) => (bytes.push(h), rest = &tail[2..]),
            None => (bytes.push(b), rest = tail),
        };
    }
    let source = String::from_utf8(bytes).ok()?;
    let at = source.get(1..)?.find('@')? + 1;
    let (name, range) = (&source[..at], &source[at + 1..]);
    // One layer: a `patch:` inside another is none that yarn writes.
    if range.contains("patch:") {
        return None;
    }
    let range = range.strip_prefix("npm:").filter(|r| semver::valid_range(r)).unwrap_or(range);
    let own = if name == dep { range.to_string() } else { format!("npm:{name}@{range}") };
    let path = path.split("::").next().unwrap_or(path);
    let patch = (!path.contains("builtin<")).then(|| (format!("{name}@{range}"), path.trim_start_matches("~/").into()));
    Some((own, patch))
}

/// Which package each patch goes to, `key -> hash`, over `(key, name, version)`. As pnpm picks: a
/// version's own patch first, then a range's, then the name's. A patch no package takes is an
/// error, as it is in pnpm, and so are two ranges that both take one version.
pub fn select<'a>(
    patches: &[Patch],
    packages: impl Iterator<Item = (&'a str, &'a str, &'a str)>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if patches.is_empty() {
        return Ok(out);
    }
    let mut used = vec![false; patches.len()];
    for (key, name, version) in packages {
        let rank = |p: &Patch| match p.range.as_deref() {
            _ if p.name != name => None,
            None => Some(2),
            Some(r) if r == version => Some(0),
            Some(r) if !semver::is_exact(r) && semver::satisfies(version, r) => Some(1),
            Some(_) => None,
        };
        let Some(best) = patches.iter().filter_map(rank).min() else { continue };
        let picked: Vec<usize> = (0..patches.len()).filter(|&i| rank(&patches[i]) == Some(best)).collect();
        if let [a, b, ..] = picked[..] {
            let (a, b) = (patches[a].selector(), patches[b].selector());
            return Err(Error::new("EPATCH", format!("{key} is patched by both {a} and {b}")));
        }
        used[picked[0]] = true;
        out.insert(key.to_string(), patches[picked[0]].hash.clone());
    }
    let unused: Vec<String> = patches
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(p, _)| format!("{} ({})", p.selector(), p.path))
        .collect();
    if !unused.is_empty() {
        return Err(Error::new("EPATCH", format!("no package in the tree is patched by {}", unused.join(", "))));
    }
    Ok(out)
}

/// One file's change.
#[derive(Debug, Default)]
struct FileDiff {
    /// `None` when the file is created.
    old: Option<String>,
    /// `None` when the file is deleted.
    new: Option<String>,
    mode: Option<u32>,
    hunks: Vec<Hunk>,
}

#[derive(Debug)]
struct Hunk {
    /// 1-based, as the header says.
    old_start: usize,
    header: String,
    /// `(b' ' | b'-' | b'+', text without its line end, ends in a newline)`.
    lines: Vec<(u8, Vec<u8>, bool)>,
}

type Diffs = Vec<FileDiff>;

/// `a/x` or `b/x` as `x`, checked to stay inside the package. `/dev/null` is `None`.
fn strip(raw: &[u8], prefixed: bool) -> std::result::Result<Option<String>, String> {
    let path = unquote(raw)?;
    if path == "/dev/null" {
        return Ok(None);
    }
    let rest = if prefixed { path.split_once('/').map_or("", |(_, r)| r) } else { path.as_str() };
    if path.starts_with('/') || path.contains(':') || !crate::tar::plain(rest) || rest.split('/').any(device) {
        return Err(format!("{path} is not a path inside the package"));
    }
    Ok(Some(rest.to_string()))
}

/// A name Windows reads as a device whatever its extension: `con`, `nul.js`, `COM1.txt`.
fn device(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part).to_ascii_lowercase();
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

/// A path as git writes it: plain up to a tab, or quoted with C escapes.
fn unquote(raw: &[u8]) -> std::result::Result<String, String> {
    let bad = || format!("{} is not a path", String::from_utf8_lossy(raw));
    if raw.first() != Some(&b'"') {
        let end = raw.iter().position(|&b| b == b'\t').unwrap_or(raw.len());
        return String::from_utf8(raw[..end].to_vec()).map_err(|_| bad());
    }
    let mut out = Vec::new();
    let mut i = 1;
    while i < raw.len() {
        match raw[i] {
            b'"' => return String::from_utf8(out).map_err(|_| bad()),
            b'\\' => {
                let c = *raw.get(i + 1).ok_or_else(bad)?;
                i += 2;
                out.push(match c {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'0'..=b'7' => {
                        let digits = raw.get(i - 1..i + 2).filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
                        i += 2;
                        let d = digits.ok_or_else(bad)?;
                        (d[0] - b'0') << 6 | (d[1] - b'0') << 3 | (d[2] - b'0')
                    }
                    c => c,
                });
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Err(bad())
}

/// `diff --git a/x b/y`: the one path git names twice, for a change with no `---` line.
fn git_path(rest: &[u8]) -> std::result::Result<Option<String>, String> {
    if rest.first() == Some(&b'"') {
        return strip(rest, true);
    }
    // `a/<p> b/<p>`: the split where both halves name the same path.
    let n = rest.len();
    if n % 2 == 1 && rest[n / 2] == b' ' && rest[..n / 2].get(2..) == rest[n / 2 + 1..].get(2..) {
        return strip(&rest[..n / 2], true);
    }
    let at = rest.windows(3).position(|w| w == b" b/").ok_or("a diff --git line names no path")?;
    strip(&rest[..at], true)
}

fn number(s: &[u8]) -> Option<usize> {
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// `-a,b +c,d`: the old start and both lengths.
fn range(s: &[u8]) -> Option<(usize, usize)> {
    match s.iter().position(|&b| b == b',') {
        Some(i) => Some((number(&s[..i])?, number(&s[i + 1..])?)),
        None => Some((number(s)?, 1)),
    }
}

/// The diffs, and whether the patch was converted to CRLF whole.
fn parse(text: &[u8]) -> std::result::Result<(Diffs, bool), String> {
    let mut lines: Vec<&[u8]> = text.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    // A patch whose every line ends in CRLF was converted on its way (git's autocrlf): read as LF.
    let converted = !lines.is_empty() && lines.iter().all(|l| l.ends_with(b"\r"));
    if converted {
        for l in &mut lines {
            *l = &l[..l.len() - 1];
        }
    }
    let mut out: Diffs = Vec::new();
    // Whether the diff being read may still take headers: set by `diff --git` and `---`.
    let mut open = false;
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        i += 1;
        let field = |p: &[u8]| l.strip_prefix(p);
        if let Some(rest) = field(b"diff --git ") {
            let path = git_path(rest)?;
            out.push(FileDiff { old: path.clone(), new: path, ..FileDiff::default() });
            open = true;
            continue;
        }
        if let Some(rest) = field(b"--- ")
            && lines.get(i).is_some_and(|n| n.starts_with(b"+++ "))
        {
            if !open {
                out.push(FileDiff::default());
            }
            let d = out.last_mut().ok_or("no file")?;
            d.old = strip(rest, true)?;
            d.new = strip(&lines[i][4..], true)?;
            i += 1;
            open = false;
            continue;
        }
        if let Some(rest) = field(b"@@ -") {
            let d = out.last_mut().ok_or("a hunk before any file")?;
            open = false;
            let header = String::from_utf8_lossy(l).into_owned();
            let bad = || format!("malformed hunk header {header}");
            let mut parts = rest.split(|&b| b == b' ');
            let (old_start, old_len) = parts.next().and_then(range).ok_or_else(bad)?;
            let (_, new_len) = parts.next().and_then(|p| p.strip_prefix(b"+")).and_then(range).ok_or_else(bad)?;
            let (mut old, mut new) = (0, 0);
            let mut hunk = Hunk { old_start, header, lines: Vec::new() };
            while old < old_len || new < new_len {
                let Some(&line) = lines.get(i) else { return Err(format!("{} ends early", hunk.header)) };
                i += 1;
                // An empty line is a context line whose space an editor trimmed.
                let (kind, body) = line.split_first().map_or((b' ', &b""[..]), |(k, b)| (*k, b));
                match kind {
                    b' ' if old < old_len && new < new_len => (old, new) = (old + 1, new + 1),
                    b'-' if old < old_len => old += 1,
                    b'+' if new < new_len => new += 1,
                    b'\\' => {
                        if let Some(last) = hunk.lines.last_mut() {
                            last.2 = false;
                        }
                        continue;
                    }
                    _ => return Err(format!("{} does not hold the lines it counts", hunk.header)),
                }
                hunk.lines.push((kind, body.to_vec(), true));
            }
            if lines.get(i).is_some_and(|l| l.starts_with(b"\\")) {
                i += 1;
                if let Some(last) = hunk.lines.last_mut() {
                    last.2 = false;
                }
            }
            d.hunks.push(hunk);
            continue;
        }
        if !open {
            continue; // text between diffs, as git allows
        }
        let d = out.last_mut().ok_or("no file")?;
        let mode =
            |r: &[u8]| std::str::from_utf8(r).ok().and_then(|m| u32::from_str_radix(m, 8).ok()).map(|m| m & 0o777);
        if let Some(r) = field(b"new file mode ") {
            d.old = None;
            d.mode = mode(r);
        } else if field(b"deleted file mode ").is_some() {
            d.new = None;
        } else if let Some(r) = field(b"new mode ") {
            d.mode = mode(r);
        } else if let Some(r) = field(b"rename from ") {
            d.old = strip(r, false)?;
        } else if let Some(r) = field(b"rename to ") {
            d.new = strip(r, false)?;
        } else if field(b"copy from ").is_some() || field(b"copy to ").is_some() {
            return Err("copies are not supported".into());
        } else if field(b"GIT binary patch").is_some() || field(b"Binary files ").is_some() {
            return Err("binary diffs are not supported".into());
        }
    }
    Ok((out, converted))
}

/// A file's lines, each with its line end.
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    data.split_inclusive(|&b| b == b'\n').collect()
}

fn same(file_line: &[u8], (_, text, newline): &(u8, Vec<u8>, bool)) -> bool {
    let (body, ends) = match file_line.strip_suffix(b"\n") {
        Some(b) => (b, true),
        None => (file_line, false),
    };
    let trim = |b: &[u8]| b.strip_suffix(b"\r").map_or(b.len(), <[u8]>::len);
    ends == *newline && body[..trim(body)] == text[..trim(text)]
}

/// The hunks applied to `data`, each at the line it names or the nearest place its old lines match.
/// `crlf`: the patch lost its CRs on the way, and the file's lines end in CRLF.
fn patch_file(data: &[u8], hunks: &[Hunk], file: &str, crlf: bool) -> std::result::Result<Vec<u8>, String> {
    let lines = split_lines(data);
    let mut out = Vec::with_capacity(data.len());
    let mut cursor = 0;
    // How far the hunks so far sat from where they said: the next one is looked for there.
    let mut offset = 0isize;
    // Line comparisons in proportion to the file and the patch: a hunk that nearly fits at every
    // line (a file of one line repeated) is refused, not searched for minutes.
    let mut budget = 64 * (lines.len() + hunks.iter().map(|h| h.lines.len()).sum::<usize>()) + (1 << 20);
    for (n, h) in hunks.iter().enumerate() {
        let old: Vec<&(u8, Vec<u8>, bool)> = h.lines.iter().filter(|l| l.0 != b'+').collect();
        let stated = if old.is_empty() { h.old_start } else { h.old_start.saturating_sub(1) };
        let want = stated.saturating_add_signed(offset);
        let found = if stated > lines.len() {
            None
        } else if old.is_empty() {
            (cursor..=lines.len()).contains(&want).then_some(want)
        } else if cursor + old.len() > lines.len() {
            None
        } else {
            // The nearest start to `want` first, the lower of two, from `cursor` to the last.
            let last = lines.len() - old.len();
            let want = want.clamp(cursor, last);
            let mut found = None;
            for d in 0..=last - cursor {
                let below = want.checked_sub(d).filter(|&at| at >= cursor);
                let above = want.checked_add(d).filter(|&at| d > 0 && at <= last);
                if below.is_none() && above.is_none() {
                    break;
                }
                found = [below, above].into_iter().flatten().find(|&at| {
                    old.iter().enumerate().all(|(k, l)| {
                        budget = budget.saturating_sub(1);
                        budget > 0 && same(lines[at + k], l)
                    })
                });
                if found.is_some() || budget == 0 {
                    break;
                }
            }
            found
        };
        let Some(at) = found else {
            return Err(format!("{file}: hunk #{} ({}) does not apply", n + 1, h.header));
        };
        offset = at as isize - stated as isize;
        for l in &lines[cursor..at] {
            out.extend_from_slice(l);
        }
        let mut k = at;
        for (kind, text, newline) in &h.lines {
            match kind {
                b'-' => k += 1,
                // The file's own line: its line end, whatever the patch lost of it.
                b' ' => {
                    out.extend_from_slice(lines[k]);
                    k += 1;
                }
                _ => {
                    out.extend_from_slice(text);
                    if *newline {
                        if crlf {
                            out.push(b'\r');
                        }
                        out.push(b'\n');
                    }
                }
            }
        }
        cursor = at + old.len();
    }
    for l in &lines[cursor..] {
        out.extend_from_slice(l);
    }
    Ok(out)
}

/// Apply the diff `text` to the package in `dir`. No file is written in place: it may be a
/// hardlink into the store, so it is removed and written anew. `sealed`: files it writes are
/// read-only, as the store's are.
pub fn apply(dir: &Path, text: &[u8], sealed: bool) -> std::result::Result<(), String> {
    let (diffs, converted) = parse(text)?;
    if diffs.is_empty() {
        return Err("it changes no file".into());
    }
    for d in diffs {
        let name = d.new.as_deref().or(d.old.as_deref()).unwrap_or("");
        let io = |e: std::io::Error| format!("{name}: {e}");
        let (data, mode) = match &d.old {
            Some(old) => {
                let at = dir.join(old);
                let meta = fs::symlink_metadata(&at).map_err(|_| format!("{old}: no such file in the package"))?;
                if !meta.is_file() {
                    return Err(format!("{old}: not a file"));
                }
                (fs::read(&at).map_err(io)?, file_mode(&meta))
            }
            None => (Vec::new(), 0o644),
        };
        let crlf = converted && data.windows(2).any(|w| w == b"\r\n");
        let patched = patch_file(&data, &d.hunks, name, crlf)?;
        let Some(new) = &d.new else {
            if !patched.is_empty() {
                return Err(format!("{name}: the file to delete holds more than the patch removes"));
            }
            fs::remove_file(dir.join(name)).map_err(io)?;
            continue;
        };
        let at = dir.join(new);
        if d.old.as_deref() != Some(new.as_str()) {
            if fs::symlink_metadata(&at).is_ok() {
                return Err(format!("{new}: already exists in the package"));
            }
            if let Some(old) = &d.old {
                fs::remove_file(dir.join(old)).map_err(io)?;
            }
        }
        write(&at, &patched, d.mode.unwrap_or(mode), sealed).map_err(io)?;
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_mode(_: &fs::Metadata) -> u32 {
    0o644
}

/// Copy a package's files into `to`, writable, leaving out any `node_modules` and links.
pub fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        let (kind, at) = (e.file_type()?, to.join(e.file_name()));
        if kind.is_dir() && e.file_name() != "node_modules" {
            copy_tree(&e.path(), &at)?;
        } else if kind.is_file() {
            write(&at, &fs::read(e.path())?, file_mode(&e.metadata()?), false)?;
        }
    }
    Ok(())
}

/// A new file where the old one was: removed first, never written through.
fn write(at: &Path, data: &[u8], mode: u32, sealed: bool) -> std::io::Result<()> {
    match fs::remove_file(at) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    if let Some(parent) = at.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(at, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let exec = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
        fs::set_permissions(at, fs::Permissions::from_mode(if sealed { exec & !0o222 } else { exec }))?;
    }
    #[cfg(not(unix))]
    let _ = (mode, sealed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = crate::store::tests::scratch("patch");
        for (path, text) in files {
            let at = dir.join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(at, text).unwrap();
        }
        dir
    }

    fn read(dir: &Path, path: &str) -> String {
        fs::read_to_string(dir.join(path)).unwrap()
    }

    const EDIT: &str = "diff --git a/lib/x.js b/lib/x.js\nindex 1..2 100644\n--- a/lib/x.js\n+++ b/lib/x.js\n\
                        @@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n";

    #[test]
    fn applies_a_git_diff() {
        let dir = tree(&[("lib/x.js", "one\ntwo\nthree\n"), ("gone.js", "a\nb\n"), ("old.js", "keep\n")]);
        let text = format!(
            "{EDIT}diff --git a/new.js b/new.js\nnew file mode 100755\n--- /dev/null\n+++ b/new.js\n@@ -0,0 +1,2 @@\n+#!/bin/sh\n+x\n\
             diff --git a/gone.js b/gone.js\ndeleted file mode 100644\n--- a/gone.js\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n\
             diff --git a/old.js b/moved/new.js\nsimilarity index 100%\nrename from old.js\nrename to moved/new.js\n"
        );
        apply(&dir, text.as_bytes(), true).unwrap();
        assert_eq!(read(&dir, "lib/x.js"), "one\nTWO\nthree\n");
        assert_eq!(read(&dir, "new.js"), "#!/bin/sh\nx\n");
        assert!(!dir.join("gone.js").exists() && !dir.join("old.js").exists());
        assert_eq!(read(&dir, "moved/new.js"), "keep\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!((mode("new.js"), mode("lib/x.js")), (0o555, 0o444), "sealed: read-only");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn never_writes_through_a_hardlink() {
        let dir = tree(&[("store.js", "one\ntwo\nthree\n")]);
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::hard_link(dir.join("store.js"), dir.join("lib/x.js")).unwrap();
        apply(&dir, EDIT.as_bytes(), false).unwrap();
        assert_eq!(read(&dir, "lib/x.js"), "one\nTWO\nthree\n");
        assert_eq!(read(&dir, "store.js"), "one\ntwo\nthree\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_line_ends_and_offsets() {
        // No newline at the end, before and after.
        let dir = tree(&[("a", "x\ny"), ("b", "p\nq\n")]);
        let text = "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n x\n-y\n\\ No newline at end of file\n+z\n\
                    --- a/b\n+++ b/b\n@@ -2 +2 @@\n-q\n+r\n\\ No newline at end of file\n";
        apply(&dir, text.as_bytes(), false).unwrap();
        assert_eq!((read(&dir, "a"), read(&dir, "b")), ("x\nz\n".into(), "p\nr".into()));
        // A CRLF file, a patch converted to CRLF, and a hunk three lines from where it says.
        let dir2 = tree(&[("lib/x.js", "a\r\nb\r\nc\r\none\r\ntwo\r\nthree\r\n")]);
        apply(&dir2, EDIT.replace('\n', "\r\n").as_bytes(), false).unwrap();
        assert_eq!(read(&dir2, "lib/x.js"), "a\r\nb\r\nc\r\none\r\nTWO\r\nthree\r\n");
        // A context line an editor trimmed to nothing.
        let dir3 = tree(&[("lib/x.js", "one\n\nthree\n")]);
        apply(&dir3, b"--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1,3 +1,3 @@\n one\n\n-three\n+3\n", false).unwrap();
        assert_eq!(read(&dir3, "lib/x.js"), "one\n\n3\n");
        for d in [dir, dir2, dir3] {
            fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn refuses_what_does_not_apply() {
        let dir = tree(&[("lib/x.js", "one\n2\nthree\n"), ("y", "y\n")]);
        let err = |text: &str| apply(&dir, text.as_bytes(), false).unwrap_err();
        assert_eq!(err(EDIT), "lib/x.js: hunk #1 (@@ -1,3 +1,3 @@) does not apply");
        assert!(err(&EDIT.replace("lib/x.js", "nope.js")).contains("no such file"));
        assert!(err(&EDIT.replace("@@ -1,3 +1,3 @@", "@@ -1,9 +1,3 @@")).contains("ends early"));
        assert!(err(&EDIT.replace("@@ -1,3 +1,3 @@", "@@ -x +1 @@")).contains("malformed"));
        assert!(err("--- /dev/null\n+++ b/y\n@@ -0,0 +1 @@\n+y\n").contains("already exists"));
        assert!(err("--- a/y\n+++ /dev/null\n@@ -1 +0,0 @@\n-z\n").contains("does not apply"));
        assert!(err("just words\n").contains("changes no file"));
        assert!(err("diff --git a/y b/y\nGIT binary patch\nliteral 0\n").contains("binary"));
        // Paths that leave the package.
        for path in ["../../etc/passwd", "a/../../x", "/etc/passwd", "C:/x", "a/C:x", "\"a/..\\057..\\057x\""] {
            let text = format!("--- a/y\n+++ {}\n@@ -1 +1 @@\n-y\n+z\n", path);
            assert!(err(&text).contains("not a path inside the package"), "{path}: {}", err(&text));
        }
        let rename = "diff --git a/y b/z\nrename from y\nrename to ../../z\n";
        assert!(err(rename).contains("not a path inside the package"));
        assert!(!dir.parent().unwrap().join("z").exists());
        assert_eq!(read(&dir, "y"), "y\n", "nothing written by a refused patch");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_yarns_patch_protocol() {
        let (range, patch) = yarn("x", "patch:x@npm%3A1.2.3#./.yarn/patches/x-npm-1.2.3-abc.patch").unwrap();
        assert_eq!(
            (range.as_str(), patch),
            ("1.2.3", Some(("x@1.2.3".into(), "./.yarn/patches/x-npm-1.2.3-abc.patch".into())))
        );
        let scoped =
            "patch:@s/x@npm%3A%5E2.0.0#~/.yarn/patches/x.patch::version=2.1.0&hash=abc&locator=app%40workspace%3A.";
        assert_eq!(
            yarn("@s/x", scoped).unwrap(),
            ("^2.0.0".into(), Some(("@s/x@^2.0.0".into(), ".yarn/patches/x.patch".into())))
        );
        assert_eq!(yarn("y", "patch:x@1.0.0#p.patch").unwrap().0, "npm:x@1.0.0", "an alias stays one");
        for builtin in ["optional!builtin<compat/typescript>", "~builtin<compat/fsevents>"] {
            assert_eq!(
                yarn("typescript", &format!("patch:typescript@npm%3A^5#{builtin}")).unwrap(),
                ("^5".into(), None)
            );
        }
        assert_eq!(yarn("x", "^1.0.0"), None);
        assert_eq!(yarn("x", "patch:x@1.0.0"), None);
    }

    #[test]
    fn picks_a_patch_per_version() {
        let p = |sel: &str| {
            let (name, range) = sel.split_once('@').map_or((sel, None), |(n, r)| (n, Some(r.to_string())));
            Patch { name: name.into(), range, path: format!("{sel}.patch"), hash: sel.into(), text: Vec::new() }
        };
        let tree = [
            ("a@1.0.0", "a", "1.0.0"),
            ("a@1.1.0", "a", "1.1.0"),
            ("a@2.0.0", "a", "2.0.0"),
            ("b@1.0.0", "b", "1.0.0"),
        ];
        let pick = |list: &[&str]| select(&list.iter().map(|s| p(s)).collect::<Vec<_>>(), tree.iter().copied());
        let got = pick(&["a@1.0.0", "a@^1", "a", "b@1.0.0"]).unwrap();
        let want: BTreeMap<String, String> =
            [("a@1.0.0", "a@1.0.0"), ("a@1.1.0", "a@^1"), ("a@2.0.0", "a"), ("b@1.0.0", "b@1.0.0")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        assert_eq!(got, want);
        assert!(pick(&["a@3.0.0"]).unwrap_err().message.contains("no package in the tree is patched by a@3.0.0"));
        assert!(pick(&["a", "b@^3"]).unwrap_err().message.contains("patched by b@^3 (b@^3.patch)"));
        assert!(pick(&["a@^1", "a@>=1.1"]).unwrap_err().message.contains("a@1.1.0 is patched by both"));
    }

    /// Random files, random edits, the diff git writes for them, applied back.
    #[test]
    fn applies_what_git_diff_writes() {
        let git = |args: &[&str], dir: &Path| std::process::Command::new("git").args(args).current_dir(dir).output();
        let dir = crate::store::tests::scratch("patch-fuzz");
        if git(&["--version"], &dir).is_err() {
            return; // no git here
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for case in 0..60 {
            let (a, b) = (dir.join(format!("a{case}")), dir.join(format!("b{case}")));
            fs::create_dir_all(&a).unwrap();
            let words = ["x", "y", "z", "", "  ", "x y", "\r"];
            let mut lines: Vec<String> = (0..next(40)).map(|_| words[next(7) as usize].to_string()).collect();
            let end = if next(4) == 0 { "" } else { "\n" };
            fs::write(a.join("f"), lines.join("\n") + end).unwrap();
            for _ in 0..next(6) {
                let at = next(lines.len() as u64 + 1) as usize;
                match next(3) {
                    0 if at < lines.len() => drop(lines.remove(at)),
                    1 if at < lines.len() => lines[at] = format!("changed{}", next(9)),
                    _ => lines.insert(at, format!("new{}", next(9))),
                }
            }
            let end = if next(4) == 0 { "" } else { "\n" };
            let after = lines.join("\n") + end;
            fs::create_dir_all(&b).unwrap();
            fs::write(b.join("f"), &after).unwrap();
            let args = ["-c", "core.autocrlf=false", "diff", "--no-index", "--no-color", "-U2"];
            let out = git(&[&args[..], &[&format!("a{case}/f"), &format!("b{case}/f")]].concat(), &dir).unwrap();
            let text = String::from_utf8(out.stdout)
                .unwrap()
                .replace(&format!("a/a{case}/"), "a/")
                .replace(&format!("b/b{case}/"), "b/");
            if text.is_empty() {
                continue;
            }
            apply(&a, text.as_bytes(), false).unwrap_or_else(|e| panic!("case {case}: {e}\n{text}"));
            assert_eq!(fs::read_to_string(a.join("f")).unwrap(), after, "case {case}:\n{text}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_hunks_that_name_lines_past_the_end() {
        let dir = tree(&[("f", "a\nb\n")]);
        for start in ["18446744073709551615", "4611686018427387904", "4"] {
            let text = format!("--- a/f\n+++ b/f\n@@ -{start},2 +1,2 @@\n a\n-b\n+c\n");
            assert!(apply(&dir, text.as_bytes(), false).unwrap_err().contains("does not apply"), "{start}");
        }
        assert_eq!(read(&dir, "f"), "a\nb\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A hunk that nearly fits at every line of a large file is refused, not searched for hours.
    #[test]
    fn bounds_the_search_for_a_hunk() {
        let dir = tree(&[("f", &"a\n".repeat(512 * 1024))]);
        let k = 20_000;
        let text = format!("--- a/f\n+++ b/f\n@@ -1,{k} +1,{k} @@\n{} zzz\n", " a\n".repeat(k - 1));
        let t = std::time::Instant::now();
        assert!(apply(&dir, text.as_bytes(), false).unwrap_err().contains("does not apply"));
        assert!(t.elapsed() < std::time::Duration::from_secs(30), "{:?}", t.elapsed());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Lines added above every hunk: each is found where the one before it was.
    #[test]
    fn carries_a_hunks_offset_to_the_next() {
        let body: String = (0..60).map(|i| format!("l{i}\n")).collect();
        let dir = tree(&[("f", &format!("{}{body}", "new\n".repeat(40)))]);
        let text = "--- a/f\n+++ b/f\n@@ -2,3 +2,3 @@\n l1\n-l2\n+L2\n l3\n@@ -50,3 +50,3 @@\n l49\n-l50\n+L50\n l51\n";
        apply(&dir, text.as_bytes(), false).unwrap();
        let want = body.replace("l2\n", "L2\n").replace("l50\n", "L50\n");
        assert_eq!(read(&dir, "f"), format!("{}{want}", "new\n".repeat(40)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_windows_device_names() {
        for path in ["b/con", "b/lib/NUL.js", "b/aux.d.ts", "b/com1", "b/x/LPT9.txt", "b/Prn"] {
            assert!(strip(path.as_bytes(), true).is_err(), "{path}");
        }
        for path in ["b/console.js", "b/com10", "b/lpt0", "b/auxiliary", "b/nul_js"] {
            assert!(strip(path.as_bytes(), true).is_ok(), "{path}");
        }
    }

    #[test]
    fn reads_a_patch_from_the_project_only() {
        let dir = tree(&[("patches/a.patch", EDIT), ("big.patch", "")]);
        let read = |path: &str| Patch::read(&dir, "x".into(), None, path);
        let p = read("./patches/a.patch").unwrap();
        assert_eq!((p.text.as_slice(), p.hash.as_str()), (EDIT.as_bytes(), crate::util::sha256_hex(EDIT).as_str()));
        for path in ["../x.patch", "/etc/passwd", "patches/../patches/a.patch", "C:/x", "patches\\a.patch", "", "a//b"]
        {
            assert!(read(path).unwrap_err().message.contains("not a path inside the project"), "{path}");
        }
        assert!(read("patches").unwrap_err().message.contains("not a file"));
        fs::write(dir.join("big.patch"), vec![b' '; (MAX_PATCH + 1) as usize]).unwrap();
        assert!(read("big.patch").unwrap_err().message.contains("larger than 16 MiB"));
        #[cfg(unix)]
        {
            // A checkout's links, to a directory or a file (or a device) anywhere.
            std::os::unix::fs::symlink(dir.join("patches"), dir.join("linked")).unwrap();
            std::os::unix::fs::symlink(dir.join("patches/a.patch"), dir.join("a.patch")).unwrap();
            for path in ["linked/a.patch", "a.patch"] {
                assert!(read(path).unwrap_err().message.contains("is a link"), "{path}");
            }
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// yarn writes one layer; a `patch:` inside one would have the spec reader recurse per layer.
    #[test]
    fn refuses_a_patch_inside_a_patch() {
        let mut v = "patch:b@npm%3A1.0.0#builtin<x>".to_string();
        assert_eq!(yarn("b", &v), Some(("1.0.0".into(), None)));
        for _ in 0..50 {
            v = format!("patch:b@{}#builtin<x>", v.replace('%', "%25").replace('#', "%23"));
        }
        assert_eq!(yarn("b", &v), None);
        assert!(crate::spec::parse_dep("b", &v).unwrap_err().message.contains("not a patch: range jpm reads"));
    }

    /// Hostile diffs: well-formed hunks and lines from a grammar of headers, counts and paths,
    /// applied to a small package. No panic, and nothing written beside it. `PATCH_FUZZ` sets
    /// how many.
    #[test]
    fn survives_hostile_diffs() {
        let iters: u64 = std::env::var("PATCH_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(500);
        let root = crate::store::tests::scratch("patch-fuzz-hostile");
        let mut seed = 0xDEAD_BEEF_1234_5678_u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n.max(1)
        };
        let paths = [
            "a/f",
            "b/f",
            "a/g",
            "b/g",
            "a/d/h",
            "/dev/null",
            "a/../x",
            "a/",
            "a",
            "\"a/f\"",
            "\"a/\\146\"",
            "\"a/..\\057x\"",
            "\"a/\\0\"",
            "\"a/f",
            "a/f\tjunk",
            "b/new",
            "b/d",
            "b/f/x",
            "b/F",
            "a/d",
        ];
        let nums = ["0", "1", "2", "3", "", "x", "-1", "99", "70000", "4611686018427387904", "18446744073709551615"];
        let mut applied = 0;
        for case in 0..iters {
            let pkg = root.join(format!("p{case}"));
            fs::create_dir_all(pkg.join("d")).unwrap();
            fs::write(pkg.join("f"), "one\ntwo\r\nthree\n\nfour").unwrap();
            fs::write(pkg.join("g"), "").unwrap();
            fs::write(pkg.join("d/h"), "h\n").unwrap();
            let mut text = Vec::new();
            // Well-formed hunks most of the time, so the applier's search and writes run.
            for _ in 0..next(4) {
                let (a, b) = (paths[next(paths.len() as u64) as usize], paths[next(paths.len() as u64) as usize]);
                let (a, b) = if next(2) == 0 { ("a/f", "b/f") } else { (a, b) };
                text.extend_from_slice(format!("diff --git {a} {b}\n--- {a}\n+++ {b}\n").as_bytes());
                for _ in 0..next(3) {
                    let body: Vec<&str> = (0..next(6))
                        .map(|_| {
                            [" one", "-two\r", " three", "", "-four", "+x", "+y", " two\r", "-one"][next(9) as usize]
                        })
                        .collect();
                    let old = body.iter().filter(|l| !l.starts_with('+')).count();
                    let new = body.iter().filter(|l| !l.starts_with('-')).count();
                    let at = next(6);
                    text.extend_from_slice(format!("@@ -{at},{old} +{at},{new} @@\n").as_bytes());
                    for l in body {
                        text.extend_from_slice(l.as_bytes());
                        text.push(b'\n');
                        if next(8) == 0 {
                            text.extend_from_slice(b"\\ No newline at end of file\n");
                        }
                    }
                }
            }
            for _ in 0..next(10) {
                let p = |next: &mut dyn FnMut(u64) -> u64| paths[next(paths.len() as u64) as usize];
                let n = |next: &mut dyn FnMut(u64) -> u64| nums[next(nums.len() as u64) as usize];
                let line = match next(16) {
                    0 => format!("diff --git {} {}", p(&mut next), p(&mut next)),
                    1 => format!("--- {}", p(&mut next)),
                    2 => format!("+++ {}", p(&mut next)),
                    3 => format!("@@ -{},{} +{},{} @@", n(&mut next), n(&mut next), n(&mut next), n(&mut next)),
                    4 => format!("@@ -{} +{} @@", n(&mut next), n(&mut next)),
                    5 => " one".into(),
                    6 => "-two\r".into(),
                    7 => "+new".into(),
                    8 => "\\ No newline at end of file".into(),
                    9 => String::new(),
                    10 => format!("new file mode 100{}", ["644", "755", "x", "777777"][next(4) as usize]),
                    11 => "deleted file mode 100644".into(),
                    12 => format!("rename from {}", p(&mut next)),
                    13 => format!("rename to {}", p(&mut next)),
                    14 => "new mode 100755".into(),
                    _ => ["-one", " two", "-four", " three", "+", "-", " "][next(7) as usize].into(),
                };
                text.extend_from_slice(line.as_bytes());
                text.extend_from_slice(if next(5) == 0 { b"\r\n" } else { b"\n" });
            }
            let sealed = next(2) == 0;
            let r = std::panic::catch_unwind(|| apply(&pkg, &text, sealed));
            assert!(r.is_ok(), "case {case} panicked:\n{}", String::from_utf8_lossy(&text));
            if matches!(r, Ok(Ok(()))) {
                applied += 1;
            }
            let _ = fs::remove_dir_all(&pkg);
            let outside: Vec<_> = fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name()).collect();
            assert!(outside.is_empty(), "case {case} wrote {outside:?}:\n{}", String::from_utf8_lossy(&text));
        }
        assert!(applied > iters / 50, "{applied} of {iters} applied: the grammar no longer reaches the writes");
        fs::remove_dir_all(&root).unwrap();
    }
}
