//! Globs for workspace patterns: `*`, `**`, `?`, `[abc]`, `[!a-z]` and `{a,b}`, matched against
//! `/`-separated paths, and expanded against a directory tree.

use std::path::Path;

/// Whether `path` matches `pattern`. `*` and `?` stay within a segment; `**` spans any number.
pub fn matches(pattern: &str, path: &str) -> bool {
    braces(pattern).iter().any(|p| {
        let pat: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        segments(&pat, &parts)
    })
}

fn segments(pat: &[&str], parts: &[&str]) -> bool {
    match pat.first() {
        None => parts.is_empty(),
        Some(&"**") => (0..=parts.len()).any(|i| segments(&pat[1..], &parts[i..])),
        Some(p) => {
            parts.first().is_some_and(|s| segment(p.as_bytes(), s.as_bytes()) && segments(&pat[1..], &parts[1..]))
        }
    }
}

/// One segment. A leading `.` is only matched by a pattern that spells it, as with shell globs.
fn segment(p: &[u8], s: &[u8]) -> bool {
    if s.first() == Some(&b'.') && p.first() != Some(&b'.') {
        return false;
    }
    wild(p, s)
}

/// Iterative, with one backtrack point per `*`: linear in practice, where recursion on every
/// `*` would take exponential time on a pattern like `*a*a*a*a*b` from a package.json.
fn wild(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if p.get(pi) == Some(&b'*') {
            star = Some((pi, si));
            pi += 1;
            continue;
        }
        if let Some(used) = one(&p[pi..], s[si]) {
            pi += used;
            si += 1;
            continue;
        }
        match star {
            Some((sp, ss)) => {
                pi = sp + 1;
                si = ss + 1;
                star = Some((sp, ss + 1));
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|c| *c == b'*')
}

/// Whether the pattern's next token matches `c`, and how many pattern bytes it spans.
fn one(p: &[u8], c: u8) -> Option<usize> {
    match p.first()? {
        b'*' => None,
        b'?' => Some(1),
        b'[' => match class(&p[1..], Some(c)) {
            Some((true, used)) => Some(1 + used),
            Some((false, _)) => None,
            None => (c == b'[').then_some(1),
        },
        b'\\' if p.len() > 1 => (p[1] == c).then_some(2),
        x => (*x == c).then_some(1),
    }
}

/// A `[...]` class after its `[`: whether `c` is in it, and the bytes it spans with its `]`.
fn class(p: &[u8], c: Option<u8>) -> Option<(bool, usize)> {
    let c = c?;
    let (negate, start) = match p.first() {
        Some(b'!' | b'^') => (true, 1),
        _ => (false, 0),
    };
    let mut i = start;
    let mut found = false;
    while i < p.len() {
        if p[i] == b']' && i > start {
            return Some((found != negate, i + 1));
        }
        if i + 2 < p.len() && p[i + 1] == b'-' && p[i + 2] != b']' {
            found |= (p[i]..=p[i + 2]).contains(&c);
            i += 3;
        } else {
            found |= p[i] == c;
            i += 1;
        }
    }
    None
}

/// Brace alternatives kept at most: `{a,b}` thirty times over is a billion patterns otherwise.
const MAX_BRACES: usize = 1024;

/// `{a,b}` expanded, nested too: `x{a,{b,c}}` is `xa`, `xb`, `xc`. At most `MAX_BRACES`.
pub fn braces(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_braces(pattern, &mut out);
    out
}

fn expand_braces(pattern: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_BRACES {
        return;
    }
    let bytes = pattern.as_bytes();
    let Some(open) = bytes.iter().position(|b| *b == b'{') else {
        out.push(pattern.to_string());
        return;
    };
    let mut depth = 0;
    let mut commas = Vec::new();
    let mut close = None;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close.filter(|_| !commas.is_empty()) else {
        out.push(pattern.to_string());
        return;
    };
    let (head, tail) = (&pattern[..open], &pattern[close + 1..]);
    let mut starts = vec![open + 1];
    starts.extend(commas.iter().map(|c| c + 1));
    let mut ends = commas.clone();
    ends.push(close);
    for (s, e) in starts.iter().zip(&ends) {
        expand_braces(&format!("{head}{}{tail}", &pattern[*s..*e]), out);
    }
}

/// The directories under `root` that `pattern` matches and no `exclude` pattern does, as
/// root-relative `/` paths. `node_modules` and dot directories are never entered.
pub fn expand(root: &Path, pattern: &str, exclude: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for p in braces(pattern) {
        let pat: Vec<String> = p.split('/').filter(|s| !s.is_empty() && *s != ".").map(str::to_string).collect();
        walk(root, String::new(), &pat, &mut out);
    }
    out.retain(|path| !exclude.iter().any(|e| matches(e, path)));
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, rel: String, pat: &[String], out: &mut Vec<String>) {
    let Some(first) = pat.first() else {
        out.push(rel);
        return;
    };
    let join = |name: &str| if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") };
    let literal = !first.contains(['*', '?', '[', '\\']);
    if literal {
        let next = dir.join(first);
        if next.is_dir() {
            walk(&next, join(first), &pat[1..], out);
        }
        return;
    }
    if first == "**" {
        walk(dir, rel.clone(), &pat[1..], out);
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Real directories only: a symlink loop under `**` would never end.
        if name == "node_modules" || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        if first == "**" {
            if !name.starts_with('.') {
                walk(&entry.path(), join(&name), pat, out);
            }
        } else if segment(first.as_bytes(), name.as_bytes()) {
            walk(&entry.path(), join(&name), &pat[1..], out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_globs() {
        assert!(matches("packages/*", "packages/a"));
        assert!(!matches("packages/*", "packages/a/b"));
        assert!(matches("packages/**", "packages/a/b"));
        assert!(matches("**/node_modules/**", "x/node_modules/y"));
        assert!(matches("p/{a,b}", "p/b"));
        assert!(matches("p/[a-c]x", "p/bx"));
        assert!(!matches("p/[!a-c]x", "p/bx"));
        assert!(!matches("p/*", "p/.hidden"));
        assert!(matches("p/?", "p/z"));
    }

    #[test]
    fn expands_braces() {
        assert_eq!(braces("a{b,{c,d}}e"), ["abe", "ace", "ade"]);
        assert_eq!(braces("no"), ["no"]);
        // Thirty pairs would be 2^30 patterns: capped, and quick.
        let start = std::time::Instant::now();
        assert_eq!(braces(&"{a,b}".repeat(30)).len(), MAX_BRACES);
        assert!(start.elapsed().as_secs() < 1);
    }

    #[test]
    fn matches_stars_in_linear_time() {
        let start = std::time::Instant::now();
        assert!(!matches(&format!("{}b", "*a".repeat(30)), &"a".repeat(80)));
        assert!(start.elapsed().as_millis() < 100);
        assert!(matches("p/*x*y", "p/axbby"));
        assert!(matches("p/a*", "p/a"));
        assert!(!matches("p/a*b", "p/ab/c"));
        assert!(matches("p/\\*", "p/*"));
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_symlinks_under_stars() {
        let root = std::env::temp_dir().join(format!("jpm-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("packages/a")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("packages/loop")).unwrap();
        std::os::unix::fs::symlink("/", root.join("packages/out")).unwrap();
        assert_eq!(expand(&root, "packages/**", &[]), ["packages", "packages/a"]);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
