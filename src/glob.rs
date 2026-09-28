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

fn wild(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') => (0..=s.len()).any(|i| wild(&p[1..], &s[i..])),
        Some(b'?') => !s.is_empty() && wild(&p[1..], &s[1..]),
        Some(b'[') => match class(&p[1..], s.first().copied()) {
            Some((true, used)) => wild(&p[1 + used..], &s[1..]),
            Some((false, _)) => false,
            None => s.first() == Some(&b'[') && wild(&p[1..], &s[1..]),
        },
        Some(b'\\') if p.len() > 1 => s.first() == Some(&p[1]) && wild(&p[2..], &s[1..]),
        Some(c) => s.first() == Some(c) && wild(&p[1..], &s[1..]),
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

/// `{a,b}` expanded, nested too: `x{a,{b,c}}` is `xa`, `xb`, `xc`.
fn braces(pattern: &str) -> Vec<String> {
    let bytes = pattern.as_bytes();
    let Some(open) = bytes.iter().position(|b| *b == b'{') else { return vec![pattern.to_string()] };
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
    let Some(close) = close.filter(|_| !commas.is_empty()) else { return vec![pattern.to_string()] };
    let (head, tail) = (&pattern[..open], &pattern[close + 1..]);
    let mut starts = vec![open + 1];
    starts.extend(commas.iter().map(|c| c + 1));
    let mut ends = commas.clone();
    ends.push(close);
    starts.iter().zip(&ends).flat_map(|(s, e)| braces(&format!("{head}{}{tail}", &pattern[*s..*e]))).collect()
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
        if name == "node_modules" || !entry.path().is_dir() {
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
    }
}
