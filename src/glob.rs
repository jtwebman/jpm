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

/// `**` is to segments what `*` is to bytes, so this is `wild` again, one backtrack point for
/// the last `**`: recursion on every `**` would take exponential time on `**/**/**/…/x`.
fn segments(pat: &[&str], parts: &[&str]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < parts.len() {
        if pat.get(pi) == Some(&"**") {
            star = Some((pi, si));
            pi += 1;
        } else if pat.get(pi).is_some_and(|p| segment(p.as_bytes(), parts[si].as_bytes())) {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    pat[pi..].iter().all(|p| *p == "**")
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
pub const MAX_BRACES: usize = 1024;

/// The longest pattern, and the most `{`, a glob is read with. Expanding holds a copy of the
/// pattern for each brace group it is inside, so past these a pattern is refused, not expanded.
pub const MAX_PATTERN: usize = 4096;
const MAX_GROUPS: usize = 64;

/// Whether a pattern is past `MAX_PATTERN` or `MAX_GROUPS`: one no package.json writes.
pub fn too_big(pattern: &str) -> bool {
    pattern.len() > MAX_PATTERN || pattern.bytes().filter(|b| *b == b'{').count() > MAX_GROUPS
}

/// `{a,b}` expanded, nested too: `x{a,{b,c}}` is `xa`, `xb`, `xc`. At most `MAX_BRACES`, and
/// nothing for a pattern `too_big`.
pub fn braces(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !too_big(pattern) {
        expand_braces(pattern, &mut out);
    }
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
        let mut pat: Vec<&str> = p.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
        pat.dedup_by(|a, b| *a == "**" && *b == "**");
        walk(root, String::new(), &pat, after_stars(&pat, vec![0]), &mut out);
    }
    out.retain(|path| !exclude.iter().any(|e| matches(e, path)));
    out.sort();
    out.dedup();
    out
}

/// `at` with the position past each `**` in it added: a `**` may match no directory at all.
fn after_stars(pat: &[&str], mut at: Vec<usize>) -> Vec<usize> {
    let mut i = 0;
    while let Some(&s) = at.get(i) {
        if pat.get(s) == Some(&"**") {
            at.push(s + 1);
        }
        i += 1;
    }
    at.sort_unstable();
    at.dedup();
    at
}

/// Each directory once, with every pattern position `at` it: following each `**` on its own
/// would enter a directory once per way of sharing its path among them, and `**/a/**/a/**/a…`
/// exponentially many times.
fn walk(dir: &Path, rel: String, pat: &[&str], at: Vec<usize>, out: &mut Vec<String>) {
    let join = |name: &str| if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") };
    let literal = |s: usize| pat.get(s).is_some_and(|p| !p.contains(['*', '?', '[', '\\']));
    if let [s] = at[..]
        && literal(s)
    {
        let next = dir.join(pat[s]);
        if next.is_dir() {
            walk(&next, join(pat[s]), pat, after_stars(pat, vec![s + 1]), out);
        }
        return;
    }
    if at.contains(&pat.len()) {
        out.push(rel.clone());
        if at.len() == 1 {
            return;
        }
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Real directories only: a symlink loop under `**` would never end. A name the pattern
        // spells out is followed to wherever it leads, as it is when it stands alone.
        let real = name != "node_modules" && entry.file_type().is_ok_and(|t| t.is_dir());
        let mut next = Vec::new();
        for &s in &at {
            let Some(p) = pat.get(s) else { continue };
            if *p == "**" {
                if real && !name.starts_with('.') {
                    next.push(s);
                }
            } else if literal(s) && *p == name {
                if entry.path().is_dir() {
                    next.push(s + 1);
                }
            } else if real && segment(p.as_bytes(), name.as_bytes()) {
                next.push(s + 1);
            }
        }
        if !next.is_empty() {
            walk(&entry.path(), join(&name), pat, after_stars(pat, next), out);
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
        // Too long, or too many groups: each level would hold a copy of the pattern.
        assert!(too_big(&"{a,b}".repeat(1000)) && braces(&"{a,b}".repeat(1000)).is_empty());
        let nested = format!("{}a,b{}", "{".repeat(65), "}".repeat(65));
        assert!(braces(&nested).is_empty());
    }

    #[test]
    fn matches_double_stars_in_linear_time() {
        let path = vec!["a"; 22].join("/");
        let start = std::time::Instant::now();
        assert!(!matches(&format!("{}x", "**/".repeat(10)), &path));
        assert!(start.elapsed().as_millis() < 100, "{:?}", start.elapsed());
        assert!(matches(&format!("{}a", "**/".repeat(10)), &path));
        assert!(matches("a/**/b/**", "a/x/y/b"));
        assert!(!matches("a/**/b", "a/x/c"));
        assert!(matches("**/a/**/b", "a/b"));
    }

    #[test]
    fn expands_into_each_directory_once() {
        let root = std::env::temp_dir().join(format!("jpm-glob-deep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(vec!["a"; 24].join("/"))).unwrap();
        let start = std::time::Instant::now();
        let found = expand(&root, &"**/a/".repeat(8), &[]);
        assert!(start.elapsed().as_millis() < 500, "{:?}", start.elapsed());
        let want: Vec<String> = (8..=24).map(|n| vec!["a"; n].join("/")).collect();
        assert_eq!(found, want);
        assert_eq!(expand(&root, "**/**/**", &[]).len(), 25);
        std::fs::remove_dir_all(&root).unwrap();
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
