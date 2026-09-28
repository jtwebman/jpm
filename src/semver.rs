//! npm's semver: versions, comparison and range matching, as `node-semver` reads them.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    Num(u64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Vec<Id>,
    /// Canonical text: no `v`, `=` or build metadata.
    pub text: String,
}

impl Version {
    fn new(major: u64, minor: u64, patch: u64, pre: Vec<Id>) -> Self {
        let mut text = format!("{major}.{minor}.{patch}");
        if !pre.is_empty() {
            text.push('-');
            text.push_str(&join_ids(&pre));
        }
        Self { major, minor, patch, pre, text }
    }
}

fn join_ids(ids: &[Id]) -> String {
    ids.iter()
        .map(|id| match id {
            Id::Num(n) => n.to_string(),
            Id::Str(s) => s.clone(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| cmp_pre(&self.pre, &other.pre))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_pre(a: &[Id], b: &[Id]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    for i in 0.. {
        match (a.get(i), b.get(i)) {
            (None, None) => return Ordering::Equal,
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let o = match (x, y) {
                    (Id::Num(x), Id::Num(y)) => x.cmp(y),
                    (Id::Num(_), Id::Str(_)) => Ordering::Less,
                    (Id::Str(_), Id::Num(_)) => Ordering::Greater,
                    (Id::Str(x), Id::Str(y)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
    Ordering::Equal
}

/// `0|[1-9]\d*`, as a number.
fn num(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// A dot-separated prerelease: numeric ids without leading zeros, or alphanumerics.
fn parse_pre(s: &str) -> Option<Vec<Id>> {
    s.split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(is_ident_char) {
                None
            } else if part.bytes().all(|b| b.is_ascii_digit()) {
                num(part).map(Id::Num)
            } else {
                Some(Id::Str(part.to_string()))
            }
        })
        .collect()
}

fn valid_build(s: &str) -> bool {
    s.split('.').all(|p| !p.is_empty() && p.bytes().all(is_ident_char))
}

/// Split `core-pre+build` into its three parts, the build unchecked.
fn split_tail(s: &str) -> (&str, Option<&str>, Option<&str>) {
    let (rest, build) = match s.find('+') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    match rest.find('-') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..]), build),
        None => (rest, None, build),
    }
}

pub fn parse(v: &str) -> Option<Version> {
    let v = v.trim().trim_start_matches(|c: char| c.is_whitespace() || c == '=' || c == 'v');
    let (core, pre, build) = split_tail(v);
    if build.is_some_and(|b| !valid_build(b)) {
        return None;
    }
    let mut parts = core.split('.');
    let major = num(parts.next()?)?;
    let minor = num(parts.next()?)?;
    let patch = num(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        Some(p) => parse_pre(p)?,
        None => Vec::new(),
    };
    Some(Version::new(major, minor, patch, pre))
}

/// Whether `v` is exactly a version, spelled canonically.
pub fn is_exact(v: &str) -> bool {
    parse(v).is_some_and(|p| p.text == v)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    v: Version,
}

/// A partial version; `None` parts are wildcards.
struct Partial {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
    pre: Vec<Id>,
}

fn parse_partial(s: &str) -> Option<Partial> {
    let s = s.trim().trim_start_matches(['=', 'v']);
    let (core, pre, build) = split_tail(s);
    if build.is_some_and(|b| !valid_build(b)) {
        return None;
    }
    let part = |p: Option<&str>| -> Option<Option<u64>> {
        match p {
            None => Some(None),
            Some("x" | "X" | "*") => Some(None),
            Some(p) => num(p).map(Some),
        }
    };
    let mut pieces = core.split('.');
    let first = pieces.next()?;
    if first.is_empty() {
        return None;
    }
    let major = part(Some(first))?;
    let minor = part(pieces.next())?;
    let patch = part(pieces.next())?;
    if pieces.next().is_some() {
        return None;
    }
    // A concrete part may not follow a wildcard one.
    let gap = match major {
        None => minor.is_some() || patch.is_some(),
        Some(_) => minor.is_none() && patch.is_some(),
    };
    if gap {
        return None;
    }
    let pre = match pre {
        // A prerelease needs all three parts, so `v2-latest` stays a tag rather than a range.
        Some(_) if patch.is_none() => return None,
        Some(p) => parse_pre(p)?,
        None => Vec::new(),
    };
    Some(Partial { major, minor, patch, pre })
}

fn ge(ma: u64, mi: u64, p: u64, pre: Vec<Id>) -> Comparator {
    Comparator { op: Op::Ge, v: Version::new(ma, mi, p, pre) }
}

/// Upper bounds end in `-0` so no prerelease of the excluded version slips in.
fn lt(ma: u64, mi: u64, p: u64) -> Comparator {
    Comparator { op: Op::Lt, v: Version::new(ma, mi, p, vec![Id::Num(0)]) }
}

fn expand(op: &str, q: &Partial, inc_pr: bool) -> Vec<Comparator> {
    let partial = q.minor.is_none() || q.patch.is_none();
    let pre = if !q.pre.is_empty() {
        q.pre.clone()
    } else if inc_pr && partial {
        vec![Id::Num(0)]
    } else {
        Vec::new()
    };
    let Some(ma) = q.major else {
        // `*` matches anything; `>*` and `<*` match nothing.
        return if op == ">" || op == "<" { vec![lt(0, 0, 0)] } else { Vec::new() };
    };
    if op == "^" || op == "~" {
        let low = ge(ma, q.minor.unwrap_or(0), q.patch.unwrap_or(0), pre);
        let Some(mi) = q.minor else { return vec![low, lt(ma + 1, 0, 0)] };
        if op == "~" {
            return vec![low, lt(ma, mi + 1, 0)];
        }
        if ma != 0 {
            return vec![low, lt(ma + 1, 0, 0)];
        }
        // A caret on 0.x pins the minor, on 0.0.x the patch.
        return match q.patch {
            Some(p) if mi == 0 => vec![low, lt(0, 0, p + 1)],
            _ => vec![low, lt(0, mi + 1, 0)],
        };
    }
    if partial {
        if op.is_empty() || op == "=" {
            return match q.minor {
                None => vec![ge(ma, 0, 0, pre), lt(ma + 1, 0, 0)],
                Some(mi) => vec![ge(ma, mi, 0, pre), lt(ma, mi + 1, 0)],
            };
        }
        // A comparator against a partial version shifts to the next whole range.
        let (mut major, mut minor) = (ma, q.minor.unwrap_or(0));
        let mut o = op;
        if op == ">" || op == "<=" {
            o = if op == ">" { ">=" } else { "<" };
            if q.minor.is_none() {
                major += 1;
            } else {
                minor += 1;
            }
        }
        let op = to_op(o);
        let pre = if op == Op::Lt { vec![Id::Num(0)] } else { pre };
        return vec![Comparator { op, v: Version::new(major, minor, 0, pre) }];
    }
    let (Some(mi), Some(p)) = (q.minor, q.patch) else { return Vec::new() };
    vec![Comparator { op: to_op(op), v: Version::new(ma, mi, p, q.pre.clone()) }]
}

fn to_op(op: &str) -> Op {
    match op {
        "<" => Op::Lt,
        "<=" => Op::Le,
        ">" => Op::Gt,
        ">=" => Op::Ge,
        _ => Op::Eq,
    }
}

fn hyphen(a: &Partial, b: &Partial, inc_pr: bool) -> Vec<Comparator> {
    let mut out = Vec::new();
    let low = if !a.pre.is_empty() {
        a.pre.clone()
    } else if inc_pr {
        vec![Id::Num(0)]
    } else {
        Vec::new()
    };
    if let Some(ma) = a.major {
        out.push(ge(ma, a.minor.unwrap_or(0), a.patch.unwrap_or(0), low));
    }
    if let Some(ma) = b.major {
        match (b.minor, b.patch) {
            (None, _) => out.push(lt(ma + 1, 0, 0)),
            (Some(mi), None) => out.push(lt(ma, mi + 1, 0)),
            (Some(mi), Some(p)) if b.pre.is_empty() && inc_pr => out.push(lt(ma, mi, p + 1)),
            (Some(mi), Some(p)) => {
                out.push(Comparator { op: Op::Le, v: Version::new(ma, mi, p, b.pre.clone()) });
            }
        }
    }
    out
}

/// Split an operator off a token: `~>`, `<`, `<=`, `>`, `>=`, `~`, `^`, `=`.
fn split_op(token: &str) -> (&str, &str) {
    for op in ["~>", "<=", ">=", "<", ">", "~", "^", "="] {
        if let Some(rest) = token.strip_prefix(op) {
            return (op, rest);
        }
    }
    ("", token)
}

fn parse_set(branch: &str, inc_pr: bool) -> Option<Vec<Comparator>> {
    // An operator followed by spaces binds to the next word: `>= 1.2` is `>=1.2`.
    let mut joined = String::with_capacity(branch.len());
    let mut words = branch.split_whitespace().peekable();
    while let Some(word) = words.next() {
        joined.push_str(word);
        let (op, rest) = split_op(word);
        if !(rest.is_empty() && !op.is_empty() && words.peek().is_some()) {
            joined.push(' ');
        }
    }
    let tokens: Vec<&str> = joined.split_whitespace().collect();
    let mut set = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens.get(i + 1) == Some(&"-") {
            let a = parse_partial(tokens[i])?;
            let b = parse_partial(tokens.get(i + 2).copied().unwrap_or(""))?;
            set.extend(hyphen(&a, &b, inc_pr));
            i += 3;
            continue;
        }
        let (op, rest) = split_op(tokens[i]);
        let q = parse_partial(rest)?;
        set.extend(expand(if op == "~>" { "~" } else { op }, &q, inc_pr));
        i += 1;
    }
    Some(set)
}

type Sets = Arc<Vec<Vec<Comparator>>>;

/// Ranking a packument tests one range against every version, so parses are kept.
fn parse_range(range: &str, inc_pr: bool) -> Option<Sets> {
    type Cache = Mutex<HashMap<(bool, String), Option<Sets>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (inc_pr, range.to_string());
    if let Some(hit) = cache.lock().ok()?.get(&key) {
        return hit.clone();
    }
    let sets: Option<Vec<_>> = range.split("||").map(|b| parse_set(b, inc_pr)).collect();
    let sets = sets.map(Arc::new);
    if let Ok(mut c) = cache.lock() {
        c.insert(key, sets.clone());
    }
    sets
}

fn holds(o: Ordering, op: Op) -> bool {
    match o {
        Ordering::Equal => !matches!(op, Op::Lt | Op::Gt),
        Ordering::Less => matches!(op, Op::Lt | Op::Le),
        Ordering::Greater => matches!(op, Op::Gt | Op::Ge),
    }
}

fn test_set(v: &Version, set: &[Comparator], inc_pr: bool) -> bool {
    if !set.iter().all(|c| holds(v.cmp(&c.v), c.op)) {
        return false;
    }
    // A prerelease only matches if some comparator opts into that exact tuple.
    if !v.pre.is_empty() && !inc_pr {
        return set
            .iter()
            .any(|c| !c.v.pre.is_empty() && c.v.major == v.major && c.v.minor == v.minor && c.v.patch == v.patch);
    }
    true
}

pub fn valid_range(range: &str) -> bool {
    parse_range(range, false).is_some()
}

pub fn satisfies_version(v: &Version, range: &str, inc_pr: bool) -> bool {
    parse_range(range, inc_pr).is_some_and(|sets| sets.iter().any(|s| test_set(v, s, inc_pr)))
}

pub fn satisfies(version: &str, range: &str) -> bool {
    parse(version).is_some_and(|v| satisfies_version(&v, range, false))
}

/// The highest of `versions` the range allows, as written in the list.
pub fn max_satisfying<'a, I>(versions: I, range: &str) -> Option<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let sets = parse_range(range, false)?;
    let mut best: Option<(Version, &str)> = None;
    for raw in versions {
        let Some(v) = parse(raw) else { continue };
        if !sets.iter().any(|s| test_set(&v, s, false)) {
            continue;
        }
        if best.as_ref().is_none_or(|(b, _)| v > *b) {
            best = Some((v, raw));
        }
    }
    best.map(|(_, raw)| raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse("v1.2.3").unwrap().text, "1.2.3");
        assert_eq!(parse(" =1.2.3-beta.1+build.5 ").unwrap().text, "1.2.3-beta.1");
        assert!(parse("1.2").is_none());
        assert!(parse("01.2.3").is_none());
        assert!(parse("1.2.3-01").is_none());
        assert!(is_exact("1.2.3"));
        assert!(!is_exact("v1.2.3"));
    }

    #[test]
    fn orders_prereleases() {
        let ord = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ord.windows(2) {
            assert!(parse(pair[0]).unwrap() < parse(pair[1]).unwrap(), "{pair:?}");
        }
    }

    #[test]
    fn matches_ranges() {
        let yes = [
            ("1.2.3", "^1.0.0"),
            ("1.2.3", "~1.2.0"),
            ("0.2.5", "^0.2.1"),
            ("0.0.3", "^0.0.3"),
            ("1.2.3", "1.x"),
            ("1.2.3", "*"),
            ("1.2.3", ""),
            ("2.0.0", ">=1.2.3 <3"),
            ("1.2.3", "1.2.3 - 2"),
            ("1.2.3", ">= 1.2.3"),
            ("1.2.3", "<1 || >=1.2"),
            ("1.2.3-beta.2", "^1.2.3-beta.1"),
            ("1.2.4", "~>1.2"),
            ("3.0.0", ">2"),
        ];
        for (v, r) in yes {
            assert!(satisfies(v, r), "{v} should satisfy {r}");
        }
        let no = [
            ("2.0.0", "^1.0.0"),
            ("0.3.0", "^0.2.1"),
            ("0.0.4", "^0.0.3"),
            ("1.3.0", "~1.2.0"),
            ("1.2.4-beta", "^1.2.3"),
            ("2.0.0-0", "<2"),
            ("1.0.0", ">*"),
            ("2.1.0", "1.2.3 - 2.0"),
        ];
        for (v, r) in no {
            assert!(!satisfies(v, r), "{v} should not satisfy {r}");
        }
        assert!(!valid_range("latest"));
        assert!(!valid_range("v2-latest"));
        assert!(valid_range("1.2.3"));
    }

    #[test]
    fn picks_the_max() {
        let versions = ["1.0.0", "1.5.0", "2.0.0", "1.9.9-beta", "junk"];
        assert_eq!(max_satisfying(versions, "^1"), Some("1.5.0"));
        assert_eq!(max_satisfying(versions, "^3"), None);
    }
}
