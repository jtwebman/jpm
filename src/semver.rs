//! npm's semver: versions, comparison and range matching, as `node-semver` reads them with
//! `loose: true`, the way npm-package-arg and npm-pick-manifest call it.
//!
//! node-semver reads a range by rewriting its text (hyphens, operators' spaces, carets, tildes,
//! x-ranges) and then parsing what is left as comparators. Its answers follow from those
//! rewrites, oddities included, so ranges here go through the same steps as text.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// node-semver refuses a version longer than this, or with a part above 2^53-1.
const MAX_LENGTH: usize = 256;
const MAX_SAFE: u64 = (1 << 53) - 1;

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

    fn same_tuple(&self, other: &Version) -> bool {
        (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)
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
                let o = cmp_id(x, y);
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
    Ordering::Equal
}

/// Numbers sort below words. An all-digit identifier too big to be a number is still compared
/// as one, as a JavaScript number is: a float.
fn cmp_id(a: &Id, b: &Id) -> Ordering {
    let num = |id: &Id| match id {
        Id::Num(n) => Some(*n as f64),
        Id::Str(s) => s.bytes().all(|b| b.is_ascii_digit()).then(|| s.parse().unwrap_or(f64::INFINITY)),
    };
    match (a, b) {
        (Id::Num(x), Id::Num(y)) => x.cmp(y),
        (Id::Str(x), Id::Str(y)) if num(a).is_none() && num(b).is_none() => x.cmp(y),
        _ => match (num(a), num(b)) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            _ => Ordering::Greater,
        },
    }
}

// --- reading text ------------------------------------------------------------------------------

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// Dot-separated identifiers of `[0-9A-Za-z-]`, none empty.
fn ids_ok(s: &str) -> bool {
    s.split('.').all(|p| !p.is_empty() && p.bytes().all(is_ident))
}

fn digits(s: &str) -> usize {
    s.bytes().take_while(u8::is_ascii_digit).count()
}

/// The `v`, `=` and spaces node-semver lets stand before a version.
fn skip_prefix(s: &str) -> &str {
    s.trim_start_matches(|c: char| c == 'v' || c == '=' || c.is_whitespace())
}

/// What may follow a patch: a prerelease, its `-` optional, then build metadata. The `-` is the
/// separator when the rest reads without it; otherwise it starts the first identifier.
fn tail(s: &str) -> Option<Option<&str>> {
    let (pre, build) = match s.split_once('+') {
        Some((p, b)) => (p, Some(b)),
        None => (s, None),
    };
    if build.is_some_and(|b| !ids_ok(b)) {
        return None;
    }
    if pre.is_empty() {
        return Some(None);
    }
    match pre.strip_prefix('-') {
        Some(p) if ids_ok(p) => Some(Some(p)),
        _ => ids_ok(pre).then_some(Some(pre)),
    }
}

/// A patch's digits and its tail. Digits give way to the tail one at a time, as the regex
/// backtracks: `1.2.34.5` is `1.2.3-4.5`.
fn patch_tail(s: &str) -> Option<(&str, Option<&str>)> {
    (1..=digits(s)).rev().find_map(|k| Some((&s[..k], tail(&s[k..])?)))
}

/// A whole version as written: node-semver's LOOSEPLAIN.
struct Plain<'a> {
    major: &'a str,
    minor: &'a str,
    patch: &'a str,
    pre: Option<&'a str>,
}

fn loose_plain(s: &str) -> Option<Plain<'_>> {
    let s = skip_prefix(s);
    let (major, s) = s.split_at(digits(s));
    let s = s.strip_prefix('.').filter(|_| !major.is_empty())?;
    let (minor, s) = s.split_at(digits(s));
    let s = s.strip_prefix('.').filter(|_| !minor.is_empty())?;
    let (patch, pre) = patch_tail(s)?;
    Some(Plain { major, minor, patch, pre })
}

/// Leading zeros are fine; a prerelease number from 2^53-1 up stays text, as node-semver keeps it.
fn version(p: &Plain) -> Option<Version> {
    let part = |s: &str| s.parse::<u64>().ok().filter(|n| *n <= MAX_SAFE);
    let id = |s: &str| match s.parse::<u64>() {
        Ok(n) if n < MAX_SAFE && s.bytes().all(|b| b.is_ascii_digit()) => Id::Num(n),
        _ => Id::Str(s.to_string()),
    };
    let pre = p.pre.map_or_else(Vec::new, |pre| pre.split('.').map(id).collect());
    Some(Version::new(part(p.major)?, part(p.minor)?, part(p.patch)?, pre))
}

pub fn parse(v: &str) -> Option<Version> {
    if v.len() > MAX_LENGTH {
        return None;
    }
    version(&loose_plain(v.trim())?)
}

/// Whether `v` is exactly a version, spelled canonically.
pub fn is_exact(v: &str) -> bool {
    parse(v).is_some_and(|p| p.text == v)
}

// --- ranges as text ----------------------------------------------------------------------------

/// A version with wildcards, as written: node-semver's XRANGEPLAINLOOSE. Missing parts are `None`.
struct XPlain<'a> {
    major: &'a str,
    minor: Option<&'a str>,
    patch: Option<&'a str>,
    pre: Option<&'a str>,
}

fn is_x(part: Option<&str>) -> bool {
    part.is_none_or(|p| p.eq_ignore_ascii_case("x") || p == "*")
}

fn xid(s: &str) -> usize {
    match s.as_bytes().first() {
        Some(b'x' | b'X' | b'*') => 1,
        _ => digits(s),
    }
}

fn xrange_plain(s: &str) -> Option<XPlain<'_>> {
    let s = skip_prefix(s);
    let (major, s) = s.split_at(xid(s));
    if major.is_empty() {
        return None;
    }
    let short = |minor| XPlain { major, minor, patch: None, pre: None };
    let Some(s) = s.strip_prefix('.') else { return s.is_empty().then(|| short(None)) };
    let (minor, s) = s.split_at(xid(s));
    if minor.is_empty() {
        return None;
    }
    let Some(s) = s.strip_prefix('.') else { return s.is_empty().then(|| short(Some(minor))) };
    let (patch, pre) = match xid(s) {
        0 => return None,
        1 if !s.as_bytes()[0].is_ascii_digit() => (&s[..1], tail(&s[1..])?),
        _ => patch_tail(s)?,
    };
    Some(XPlain { major, minor: Some(minor), patch: Some(patch), pre })
}

/// `+part + 1` as JavaScript prints it: rounded past 2^53, exponential from 1e21. Either way
/// the comparator it lands in is then refused or dropped, as node-semver's would be.
fn inc(part: &str) -> String {
    let n = part.parse::<f64>().unwrap_or(f64::INFINITY) + 1.0;
    if !n.is_finite() {
        "Infinity".into()
    } else if n < 1e21 {
        (n as u128).to_string()
    } else {
        format!("{n:e}").replace('e', "e+")
    }
}

/// `(<|>)?=?` at the front, greedily.
fn split_gtlt(s: &str) -> (&str, &str) {
    let b = s.as_bytes();
    let mut n = usize::from(matches!(b.first(), Some(b'<' | b'>')));
    if b.get(n) == Some(&b'=') {
        n += 1;
    }
    s.split_at(n)
}

/// Build metadata is cut out of the whole range first, wherever it stands.
fn strip_builds(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i, mut kept) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if b[i] != b'+' || !b.get(i + 1).copied().is_some_and(is_ident) {
            i += 1;
            continue;
        }
        out.push_str(&s[kept..i]);
        i += 1;
        loop {
            while b.get(i).copied().is_some_and(is_ident) {
                i += 1;
            }
            if b.get(i) == Some(&b'.') && b.get(i + 1).copied().is_some_and(is_ident) {
                i += 1;
            } else {
                break;
            }
        }
        kept = i;
    }
    out.push_str(&s[kept..]);
    out
}

/// `a - b` as bounds; the whole set has to be that one hyphen range.
fn hyphen(set: &str, inc_pr: bool) -> Option<String> {
    let set = set.strip_prefix(' ').unwrap_or(set);
    let set = set.strip_suffix(' ').unwrap_or(set);
    let (from, to) = set.split_once(" - ")?;
    let (f, t) = (xrange_plain(from)?, xrange_plain(to)?);
    let z = if inc_pr { "-0" } else { "" };
    let (fm, tm) = (f.minor.unwrap_or_default(), t.minor.unwrap_or_default());
    let low = if is_x(Some(f.major)) {
        String::new()
    } else if is_x(f.minor) {
        format!(">={}.0.0{z}", f.major)
    } else if is_x(f.patch) {
        format!(">={}.{fm}.0{z}", f.major)
    } else if f.pre.is_some() {
        format!(">={from}")
    } else {
        format!(">={from}{z}")
    };
    let high = if is_x(Some(t.major)) {
        String::new()
    } else if is_x(t.minor) {
        format!("<{}.0.0-0", inc(t.major))
    } else if is_x(t.patch) {
        format!("<{}.{}.0-0", t.major, inc(tm))
    } else if let Some(pr) = t.pre {
        format!("<={}.{tm}.{}-{pr}", t.major, t.patch.unwrap_or_default())
    } else if inc_pr {
        format!("<{}.{tm}.{}-0", t.major, inc(t.patch.unwrap_or_default()))
    } else {
        format!("<={to}")
    };
    Some(format!("{low} {high}").trim().to_string())
}

/// How much of `s` a version-like match takes, if one starts there: a `v`/`=`/space prefix, then
/// a digit, `x` or `*`, and the version's characters after it.
fn versionish(s: &str) -> Option<usize> {
    let body = skip_prefix(s);
    let start = s.len() - body.len();
    if !matches!(body.as_bytes().first(), Some(b'0'..=b'9' | b'x' | b'X' | b'*')) {
        return None;
    }
    let run = body.bytes().take_while(|&b| is_ident(b) || matches!(b, b'.' | b'+' | b'*')).count();
    Some(start + run)
}

/// The spaces node-semver closes up: after an operator before a version (`>= 1.2.3`), after `~`,
/// `~>` and `^`. The first pass runs left to right, each match taking its version along.
fn close_ops(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let start = i + usize::from(s[i..].starts_with(' '));
        let op = split_gtlt(&s[start..]).0.len();
        let gap = usize::from(s[start + op..].starts_with(' '));
        let at = start + op + gap;
        if let Some(n) = versionish(&s[at..]) {
            out.push_str(&s[i..start + op]);
            out.push_str(&s[at..at + n]);
            i = at + n;
        } else {
            let c = s[i..].chars().next().unwrap_or(' ');
            out.push(c);
            i += c.len_utf8();
        }
    }
    let mut closed = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(c) = rest.chars().next() {
        closed.push(c);
        rest = &rest[c.len_utf8()..];
        if c == '~' {
            rest = rest.strip_prefix("> ").or_else(|| rest.strip_prefix(' ')).unwrap_or(rest);
        } else if c == '^' {
            rest = rest.strip_prefix(' ').unwrap_or(rest);
        }
    }
    closed
}

/// `^x.y.z`: up to the next change of the first part that is not zero.
fn caret(x: &XPlain, z: &str) -> String {
    let (ma, mi, pa) = (x.major, x.minor.unwrap_or_default(), x.patch.unwrap_or_default());
    if is_x(Some(ma)) {
        return String::new();
    }
    if is_x(x.minor) {
        return format!(">={ma}.0.0{z} <{}.0.0-0", inc(ma));
    }
    if is_x(x.patch) {
        let high = if ma == "0" { format!("{ma}.{}.0", inc(mi)) } else { format!("{}.0.0", inc(ma)) };
        return format!(">={ma}.{mi}.0{z} <{high}-0");
    }
    let low = match x.pre {
        Some(pr) => format!(">={ma}.{mi}.{pa}-{pr}"),
        None => format!(">={ma}.{mi}.{pa}"),
    };
    // node-semver asks whether a part is spelled "0", so `^00.1.2` reaches the next major.
    let high = match (ma, mi) {
        ("0", "0") => format!("{ma}.{mi}.{}", inc(pa)),
        ("0", _) => format!("{ma}.{}.0", inc(mi)),
        _ => format!("{}.0.0", inc(ma)),
    };
    format!("{low} <{high}-0")
}

/// `~x.y.z`: up to the next minor, or the next major when only that is given.
fn tilde(x: &XPlain, z: &str) -> String {
    let (ma, mi, pa) = (x.major, x.minor.unwrap_or_default(), x.patch.unwrap_or_default());
    if is_x(Some(ma)) {
        String::new()
    } else if is_x(x.minor) {
        format!(">={ma}.0.0{z} <{}.0.0-0", inc(ma))
    } else if is_x(x.patch) {
        format!(">={ma}.{mi}.0{z} <{ma}.{}.0-0", inc(mi))
    } else if let Some(pr) = x.pre {
        format!(">={ma}.{mi}.{pa}-{pr} <{ma}.{}.0-0", inc(mi))
    } else {
        format!(">={ma}.{mi}.{pa} <{ma}.{}.0-0", inc(mi))
    }
}

/// `1.x`, `>=1.2`, `<=1`: wildcards become bounds. A wildcard's prerelease is ignored, and a
/// token with a number after a wildcard (`1.x.3`) is left as it is, to be dropped.
fn xrange(op: &str, x: &XPlain, token: &str, inc_pr: bool) -> String {
    let (ma, mi) = (x.major, x.minor.unwrap_or_default());
    if (is_x(Some(ma)) && !is_x(x.minor)) || (is_x(x.minor) && x.patch.is_some() && !is_x(x.patch)) {
        return token.to_string();
    }
    let xma = is_x(Some(ma));
    let xmi = xma || is_x(x.minor);
    let any = xmi || is_x(x.patch);
    let mut op = if op == "=" && any { "" } else { op };
    let mut pr = if inc_pr { "-0" } else { "" };
    if xma {
        return if op == ">" || op == "<" { "<0.0.0-0" } else { "*" }.into();
    }
    if !op.is_empty() && any {
        let (mut ma, mut mi) = (ma.to_string(), if xmi { "0".to_string() } else { mi.to_string() });
        if op == ">" || op == "<=" {
            // `>1.2` is `>=1.3.0`; `<=1.2` is `<1.3.0-0`.
            op = if op == ">" { ">=" } else { "<" };
            if xmi {
                ma = inc(&ma);
                mi = "0".into();
            } else {
                mi = inc(&mi);
            }
        }
        if op == "<" {
            pr = "-0";
        }
        return format!("{op}{ma}.{mi}.0{pr}");
    }
    if xmi {
        format!(">={ma}.0.0{pr} <{}.0.0-0", inc(ma))
    } else if any {
        format!(">={ma}.{mi}.0{pr} <{ma}.{}.0-0", inc(mi))
    } else {
        token.to_string()
    }
}

/// One token's comparators as text: node-semver's parseComparator.
fn desugar(token: &str, inc_pr: bool) -> String {
    let z = if inc_pr { "-0" } else { "" };
    let out = if let Some(x) = token.strip_prefix('^').and_then(xrange_plain) {
        caret(&x, z)
    } else if let Some(x) = token.strip_prefix('~').and_then(|t| xrange_plain(t.strip_prefix('>').unwrap_or(t))) {
        tilde(&x, z)
    } else {
        let (op, rest) = split_gtlt(token);
        xrange_plain(rest).map_or_else(|| token.to_string(), |x| xrange(op, &x, token, inc_pr))
    };
    // The first `*`, with an operator before it, goes: `>=*` is anything, so is `1.2.3*`'s star.
    let Some(star) = out.find('*') else { return out };
    let head = &out[..star];
    let head = head.strip_suffix(' ').unwrap_or(head);
    let head = head.strip_suffix('=').unwrap_or(head);
    let head = head.strip_suffix(['<', '>']).unwrap_or(head);
    format!("{head}{}", &out[star + 1..])
}

/// JavaScript's `split(/\s+/)`: an empty piece at either end with a space there.
fn split_ws(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split_whitespace().collect();
    if s.is_empty() || s.starts_with(char::is_whitespace) {
        parts.insert(0, "");
    }
    if !s.is_empty() && s.ends_with(char::is_whitespace) {
        parts.push("");
    }
    parts
}

// --- comparators -------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    /// Any version: node-semver's ANY, from `*` or an empty range. Its version is unused.
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Comparator {
    op: Op,
    v: Version,
}

impl Comparator {
    fn any() -> Self {
        Comparator { op: Op::Any, v: Version::new(0, 0, 0, Vec::new()) }
    }

    /// As node-semver prints it, which is also how it tells comparators apart.
    fn value(&self) -> String {
        let op = match self.op {
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Eq => "",
            Op::Any => return String::new(),
        };
        format!("{op}{}", self.v.text)
    }

    fn is_null(&self) -> bool {
        self.op == Op::Lt && self.v.text == "0.0.0-0"
    }

    fn up(&self) -> bool {
        matches!(self.op, Op::Gt | Op::Ge)
    }

    fn down(&self) -> bool {
        matches!(self.op, Op::Lt | Op::Le)
    }

    fn test(&self, v: &Version) -> bool {
        let o = v.cmp(&self.v);
        match self.op {
            Op::Any => true,
            Op::Eq => o == Ordering::Equal,
            Op::Lt => o == Ordering::Less,
            Op::Le => o != Ordering::Greater,
            Op::Gt => o == Ordering::Greater,
            Op::Ge => o != Ordering::Less,
        }
    }
}

/// A token as a comparator: `Ok(None)` for one node-semver's loose filter drops, `Err` for one
/// it keeps but cannot read, which fails the whole range.
fn comparator(token: &str) -> Result<Option<Comparator>, ()> {
    if token.is_empty() {
        return Ok(Some(Comparator::any()));
    }
    let (op, rest) = split_gtlt(token);
    let Some(plain) = loose_plain(rest) else { return Ok(None) };
    if rest.len() > MAX_LENGTH {
        return Err(());
    }
    let op = match op {
        "<" => Op::Lt,
        "<=" => Op::Le,
        ">" => Op::Gt,
        ">=" => Op::Ge,
        _ => Op::Eq,
    };
    Ok(Some(Comparator { op, v: version(&plain).ok_or(())? }))
}

/// One `||` alternative. Empty when nothing in it reads as a comparator.
fn parse_set(set: &str, inc_pr: bool) -> Result<Vec<Comparator>, ()> {
    let set = strip_builds(set);
    let set = close_ops(&hyphen(&set, inc_pr).unwrap_or(set));
    let text = set.split(' ').map(|t| desugar(t, inc_pr)).collect::<Vec<_>>().join(" ");
    let any = if inc_pr { ">=0.0.0-0" } else { ">=0.0.0" };
    let mut comps = Vec::new();
    for token in split_ws(&text) {
        if let Some(c) = comparator(if token == any { "" } else { token })? {
            comps.push(c);
        }
    }
    let mut set: Vec<Comparator> = Vec::new();
    for c in comps {
        if c.is_null() {
            return Ok(vec![c]);
        }
        if !set.iter().any(|s| s.value() == c.value()) {
            set.push(c);
        }
    }
    if set.len() > 1 {
        set.retain(|c| c.op != Op::Any);
    }
    Ok(set)
}

fn read_range(range: &str, inc_pr: bool) -> Option<Vec<Vec<Comparator>>> {
    let range = range.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut sets = Vec::new();
    for branch in range.split("||") {
        let set = parse_set(branch.trim(), inc_pr).ok()?;
        // An alternative with nothing that reads drops out: `>=3.0.0 || insiders` is `>=3.0.0`.
        if !set.is_empty() {
            sets.push(set);
        }
    }
    if sets.len() > 1 {
        let first = sets[0].clone();
        sets.retain(|s| !s[0].is_null());
        if sets.is_empty() {
            sets.push(first);
        } else if let Some(any) = sets.iter().find(|s| s[0].op == Op::Any) {
            sets = vec![any.clone()];
        }
    }
    (!sets.is_empty()).then_some(sets)
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
    let sets = read_range(range, inc_pr).map(Arc::new);
    if let Ok(mut c) = cache.lock() {
        c.insert(key, sets.clone());
    }
    sets
}

fn test_set(v: &Version, set: &[Comparator], inc_pr: bool) -> bool {
    if !set.iter().all(|c| c.test(v)) {
        return false;
    }
    // A prerelease only matches if some comparator opts into that exact tuple.
    if !v.pre.is_empty() && !inc_pr {
        return set.iter().any(|c| c.op != Op::Any && !c.v.pre.is_empty() && c.v.same_tuple(v));
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

/// Whether two comparators leave a version between them: node-semver's Comparator.intersects,
/// which decides by operators and an exact version's fit rather than by counting versions.
fn meets(a: &Comparator, b: &Comparator) -> bool {
    // An exact version meets a comparator whose range, read alone, takes it; the order matters,
    // since `*` read as a range refuses an exact prerelease, while `*` itself meets anything.
    match (a.op, b.op) {
        (Op::Any, _) => return true,
        (Op::Eq, _) => return satisfies_version(&a.v, &b.value(), false),
        (_, Op::Any) => return true,
        (_, Op::Eq) => return satisfies_version(&b.v, &a.value(), false),
        _ => {}
    }
    // Nothing is below 0.0.0 without prereleases.
    if [a, b].iter().any(|c| c.op == Op::Lt && c.v.text.starts_with("0.0.0")) {
        return false;
    }
    (a.up() && b.up())
        || (a.down() && b.down())
        || (a.v.text == b.v.text && matches!(a.op, Op::Ge | Op::Le) && matches!(b.op, Op::Ge | Op::Le))
        || (a.v < b.v && a.up() && b.down())
        || (a.v > b.v && a.down() && b.up())
}

/// Each comparator meets every one before it.
fn satisfiable(set: &[Comparator]) -> bool {
    (1..set.len()).rev().all(|i| set[..i].iter().all(|o| meets(&set[i], o)))
}

/// Whether some version satisfies both ranges, as npm's `intersects` judges it: comparator by
/// comparator, so `^1.2.3-beta.1` and `1.2.3-beta.2` do not meet.
pub fn intersects(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (parse_range(a, false), parse_range(b, false)) else { return false };
    a.iter()
        .any(|x| satisfiable(x) && b.iter().any(|y| satisfiable(y) && x.iter().all(|c| y.iter().all(|d| meets(c, d)))))
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
mod conformance;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_alternatives_that_do_not_parse() {
        // tailwindcss-animate's peer range for tailwindcss.
        assert!(valid_range(">=3.0.0 || insiders"));
        assert!(satisfies("3.4.17", ">=3.0.0 || insiders"));
        assert!(!satisfies("2.0.0", ">=3.0.0 || insiders"));
        assert!(!valid_range("insiders"));
        assert!(!valid_range("foo || bar"));
    }

    #[test]
    fn compares_ranges() {
        for (a, b, meet) in [
            ("^1.2.0", "^1.5.0", true),
            ("^1.0.0", "^2.0.0", false),
            ("1.2.3", ">=1.2.3", true),
            ("1.2.3", ">1.2.3", false),
            ("<1.0.0", ">=1.0.0", false),
            ("<=1.0.0", ">=1.0.0", true),
            ("*", "^3", true),
            ("^1 || ^3", "3.1.0", true),
            // node-semver's answers, around the `-0` a caret or x-range ends with.
            ("1.x", "^1.5.0", true),
            ("<2", ">=2.0.0-0", false),
            ("<2", "2.0.0", false),
            ("<2", ">=2", false),
            ("~1.2", "1.2.9", true),
            ("~1.2", ">=1.2.9 <1.3.0", true),
            // An exact version meets each comparator on its own, and `<2.0.0-0` alone refuses
            // a 1.2.3 prerelease, so node-semver says no even though the caret takes it.
            ("^1.2.3-beta.1", "1.2.3-beta.2", false),
            ("<2.0.0", "2.0.0-rc.1", false),
            ("^1", "1.5.0-rc.1", false),
        ] {
            assert_eq!(intersects(a, b), meet, "{a} {b}");
            assert_eq!(intersects(b, a), meet, "{b} {a}");
        }
    }

    #[test]
    fn huge_numbers_do_not_overflow() {
        let max = u64::MAX;
        for range in
            [format!("^{max}"), format!("~{max}.0"), format!("{max}.x"), format!("0.{max}.x"), format!("~0.{max}")]
        {
            let _ = valid_range(&range);
            let _ = satisfies("1.0.0", &range);
        }
        // Parts above 2^53-1 are refused, as node-semver does, bounds included: a range whose
        // upper bound would pass the limit is no range.
        let safe = (1u64 << 53) - 1;
        assert!(parse(&format!("{}.0.0", safe + 1)).is_none());
        assert!(!satisfies("1.0.0", &format!(">{max}")) && !valid_range(&format!(">{max}")));
        for range in
            [format!("^0.{safe}.0"), format!("^0.0.{safe}"), format!("^{safe}.0.0"), format!("<={safe}.{safe}")]
        {
            assert!(!valid_range(&range), "{range}");
        }
        assert!(satisfies(&format!("{safe}.{safe}.{safe}"), &format!("1 - {safe}.{safe}.{safe}")));
        assert!(!satisfies(&format!("{safe}.0.0"), &format!(">{safe}")));
    }

    #[test]
    fn parses_versions() {
        assert_eq!(parse("v1.2.3").unwrap().text, "1.2.3");
        assert_eq!(parse(" =1.2.3-beta.1+build.5 ").unwrap().text, "1.2.3-beta.1");
        assert!(parse("1.2").is_none());
        // Loose, as npm reads them: leading zeros go, a prerelease's `-` may be left out.
        assert_eq!(parse("01.2.3").unwrap().text, "1.2.3");
        assert_eq!(parse("1.2.3-01").unwrap().text, "1.2.3-1");
        assert_eq!(parse("1.2.3beta").unwrap().text, "1.2.3-beta");
        assert!(is_exact("1.2.3"));
        assert!(!is_exact("v1.2.3"));
        assert!(!is_exact("01.2.3"));
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
