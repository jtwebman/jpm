//! What a registry sends: packuments and manifests, read leniently. A registry document is
//! publisher-written data, so a field with the wrong shape is dropped rather than failing the
//! whole document. A packument is scanned once for its few top-level fields and the span of each
//! version; a version's manifest is parsed only when it is picked.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::bin::{self, Bins};
use crate::error::{Error, Result};
use crate::integrity::from_shasum;
use crate::json::{Scan, Value};

pub type Map = BTreeMap<String, String>;

#[derive(Debug, Clone, Default)]
pub struct Dist {
    pub tarball: Option<String>,
    pub integrity: Option<String>,
    pub shasum: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub dependencies: Map,
    pub optional_dependencies: Map,
    pub peer_dependencies: Map,
    /// Peers `peerDependenciesMeta` marks optional.
    pub peer_optional: Vec<String>,
    pub bin: Option<Value>,
    pub engines: Map,
    pub os: Option<Vec<String>>,
    pub cpu: Option<Vec<String>>,
    pub libc: Option<Vec<String>>,
    pub deprecated: bool,
    /// Has a `preinstall`, `install` or `postinstall` script, or a `binding.gyp` npm builds with
    /// node-gyp (the registry's `hasInstallScript`).
    pub scripts: bool,
    pub dist: Dist,
    /// Not the registry's: this came from a full document, so a missing `libc` means none.
    pub full: bool,
    /// Dependencies its tarball ships in its own node_modules (`bundleDependencies`), taken out
    /// of `dependencies` and `optionalDependencies`: npm, pnpm and bun install none of them.
    pub bundled: Map,
}

impl Manifest {
    pub fn bins(&self) -> Bins {
        bin::normalize(Some(&self.name), self.bin.as_ref())
    }

    /// Packages published before 2017 carry only a legacy sha1 `shasum`.
    pub fn integrity(&self) -> Result<String> {
        if let Some(i) = self.dist.integrity.as_deref().filter(|i| !i.is_empty()) {
            return Ok(i.to_string());
        }
        if let Some(s) = &self.dist.shasum {
            return from_shasum(s);
        }
        Err(Error::new("EINTEGRITY", format!("{}@{} has no dist integrity or shasum", self.name, self.version)))
    }

    pub fn is_optional_peer(&self, name: &str) -> bool {
        self.peer_optional.iter().any(|n| n == name)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        let mut s = Scan::new(text);
        Self::read(&mut s)
    }

    /// The manifest at the cursor. The fields the resolver reads are taken; everything else,
    /// a readme included, is skipped without being built.
    fn read(s: &mut Scan) -> Result<Self> {
        let mut m = Self::default();
        let mut bundle = Value::Null;
        s.members(|s, key| {
            match key.as_ref() {
                "name" => m.name = opt_string(s)?.unwrap_or_default(),
                "version" => m.version = opt_string(s)?.unwrap_or_default(),
                "dependencies" => m.dependencies = string_map(s)?,
                "optionalDependencies" => m.optional_dependencies = string_map(s)?,
                "peerDependencies" => m.peer_dependencies = string_map(s)?,
                "engines" => m.engines = string_map(s)?,
                "peerDependenciesMeta" => {
                    let meta = s.value()?;
                    m.peer_optional = meta
                        .as_object()
                        .map(|o| {
                            let optional = |v: &Value| v.get("optional").and_then(Value::as_bool) == Some(true);
                            o.iter().filter(|(_, v)| optional(v)).map(|(k, _)| k.clone()).collect()
                        })
                        .unwrap_or_default();
                }
                "bin" => m.bin = Some(s.value()?),
                "bundleDependencies" | "bundledDependencies" => bundle = s.value()?,
                "os" => m.os = string_list(s)?,
                "cpu" => m.cpu = string_list(s)?,
                "libc" => m.libc = string_list(s)?,
                // A message; `false` or an empty string is not deprecated.
                "deprecated" => m.deprecated = opt_string(s)?.is_some_and(|d| !d.is_empty()),
                "hasInstallScript" => m.scripts |= s.value()?.as_bool() == Some(true),
                "scripts" if s.at_object() => s.members(|s, key| {
                    m.scripts |= matches!(key.as_ref(), "preinstall" | "install" | "postinstall");
                    s.skip()
                })?,
                "dist" if s.at_object() => s.members(|s, key| {
                    match key.as_ref() {
                        "tarball" => m.dist.tarball = opt_string(s)?,
                        "integrity" => m.dist.integrity = opt_string(s)?,
                        "shasum" => m.dist.shasum = opt_string(s)?,
                        _ => s.skip()?,
                    }
                    Ok(())
                })?,
                _ => s.skip()?,
            }
            Ok(())
        })?;
        // `true` bundles every dependency; a list, those it names.
        let bundled = |name: &String| match &bundle {
            Value::Bool(all) => *all,
            Value::Array(names) => names.iter().any(|n| n.as_str() == Some(name)),
            _ => false,
        };
        for group in [&mut m.dependencies, &mut m.optional_dependencies] {
            let (inside, rest) = std::mem::take(group).into_iter().partition(|(n, _)| bundled(n));
            *group = rest;
            m.bundled.extend::<Map>(inside);
        }
        // An optional peer named in peerDependenciesMeta alone takes any version, as pnpm and yarn
        // read it (mobx-react-lite's react-dom).
        for name in &m.peer_optional {
            m.peer_dependencies.entry(name.clone()).or_insert_with(|| "*".into());
        }
        Ok(m)
    }
}

/// A string, or `None` for anything else (which is skipped).
fn opt_string(s: &mut Scan) -> Result<Option<String>> {
    if s.at_string() {
        return Ok(Some(s.string()?.into_owned()));
    }
    s.skip()?;
    Ok(None)
}

/// A map of strings: other values, and a map that is not a map, are dropped.
fn string_map(s: &mut Scan) -> Result<Map> {
    let mut out = Map::new();
    if !s.at_object() {
        s.skip()?;
        return Ok(out);
    }
    s.members(|s, key| {
        if let Some(v) = opt_string(s)? {
            out.insert(key.into_owned(), v);
        }
        Ok(())
    })?;
    Ok(out)
}

/// A list of strings; npm takes a bare string as a list of one. Anything else is no list.
fn string_list(s: &mut Scan) -> Result<Option<Vec<String>>> {
    Ok(match s.value()? {
        Value::String(one) => Some(vec![one]),
        Value::Array(items) => {
            Some(items.into_iter().filter_map(|v| if let Value::String(s) = v { Some(s) } else { None }).collect())
        }
        _ => None,
    })
}

/// A packument whose versions are parsed one at a time, when asked for: a pick usually reads
/// one manifest out of hundreds.
#[derive(Debug, Default)]
pub struct Packument {
    pub name: String,
    pub tags: Map,
    pub modified: Option<String>,
    pub time: Map,
    text: String,
    /// Each version's manifest, as its span of `text`.
    spans: BTreeMap<String, (usize, usize)>,
    parsed: Mutex<BTreeMap<String, Option<Arc<Manifest>>>>,
    /// Set when a release cutoff hid versions: the cutoff, as an ISO date.
    pub before: Option<String>,
}

impl Packument {
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        let text = String::from_utf8(bytes)
            .map_err(|_| Error::new("EJSONPARSE", "registry sent a document that is not UTF-8"))?;
        let mut doc = Self::default();
        let mut s = Scan::new(&text);
        s.members(|s, key| {
            match key.as_ref() {
                "name" => doc.name = opt_string(s)?.unwrap_or_default(),
                "dist-tags" => doc.tags = string_map(s)?,
                "modified" => doc.modified = opt_string(s)?,
                "time" => doc.time = string_map(s)?,
                "versions" if s.at_object() => s.members(|s, version| {
                    let span = s.span()?;
                    doc.spans.insert(version.into_owned(), span);
                    Ok(())
                })?,
                _ => s.skip()?,
            }
            Ok(())
        })
        .map_err(|e| Error::new("EJSONPARSE", format!("registry sent invalid JSON: {}", e.message)))?;
        doc.text = text;
        Ok(doc)
    }

    pub fn versions(&self) -> impl Iterator<Item = &str> {
        self.spans.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn version(&self, version: &str) -> Option<Arc<Manifest>> {
        let mut parsed = self.parsed.lock().ok()?;
        if let Some(hit) = parsed.get(version) {
            return hit.clone();
        }
        let found = self.spans.get(version).and_then(|&(a, b)| {
            let mut s = Scan::new(&self.text[a..b]);
            if !s.at_object() {
                return None;
            }
            Manifest::read(&mut s).ok().map(Arc::new)
        });
        parsed.insert(version.to_string(), found.clone());
        found
    }

    /// Another packument of the same document, to cut without touching this one.
    pub fn copy(&self) -> Self {
        Self {
            name: self.name.clone(),
            tags: self.tags.clone(),
            modified: self.modified.clone(),
            time: self.time.clone(),
            text: self.text.clone(),
            spans: self.spans.clone(),
            parsed: Mutex::default(),
            before: self.before.clone(),
        }
    }

    /// As the registry stood at `before` (epoch ms): later versions gone, and a tag on one moved to
    /// the highest version at or below it that is left. A version with no date passes.
    pub fn until(mut self, times: &Map, before: i64) -> Self {
        self.spans.retain(|v, _| times.get(v).and_then(|t| parse_date(t)).is_none_or(|t| t <= before));
        let kept: Vec<String> = self.spans.keys().cloned().collect();
        let mut tags = BTreeMap::new();
        for (tag, v) in &self.tags {
            let found = if self.spans.contains_key(v) {
                Some(v.clone())
            } else {
                crate::semver::max_satisfying(kept.iter().map(String::as_str), &format!("<={v}")).map(str::to_string)
            };
            if let Some(found) = found {
                tags.insert(tag.clone(), found);
            }
        }
        self.tags = tags;
        self.before = Some(iso_date(before));
        self
    }
}

/// Milliseconds since the epoch for an ISO 8601 date (`2024-01-02T03:04:05.678Z`), or a
/// plain `YYYY-MM-DD`. Enough of the format for registry `time` fields and `--before`.
pub fn parse_date(text: &str) -> Option<i64> {
    let t = text.trim();
    let num = |s: &str| s.parse::<i64>().ok();
    let year = num(t.get(0..4)?)?;
    if t.get(4..5)? != "-" {
        return None;
    }
    let month = num(t.get(5..7)?)?;
    let day = num(t.get(8..10)?)?;
    let (mut h, mut m, mut s, mut ms, mut offset) = (0, 0, 0, 0, 0);
    if let Some(rest) = t.get(10..).filter(|r| !r.is_empty()) {
        let rest = rest.strip_prefix(['T', ' '])?;
        h = num(rest.get(0..2)?)?;
        m = num(rest.get(3..5)?)?;
        let mut tail = rest.get(5..)?;
        if let Some(r) = tail.strip_prefix(':') {
            s = num(r.get(0..2)?)?;
            tail = r.get(2..)?;
        }
        if let Some(r) = tail.strip_prefix('.') {
            let digits: String = r.chars().take_while(char::is_ascii_digit).collect();
            ms = num(&format!("{digits:0<3}")[..3])?;
            tail = &r[digits.len()..];
        }
        if let Some(sign) = tail.chars().next().filter(|c| *c == '+' || *c == '-') {
            let z = &tail[1..];
            let oh = num(z.get(0..2)?)?;
            let om = num(z.get(z.len() - 2..)?)?;
            offset = (oh * 60 + om) * 60_000 * if sign == '+' { 1 } else { -1 };
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 24 + h) * 60 + m) * 60_000 + s * 1000 + ms - offset)
}

/// Howard Hinnant's algorithm: days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn iso_date(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hostile_manifests() {
        let m = Manifest::from_json(
            r#"{"name":"a","version":"1.0.0","dependencies":["x"],"os":"linux",
                "optionalDependencies":{"b":"1","c":2},"deprecated":false,"readme":"{\"}",
                "peerDependenciesMeta":{"p":{"optional":true},"q":{}},"dist":{"integrity":5}}"#,
        )
        .unwrap();
        assert!(m.dependencies.is_empty());
        assert_eq!(m.os, Some(vec!["linux".into()]));
        assert_eq!(m.optional_dependencies.len(), 1);
        assert!(!m.deprecated);
        assert_eq!(m.peer_optional, vec!["p"]);
        assert!(m.dist.integrity.is_none());
    }

    #[test]
    fn reads_versions_lazily() {
        let p = Packument::parse(br#"{"name":"a","readme":"x","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"a","version":"1.0.0"},"0.1.0":{"name":"a","version":"0.1.0"},"bad":7}}"#.to_vec()).unwrap();
        assert_eq!(p.versions().count(), 3);
        assert_eq!(p.version("1.0.0").unwrap().version, "1.0.0");
        assert!(p.version("2.0.0").is_none());
        assert!(p.version("bad").is_none());
        assert!(Packument::parse(b"{\"versions\":{".to_vec()).is_err());
    }

    #[test]
    fn filters_by_date() {
        let p = Packument::parse(
            br#"{"name":"a","dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"2.0.0":{}}}"#.to_vec(),
        )
        .unwrap();
        let times: Map =
            [("1.0.0".into(), "2020-01-01T00:00:00.000Z".into()), ("2.0.0".into(), "2024-01-01T00:00:00.000Z".into())]
                .into();
        let p = p.until(&times, parse_date("2022-01-01").unwrap());
        assert_eq!(p.tags["latest"], "1.0.0");
        assert_eq!(p.versions().count(), 1);
    }

    #[test]
    fn dates_round_trip() {
        let ms = parse_date("2024-02-29T13:45:07.123Z").unwrap();
        assert_eq!(iso_date(ms), "2024-02-29T13:45:07.123Z");
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2020-01-01T01:00:00+01:00"), parse_date("2020-01-01"));
        assert_eq!(parse_date("nope"), None);
    }
}
