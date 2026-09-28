//! What a registry sends: packuments and manifests, read leniently. A registry document is
//! publisher-written data, so a field with the wrong shape is dropped rather than failing the
//! whole document.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::bin::{self, Bins};
use crate::error::{Error, Result};
use crate::integrity::from_shasum;

pub type Map = BTreeMap<String, String>;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Dist {
    #[serde(default, deserialize_with = "opt_str")]
    pub tarball: Option<String>,
    #[serde(default, deserialize_with = "opt_str")]
    pub integrity: Option<String>,
    #[serde(default, deserialize_with = "opt_str")]
    pub shasum: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Manifest {
    #[serde(default, deserialize_with = "any_str")]
    pub name: String,
    #[serde(default, deserialize_with = "any_str")]
    pub version: String,
    #[serde(default, deserialize_with = "str_map")]
    pub dependencies: Map,
    #[serde(default, rename = "optionalDependencies", deserialize_with = "str_map")]
    pub optional_dependencies: Map,
    #[serde(default, rename = "peerDependencies", deserialize_with = "str_map")]
    pub peer_dependencies: Map,
    #[serde(default, rename = "peerDependenciesMeta", deserialize_with = "optional_meta")]
    pub peer_optional: Vec<String>,
    #[serde(default)]
    pub bin: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "str_map")]
    pub engines: Map,
    #[serde(default, deserialize_with = "str_list")]
    pub os: Option<Vec<String>>,
    #[serde(default, deserialize_with = "str_list")]
    pub cpu: Option<Vec<String>>,
    #[serde(default, deserialize_with = "str_list")]
    pub libc: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deprecated")]
    pub deprecated: bool,
    #[serde(default)]
    pub dist: Dist,
    /// Not the registry's: this came from a full document, so a missing `libc` means none.
    #[serde(skip)]
    pub full: bool,
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
        serde_json::from_str(text).map_err(|e| Error::new("EJSONPARSE", e.to_string()))
    }
}

/// A packument whose versions are parsed one at a time, when asked for: a pick usually reads
/// one manifest out of hundreds.
#[derive(Debug, Default)]
pub struct Packument {
    pub name: String,
    pub tags: BTreeMap<String, String>,
    pub modified: Option<String>,
    pub time: BTreeMap<String, String>,
    raw: BTreeMap<String, Box<RawValue>>,
    parsed: Mutex<BTreeMap<String, Option<Arc<Manifest>>>>,
    /// Set when a release cutoff hid versions: the cutoff, as an ISO date.
    pub before: Option<String>,
}

#[derive(Deserialize)]
struct RawPackument {
    #[serde(default, deserialize_with = "any_str")]
    name: String,
    #[serde(default, rename = "dist-tags", deserialize_with = "str_map")]
    tags: Map,
    #[serde(default, deserialize_with = "opt_str")]
    modified: Option<String>,
    #[serde(default, deserialize_with = "str_map")]
    time: Map,
    #[serde(default)]
    versions: Option<BTreeMap<String, Box<RawValue>>>,
}

impl Packument {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw: RawPackument = serde_json::from_slice(bytes)
            .map_err(|e| Error::new("EJSONPARSE", format!("registry sent invalid JSON: {e}")))?;
        Ok(Self {
            name: raw.name,
            tags: raw.tags,
            modified: raw.modified,
            time: raw.time,
            raw: raw.versions.unwrap_or_default(),
            parsed: Mutex::default(),
            before: None,
        })
    }

    pub fn versions(&self) -> impl Iterator<Item = &str> {
        self.raw.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn version(&self, version: &str) -> Option<Arc<Manifest>> {
        let mut parsed = self.parsed.lock().ok()?;
        if let Some(hit) = parsed.get(version) {
            return hit.clone();
        }
        let found =
            self.raw.get(version).and_then(|raw| serde_json::from_str::<Manifest>(raw.get()).ok()).map(Arc::new);
        parsed.insert(version.to_string(), found.clone());
        found
    }

    /// As the registry stood at `before` (epoch ms): later versions gone, and a tag on one moved to
    /// the highest version at or below it that is left. A version with no date passes.
    pub fn until(mut self, times: &Map, before: i64) -> Self {
        self.raw.retain(|v, _| times.get(v).and_then(|t| parse_date(t)).is_none_or(|t| t <= before));
        let kept: Vec<String> = self.raw.keys().cloned().collect();
        let mut tags = BTreeMap::new();
        for (tag, v) in &self.tags {
            let found = if self.raw.contains_key(v) {
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

// --- lenient field readers ------------------------------------------------------------------

/// Deserializes to `Some(string)` for a string and `None` for anything else, consuming it.
struct MaybeStr(Option<String>);

impl<'de> Deserialize<'de> for MaybeStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MaybeStr;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("anything")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<MaybeStr, E> {
                Ok(MaybeStr(Some(v.to_string())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<MaybeStr, E> {
                Ok(MaybeStr(Some(v)))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_none<E: de::Error>(self) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<MaybeStr, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(MaybeStr(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<MaybeStr, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(MaybeStr(None))
            }
        }
        d.deserialize_any(V)
    }
}

fn opt_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(MaybeStr::deserialize(d)?.0)
}

fn any_str<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(MaybeStr::deserialize(d)?.0.unwrap_or_default())
}

/// `deprecated` is a message; `false` or an empty string is not deprecated.
fn deprecated<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(MaybeStr::deserialize(d)?.0.is_some_and(|s| !s.is_empty()))
}

/// A map of strings: other values, and a map that is not a map, are dropped.
fn str_map<'de, D: Deserializer<'de>>(d: D) -> Result<Map, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Map;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Map, A::Error> {
            let mut out = Map::new();
            while let Some((k, v)) = m.next_entry::<String, MaybeStr>()? {
                if let Some(v) = v.0 {
                    out.insert(k, v);
                }
            }
            Ok(out)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Map, A::Error> {
            while s.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Map::new())
        }
        fn visit_str<E: de::Error>(self, _: &str) -> Result<Map, E> {
            Ok(Map::new())
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Map, E> {
            Ok(Map::new())
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Map, E> {
            Ok(Map::new())
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Map, E> {
            Ok(Map::new())
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Map, E> {
            Ok(Map::new())
        }
        fn visit_unit<E: de::Error>(self) -> Result<Map, E> {
            Ok(Map::new())
        }
    }
    d.deserialize_any(V)
}

/// A list of strings; npm takes a bare string as a list of one.
fn str_list<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Option<Vec<String>>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = s.next_element::<MaybeStr>()? {
                out.extend(v.0);
            }
            Ok(Some(out))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(vec![v.to_string()]))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(None)
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }
    d.deserialize_any(V)
}

/// The names `peerDependenciesMeta` marks optional.
fn optional_meta<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    let Some(map) = value.as_object() else { return Ok(Vec::new()) };
    Ok(map
        .iter()
        .filter(|(_, m)| m.get("optional").and_then(serde_json::Value::as_bool) == Some(true))
        .map(|(k, _)| k.clone())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hostile_manifests() {
        let m: Manifest = serde_json::from_str(
            r#"{"name":"a","version":"1.0.0","dependencies":["x"],"os":"linux",
                "optionalDependencies":{"b":"1","c":2},"deprecated":false,
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
        let p = Packument::parse(br#"{"name":"a","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"a","version":"1.0.0"},"0.1.0":{"name":"a","version":"0.1.0"}}}"#).unwrap();
        assert_eq!(p.versions().count(), 2);
        assert_eq!(p.version("1.0.0").unwrap().version, "1.0.0");
        assert!(p.version("2.0.0").is_none());
    }

    #[test]
    fn filters_by_date() {
        let p = Packument::parse(br#"{"name":"a","dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"2.0.0":{}}}"#)
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
