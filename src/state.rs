//! The install state, `node_modules/.jpm.json`, written after every successful link. With it a
//! repeat install checks a few directories instead of the whole tree: if the recorded hash
//! still describes what would be installed, the tree on disk is already that tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::json::{self, Object, Value};

use crate::util::{short_hash, write_atomic};

pub const STATE_FILE: &str = ".jpm.json";

/// A file as `stat` sees it: size, mtime and ctime in nanoseconds, inode. The same stamp again
/// means the same bytes: a content change moves the ctime, which no unprivileged tool sets back.
pub type Stamp = [String; 4];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub packages: usize,
    pub other_platforms: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RootLinks {
    pub links: BTreeMap<String, String>,
    pub bins: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stamps {
    pub lock: Stamp,
    pub manifest: Stamp,
    pub settings: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub version: u32,
    /// Covers the graph and the flags that change what is linked.
    pub hash: String,
    /// Sorted entry names that should exist under `node_modules/.jpm`.
    pub entries: Vec<String>,
    /// Sorted entry names this tree links to in the global store.
    pub shared: Vec<String>,
    /// False when something the graph named could not be linked.
    pub complete: bool,
    pub store: String,
    pub production: bool,
    /// Every local tarball the lockfile names, with the stamp it had when last checked.
    pub tarballs: Option<BTreeMap<String, Option<Stamp>>>,
    /// The inputs' hash, when the lockfile and root manifest alone decide the tree.
    pub inputs: Option<String>,
    pub summary: Option<Summary>,
    pub root: Option<RootLinks>,
    pub stamps: Option<Stamps>,
}

fn stamp_value(s: &Stamp) -> Value {
    Value::from(s.to_vec())
}

fn stamp_of_value(v: &Value) -> Option<Stamp> {
    let items = v.as_array()?;
    let parts: Vec<String> = items.iter().map(|i| i.as_str().map(str::to_string)).collect::<Option<_>>()?;
    parts.try_into().ok()
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?.iter().map(|i| i.as_str().map(str::to_string)).collect()
}

impl State {
    fn to_value(&self) -> Value {
        let mut o = Object::new();
        o.insert("version", u64::from(self.version).into());
        o.insert("hash", (&self.hash).into());
        o.insert("entries", Value::from(self.entries.clone()));
        if !self.shared.is_empty() {
            o.insert("shared", Value::from(self.shared.clone()));
        }
        o.insert("complete", self.complete.into());
        o.insert("store", (&self.store).into());
        if self.production {
            o.insert("production", true.into());
        }
        if let Some(t) = &self.tarballs {
            let files = t.iter().map(|(k, s)| (k.clone(), s.as_ref().map_or(Value::Null, stamp_value))).collect();
            o.insert("tarballs", Value::Object(files));
        }
        if let Some(i) = &self.inputs {
            o.insert("inputs", i.into());
        }
        if let Some(s) = &self.summary {
            o.insert(
                "summary",
                json::obj([
                    ("packages", s.packages.into()),
                    ("otherPlatforms", s.other_platforms.into()),
                    ("warnings", Value::from(s.warnings.clone())),
                ]),
            );
        }
        if let Some(r) = &self.root {
            o.insert("root", json::obj([("links", json::str_map(&r.links)), ("bins", Value::from(r.bins.clone()))]));
        }
        if let Some(s) = &self.stamps {
            o.insert(
                "stamps",
                json::obj([
                    ("lock", stamp_value(&s.lock)),
                    ("manifest", stamp_value(&s.manifest)),
                    ("settings", (&s.settings).into()),
                ]),
            );
        }
        o.into()
    }

    /// `None` for anything that is not a state this version wrote.
    fn from_value(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let count = |v: Option<&Value>| match v? {
            Value::Number(n) => n.parse::<usize>().ok(),
            _ => None,
        };
        let summary = match o.get("summary") {
            None => None,
            Some(s) => Some(Summary {
                packages: count(s.get("packages"))?,
                other_platforms: count(s.get("otherPlatforms"))?,
                warnings: strings(s.get("warnings"))?,
            }),
        };
        let root = match o.get("root") {
            None => None,
            Some(r) => Some(RootLinks { links: json::string_map(r.get("links")?)?, bins: strings(r.get("bins"))? }),
        };
        let stamps = match o.get("stamps") {
            None => None,
            Some(s) => Some(Stamps {
                lock: stamp_of_value(s.get("lock")?)?,
                manifest: stamp_of_value(s.get("manifest")?)?,
                settings: s.get("settings")?.as_str()?.to_string(),
            }),
        };
        let tarballs = match o.get("tarballs") {
            None => None,
            Some(t) => Some(
                t.as_object()?
                    .iter()
                    .map(|(k, v)| match v {
                        Value::Null => Some((k.clone(), None)),
                        other => Some((k.clone(), Some(stamp_of_value(other)?))),
                    })
                    .collect::<Option<_>>()?,
            ),
        };
        Some(Self {
            version: u32::try_from(count(o.get("version"))?).ok()?,
            hash: o.get("hash")?.as_str()?.to_string(),
            entries: strings(o.get("entries"))?,
            shared: match o.get("shared") {
                None => Vec::new(),
                v => strings(v)?,
            },
            complete: o.get("complete")?.as_bool()?,
            store: o.get("store")?.as_str()?.to_string(),
            production: o.get("production").and_then(Value::as_bool).unwrap_or(false),
            tarballs,
            inputs: o.get("inputs").and_then(Value::as_str).map(str::to_string),
            summary,
            root,
            stamps,
        })
    }
}

pub fn path(dir: &Path) -> PathBuf {
    dir.join("node_modules").join(STATE_FILE)
}

/// Every failure is "unknown", never an error: the worst this file may cost is a full link.
pub fn read(dir: &Path) -> Option<State> {
    let text = std::fs::read_to_string(path(dir)).ok()?;
    State::from_value(&json::parse(&text).ok()?).filter(|s| s.version == 1)
}

pub fn write(dir: &Path, state: &State) -> crate::error::Result<()> {
    let _ = std::fs::create_dir_all(dir.join("node_modules"));
    write_atomic(&path(dir), json::to_pretty(&state.to_value(), "  ").as_bytes())
}

/// While the tree is being rewritten its state is unknown.
pub fn clear(dir: &Path) {
    let _ = std::fs::remove_file(path(dir));
}

pub fn stamp_of(file: &Path) -> Option<Stamp> {
    let m = std::fs::metadata(file).ok()?;
    let ns = |t: std::io::Result<std::time::SystemTime>| {
        t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos())
    };
    #[cfg(unix)]
    let (ctime, ino) = {
        use std::os::unix::fs::MetadataExt;
        (m.ctime() as i128 * 1_000_000_000 + i128::from(m.ctime_nsec()), m.ino())
    };
    #[cfg(not(unix))]
    let (ctime, ino) = (ns(m.created()) as i128, 0u64);
    Some([m.len().to_string(), ns(m.modified()).to_string(), ctime.to_string(), ino.to_string()])
}

/// The one value a warm install compares: the lockfile's content (which decides the graph, its
/// bins and every store entry), and what this install links out of it, from which store.
pub fn state_hash(
    lock_hash: &str,
    production: bool,
    store: &Path,
    global: bool,
    platform: &crate::sys::Platform,
) -> String {
    short_hash(&format!(
        "jpm-state-2\n{lock_hash}\nproduction:{}\nstore:{}\nglobal:{}\n{}",
        u8::from(production),
        store.display(),
        u8::from(global),
        json::to_string(&platform.to_value())
    ))
}

/// One value over what the tree is a function of: the lockfile's bytes, the root manifest and
/// the settings. Same value, same tree.
pub fn inputs_hash(lock: &str, manifest: &Object, settings: &str) -> String {
    let manifest = json::to_string(&Value::Object(manifest.clone()));
    short_hash(&format!("jpm-inputs-1\n{manifest}\n{settings}\n{lock}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_change_with_content() {
        let dir = crate::store::tests::scratch("state");
        let f = dir.join("x");
        std::fs::write(&f, "a").unwrap();
        let a = stamp_of(&f).unwrap();
        assert_eq!(stamp_of(&f).unwrap(), a);
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&f, "bb").unwrap();
        assert_ne!(stamp_of(&f).unwrap(), a);
        assert!(stamp_of(&dir.join("missing")).is_none());
    }

    #[test]
    fn round_trips() {
        let dir = crate::store::tests::scratch("state2");
        let s = State { version: 1, hash: "h".into(), complete: true, ..State::default() };
        write(&dir, &s).unwrap();
        assert_eq!(read(&dir), Some(s));
        std::fs::write(path(&dir), "{torn").unwrap();
        assert_eq!(read(&dir), None);
    }
}
