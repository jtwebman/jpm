//! The install state, `node_modules/.jpm.json`, written after every successful link. With it a
//! repeat install checks a few directories instead of the whole tree: if the recorded hash
//! still describes what would be installed, the tree on disk is already that tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::graph::Resolution;
use crate::keys::graph_hash;
use crate::util::{short_hash, write_atomic};

pub const STATE_FILE: &str = ".jpm.json";

/// A file as `stat` sees it: size, mtime and ctime in nanoseconds, inode. The same stamp again
/// means the same bytes: a content change moves the ctime, which no unprivileged tool sets back.
pub type Stamp = [String; 4];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub packages: usize,
    #[serde(rename = "otherPlatforms")]
    pub other_platforms: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RootLinks {
    pub links: BTreeMap<String, String>,
    pub bins: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Stamps {
    pub lock: Stamp,
    pub manifest: Stamp,
    pub settings: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Covers the graph and the flags that change what is linked.
    pub hash: String,
    /// Sorted entry names that should exist under `node_modules/.jpm`.
    pub entries: Vec<String>,
    /// False when something the graph named could not be linked.
    pub complete: bool,
    pub store: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub production: bool,
    /// Every local tarball the lockfile names, with the stamp it had when last checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarballs: Option<BTreeMap<String, Option<Stamp>>>,
    /// The inputs' hash, when the lockfile and root manifest alone decide the tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<RootLinks>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamps: Option<Stamps>,
}

pub fn path(dir: &Path) -> PathBuf {
    dir.join("node_modules").join(STATE_FILE)
}

/// Every failure is "unknown", never an error: the worst this file may cost is a full link.
pub fn read(dir: &Path) -> Option<State> {
    let text = std::fs::read_to_string(path(dir)).ok()?;
    serde_json::from_str::<State>(&text).ok().filter(|s| s.version == 1)
}

pub fn write(dir: &Path, state: &State) -> crate::error::Result<()> {
    let _ = std::fs::create_dir_all(dir.join("node_modules"));
    write_atomic(&path(dir), crate::util::pretty(state).as_bytes())
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

/// The one value a warm install compares: the graph, what is linked out of it, and the store.
pub fn state_hash(res: &Resolution, production: bool, store: &Path) -> String {
    let mut lines = vec![
        "jpm-state-1".to_string(),
        graph_hash(res),
        format!("production:{}", u8::from(production)),
        format!("store:{}", store.display()),
    ];
    for (id, p) in &res.packages {
        let bin: Vec<String> = p.bin.iter().flat_map(|(k, v)| [k.clone(), v.clone()]).collect();
        let bin = bin.join(",");
        match &p.local {
            Some(path) => lines.push(format!("{id}:local:{path}:{bin}")),
            None => lines.push(format!(
                "{id}:{}:{bin}:{}{}",
                p.integrity,
                if p.dev { "d" } else { "" },
                if p.optional { "o" } else { "" }
            )),
        }
    }
    short_hash(&lines.join("\n"))
}

/// One value over what the tree is a function of: the lockfile's bytes, the root manifest and
/// the settings. Same value, same tree.
pub fn inputs_hash(lock: &str, manifest: &serde_json::Map<String, serde_json::Value>, settings: &str) -> String {
    let manifest = serde_json::to_string(manifest).unwrap_or_default();
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
