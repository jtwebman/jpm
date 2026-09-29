//! Reclaiming space: a project's stale `.jpm` entries, and store content nothing can use.
//! Mark and sweep, never refcounts: a refcount survives neither a second jpm running nor
//! `rm -rf node_modules`. The marks come from every project registered with the store: the
//! global entries its install state names and the packages its lockfile names. The store's
//! lock keeps a prune and an install (or fetch) apart, so what is unused goes at once.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::store::{Store, remove_tree};
use crate::{lock, state, sys};

/// How long a dead process's temp directory is left alone, in case its pid was reused.
const TMP_GRACE: Duration = Duration::from_secs(3600);

#[derive(Debug, Default)]
pub struct Swept {
    pub removed: usize,
    pub bytes: u64,
}

impl Swept {
    pub fn to_value(&self) -> crate::json::Value {
        crate::json::obj([("removed", self.removed.into()), ("bytes", self.bytes.into())])
    }
}

/// A temp directory whose process is gone: `<pid>-...` by name, and not written lately.
fn abandoned(path: &Path, name: &str) -> bool {
    let pid = name.split('-').next().and_then(|p| p.parse::<u32>().ok());
    let Ok(meta) = fs::symlink_metadata(path) else { return false };
    let old =
        meta.modified().ok().and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|a| a >= TMP_GRACE);
    pid.is_some_and(|p| p > 0 && !sys::alive(p)) && old
}

/// Bytes a removal really frees: a hardlinked file frees nothing while another link survives.
fn freed(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else { return 0 };
    if meta.is_dir() {
        return fs::read_dir(path).into_iter().flatten().flatten().map(|e| freed(&e.path())).sum();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return 0;
        }
    }
    #[cfg(windows)]
    if crate::sys::file_info(path).is_some_and(|i| i.links > 1) {
        return 0;
    }
    meta.len()
}

/// Drop `<dir>/node_modules/.jpm` entries the last install did not want.
pub fn sweep_entries(dir: &Path, keep: &HashSet<String>) -> Swept {
    let nm = dir.join("node_modules");
    let entries = nm.join(".jpm");
    let mut out = Swept::default();
    // Never through a symlink: a cloned repo could point either one at a directory to empty.
    if [&nm, &entries].iter().any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())) {
        return out;
    }
    for e in fs::read_dir(&entries).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !entry_name(&name) || keep.contains(&name) || !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        out.bytes += freed(&e.path());
        remove_tree(&e.path());
        out.removed += 1;
    }
    out
}

/// `<name>@<version>-<22-character digest>`: only what jpm itself names an entry.
fn entry_name(name: &str) -> bool {
    let Some((head, digest)) = name.len().checked_sub(22).and_then(|at| name.split_at_checked(at)) else {
        return false;
    };
    head.len() > 2
        && head.ends_with('-')
        && head[1..].contains('@')
        && digest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// What the registered projects use: global entry names, and the store directories of the
/// packages their lockfiles name. A project gone, or no longer installed from this store, is
/// dropped from the register.
pub fn mark(store: &Store) -> (HashSet<String>, HashSet<PathBuf>) {
    let (mut shared, mut used) = (HashSet::new(), HashSet::new());
    for e in fs::read_dir(store.projects_dir()).into_iter().flatten().flatten() {
        let dir = PathBuf::from(fs::read_to_string(e.path()).unwrap_or_default());
        let Some(st) = state::read(&dir).filter(|st| Path::new(&st.store) == store.dir) else {
            let _ = fs::remove_file(e.path());
            continue;
        };
        shared.extend(st.shared);
        // A lockfile that cannot be read marks nothing: store content costs only a download.
        if let Ok(Some((lock, _))) = lock::read_lockfile(&dir) {
            // A runtime keeps each platform's build: a store shared across machines may hold several.
            let all =
                lock.packages.values().flat_map(|p| p.variants.iter().map(|v| &v.integrity).chain([&p.integrity]));
            used.extend(all.filter_map(|i| store.pkg_dir(i).ok()));
        }
    }
    (shared, used)
}

/// Global entries no registered project uses, and temp entries of dead processes.
pub fn sweep_shared(links: &Path, keep: &HashSet<String>) -> Swept {
    let mut out = Swept::default();
    for e in fs::read_dir(links).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let gone = match name.strip_prefix(".tmp-") {
            Some(rest) => abandoned(&e.path(), rest),
            None => !name.starts_with('.') && !keep.contains(&name),
        };
        if gone {
            out.bytes += freed(&e.path());
            remove_tree(&e.path());
            out.removed += 1;
        }
    }
    out
}

/// Store entries no registered project's lockfile names or with no index (a torn unpack),
/// indexes whose directory is gone, and temp directories of dead processes.
pub fn prune_store(pkg_root: &Path, tmp: &Path, used: &HashSet<PathBuf>) -> Swept {
    let mut out = Swept::default();
    for shard in fs::read_dir(pkg_root).into_iter().flatten().flatten() {
        let names: HashSet<String> = fs::read_dir(shard.path())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        for name in &names {
            let path = shard.path().join(name);
            let orphan = match name.strip_suffix(".idx") {
                Some(dir) => !names.contains(dir),
                None => !name.ends_with(".tmp") && (!used.contains(&path) || !names.contains(&format!("{name}.idx"))),
            };
            if orphan {
                out.bytes += freed(&path);
                if path.is_dir() {
                    remove_tree(&path);
                    // The index goes too: without its files it would claim content that is gone.
                    let _ = fs::remove_file(shard.path().join(format!("{name}.idx")));
                } else {
                    let _ = fs::remove_file(&path);
                }
                out.removed += 1;
            }
        }
        let _ = fs::remove_dir(shard.path()); // only when the sweep emptied it
    }
    for e in fs::read_dir(tmp).into_iter().flatten().flatten() {
        if abandoned(&e.path(), &e.file_name().to_string_lossy()) {
            out.bytes += freed(&e.path());
            remove_tree(&e.path());
            out.removed += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_torn_and_unused_content() {
        let root = crate::store::tests::scratch("gc");
        let shard = root.join("pkg").join("ab");
        fs::create_dir_all(shard.join("kept")).unwrap();
        fs::write(shard.join("kept.idx"), "x").unwrap();
        fs::create_dir_all(shard.join("torn")).unwrap();
        fs::create_dir_all(shard.join("unused")).unwrap();
        fs::write(shard.join("unused.idx"), "x").unwrap();
        // A live process's temp directory stays, however it looks.
        let tmp = root.join("tmp").join(format!("{}-x", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let used: HashSet<PathBuf> = [shard.join("kept")].into();
        let out = prune_store(&root.join("pkg"), &root.join("tmp"), &used);
        assert_eq!(out.removed, 2);
        assert!(shard.join("kept").exists() && !shard.join("torn").exists() && tmp.exists());
        assert!(!shard.join("unused").exists() && !shard.join("unused.idx").exists());
        remove_tree(&root);
    }

    #[test]
    fn sweeps_unwanted_entries() {
        let dir = crate::store::tests::scratch("gc2");
        let entries = dir.join("node_modules").join(".jpm");
        let (a, b) = ("a@1.0.0-aaaaaaaaaaaaaaaaaaaaaa", "b@1.0.0-bbbbbbbbbbbbbbbbbbbbbb");
        for name in [a, b, ".tmp-1", "not-an-entry"] {
            fs::create_dir_all(entries.join(name)).unwrap();
        }
        let keep: HashSet<String> = [a.to_string()].into();
        assert_eq!(sweep_entries(&dir, &keep).removed, 1);
        assert!(entries.join(a).exists() && entries.join(".tmp-1").exists() && entries.join("not-an-entry").exists());
        assert!(!entries.join(b).exists());
        remove_tree(&dir);
    }
}
