//! Reclaiming space: a project's stale `.jpm` entries, and store content nothing can use.
//! Mark and sweep, never refcounts: a refcount survives neither a second jpm running nor
//! `rm -rf node_modules`. Nothing written in the last hour is touched, to stay clear of a
//! running install.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::store::remove_tree;
use crate::sys;

const GRACE: Duration = Duration::from_secs(3600);

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

fn young(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else { return true };
    meta.modified().ok().and_then(|t| SystemTime::now().duration_since(t).ok()).is_none_or(|age| age < GRACE)
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
    meta.len()
}

/// Drop `<dir>/node_modules/.jpm` entries the last install did not want.
pub fn sweep_entries(dir: &Path, keep: &HashSet<String>) -> Swept {
    let entries = dir.join("node_modules").join(".jpm");
    let mut out = Swept::default();
    for e in fs::read_dir(&entries).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || keep.contains(&name) || !e.file_type().is_ok_and(|t| t.is_dir()) || young(&e.path())
        {
            continue;
        }
        out.bytes += freed(&e.path());
        remove_tree(&e.path());
        out.removed += 1;
    }
    out
}

/// Store entries with no index (a torn unpack), indexes whose directory is gone, and temp
/// directories of dead processes.
pub fn prune_store(pkg_root: &Path, tmp: &Path) -> Swept {
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
                None => !name.ends_with(".tmp") && !names.contains(&format!("{name}.idx")),
            };
            if orphan && !young(&path) {
                out.bytes += freed(&path);
                if path.is_dir() {
                    remove_tree(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
                out.removed += 1;
            }
        }
        let _ = fs::remove_dir(shard.path()); // only when the sweep emptied it
    }
    for e in fs::read_dir(tmp).into_iter().flatten().flatten() {
        let pid = e.file_name().to_string_lossy().split('-').next().and_then(|p| p.parse::<u32>().ok());
        if pid.is_some_and(|p| p > 0 && !sys::alive(p)) && !young(&e.path()) {
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

    fn age(path: &Path) {
        let old = SystemTime::now() - Duration::from_secs(7200);
        let f = fs::File::open(path).unwrap();
        f.set_modified(old).unwrap();
    }

    #[test]
    fn prunes_orphans_but_not_young_or_kept() {
        let root = crate::store::tests::scratch("gc");
        let shard = root.join("pkg").join("ab");
        fs::create_dir_all(shard.join("kept")).unwrap();
        fs::write(shard.join("kept.idx"), "x").unwrap();
        fs::create_dir_all(shard.join("torn")).unwrap();
        fs::create_dir_all(shard.join("fresh")).unwrap();
        age(&shard.join("torn"));
        let out = prune_store(&root.join("pkg"), &root.join("tmp"));
        assert_eq!(out.removed, 1);
        assert!(shard.join("kept").exists() && shard.join("fresh").exists() && !shard.join("torn").exists());
        remove_tree(&root);
    }

    #[test]
    fn sweeps_unwanted_entries() {
        let dir = crate::store::tests::scratch("gc2");
        let entries = dir.join("node_modules").join(".jpm");
        for name in ["a@1.0.0-x", "b@1.0.0-y", ".tmp-1"] {
            fs::create_dir_all(entries.join(name)).unwrap();
            age(&entries.join(name));
        }
        let keep: HashSet<String> = ["a@1.0.0-x".to_string()].into();
        assert_eq!(sweep_entries(&dir, &keep).removed, 1);
        assert!(entries.join("a@1.0.0-x").exists() && entries.join(".tmp-1").exists());
        remove_tree(&dir);
    }
}
