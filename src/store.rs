//! The content store: one directory per tarball, named by its integrity, holding the unpacked
//! files read-only, plus an index of them. A tarball seen before is never fetched or unpacked
//! again, and the linker hardlinks (or clones) out of here into every project.
//!
//! Layout under the store root:
//! - `v1/pkg/<shard>/<name>/`: the files, never written after the rename that publishes them.
//! - `v1/pkg/<shard>/<name>.idx`: the index; its presence is what makes the entry real.
//! - `v1/tmp/`: entries being unpacked, renamed into `pkg/` once whole.
//! - `v1/links/`: the global virtual store's entries (see `link`).
//! - `v1/projects/`: one file per project installed from this store, holding its path.
//! - `v1/lock`: held shared by installs and exclusively by a prune.
//! - `metadata/`: registry documents kept between runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use flate2::read::GzDecoder;

use crate::error::{Error, Result};
use crate::integrity::Integrity;
use crate::util::{short_hash, temp_suffix, to_base64, to_base64_url, write_atomic};
use crate::{bin, http, tar};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub exec: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Index {
    pub files: Vec<FileEntry>,
    pub unpacked_size: u64,
}

impl Index {
    fn render(&self) -> String {
        let mut out = format!("jpm-index 1 {}\n", self.unpacked_size);
        for f in &self.files {
            out.push_str(&format!("{} {} {}\n", if f.exec { 'x' } else { '-' }, f.size, f.path));
        }
        out
    }

    /// A torn or hand-edited index reads as absent: the entry is fetched again.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let unpacked_size = lines.next()?.strip_prefix("jpm-index 1 ")?.parse().ok()?;
        let files = lines
            .map(|line| {
                let (flag, rest) = line.split_once(' ')?;
                let (size, path) = rest.split_once(' ')?;
                // The linker joins it under the entry, so it must never climb out.
                if !crate::tar::plain(path) {
                    return None;
                }
                Some(FileEntry { path: path.to_string(), size: size.parse().ok()?, exec: flag == "x" })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { files, unpacked_size })
    }
}

/// Where a tarball is. Only a caller that means a local file can name one, so no url a registry
/// sends is ever read off the disk.
#[derive(Debug, Clone)]
pub enum Tarball {
    Url(String),
    File(PathBuf),
}

impl std::fmt::Display for Tarball {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(u) => f.write_str(u),
            Self::File(p) => write!(f, "{}", p.display()),
        }
    }
}

type Pending = Arc<OnceLock<Result<Arc<Index>>>>;

/// From this size a tarball unpacks while it downloads.
const STREAM_MIN: u64 = 1024 * 1024;

pub struct Store {
    pub dir: PathBuf,
    root: PathBuf,
    auth: BTreeMap<String, String>,
    offline: bool,
    /// Check that stored files still have their recorded sizes instead of trusting the index.
    verify: bool,
    pending: Mutex<HashMap<String, Pending>>,
    loaded: Mutex<HashMap<String, Arc<Index>>>,
    /// Entries this process fetched, to tell a download from a cache hit.
    fetched: Mutex<HashSet<String>>,
}

/// `dir`, else `JPM_STORE`, else `~/.jpm/store`.
pub fn store_dir(dir: Option<&Path>) -> PathBuf {
    if let Some(d) = dir.filter(|d| !d.as_os_str().is_empty()) {
        return std::path::absolute(d).unwrap_or_else(|_| d.to_path_buf());
    }
    if let Some(env) = std::env::var_os("JPM_STORE").filter(|e| !e.is_empty()) {
        let p = PathBuf::from(env);
        return std::path::absolute(&p).unwrap_or(p);
    }
    crate::config::home().join(".jpm").join("store")
}

/// `sha512-a+b/c=` -> shard `ab`, name `sha512-c`: base64url, so both are safe path segments.
fn shard_of(integrity: &str) -> Result<(String, String)> {
    let parsed = Integrity::parse(integrity)?;
    let safe = to_base64_url(&parsed.digest);
    Ok((safe[..2].to_string(), format!("{}-{}", parsed.algorithm, &safe[2..])))
}

impl Store {
    pub fn new(dir: PathBuf, auth: BTreeMap<String, String>, offline: bool, verify: bool) -> Self {
        let root = dir.join("v1");
        Self {
            dir,
            root,
            auth,
            offline,
            verify,
            pending: Mutex::default(),
            loaded: Mutex::default(),
            fetched: Mutex::default(),
        }
    }

    pub fn metadata_dir(&self) -> PathBuf {
        self.dir.join("metadata")
    }

    pub fn pkg_dir(&self, integrity: &str) -> Result<PathBuf> {
        let (shard, name) = shard_of(integrity)?;
        Ok(self.root.join("pkg").join(shard).join(name))
    }

    fn index_path(&self, integrity: &str) -> Result<PathBuf> {
        let mut p = self.pkg_dir(integrity)?;
        p.as_mut_os_string().push(".idx");
        Ok(p)
    }

    /// Whether the entry is there, without reading its index.
    pub fn has(&self, integrity: &str) -> bool {
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner).contains_key(integrity)
            || self.index_path(integrity).is_ok_and(|p| p.is_file())
    }

    /// The entry's index, read once.
    pub fn index(&self, integrity: &str) -> Option<Arc<Index>> {
        if let Some(hit) = self.loaded.lock().unwrap_or_else(PoisonError::into_inner).get(integrity) {
            return Some(hit.clone());
        }
        let text = fs::read_to_string(self.index_path(integrity).ok()?).ok()?;
        let index = Arc::new(Index::parse(&text)?);
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner).insert(integrity.to_string(), index.clone());
        Some(index)
    }

    /// Every file still there at the size the index says: what `--verify` pays for.
    fn intact(&self, integrity: &str, index: &Index) -> bool {
        let Ok(dir) = self.pkg_dir(integrity) else { return false };
        index.files.iter().all(|f| fs::metadata(dir.join(&f.path)).is_ok_and(|m| m.len() == f.size))
    }

    pub fn was_fetched(&self, integrity: &str) -> bool {
        self.fetched.lock().unwrap_or_else(PoisonError::into_inner).contains(integrity)
    }

    /// The entry, fetched and unpacked if it is not here. Concurrent callers share one download.
    pub fn ensure(&self, tarball: &Tarball, integrity: &str) -> Result<Arc<Index>> {
        if !self.verify
            && let Some(index) = self.index(integrity)
        {
            return Ok(index);
        }
        let cell = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(integrity.to_string())
            .or_default()
            .clone();
        cell.get_or_init(|| self.build(tarball, integrity)).clone()
    }

    fn build(&self, tarball: &Tarball, integrity: &str) -> Result<Arc<Index>> {
        let hit = self.index(integrity);
        if let Some(index) = &hit
            && (!self.verify || self.intact(integrity, index))
        {
            return Ok(index.clone());
        }
        let expected = Integrity::parse(integrity)?;
        let (unpacked, temp, digest) = self.fetch(tarball, expected.hasher())?;
        // The bytes are checked before anything they said is trusted, or kept.
        let checked = expected.check(&digest).map_err(|e| e.context(tarball)).and(unpacked);
        let index = match checked {
            Ok(index) => self.publish(integrity, index, &temp, hit.is_some()),
            Err(e) => Err(e),
        };
        remove_tree(&temp);
        let index = index?;
        self.fetched.lock().unwrap_or_else(PoisonError::into_inner).insert(integrity.to_string());
        Ok(index)
    }

    /// A tarball whose integrity is not known yet (a tarball dependency's first read): stored
    /// under the sha512 of its bytes, which is its integrity from then on.
    pub fn adopt(&self, tarball: &Tarball) -> Result<(Arc<Index>, String)> {
        let (unpacked, temp, digest) =
            self.fetch(tarball, jpm_crypto::hash::Hasher::new(jpm_crypto::hash::Alg::Sha512))?;
        let integrity = format!("sha512-{}", to_base64(&digest));
        let result = match self.index(&integrity) {
            Some(index) if self.intact(&integrity, &index) => Ok(index),
            _ => unpacked.and_then(|index| self.publish(&integrity, index, &temp, true)),
        };
        remove_tree(&temp);
        Ok((result?, integrity))
    }

    /// Stream a tarball into a temp directory, hashing its bytes as they pass: the download,
    /// the inflate and the writes overlap. What was unpacked comes back with the digest of every
    /// byte, read to the end even when unpacking failed, so a corrupt download is reported as
    /// one. A connection that drops mid-body is tried again.
    fn fetch(&self, tarball: &Tarball, hasher: jpm_crypto::hash::Hasher) -> Result<(Result<Index>, PathBuf, Vec<u8>)> {
        let tmp_root = self.root.join("tmp");
        fs::create_dir_all(&tmp_root).map_err(|e| Error::io(&e, format!("cannot create {}", tmp_root.display())))?;
        let mut last = None;
        for _ in 0..3 {
            let temp = tmp_root.join(temp_suffix());
            let (source, length) = self.open(tarball)?;
            let mut input = Hashing { inner: source, hash: hasher.clone(), failed: None };
            // A small tarball is read whole first: its connection goes back to the pool at network
            // speed, not at the pace of its writes. A big one unpacks as it downloads.
            let unpacked = if length.is_some_and(|n| n < STREAM_MIN) {
                let mut bytes = Vec::with_capacity(length.unwrap_or(0) as usize);
                match input.read_to_end(&mut bytes) {
                    Ok(_) => extract(bytes.as_slice(), &temp),
                    Err(e) => Err(Error::io(&e, format!("cannot read {tarball}"))),
                }
            } else {
                extract(&mut input, &temp)
            };
            // The rest still counts toward the hash; a source that never ends is refused.
            let drained = io::copy(&mut (&mut input).take(crate::tar::MAX_ARCHIVE), &mut io::sink()).and_then(|_| {
                match input.read(&mut [0u8; 1])? {
                    0 => Ok(()),
                    _ => Err(io::Error::other("tarball larger than 1 GiB")),
                }
            });
            if let Some(dropped) = input.failed.take() {
                remove_tree(&temp);
                last = Some(dropped);
                continue;
            }
            if let Err(e) = drained {
                remove_tree(&temp);
                return Err(Error::io(&e, format!("cannot read {tarball}")));
            }
            return Ok((unpacked, temp, input.hash.finish().to_vec()));
        }
        Err(last.unwrap_or_else(|| Error::new("ENETWORK", format!("{tarball} failed"))))
    }

    fn open(&self, tarball: &Tarball) -> Result<(Box<dyn Read + Send>, Option<u64>)> {
        match tarball {
            Tarball::File(path) => {
                let cannot = |e: io::Error| Error::io(&e, format!("Tarball {} cannot be read", path.display()));
                if !fs::metadata(path).map_err(cannot)?.is_file() {
                    return Err(Error::new("EINVAL", format!("Tarball {} is not a regular file", path.display())));
                }
                Ok((Box::new(fs::File::open(path).map_err(cannot)?), None))
            }
            Tarball::Url(_) if self.offline => {
                Err(Error::new("EOFFLINE", format!("offline: {tarball} is not in the store")))
            }
            Tarball::Url(url) => http::open(url, &self.auth),
        }
    }

    /// Publish an unpacked, verified entry: rename it into place, then write its index. Nothing is
    /// addressable before the integrity has passed.
    fn publish(&self, integrity: &str, index: Index, temp: &Path, repair: bool) -> Result<Arc<Index>> {
        let dest = self.pkg_dir(integrity)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())))?;
        }
        if repair && dest.exists() {
            remove_tree(&dest);
        }
        // Another process may have published the same bytes first; its copy is as good.
        if let Err(e) = fs::rename(temp, &dest)
            && !dest.is_dir()
        {
            return Err(Error::io(&e, format!("cannot store {}", dest.display())));
        }
        write_atomic(&self.index_path(integrity)?, index.render().as_bytes())?;
        let index = Arc::new(index);
        self.loaded.lock().unwrap_or_else(PoisonError::into_inner).insert(integrity.to_string(), index.clone());
        Ok(index)
    }

    /// A file of a stored entry.
    pub fn file(&self, integrity: &str, path: &str) -> Result<PathBuf> {
        Ok(self.pkg_dir(integrity)?.join(path))
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// The global virtual store: package entries with their dependency links, shared by projects.
    pub fn links_dir(&self) -> PathBuf {
        links_dir_of(&self.dir)
    }

    pub fn projects_dir(&self) -> PathBuf {
        self.root.join("projects")
    }

    /// Record `project` as installed from this store, for a prune to find what it uses. Best
    /// effort: a project left out only risks losing shared entries its next install rebuilds.
    pub fn register(&self, project: &Path) {
        let path = fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
        let text = path.to_string_lossy();
        let file = self.projects_dir().join(short_hash(&text));
        if file.exists() {
            return;
        }
        let _ = fs::create_dir_all(self.projects_dir());
        let _ = write_atomic(&file, text.as_bytes());
    }

    /// The store's lock: shared while an install uses the store, exclusive while a prune empties
    /// it, so a prune never removes what an install is about to link. `None` when the store
    /// cannot be written, which leaves nothing to prune either.
    pub fn hold(&self, exclusive: bool) -> Option<fs::File> {
        let _ = fs::create_dir_all(&self.root);
        let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(self.root.join("lock")).ok()?;
        if exclusive { file.lock() } else { file.lock_shared() }.ok()?;
        Some(file)
    }

    pub fn pkg_root(&self) -> PathBuf {
        self.root.join("pkg")
    }
}

/// The global virtual store under a store directory.
pub fn links_dir_of(store_dir: &Path) -> PathBuf {
    store_dir.join("v1").join("links")
}

/// Remove a store tree, lifting the read-only bits first where the OS needs that.
pub fn remove_tree(dir: &Path) {
    if fs::remove_dir_all(dir).is_ok() || !dir.exists() {
        return;
    }
    writable(dir);
    let _ = fs::remove_dir_all(dir);
}

/// Windows will not delete a read-only file; unix needs write access to each directory. A
/// symlink is left alone: setting its permissions would set its target's.
fn writable(p: &Path) {
    if let Ok(meta) = fs::symlink_metadata(p)
        && !meta.file_type().is_symlink()
    {
        let mut perm = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = fs::set_permissions(p, perm);
        if meta.is_dir() {
            for e in fs::read_dir(p).into_iter().flatten().flatten() {
                writable(&e.path());
            }
        }
    }
}

/// Gunzip (when gzipped) and write every regular file under `dest`, read-only, the
/// executables and declared bins executable.
pub fn extract(mut source: impl Read, dest: &Path) -> Result<Index> {
    fs::create_dir_all(dest).map_err(|e| Error::io(&e, format!("cannot create {}", dest.display())))?;
    let mut head = Vec::with_capacity(2);
    (&mut source).take(2).read_to_end(&mut head).map_err(|e| Error::new("EBADTAR", format!("Corrupt tarball: {e}")))?;
    let gz = head.starts_with(&[0x1f, 0x8b]);
    let raw = io::BufReader::with_capacity(256 * 1024, io::Cursor::new(head).chain(source));
    let input: Box<dyn Read + '_> = if gz { Box::new(GzDecoder::new(raw)) } else { Box::new(raw) };
    let mut input = input.take(tar::MAX_ARCHIVE + 1);
    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut made: HashSet<PathBuf> = HashSet::new();
    let mut manifest: Option<Vec<u8>> = None;
    tar::read_entries(&mut input, |path, mode, size, body| {
        let file = dest.join(path);
        if let Some(parent) = file.parent()
            && made.insert(parent.to_path_buf())
        {
            fs::create_dir_all(parent).map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())))?;
        }
        let exec = mode & 0o111 != 0;
        // A later entry for the path wins, as tar has it.
        if files.contains_key(path) {
            let _ = make_writable(&file);
            let _ = fs::remove_file(&file);
        }
        let mut out = create(&file, exec).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
        if path == "package.json" {
            if size > crate::tar::MAX_META {
                return Err(Error::new("EBADTAR", format!("package.json of {size} bytes")));
            }
            let mut data = Vec::with_capacity(size as usize);
            body.read_to_end(&mut data).map_err(|e| Error::new("EBADTAR", format!("Corrupt tarball: {e}")))?;
            out.write_all(&data).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
            manifest = Some(data);
        } else {
            io::copy(body, &mut out).map_err(|e| Error::new("EBADTAR", format!("Corrupt tarball: {e}")))?;
        }
        files.insert(path.to_string(), FileEntry { path: path.to_string(), size, exec });
        Ok(())
    })?;
    if input.limit() == 0 {
        return Err(Error::new("EBADTAR", format!("Tarball inflates past {} bytes", tar::MAX_ARCHIVE)));
    }
    // A declared bin must run, whatever mode the tarball gave it.
    let declared = manifest
        .and_then(|m| String::from_utf8(m).ok())
        .and_then(|m| crate::json::parse(&m).ok())
        .map(|v| bin::normalize(v.get("name").and_then(|n| n.as_str()), v.get("bin")))
        .unwrap_or_default();
    for target in declared.values() {
        if let Some(f) = files.get_mut(target.trim_end_matches('/'))
            && !f.exec
        {
            f.exec = true;
            set_mode(&dest.join(&f.path), true);
        }
    }
    let unpacked_size = files.values().map(|f| f.size).sum();
    Ok(Index { files: files.into_values().collect(), unpacked_size })
}

/// Passes bytes through while hashing them, and remembers a read error: the connection
/// dropped, which is worth another try, where bad bytes are not.
struct Hashing<R> {
    inner: R,
    hash: jpm_crypto::hash::Hasher,
    failed: Option<Error>,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.hash.update(&buf[..n]);
                Ok(n)
            }
            Err(e) => {
                self.failed.get_or_insert_with(|| Error::new("ENETWORK", format!("download failed: {e}")));
                Err(e)
            }
        }
    }
}

/// Created read-only: content is hardlinked into every project, so a write through one link
/// would change all of them. The fd that creates it may still write.
fn create(file: &Path, exec: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if exec { 0o555 } else { 0o444 });
    }
    #[cfg(not(unix))]
    let _ = exec;
    options.open(file)
}

fn set_mode(file: &Path, exec: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(file, fs::Permissions::from_mode(if exec { 0o555 } else { 0o444 }));
    }
    #[cfg(not(unix))]
    let _ = (file, exec);
}

fn make_writable(file: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file, fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    #[test]
    fn refuses_index_paths_that_leave_the_entry() {
        for bad in ["C:/x", "a/../b", "a:stream", "/abs", "a/./b", "a\\b", "x."] {
            assert!(super::Index::parse(&format!("jpm-index 1 1\n- 1 {bad}\n")).is_none(), "{bad}");
        }
        assert!(super::Index::parse("jpm-index 1 1\n- 1 lib/ok.js\n").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn remove_tree_never_changes_a_link_target() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("rt-link");
        let outside = root.join("outside");
        fs::write(&outside, "x").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let tree = root.join("tree");
        fs::create_dir_all(&tree).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        super::writable(&tree);
        assert_eq!(fs::metadata(&outside).unwrap().permissions().mode() & 0o777, 0o600);
        super::remove_tree(&root);
    }

    use super::*;
    use crate::integrity::sha512;
    use crate::tar::tests::build;

    pub fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    pub fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jpm-test-{name}-{}", temp_suffix()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn stores_a_local_tarball() {
        let dir = scratch("store");
        let tgz = gzip(&build(&[
            ("package/package.json", 0o644, br#"{"name":"a","bin":"cli.js"}"#),
            ("package/cli.js", 0o644, b"#!/usr/bin/env node"),
            ("package/lib/x.js", 0o644, b"x"),
        ]));
        let file = dir.join("a.tgz");
        fs::write(&file, &tgz).unwrap();
        let store = Store::new(dir.join("store"), BTreeMap::new(), false, false);
        let (index, integrity) = store.adopt(&Tarball::File(file.clone())).unwrap();
        assert_eq!(integrity, sha512(&tgz));
        assert_eq!(index.files.len(), 3);
        assert!(index.files.iter().find(|f| f.path == "cli.js").unwrap().exec);
        assert_eq!(fs::read(store.file(&integrity, "lib/x.js").unwrap()).unwrap(), b"x");
        // A second read is the index on disk.
        let again = Store::new(dir.join("store"), BTreeMap::new(), true, false);
        assert_eq!(*again.ensure(&Tarball::Url("http://nowhere".into()), &integrity).unwrap(), *index);
        // Wrong bytes for an integrity fail before anything is stored.
        let bad = sha512(b"other");
        assert_eq!(store.ensure(&Tarball::File(file), &bad).unwrap_err().code, "EINTEGRITY");
        assert!(!store.has(&bad));
        remove_tree(&dir);
    }

    #[test]
    fn index_refuses_escapes() {
        assert!(Index::parse("jpm-index 1 1\n- 1 ../x\n").is_none());
        assert!(Index::parse("jpm-index 1 1\n- 1 a/b\n").is_some());
        assert!(Index::parse("garbage").is_none());
    }
}
