//! The content store: one directory per tarball, named by its integrity, holding the unpacked
//! files read-only, plus an index of them. A tarball seen before is never fetched or unpacked
//! again, and the linker hardlinks (or clones) out of here into every project.
//!
//! Layout under the store root:
//! - `v1/pkg/<shard>/<name>/`: the files, never written after the rename that publishes them.
//!   On Windows each is stored as `<path>.jpm` (the index says so): Windows Defender scans a file
//!   it sees written as `.js` as script, a third more work than one with a name it does not
//!   know, and every cold install writes thousands. Links into projects keep the real names.
//! - `v1/pkg/<shard>/<name>.idx`: the index; its presence is what makes the entry real.
//! - `v1/tmp/`: entries being unpacked, renamed into `pkg/` once whole.
//! - `v1/links/`: the global virtual store's entries (see `link`).
//! - `v1/projects/`: one file per project installed from this store, holding its path.
//! - `v1/lock`: held shared by installs and exclusively by a prune.
//! - `v1/salt`: this store's random salt (see `salt`).
//! - `metadata/`: registry documents kept between runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};

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
    /// Each file is stored as `<path>.jpm` (Windows); see `stored`.
    pub suffixed: bool,
}

/// What a stored file's name ends with where the store suffixes names.
pub const STORED_SUFFIX: &str = ".jpm";

/// Whether this platform's store suffixes the files it unpacks: Windows, for Defender.
pub const SUFFIX_FILES: bool = cfg!(windows);

impl Index {
    /// A file's name in the store: its path, with the suffix when this entry has one.
    pub fn stored(&self, path: &str) -> String {
        if self.suffixed { format!("{path}{STORED_SUFFIX}") } else { path.to_string() }
    }

    fn render(&self) -> String {
        let mut out = format!("jpm-index {} {}\n", if self.suffixed { 2 } else { 1 }, self.unpacked_size);
        for f in &self.files {
            out.push_str(&format!("{} {} {}\n", if f.exec { 'x' } else { '-' }, f.size, f.path));
        }
        out
    }

    /// A torn or hand-edited index reads as absent: the entry is fetched again.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let head = lines.next()?;
        let (suffixed, size) = match head.strip_prefix("jpm-index 2 ") {
            Some(size) => (true, size),
            None => (false, head.strip_prefix("jpm-index 1 ")?),
        };
        let unpacked_size = size.parse().ok()?;
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
        Some(Self { files, unpacked_size, suffixed })
    }
}

/// Where a tarball is. Only a caller that means a local file can name one, so no url a registry
/// sends is ever read off the disk.
#[derive(Debug, Clone)]
pub enum Tarball {
    Url(String),
    File(PathBuf),
    /// A git commit, `<url>#<commit>`. Its integrity is the tree's (see `tree_integrity`), not
    /// an archive's bytes, which a host may compress differently from one day to the next.
    Git(String),
}

impl std::fmt::Display for Tarball {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(u) | Self::Git(u) => f.write_str(u),
            Self::File(p) => write!(f, "{}", p.display()),
        }
    }
}

type Pending = Arc<OnceLock<Result<Arc<Index>>>>;

/// From this size a tarball unpacks while it downloads.
const STREAM_MIN: u64 = 1024 * 1024;

/// Files of a tarball written by the thread reading it; past these, writer threads take over.
const INLINE_FILES: usize = 64;
/// Inflated bytes read ahead of the tar reader.
const INFLATED_BUF: usize = 64 * 1024;
/// The largest write of a file the reading thread writes itself.
const COPY_BUF: usize = 128 * 1024;
/// Writer threads for one tarball, at most.
const WRITERS: usize = 8;
/// File bodies read ahead of the writers.
const WRITE_QUEUE: usize = 64;
/// The largest body handed to a writer; a bigger one streams to disk from the reader.
const QUEUED_MAX: u64 = 8 * 1024 * 1024;
/// Bytes of bodies read but not yet written, at most: what a tarball may hold in memory, however
/// big or repetitive its files. The reader waits for the writers past it.
const QUEUED_BYTES: u64 = 32 * 1024 * 1024;

/// Tarballs being unpacked in this process, for `idle_cores`.
static UNPACKING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether a tarball past its first files may hand the rest to writer threads. On Windows,
/// always: they overlap Defender's scan of each file as it is closed. On Linux, only while fewer
/// tarballs unpack than there are cores: when every core is unpacking a tarball of its own, the
/// hand-off only adds a copy of each file and the threads' wakeups (next from a lockfile: 17%
/// of the CPU and half the peak memory), and a lone big tarball still gets them.
fn idle_cores() -> bool {
    !cfg!(target_os = "linux") || UNPACKING.load(std::sync::atomic::Ordering::Relaxed) < crate::pool::disk_threads()
}

/// A tarball counted in `UNPACKING` while it lives.
struct Unpacking;

impl Unpacking {
    fn start() -> Self {
        UNPACKING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self
    }
}

impl Drop for Unpacking {
    fn drop(&mut self) {
        UNPACKING.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A file body for a writer thread: where, whether it runs, the bytes, and what they took of the
/// budget.
type Queued = (PathBuf, bool, Vec<u8>, u64);

/// Bytes queued to `extract`'s writers and not yet written.
#[derive(Default)]
struct Budget {
    used: Mutex<u64>,
    freed: std::sync::Condvar,
}

impl Budget {
    /// Room for `n` more bytes, waiting for the writers while the queue holds too much.
    fn take(&self, n: u64) {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        while *used > 0 && *used + n > QUEUED_BYTES {
            used = self.freed.wait(used).unwrap_or_else(PoisonError::into_inner);
        }
        *used += n;
    }

    fn give(&self, n: u64) {
        *self.used.lock().unwrap_or_else(PoisonError::into_inner) -= n;
        self.freed.notify_all();
    }
}

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

/// The store's salt, `v1/salt`: random, made the first time it is asked for. An install state
/// records it among its inputs, so a state written against another store (on another machine,
/// or shipped in a repository) never passes for one of this store's. `None` when the store
/// cannot be written.
pub fn salt(store: &Path) -> Option<String> {
    let file = store.join("v1").join("salt");
    let read = || fs::read_to_string(&file).ok().filter(|s| s.len() == 22);
    if let Some(s) = read() {
        return Some(s);
    }
    let mut bytes = [0u8; 16];
    jpm_crypto::rand::fill(&mut bytes);
    fs::create_dir_all(file.parent()?).ok()?;
    write_atomic(&file, to_base64_url(&bytes).as_bytes()).ok()?;
    // Two installs making it at once: whichever rename came last is the salt.
    read()
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
        index.files.iter().all(|f| fs::metadata(dir.join(index.stored(&f.path))).is_ok_and(|m| m.len() == f.size))
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
        let (unpacked, temp, digest) = match tarball {
            Tarball::Git(source) => self.fetch_git(source)?,
            _ => self.fetch(tarball, expected.hasher())?,
        };
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
        let (unpacked, temp, digest) = match tarball {
            Tarball::Git(source) => self.fetch_git(source)?,
            _ => self.fetch(tarball, jpm_crypto::hash::Hasher::new(jpm_crypto::hash::Alg::Sha512))?,
        };
        let integrity = format!("sha512-{}", to_base64(&digest));
        // Only a broken entry is replaced: one with no index yet may be another adopt's, mid-publish.
        let result = match self.index(&integrity) {
            Some(index) if self.intact(&integrity, &index) => Ok(index),
            hit => unpacked.and_then(|index| self.publish(&integrity, index, &temp, hit.is_some())),
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
            // One budget for every byte read, unpacked or drained.
            let mut input = Hashing { inner: source.take(tar::MAX_ARCHIVE + 1), hash: hasher.clone(), failed: None };
            let unpacked = match small_head(&mut input, length) {
                Ok(head) if tarball.to_string().ends_with(".exe") => {
                    store_exe(&mut head.as_slice().chain(&mut input), &temp, &tarball.to_string())
                }
                Ok(head) => extract(&mut head.as_slice().chain(&mut input), &temp, SUFFIX_FILES),
                Err(e) => Err(Error::io(&e, format!("cannot read {tarball}"))),
            };
            // The rest still counts toward the hash; a source that never ends is refused.
            let drained = io::copy(&mut input, &mut io::sink()).and_then(|_| match input.inner.limit() {
                0 => Err(io::Error::other("tarball larger than 1 GiB")),
                _ => Ok(()),
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

    /// A git commit's files in a temp directory, only those `npm pack` would keep (see `pack`),
    /// with the digest of that tree: what its integrity is, however the files came.
    fn fetch_git(&self, source: &str) -> Result<(Result<Index>, PathBuf, Vec<u8>)> {
        if self.offline {
            return Err(Error::new("EOFFLINE", format!("offline: {source} is not in the store")));
        }
        let tmp_root = self.root.join("tmp");
        fs::create_dir_all(&tmp_root).map_err(|e| Error::io(&e, format!("cannot create {}", tmp_root.display())))?;
        let (temp, work) = (tmp_root.join(temp_suffix()), tmp_root.join(temp_suffix()));
        let packed = crate::git::fetch(source, &work, &temp).and_then(|index| pack(&temp, index));
        match packed.and_then(|index| Ok((tree_digest(&temp, &index)?, index))) {
            Ok((digest, index)) => Ok((Ok(index), temp, digest)),
            Err(e) => {
                remove_tree(&temp);
                Err(e)
            }
        }
    }

    fn open(&self, tarball: &Tarball) -> Result<(Box<dyn Read + Send>, Option<u64>)> {
        match tarball {
            Tarball::Git(_) => Err(Error::new("EGIT", format!("{tarball} is a git commit, not a tarball"))),
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

    /// A stored entry's files in `to` under their own names, as copies to edit: writable, an
    /// executable still executable, no `node_modules`.
    pub fn copy_out(&self, integrity: &str, to: &Path) -> Result<()> {
        let index =
            self.index(integrity).ok_or_else(|| Error::new("ENOENT", format!("{integrity} is not in the store")))?;
        let from = self.pkg_dir(integrity)?;
        fs::create_dir_all(to).map_err(|e| Error::io(&e, format!("cannot create {}", to.display())))?;
        for f in index.files.iter().filter(|f| f.path.split('/').all(|p| p != "node_modules")) {
            let at = to.join(&f.path);
            if let Some(parent) = at.parent() {
                fs::create_dir_all(parent).map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())))?;
            }
            fs::copy(from.join(index.stored(&f.path)), &at)
                .map_err(|e| Error::io(&e, format!("cannot copy {}", at.display())))?;
            editable(&at, f.exec).map_err(|e| Error::io(&e, format!("cannot write {}", at.display())))?;
        }
        Ok(())
    }

    /// A file of a stored entry, under its stored name.
    pub fn file(&self, integrity: &str, path: &str) -> Result<PathBuf> {
        let stored = self.index(integrity).map_or_else(|| path.to_string(), |i| i.stored(path));
        Ok(self.pkg_dir(integrity)?.join(stored))
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
/// executables and declared bins executable. One copy of this for every kind of source.
/// With `suffix`, each file is written as `<path>.jpm` (see `Index::stored`).
pub fn extract(source: &mut dyn Read, dest: &Path, suffix: bool) -> Result<Index> {
    fs::create_dir_all(dest).map_err(|e| Error::io(&e, format!("cannot create {}", dest.display())))?;
    let mut head = Vec::with_capacity(2);
    (&mut *source)
        .take(2)
        .read_to_end(&mut head)
        .map_err(|e| Error::new("EBADTAR", format!("Corrupt tarball: {e}")))?;
    let gz = head.starts_with(&[0x1f, 0x8b]);
    let raw = io::Cursor::new(head).chain(source);
    // The buffer is on the inflated side: the decoder buffers its own input, and has no
    // `read_buf`, so each of the tar reader's small reads (every header, every small file) would
    // zero its buffer first and inflate a few hundred bytes at a time.
    let input: Box<dyn Read + '_> = if gz {
        Box::new(io::BufReader::with_capacity(INFLATED_BUF, GzDecoder::new(raw)))
    } else {
        Box::new(io::BufReader::with_capacity(INFLATED_BUF, raw))
    };
    let mut input = input.take(tar::MAX_ARCHIVE + 1);
    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut made: HashSet<PathBuf> = HashSet::new();
    let mut folded: HashMap<String, String> = HashMap::new();
    let mut manifest: Option<Vec<u8>> = None;
    // The buffer the files this thread writes itself pass through, one for the whole tarball:
    // one per file was 65 MB allocated and zeroed on nuxt.
    let mut copy: Vec<u8> = Vec::new();
    let name = |path: &str| if suffix { format!("{path}{STORED_SUFFIX}") } else { path.to_string() };
    // Past the first files, small bodies go to writer threads (see `idle_cores`): one tarball of
    // thousands of files (next has 8,000) would otherwise be written, and on Windows scanned, one
    // file at a time.
    let failed = &Mutex::new(None::<Error>);
    let budget = &Budget::default();
    let _unpacking = Unpacking::start();
    std::thread::scope(|scope| {
        let mut writers: Option<Writers<'_>> = None;
        let read = tar::read_entries(&mut input, |path, mode, size, body| {
            if let Some(e) = failed.lock().unwrap_or_else(PoisonError::into_inner).take() {
                return Err(e);
            }
            let file = dest.join(name(path));
            if let Some(parent) = file.parent()
                && made.insert(parent.to_path_buf())
            {
                fs::create_dir_all(parent).map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())))?;
            }
            let exec = mode & 0o111 != 0;
            let mut seen = files.insert(path.to_string(), FileEntry { path: path.to_string(), size, exec }).is_some();
            // Foo.js then foo.js: one file where the disk folds case, and the later one wins.
            if crate::sys::FOLDS_CASE
                && let Some(old) = folded.insert(path.to_lowercase(), path.to_string())
                && old != path
            {
                files.remove(&old);
                seen = true;
            }
            let corrupt = |e: io::Error| Error::new("EBADTAR", format!("Corrupt tarball: {e}"));
            if seen {
                // A later entry for the path wins, as tar has it: any queued write of it first.
                finish(&mut writers);
                let _ = make_writable(&file);
                let _ = fs::remove_file(&file);
            } else if path != "package.json"
                && size <= QUEUED_MAX
                && files.len() > INLINE_FILES
                && (writers.is_some() || idle_cores())
            {
                budget.take(size);
                let mut data = Vec::with_capacity(size as usize);
                if let Err(e) = body.read_to_end(&mut data) {
                    budget.give(size);
                    return Err(corrupt(e));
                }
                let (send, _) = writers.get_or_insert_with(|| {
                    let (send, recv) = mpsc::sync_channel::<Queued>(WRITE_QUEUE);
                    let recv = Arc::new(Mutex::new(recv));
                    let spawn = |_| {
                        let recv = recv.clone();
                        scope.spawn(move || write_queued(&recv, failed, budget))
                    };
                    (send, (0..crate::pool::disk_threads().min(WRITERS)).map(spawn).collect())
                });
                if send.send((file, exec, data, size)).is_err() {
                    budget.give(size);
                }
                return Ok(());
            }
            let mut out = create(&file, exec).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
            if path == "package.json" {
                if size > crate::tar::MAX_META {
                    return Err(Error::new("EBADTAR", format!("package.json of {size} bytes")));
                }
                let mut data = Vec::with_capacity(size as usize);
                body.read_to_end(&mut data).map_err(corrupt)?;
                out.write_all(&data).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
                manifest = Some(data);
            } else {
                // Only as big as the tarball's biggest such file: 32 downloads unpack at once,
                // and most files are small.
                let want = usize::try_from(size).unwrap_or(COPY_BUF).clamp(1, COPY_BUF);
                if copy.len() < want {
                    copy.resize(want, 0);
                }
                copy_body(body, &mut out, &mut copy[..want], &file)?;
            }
            Ok(())
        });
        finish(&mut writers);
        read
    })?;
    if let Some(e) = failed.lock().unwrap_or_else(PoisonError::into_inner).take() {
        return Err(e);
    }
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
            set_mode(&dest.join(name(&f.path)), true);
        }
    }
    let unpacked_size = files.values().map(|f| f.size).sum();
    Ok(Index { files: files.into_values().collect(), unpacked_size, suffixed: suffix })
}

/// A file's body into `out` in `buf`-sized writes: one write for most files, where `io::copy`
/// would write every 8 KiB. A read error is a corrupt tarball, a write error the disk's.
fn copy_body(body: &mut dyn Read, out: &mut impl Write, buf: &mut [u8], file: &Path) -> Result<()> {
    loop {
        let mut n = 0;
        while n < buf.len() {
            match body.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::new("EBADTAR", format!("Corrupt tarball: {e}"))),
            }
        }
        out.write_all(&buf[..n]).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
        if n < buf.len() {
            return Ok(());
        }
    }
}

/// A download that is a Windows program, not an archive (Node's `win-x64/node.exe`): kept as the
/// one executable file it is, under its own name.
fn store_exe(source: &mut dyn Read, dest: &Path, url: &str) -> Result<Index> {
    let name = url.rsplit(['/', '\\']).next().unwrap_or_default();
    if !tar::plain(name) {
        return Err(Error::new("EBADTAR", format!("{url} does not end in a file name")));
    }
    fs::create_dir_all(dest).map_err(|e| Error::io(&e, format!("cannot create {}", dest.display())))?;
    let file = dest.join(if SUFFIX_FILES { format!("{name}{STORED_SUFFIX}") } else { name.to_string() });
    let mut out = create(&file, true).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
    let size = io::copy(&mut source.take(tar::MAX_ARCHIVE), &mut out)
        .map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
    let files = vec![FileEntry { path: name.to_string(), size, exec: true }];
    Ok(Index { files, unpacked_size: size, suffixed: SUFFIX_FILES })
}

/// Take out of an unpacked repository what `npm pack` would leave out under package.json's
/// `files`: a pattern keeps a file it names, or everything under a directory it names, and a `!`
/// pattern takes it out again, the last to match winning. package.json, the readme, the licence,
/// `main` and the bins are always kept, and a `node_modules` never is. With no `files`, all is
/// kept: `.npmignore` and `.gitignore` are not read.
fn pack(dir: &Path, index: Index) -> Result<Index> {
    let doc = fs::read_to_string(dir.join("package.json")).ok().and_then(|t| crate::json::parse(&t).ok());
    let doc = doc.unwrap_or(crate::json::Value::Null);
    let files: Option<Vec<&str>> = doc.get("files").and_then(|f| f.as_array()).map(|l| {
        l.iter().filter_map(|v| v.as_str()).map(|p| p.trim_start_matches("./").trim_end_matches('/')).collect()
    });
    let main = doc.get("main").and_then(|m| m.as_str()).unwrap_or("").trim_start_matches("./");
    let bins = bin::normalize(doc.get("name").and_then(|n| n.as_str()), doc.get("bin"));
    let always = |path: &str| {
        let lower = path.to_ascii_lowercase();
        let top = !path.contains('/')
            && ["package.json", "readme", "license", "licence"].iter().any(|p| lower.starts_with(p));
        top || path == main || path.strip_suffix(".js") == Some(main) || bins.values().any(|b| b == path)
    };
    let kept = |path: &str| {
        let Some(files) = &files else { return true };
        let mut kept = always(path);
        for pattern in files {
            let (out, pattern) = match pattern.strip_prefix('!') {
                Some(p) => (true, p.trim_start_matches("./")),
                None => (false, *pattern),
            };
            let mut at = Some(path);
            while let Some(p) = at {
                if !pattern.is_empty() && crate::glob::matches(pattern, p) {
                    kept = !out;
                    break;
                }
                at = p.rsplit_once('/').map(|(d, _)| d);
            }
        }
        kept
    };
    let mut out = Index::default();
    let mut emptied = Vec::new();
    for f in index.files {
        if f.path.split('/').all(|p| p != "node_modules") && kept(&f.path) {
            out.unpacked_size += f.size;
            out.files.push(f);
            continue;
        }
        let file = dir.join(&f.path);
        let _ = make_writable(&file);
        fs::remove_file(&file).map_err(|e| Error::io(&e, format!("cannot remove {}", file.display())))?;
        emptied.push(f.path);
    }
    // No directory left empty either: macOS clones the whole directory, not the index.
    for path in emptied {
        let mut at = Path::new(&path).parent();
        while let Some(d) = at.filter(|d| !d.as_os_str().is_empty()) {
            if fs::remove_dir(dir.join(d)).is_err() {
                break;
            }
            at = d.parent();
        }
    }
    Ok(out)
}

/// The sha512 of a tree: each file in path order as `<path>\0<x or ->\<size>\n` and its bytes.
/// The same files give the same digest whatever archive or clone they came out of.
fn tree_digest(dir: &Path, index: &Index) -> Result<Vec<u8>> {
    let mut hash = jpm_crypto::hash::Hasher::new(jpm_crypto::hash::Alg::Sha512);
    let mut buf = vec![0; 64 * 1024];
    for f in &index.files {
        hash.update(format!("{}\0{}{}\n", f.path, if f.exec { 'x' } else { '-' }, f.size).as_bytes());
        let file = dir.join(&f.path);
        let mut input = fs::File::open(&file).map_err(|e| Error::io(&e, format!("cannot read {}", file.display())))?;
        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hash.update(&buf[..n]),
                Err(e) => return Err(Error::io(&e, format!("cannot read {}", file.display()))),
            }
        }
    }
    Ok(hash.finish().to_vec())
}

/// A small tarball is read whole first: its connection goes back to the pool at network speed,
/// not at the pace of its writes. The length is only a hint (a chunked or gzipped body can
/// run past it), so at most `STREAM_MIN + 1` bytes are held; the rest unpacks as it downloads,
/// as a big tarball does whole.
fn small_head(input: &mut impl Read, length: Option<u64>) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    if let Some(n) = length.filter(|n| *n < STREAM_MIN) {
        head.reserve(n as usize);
        input.take(STREAM_MIN + 1).read_to_end(&mut head)?;
    }
    Ok(head)
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

/// `extract`'s queue to its writer threads, and the threads.
type Writers<'scope> = (mpsc::SyncSender<Queued>, Vec<std::thread::ScopedJoinHandle<'scope, ()>>);

/// Everything queued written: the queue closed and its writers joined.
fn finish(writers: &mut Option<Writers<'_>>) {
    if let Some((send, handles)) = writers.take() {
        drop(send);
        for h in handles {
            let _ = h.join();
        }
    }
}

/// A writer thread of `extract`: queued files until the queue closes, the first error kept.
fn write_queued(recv: &Mutex<mpsc::Receiver<Queued>>, failed: &Mutex<Option<Error>>, budget: &Budget) {
    loop {
        let job = recv.lock().unwrap_or_else(PoisonError::into_inner).recv();
        let Ok((file, exec, data, taken)) = job else { return };
        let written = create(&file, exec).and_then(|mut out| out.write_all(&data));
        budget.give(taken);
        if let Err(e) = written {
            failed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_or_insert(Error::io(&e, format!("cannot write {}", file.display())));
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

/// A copy out of the store made writable, keeping whether it runs.
fn editable(file: &Path, exec: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }))
    }
    #[cfg(not(unix))]
    {
        let _ = exec;
        let mut perm = fs::metadata(file)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        fs::set_permissions(file, perm)
    }
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
        // Stored as `<path>.jpm` on Windows, for Defender; by its own name elsewhere.
        assert_eq!(index.suffixed, SUFFIX_FILES);
        let on_disk = store.pkg_dir(&integrity).unwrap().join("lib");
        assert_eq!(on_disk.join("x.js.jpm").is_file(), SUFFIX_FILES);
        assert_eq!(on_disk.join("x.js").is_file(), !SUFFIX_FILES);
        assert_eq!(Index::parse(&index.render()).as_ref(), Some(&*index), "the index says which");
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
    fn stores_a_windows_program_as_it_is() {
        let dir = scratch("exe");
        let file = dir.join("node.exe");
        fs::write(&file, b"MZ not an archive").unwrap();
        let store = Store::new(dir.join("store"), BTreeMap::new(), false, false);
        let integrity = sha512(b"MZ not an archive");
        let index = store.ensure(&Tarball::File(file), &integrity).unwrap();
        assert_eq!(index.files, [FileEntry { path: "node.exe".into(), size: 17, exec: true }]);
        assert_eq!(fs::read(store.file(&integrity, "node.exe").unwrap()).unwrap(), b"MZ not an archive");
        remove_tree(&dir);
    }

    #[test]
    fn reads_an_index_from_before_suffixes() {
        // A store written before `.jpm` names: its entries stay as they are, found by their names.
        let old = Index::parse("jpm-index 1 3\n- 3 lib/x.js\n").unwrap();
        assert!(!old.suffixed);
        assert_eq!(old.stored("lib/x.js"), "lib/x.js");
        let new = Index::parse("jpm-index 2 3\n- 3 lib/x.js\n").unwrap();
        assert!(new.suffixed);
        assert_eq!(new.stored("lib/x.js"), "lib/x.js.jpm");
    }

    #[test]
    fn holds_little_of_a_body_longer_than_its_length() {
        // A chunked or gzipped body can run past its Content-Length: only a small head is held.
        let mut long = io::repeat(0).take(4 * STREAM_MIN);
        assert_eq!(small_head(&mut long, Some(10)).unwrap().len() as u64, STREAM_MIN + 1);
        assert!(small_head(&mut io::repeat(0).take(10), None).unwrap().is_empty());
        // What was held unpacks with the rest.
        let big = vec![b'x'; 2 * STREAM_MIN as usize];
        let tar = build(&[("package/big.js", 0o644, &big), ("package/a.js", 0o644, b"a")]);
        let mut input = tar.as_slice();
        let head = small_head(&mut input, Some(100)).unwrap();
        assert_eq!(head.len() as u64, STREAM_MIN + 1);
        let dir = scratch("head");
        let index = extract(&mut head.as_slice().chain(input), &dir.join("x"), false).unwrap();
        assert_eq!(index.unpacked_size, big.len() as u64 + 1);
        remove_tree(&dir);
    }

    #[test]
    fn unpacks_a_large_tarball_on_writer_threads() {
        // Past INLINE_FILES the writes go to threads; a path repeated after that still ends as
        // the later entry has it, and one repeated before it too.
        let names: Vec<String> = (0..3 * INLINE_FILES).map(|i| format!("package/d{}/f{i}.js", i % 7)).collect();
        let mut entries: Vec<(&str, u32, &[u8])> = vec![("package/package.json", 0o644, br#"{"name":"a"}"#)];
        entries.extend(names.iter().map(|n| (n.as_str(), 0o644, n.as_bytes())));
        entries.push(("package/d0/f0.js", 0o755, b"early, again"));
        entries.push(("package/d2/f100.js", 0o644, b"late, again"));
        let dir = scratch("writers");
        let index = extract(&mut gzip(&build(&entries)).as_slice(), &dir.join("x"), false).unwrap();
        assert_eq!(index.files.len(), 1 + names.len());
        for f in &index.files {
            let want: &[u8] = match f.path.as_str() {
                "package.json" => br#"{"name":"a"}"#,
                "d0/f0.js" => b"early, again",
                "d2/f100.js" => b"late, again",
                p => names.iter().find(|n| n.ends_with(p)).unwrap().as_bytes(),
            };
            assert_eq!(fs::read(dir.join("x").join(&f.path)).unwrap(), want, "{}", f.path);
            assert_eq!(f.size, want.len() as u64);
        }
        assert!(index.files.iter().find(|f| f.path == "d0/f0.js").unwrap().exec);
        remove_tree(&dir);
    }

    #[test]
    fn unpacks_case_twins_as_the_disk_holds_them() {
        // Where the disk folds case they are one file, the later one; elsewhere two.
        let entries: Vec<(&str, u32, &[u8])> =
            vec![("package/Foo.js", 0o644, b"upper"), ("package/foo.js", 0o644, b"lower")];
        let dir = scratch("twins");
        let index = extract(&mut build(&entries).as_slice(), &dir.join("x"), false).unwrap();
        let paths: Vec<&str> = index.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, if crate::sys::FOLDS_CASE { vec!["foo.js"] } else { vec!["Foo.js", "foo.js"] });
        assert_eq!(fs::read(dir.join("x/foo.js")).unwrap(), b"lower");
        remove_tree(&dir);
    }

    #[test]
    fn copies_a_body_in_whole_buffers() {
        /// Every write's length, and the bytes.
        #[derive(Default)]
        struct Writes(Vec<usize>, Vec<u8>);
        impl Write for Writes {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.push(b.len());
                self.1.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let data: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let file = Path::new("x");
        let mut buf = [0u8; 1000];
        // A reader that hands out a few bytes at a time still fills each write.
        let mut out = Writes::default();
        let mut trickle = io::BufReader::with_capacity(7, data.as_slice());
        copy_body(&mut trickle, &mut out, &mut buf, file).unwrap();
        assert_eq!((out.0, out.1), (vec![1000, 1000, 500], data.clone()));
        let mut out = Writes::default();
        copy_body(&mut &data[..2000], &mut out, &mut buf, file).unwrap();
        assert_eq!(out.0, [1000, 1000]);
        let mut out = Writes::default();
        copy_body(&mut io::empty(), &mut out, &mut buf, file).unwrap();
        assert!(out.0.is_empty());
        // A body that fails is a corrupt tarball; a disk that fails is not.
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("bad deflate"))
            }
        }
        impl Write for Fails {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("disk full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(copy_body(&mut Fails, &mut Writes::default(), &mut buf, file).unwrap_err().code, "EBADTAR");
        assert_ne!(copy_body(&mut &data[..], &mut Fails, &mut buf, file).unwrap_err().code, "EBADTAR");
    }

    #[test]
    fn index_refuses_escapes() {
        assert!(Index::parse("jpm-index 1 1\n- 1 ../x\n").is_none());
        assert!(Index::parse("jpm-index 1 1\n- 1 a/b\n").is_some());
        assert!(Index::parse("garbage").is_none());
    }
}
