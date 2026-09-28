//! Materialize `node_modules`. One `.jpm` entry per subgraph key holds a package's files,
//! linked out of the store; everything else is a relative symlink (a junction on Windows):
//!
//! ```text
//! node_modules/foo -> .jpm/foo@1.0.0-<hash>/node_modules/foo
//! node_modules/.jpm/foo@1.0.0-<hash>/node_modules/foo/        the files
//! node_modules/.jpm/foo@1.0.0-<hash>/node_modules/bar -> ../../bar@2.0.0-<hash>/node_modules/bar
//! ```
//!
//! A package can import only what it declared, and entries are built in parallel under temp
//! names and renamed in whole, so a reader never sees half of one.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::error::{Error, Result};
use crate::graph::{Package, Resolution};
use crate::state::{self, RootLinks, Stamp, Stamps, State, Summary};
use crate::store::{Index, Store, remove_tree};
use crate::util::{relative, temp_suffix};
use crate::{pool, sys};

const WIN: bool = cfg!(windows);
/// How long an abandoned `.tmp-*` must sit untouched before it is believed abandoned.
const TMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

pub struct Inputs {
    pub hash: String,
    pub summary: Summary,
    pub stamps: Option<Stamps>,
}

pub struct Options<'a> {
    pub dir: &'a Path,
    pub store: &'a Store,
    pub production: bool,
    pub verify: bool,
    /// `state_hash` of this resolution with these flags.
    pub hash: String,
    /// Each package's store entry name, by key.
    pub keys: HashMap<String, String>,
    /// What the state records for the no-op check: only when the tree is a function of the
    /// lockfile and root manifest alone (no workspaces).
    pub inputs: Option<Inputs>,
    pub tarballs: Option<BTreeMap<String, Option<Stamp>>>,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub entries: usize,
    pub linked: usize,
    pub copied: usize,
    pub cloned: usize,
    pub reused: usize,
    pub repaired: usize,
    pub bins: usize,
    pub removed: usize,
}

impl Stats {
    pub fn to_object(&self) -> crate::json::Object {
        let mut o = crate::json::Object::new();
        for (k, v) in [
            ("entries", self.entries),
            ("linked", self.linked),
            ("copied", self.copied),
            ("cloned", self.cloned),
            ("reused", self.reused),
            ("repaired", self.repaired),
            ("bins", self.bins),
            ("removed", self.removed),
        ] {
            o.insert(k, v.into());
        }
        o
    }
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub stats: Stats,
    /// Optional packages the store did not hold.
    pub dropped: Vec<String>,
    pub up_to_date: bool,
}

#[derive(Default)]
struct Counts {
    entries: AtomicUsize,
    linked: AtomicUsize,
    copied: AtomicUsize,
    cloned: AtomicUsize,
    reused: AtomicUsize,
    repaired: AtomicUsize,
    bins: AtomicUsize,
    removed: AtomicUsize,
}

impl Counts {
    fn add(n: &AtomicUsize, by: usize) {
        n.fetch_add(by, Ordering::Relaxed);
    }

    fn stats(&self) -> Stats {
        let g = |n: &AtomicUsize| n.load(Ordering::Relaxed);
        Stats {
            entries: g(&self.entries),
            linked: g(&self.linked),
            copied: g(&self.copied),
            cloned: g(&self.cloned),
            reused: g(&self.reused),
            repaired: g(&self.repaired),
            bins: g(&self.bins),
            removed: g(&self.removed),
        }
    }
}

struct Entry<'a> {
    pkg: &'a Package,
    key: String,
    /// `<key>/node_modules/<name>`, spelled with the platform's separator.
    home: String,
}

/// The root, or a workspace: a `node_modules` of its own holding what it declared.
struct Top {
    nm: PathBuf,
    dependencies: BTreeMap<String, String>,
}

fn tops_of(dir: &Path, res: &Resolution) -> Vec<Top> {
    let mut tops = vec![Top { nm: dir.join("node_modules"), dependencies: res.root.dependencies.clone() }];
    for p in res.packages.values() {
        if let Some(path) = &p.local {
            tops.push(Top { nm: dir.join(path).join("node_modules"), dependencies: p.all_deps() });
        }
    }
    tops
}

fn fail(message: impl Into<String>) -> Error {
    Error::new("ELINK", message)
}

fn sep(path: &str) -> String {
    if WIN { path.replace('/', "\\") } else { path.to_string() }
}

struct Linker<'a> {
    opts: &'a Options<'a>,
    res: &'a Resolution,
    entries_dir: PathBuf,
    wanted: HashMap<String, Entry<'a>>,
    counts: Counts,
    copy_only: AtomicBool,
    root_links: Mutex<RootLinks>,
}

pub fn link(res: &Resolution, opts: &Options) -> Result<Outcome> {
    let tops = tops_of(opts.dir, res);
    let entries_dir = opts.dir.join("node_modules").join(".jpm");
    let previous = state::read(opts.dir);
    let state_of = |entries: Vec<String>, complete: bool, root: RootLinks| {
        let single = tops.len() == 1;
        let inputs = opts.inputs.as_ref().filter(|_| single);
        State {
            version: 1,
            hash: opts.hash.clone(),
            entries,
            complete,
            store: opts.store.dir.display().to_string(),
            production: opts.production,
            tarballs: opts.tarballs.clone(),
            inputs: inputs.map(|i| i.hash.clone()),
            summary: inputs.map(|i| i.summary.clone()),
            root: inputs.map(|_| root),
            stamps: inputs.and_then(|i| i.stamps.clone()),
        }
    };
    if let Some(prev) = previous.as_ref().filter(|s| !opts.verify && s.hash == opts.hash && s.complete)
        && let Some(root) = standing(opts.dir, &entries_dir, &tops, res, prev, opts.production)
    {
        // The same tree from other inputs: the state learns them, so the next install is short.
        let learned = opts.inputs.as_ref().is_some_and(|i| prev.inputs.as_ref() != Some(&i.hash)) && tops.len() == 1;
        if learned || prev.tarballs != opts.tarballs {
            state::write(opts.dir, &state_of(prev.entries.clone(), true, root))?;
        }
        let stats = Stats { reused: prev.entries.len(), ..Stats::default() };
        return Ok(Outcome { stats, dropped: Vec::new(), up_to_date: true });
    }
    state::clear(opts.dir);

    let keys = &opts.keys;
    let mut wanted = HashMap::new();
    let mut dropped = Vec::new();
    for (id, pkg) in &res.packages {
        if pkg.local.is_some() || (opts.production && pkg.dev) {
            continue;
        }
        let Some(key) = keys.get(id) else { continue };
        if !opts.store.has(&pkg.integrity) {
            if !pkg.optional {
                return Err(fail(format!("{id} is not in the store at {}", opts.store.dir.display())));
            }
            dropped.push(id.clone());
            continue;
        }
        let home = sep(&format!("{key}/node_modules/{}", pkg.name));
        wanted.insert(id.clone(), Entry { pkg, key: key.clone(), home });
    }
    fs::create_dir_all(&entries_dir).map_err(|e| Error::io(&e, format!("cannot create {}", entries_dir.display())))?;
    let present: HashSet<String> = fs::read_dir(&entries_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    let linker = Linker {
        opts,
        res,
        entries_dir: entries_dir.clone(),
        wanted,
        counts: Counts::default(),
        copy_only: AtomicBool::new(false),
        root_links: Mutex::default(),
    };
    let failures: Mutex<Vec<Error>> = Mutex::default();
    let ids: Vec<&String> = linker.wanted.keys().collect();
    pool::run(pool::disk_threads() * 2, ids, |id, _| {
        let entry = &linker.wanted[id];
        if let Err(e) = linker.materialize(entry, present.contains(&entry.key)) {
            failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(e);
        }
    });
    if let Some(e) = failures.into_inner().unwrap_or_default().into_iter().next() {
        return Err(e);
    }
    let real_root =
        fs::canonicalize(opts.dir).map_err(|e| Error::io(&e, format!("cannot read {}", opts.dir.display())))?;
    for (i, top) in tops.iter().enumerate() {
        if let Some(parent) = top.nm.parent() {
            inside(parent, &real_root)?;
        }
        inside(&top.nm, &real_root)?;
        linker.link_top(top, i == 0)?;
    }
    linker.sweep_temp();
    dropped.sort();
    let mut entries: Vec<String> = linker.wanted.values().map(|e| e.key.clone()).collect();
    entries.sort();
    entries.dedup();
    let root = linker.root_links.lock().map(|r| r.clone()).unwrap_or_default();
    state::write(opts.dir, &state_of(entries, dropped.is_empty(), root))?;
    Ok(Outcome { stats: linker.counts.stats(), dropped, up_to_date: false })
}

impl Linker<'_> {
    /// A dep link's target: every entry sits at the same depth, so from `<entry>/node_modules`
    /// it is always `../../<home>`, one `..` more from under a scope directory.
    fn dep_target(&self, name: &str, dep: &Entry) -> String {
        let up = format!("..{MAIN_SEPARATOR}");
        format!("{up}{up}{}{}", if name.contains('/') { up.as_str() } else { "" }, dep.home)
    }

    /// An entry's deps that are linked. A self-dep would collide with its own directory.
    fn deps_of(&self, pkg: &Package) -> Result<Vec<(String, &Entry<'_>)>> {
        let mut out = Vec::new();
        for (name, version) in pkg.all_deps() {
            let id = format!("{name}@{version}");
            // Only a top reaches a workspace, so no entry links out of `.jpm`.
            if self.res.packages.get(&id).is_some_and(|p| p.local.is_some()) {
                return Err(fail(format!("{}@{} depends on the workspace {name}", pkg.name, pkg.version)));
            }
            if let Some(dep) = self.wanted.get(&id).filter(|_| name != pkg.name) {
                out.push((name, dep));
            }
        }
        Ok(out)
    }

    fn index(&self, entry: &Entry) -> Result<std::sync::Arc<Index>> {
        self.opts.store.index(&entry.pkg.integrity).ok_or_else(|| {
            fail(format!("{} is not in the store at {}", entry.pkg.key(), self.opts.store.dir.display()))
        })
    }

    fn materialize(&self, entry: &Entry, present: bool) -> Result<()> {
        let fin = self.entries_dir.join(&entry.key);
        if present {
            if self.intact(entry)? {
                Counts::add(&self.counts.reused, 1);
                // Touched, so a prune reads "still wanted" off its mtime.
                if let Ok(f) = fs::File::open(&fin) {
                    let _ = f.set_modified(std::time::SystemTime::now());
                }
                let nm = fin.join("node_modules");
                let deps = self.deps_of(entry.pkg)?;
                let names: HashSet<String> = deps.iter().map(|(n, _)| n.clone()).collect();
                self.sweep(&nm, &names, "");
                let bins: HashSet<String> = bins_of(&deps).into_keys().collect();
                self.sweep(&nm.join(".bin"), &bins, "");
                return Ok(());
            }
            let temp = self.temp_name();
            if let Err(e) = self.build(entry, &temp) {
                remove_tree(&temp);
                return Err(e);
            }
            let retired = self.temp_name();
            let moved = fs::rename(&fin, &retired).is_ok();
            if let Err(e) = fs::rename(&temp, &fin) {
                remove_tree(&temp);
                if fin.exists() {
                    remove_tree(&retired);
                    Counts::add(&self.counts.reused, 1);
                    return Ok(());
                }
                if moved {
                    let _ = fs::rename(&retired, &fin);
                }
                return Err(Error::io(&e, format!("cannot place {}", fin.display())).with_code("ELINK"));
            }
            remove_tree(&retired);
            Counts::add(&self.counts.repaired, 1);
            return Ok(());
        }
        let temp = self.temp_name();
        let built = self.build(entry, &temp).and_then(|()| {
            fs::rename(&temp, &fin)
                .map_err(|e| Error::io(&e, format!("cannot place {}", fin.display())).with_code("ELINK"))
        });
        match built {
            Ok(()) => Counts::add(&self.counts.entries, 1),
            Err(e) => {
                remove_tree(&temp);
                // Another install may have won the race; its entry is as good as ours.
                if !fin.is_dir() {
                    return Err(e);
                }
                Counts::add(&self.counts.reused, 1);
            }
        }
        Ok(())
    }

    fn temp_name(&self) -> PathBuf {
        self.entries_dir.join(format!(".tmp-{}", temp_suffix()))
    }

    /// Every file at its recorded size, every dep link and bin pointing where it should.
    fn intact(&self, entry: &Entry) -> Result<bool> {
        let nm = self.entries_dir.join(&entry.key).join("node_modules");
        let pkg_dir = nm.join(&entry.pkg.name);
        let index = self.index(entry)?;
        if !index.files.iter().all(|f| fs::metadata(pkg_dir.join(&f.path)).is_ok_and(|m| m.len() == f.size)) {
            return Ok(false);
        }
        let deps = self.deps_of(entry.pkg)?;
        if !deps
            .iter()
            .all(|(name, dep)| sys::read_link(&nm.join(name)).as_deref() == Some(self.dep_target(name, dep).as_str()))
        {
            return Ok(false);
        }
        let bin_dir = nm.join(".bin");
        for (bin, (dep, target)) in bins_of(&deps) {
            if WIN {
                let shims = self.shims(&bin_dir, &nm.join(&dep).join(&target), dep_pkg(&deps, &dep), &target)?;
                if !shims.iter().all(|(sfx, text)| {
                    fs::read_to_string(bin_dir.join(format!("{bin}{sfx}"))).ok().as_deref() == Some(text)
                }) {
                    return Ok(false);
                }
            } else if sys::read_link(&bin_dir.join(&bin)).as_deref() != Some(bin_link(&dep, &target).as_str()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn build(&self, entry: &Entry, temp: &Path) -> Result<()> {
        let pkg = entry.pkg;
        let nm = temp.join("node_modules");
        let pkg_dir = nm.join(&pkg.name);
        let parent = pkg_dir.parent().unwrap_or(&nm);
        fs::create_dir_all(parent)
            .map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())).with_code("ELINK"))?;
        let src = self.opts.store.pkg_dir(&pkg.integrity)?;
        let cloned = sys::clone_dir(&src, &pkg_dir)
            .map_err(|e| Error::io(&e, format!("cannot copy {}", src.display())).with_code("ELINK"))?;
        if cloned {
            Counts::add(&self.counts.cloned, 1);
        } else {
            self.place_files(&*self.index(entry)?, &src, &pkg_dir)?;
        }
        let deps = self.deps_of(pkg)?;
        let own_scope = pkg.name.split_once('/').map(|(s, _)| s);
        let mut scopes = HashSet::new();
        for (name, dep) in &deps {
            if let Some((scope, _)) = name.split_once('/')
                && Some(scope) != own_scope
                && scopes.insert(scope)
            {
                fs::create_dir_all(nm.join(scope))
                    .map_err(|e| Error::io(&e, "cannot create a scope directory").with_code("ELINK"))?;
            }
            let at = nm.join(name);
            sys::symlink_dir(&self.dep_target(name, dep), &at)
                .map_err(|e| Error::io(&e, format!("cannot link {}", at.display())).with_code("ELINK"))?;
        }
        let bins = bins_of(&deps);
        if !bins.is_empty() {
            let bin_dir = nm.join(".bin");
            fs::create_dir_all(&bin_dir).map_err(|e| Error::io(&e, "cannot create .bin").with_code("ELINK"))?;
            let final_nm = self.entries_dir.join(&entry.key).join("node_modules");
            for (bin, (dep, target)) in bins {
                if WIN {
                    let file = final_nm.join(&dep).join(&target);
                    for (sfx, text) in self.shims(&bin_dir, &file, dep_pkg(&deps, &dep), &target)? {
                        let at = bin_dir.join(format!("{bin}{sfx}"));
                        fs::write(&at, text)
                            .map_err(|e| Error::io(&e, format!("cannot write {}", at.display())).with_code("ELINK"))?;
                    }
                } else {
                    let at = bin_dir.join(&bin);
                    symlink_file(&bin_link(&dep, &target), &at)
                        .map_err(|e| Error::io(&e, format!("cannot link {}", at.display())).with_code("ELINK"))?;
                }
                Counts::add(&self.counts.bins, 1);
            }
        }
        Ok(())
    }

    /// Directories first, then one hardlink per file; a filesystem that cannot share inodes with
    /// the store gets copies from the first refusal on.
    fn place_files(&self, index: &Index, src: &Path, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest)
            .map_err(|e| Error::io(&e, format!("cannot create {}", dest.display())).with_code("ELINK"))?;
        let mut made: HashSet<&str> = HashSet::new();
        for f in &index.files {
            if let Some((dir, _)) = f.path.rsplit_once('/')
                && made.insert(dir)
            {
                let at = dest.join(dir);
                fs::create_dir_all(&at)
                    .map_err(|e| Error::io(&e, format!("cannot create {}", at.display())).with_code("ELINK"))?;
            }
        }
        for f in &index.files {
            let (from, to) = (src.join(&f.path), dest.join(&f.path));
            if !self.copy_only.load(Ordering::Relaxed) {
                match fs::hard_link(&from, &to) {
                    Ok(()) => {
                        Counts::add(&self.counts.linked, 1);
                        continue;
                    }
                    // Two names one file on a case-insensitive disk: already there.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) if e.kind() == io::ErrorKind::TooManyLinks => {}
                    Err(e) if cannot_link(&e) => self.copy_only.store(true, Ordering::Relaxed),
                    Err(e) => return Err(Error::io(&e, format!("cannot link {}", to.display())).with_code("ELINK")),
                }
            }
            match fs::copy(&from, &to) {
                Ok(_) => Counts::add(&self.counts.copied, 1),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::io(&e, format!("cannot copy {}", to.display())).with_code("ELINK")),
            }
        }
        Ok(())
    }

    /// Windows shims for a bin whose file, once linked, is `file`; its `#!` read from the store.
    fn shims(
        &self,
        bin_dir: &Path,
        file: &Path,
        pkg: Option<&Package>,
        target: &str,
    ) -> Result<Vec<(&'static str, String)>> {
        let head = match pkg {
            Some(p) if p.local.is_none() => {
                self.opts.store.file(&p.integrity, target).ok().and_then(|f| crate::shim::read_head(&f))
            }
            Some(p) => crate::shim::read_head(&self.opts.dir.join(p.local.as_deref().unwrap_or("")).join(target)),
            None => None,
        };
        crate::shim::shims_of(&relative(bin_dir, file).to_string_lossy(), head.as_deref())
    }

    /// Only direct deps get a top-level name. A registry dep links into `.jpm`; a workspace dep
    /// links to the workspace's own directory.
    fn link_top(&self, top: &Top, is_root: bool) -> Result<()> {
        let nm = &top.nm;
        fs::create_dir_all(nm)
            .map_err(|e| Error::io(&e, format!("cannot create {}", nm.display())).with_code("ELINK"))?;
        let real_root = fs::canonicalize(self.opts.dir).unwrap_or_else(|_| self.opts.dir.to_path_buf());
        let mut direct: Vec<(String, &Package)> = Vec::new();
        let mut links = BTreeMap::new();
        for (name, version) in &top.dependencies {
            let id = format!("{name}@{version}");
            let Some(pkg) = self.res.packages.get(&id) else { continue };
            let real = match (&pkg.local, self.wanted.get(&id)) {
                (Some(path), _) => self.opts.dir.join(path),
                (None, Some(entry)) => self.entries_dir.join(&entry.home),
                _ => continue, // dropped, or dev under production
            };
            let at = nm.join(name);
            let parent = at.parent().unwrap_or(nm);
            if name.contains('/') {
                inside(parent, &real_root)?;
                fs::create_dir_all(parent)
                    .map_err(|e| Error::io(&e, "cannot create a scope directory").with_code("ELINK"))?;
            }
            let target = relative(parent, &real).to_string_lossy().into_owned();
            replace_link(&at, &target, nm, true)?;
            links.insert(name.clone(), target);
            direct.push((name.clone(), pkg));
        }
        let bin_dir = nm.join(".bin");
        let mut bins: BTreeMap<String, (String, String, &Package)> = BTreeMap::new();
        for (name, pkg) in &direct {
            for (bin, target) in &pkg.bin {
                bins.insert(bin.clone(), (name.clone(), target.clone(), pkg));
            }
        }
        if !bins.is_empty() {
            fs::create_dir_all(&bin_dir).map_err(|e| Error::io(&e, "cannot create .bin").with_code("ELINK"))?;
        }
        for (bin, (name, target, pkg)) in &bins {
            let file = nm.join(name).join(target);
            if WIN {
                for (sfx, text) in self.shims(&bin_dir, &file, Some(pkg), target)? {
                    let at = bin_dir.join(format!("{bin}{sfx}"));
                    if fs::read_to_string(&at).ok().as_deref() != Some(text.as_str()) {
                        crate::util::write_atomic(&at, text.as_bytes())?;
                    }
                }
            } else {
                let link = relative(&bin_dir, &file).to_string_lossy().into_owned();
                replace_link(&bin_dir.join(bin), &link, &bin_dir, false)?;
            }
            Counts::add(&self.counts.bins, 1);
        }
        if is_root && let Ok(mut r) = self.root_links.lock() {
            *r = RootLinks { links, bins: bins.keys().cloned().collect() };
        }
        let names: HashSet<String> = direct.into_iter().map(|(n, _)| n).collect();
        self.sweep(nm, &names, "");
        self.sweep(&bin_dir, &bins.keys().cloned().collect(), "");
        Ok(())
    }

    /// Converge one `node_modules` (or `.bin`) to what was just linked: every link `keep` does
    /// not name goes. Only links: a real directory is someone else's, and dot names are not ours.
    fn sweep(&self, dir: &Path, keep: &HashSet<String>, scope: &str) {
        let shims = WIN && dir.file_name().is_some_and(|n| n == ".bin");
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(kind) = e.file_type() else { continue };
            if scope.is_empty() && name.starts_with('.') {
                continue;
            }
            if scope.is_empty() && name.starts_with('@') && kind.is_dir() && !kind.is_symlink() {
                self.sweep(&e.path(), keep, &format!("{name}/"));
                let _ = fs::remove_dir(e.path()); // fails while it still holds a package
                continue;
            }
            let full = format!("{scope}{name}");
            let bin = if shims {
                let lower = name.to_ascii_lowercase();
                if lower.ends_with(".cmd") || lower.ends_with(".ps1") {
                    name[..name.len() - 4].to_string()
                } else {
                    name.clone()
                }
            } else {
                full.clone()
            };
            if if shims { kind.is_dir() } else { !kind.is_symlink() } {
                continue;
            }
            if keep.contains(&bin) || keep.contains(&full) {
                continue;
            }
            if remove_link(&e.path()).is_ok() && bin == full {
                Counts::add(&self.counts.removed, 1);
            }
        }
    }

    /// An install killed mid-entry leaves a `.tmp-*`: it goes once its pid is gone and it is an
    /// hour old, so an install still filling it is never broken.
    fn sweep_temp(&self) {
        for e in fs::read_dir(&self.entries_dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(rest) = name.strip_prefix(".tmp-") else { continue };
            let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else { continue };
            if pid == 0 || sys::alive(pid) {
                continue;
            }
            let old = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > TMP_MAX_AGE);
            if old {
                remove_tree(&e.path());
                Counts::add(&self.counts.removed, 1);
            }
        }
    }
}

fn dep_pkg<'a>(deps: &'a [(String, &Entry)], name: &str) -> Option<&'a Package> {
    deps.iter().find(|(n, _)| n == name).map(|(_, e)| e.pkg)
}

/// Bin name -> (dep name, target). Name collisions are last-wins, as npm's are.
fn bins_of(deps: &[(String, &Entry)]) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for (name, dep) in deps {
        for (bin, target) in &dep.pkg.bin {
            out.insert(bin.clone(), (name.clone(), target.clone()));
        }
    }
    out
}

/// A bin link's text from an entry's `.bin`: `../<name>/<target>`.
fn bin_link(name: &str, target: &str) -> String {
    sep(&format!("../{name}/{}", target.trim_end_matches('/')))
}

fn cannot_link(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::CrossesDevices | io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported)
        || e.raw_os_error().is_some_and(|c| c == 1 /* EPERM */ || c == 95 /* EOPNOTSUPP */ || c == 38 /* ENOSYS */)
}

#[cfg(unix)]
fn symlink_file(target: &str, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(not(unix))]
fn symlink_file(target: &str, at: &Path) -> io::Result<()> {
    sys::symlink_dir(target, at)
}

/// Remove a link (or a junction) without following it; a real directory there goes whole.
fn remove_link(at: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(at)?;
    if meta.file_type().is_symlink() {
        fs::remove_file(at).or_else(|_| fs::remove_dir(at))
    } else if meta.is_dir() {
        fs::remove_dir_all(at)
    } else {
        fs::remove_file(at)
    }
}

/// Leaves a link that is already right alone; anything else there is replaced.
fn replace_link(at: &Path, target: &str, within: &Path, dir: bool) -> Result<()> {
    if !at.starts_with(within) || at.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(fail(format!("refusing to link outside {}: {}", within.display(), at.display())));
    }
    for attempt in 0..4 {
        if sys::read_link(at).as_deref() == Some(target) {
            return Ok(());
        }
        let _ = remove_link(at);
        let made = if dir { sys::symlink_dir(target, at) } else { symlink_file(target, at) };
        match made {
            Ok(()) => return Ok(()),
            // Taken between the removal and the link: a concurrent install of this tree.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 3 => {}
            Err(e) => {
                return Err(Error::io(&e, format!("cannot symlink {} -> {target}", at.display())).with_code("ELINK"));
            }
        }
    }
    Ok(())
}

/// A top whose directory, `node_modules` or scope directory is a symlink out of the project,
/// as a hostile checkout can arrange, would have the sweep delete there.
fn inside(path: &Path, real_root: &Path) -> Result<()> {
    match fs::canonicalize(path) {
        Ok(real) if real.starts_with(real_root) => Ok(()),
        Ok(real) => Err(fail(format!(
            "refusing to link through {}: it leads outside the project, to {}",
            path.display(),
            real.display()
        ))),
        Err(_) if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
            Err(fail(format!("refusing to link through {}: a symlink that leads nowhere", path.display())))
        }
        Err(_) => Ok(()),
    }
}

/// Is the tree a matching state describes still on disk? Its shape only: every direct dep
/// linked, every bin placed, every recorded entry a directory.
fn standing(
    dir: &Path,
    entries_dir: &Path,
    tops: &[Top],
    res: &Resolution,
    st: &State,
    production: bool,
) -> Option<RootLinks> {
    let mut root = None;
    for top in tops {
        let found = standing_top(dir, top, res, production)?;
        root.get_or_insert(found);
    }
    let present: HashSet<String> = fs::read_dir(entries_dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    st.entries.iter().all(|k| present.contains(k)).then_some(root?)
}

fn standing_top(dir: &Path, top: &Top, res: &Resolution, production: bool) -> Option<RootLinks> {
    let mut read = RootLinks::default();
    let mut bins = Vec::new();
    for (name, version) in &top.dependencies {
        let pkg = res.packages.get(&format!("{name}@{version}"));
        if production && pkg.is_some_and(|p| p.dev) {
            continue;
        }
        let at = top.nm.join(name);
        let to = sys::read_link(&at)?;
        match pkg.and_then(|p| p.local.as_ref()) {
            Some(path) => {
                if Path::new(&to) != relative(at.parent()?, &dir.join(path)) {
                    return None;
                }
            }
            None => {
                let store = relative(at.parent()?, &dir.join("node_modules").join(".jpm"));
                let tail = Path::new("node_modules").join(name);
                if !Path::new(&to).starts_with(&store) || !Path::new(&to).ends_with(&tail) {
                    return None;
                }
            }
        }
        read.links.insert(name.clone(), to);
        bins.extend(pkg.iter().flat_map(|p| p.bin.keys().cloned()));
    }
    if !bins.is_empty() {
        let placed: HashSet<String> = fs::read_dir(top.nm.join(".bin"))
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !bins.iter().all(|b| placed.contains(&if WIN { format!("{b}.cmd") } else { b.clone() })) {
            return None;
        }
    }
    bins.sort();
    bins.dedup();
    read.bins = bins;
    Some(read)
}

/// The no-op check, read off the state alone: every recorded root link pointing where it was
/// made to, every bin placed, every entry a directory. No graph needed.
pub fn tree_standing(dir: &Path, st: &State) -> bool {
    let nm = dir.join("node_modules");
    let Some(root) = st.root.as_ref().filter(|_| st.complete) else { return false };
    if !root.links.iter().all(|(name, target)| sys::read_link(&nm.join(name)).as_deref() == Some(target.as_str())) {
        return false;
    }
    if !root.bins.is_empty() {
        let Ok(dir) = fs::read_dir(nm.join(".bin")) else { return false };
        let placed: HashSet<String> = dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        if !root.bins.iter().all(|b| placed.contains(&if WIN { format!("{b}.cmd") } else { b.clone() })) {
            return false;
        }
    }
    let Ok(entries) = fs::read_dir(nm.join(".jpm")) else { return false };
    let present: HashSet<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    st.entries.iter().all(|k| present.contains(k))
}
