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
//!
//! With the global virtual store, entries are built once in `<store>/v1/links` and the project
//! links its direct deps straight to them: a warm install makes only those links.

//!
//! `node_modules/.jpm/node_modules` is the hidden hoist: a link to one entry of every package,
//! which Node reaches from any entry in the project after the entry's own `node_modules`. A
//! package that imports what it did not declare (`@nuxt/vite-builder` imports `unplugin`) still
//! finds it, as under pnpm's `.pnpm/node_modules`. Entries in the global store resolve from the
//! store and cannot see it: for them, `.jpm/hoist.cjs` beside it lets `jpm run` and `jpm exec`
//! point Node at it (see `run::hoist_env`).
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::graph::{Package, Resolution};
use crate::state::{self, RootLinks, Stamp, Stamps, State, Summary};
use crate::store::{FileEntry, Index, Store, remove_tree};
use crate::util::{relative, temp_suffix};
use crate::{pool, sys};

const WIN: bool = cfg!(windows);
/// The hidden hoist, under `.jpm`: no entry key is spelled like it.
pub const HOIST: &str = "node_modules";
/// Under `.jpm` when entries are in the global store: Node's fallback to the hoist for `import`.
pub const HOOK: &str = "hoist.cjs";
/// How long an abandoned `.tmp-*` must sit untouched before it is believed abandoned.
const TMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);
/// A global entry's file holding the whole digest of the subgraph it was built for: its name
/// holds only the start of it.
const DIGEST_FILE: &str = ".subgraph";
/// The digest's characters a global entry's name starts with; more where another subgraph
/// already holds the shorter name.
const DIGEST_SHOWN: usize = 8;
/// Files per job when one package's files are linked on several threads.
const PLACE_CHUNK: usize = 256;

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
    /// Each package's whole subgraph digest (`keys::full_digests`), by key, for the global store:
    /// its entries are named by the start of it (see `name_shared`).
    pub digests: HashMap<String, String>,
    /// The global virtual store: entries are built once there, for every project to link to.
    /// `None` builds every entry in the project's `.jpm`.
    pub global: Option<PathBuf>,
    /// Packages whose install scripts will run: their entries are copies, not links into the
    /// store the scripts could write through, and stay in the project, as do entries that
    /// depend on them.
    pub built: HashSet<String>,
    /// What the state records for the no-op check.
    pub inputs: Option<Inputs>,
    pub tarballs: Option<BTreeMap<String, Option<Stamp>>>,
    /// The project's patches, found by their hash.
    pub patches: &'a [crate::patch::Patch],
    /// Puts a package in the store, waiting for its download if one is under way. With it,
    /// entries are built as their packages arrive rather than after the last one. With the
    /// global store, optional packages must be settled before, as whether they arrived decides
    /// which entries may be shared; in the project layout each is settled as it is first needed,
    /// and one that fails is dropped as before. Without it, every package must be in the store.
    pub fetch: Option<&'a Fetch<'a>>,
}

/// See `Options::fetch`.
pub type Fetch<'a> = dyn Fn(&Package) -> Result<()> + Sync + 'a;

/// Downloads under way: which have finished (or failed), and how many workers still run.
#[derive(Default)]
pub struct Arrivals {
    state: Mutex<(HashSet<String>, usize)>,
    changed: Condvar,
}

impl Arrivals {
    pub fn start_workers(&self, n: usize) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 += n;
    }

    /// A download is done with, stored or not.
    pub fn arrive(&self, integrity: &str) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0.insert(integrity.to_string());
        self.changed.notify_all();
    }

    pub fn worker_done(&self) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.1 = s.1.saturating_sub(1);
        self.changed.notify_all();
    }

    /// Whether `wait` would wait: a worker is left, and `integrity` is not done with yet.
    pub fn pending(&self, integrity: &str) -> bool {
        let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.1 > 0 && !s.0.contains(integrity)
    }

    /// Until `integrity` is done with, or no worker is left to bring it.
    pub fn wait(&self, integrity: &str) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while s.1 > 0 && !s.0.contains(integrity) {
            s = self.changed.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
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

/// What an entry links a dependency to: another entry, or the directory of a workspace (or the
/// root) that a peer of the entry resolved to, as pnpm links nuxt's `@nuxt/schema` peer.
#[derive(Clone, Copy)]
enum Dep<'a> {
    Entry(&'a Entry<'a>),
    Dir(&'a Package),
}

impl Dep<'_> {
    fn pkg(&self) -> &Package {
        match self {
            Dep::Entry(e) => e.pkg,
            Dep::Dir(p) => p,
        }
    }
}

struct Entry<'a> {
    pkg: &'a Package,
    key: String,
    /// A global entry's whole subgraph digest, which its name may show only the start of.
    digest: Option<String>,
    /// `<key>/node_modules/<name>`, spelled with the platform's separator.
    home: String,
    /// Built in the global store, not the project.
    shared: bool,
    /// Copied, for install scripts to run in.
    build: bool,
}

/// The root, or a workspace: a `node_modules` of its own holding what it declared.
struct Top {
    /// The workspace's path; empty for the root.
    path: String,
    nm: PathBuf,
    dependencies: BTreeMap<String, String>,
}

fn tops_of(dir: &Path, res: &Resolution) -> Vec<Top> {
    let root = Top { path: String::new(), nm: dir.join("node_modules"), dependencies: res.root.dependencies.clone() };
    let mut tops = vec![root];
    for p in res.packages.values() {
        // The root listed as a workspace is already the first top; a linked directory is none.
        if let Some(path) = p.local.as_ref().filter(|path| *path != crate::project::ROOT_PATH && !p.linked) {
            tops.push(Top { path: path.clone(), nm: dir.join(path).join("node_modules"), dependencies: p.all_deps() });
        }
    }
    tops
}

fn fail(message: impl Into<String>) -> Error {
    Error::new("ELINK", message)
}

/// Where the disk folds case, `JSONStream` and `jsonstream` are one directory entry: the one
/// linked last would stand for both.
fn no_case_twins<'a>(names: impl Iterator<Item = &'a String>, at: &Path) -> Result<()> {
    let mut seen = HashMap::new();
    for name in names.filter(|_| sys::FOLDS_CASE) {
        if let Some(other) = seen.insert(name.to_lowercase(), name) {
            return Err(fail(format!(
                "{other} and {name} differ only in case, and {} can hold only one of them",
                at.display()
            )));
        }
    }
    Ok(())
}

fn sep(path: &str) -> String {
    if WIN { path.replace('/', "\\") } else { path.to_string() }
}

struct Linker<'a> {
    opts: &'a Options<'a>,
    res: &'a Resolution,
    entries_dir: PathBuf,
    /// The project, symlinks resolved: nothing is written or swept outside it.
    real_root: PathBuf,
    wanted: HashMap<String, Entry<'a>>,
    counts: Counts,
    copy_only: AtomicBool,
    /// Optional packages settled while linking (project layout): whether each arrived.
    settled: Mutex<HashMap<String, bool>>,
    /// The project's `node_modules` was made by this run.
    fresh_nm: bool,
}

pub fn link(res: &Resolution, opts: &Options) -> Result<Outcome> {
    let tops = tops_of(opts.dir, res);
    let entries_dir = opts.dir.join("node_modules").join(".jpm");
    // A cloned repo can hold `node_modules` or `.jpm` as a symlink to anywhere: entries would be
    // built there, and stale ones swept away.
    let real_root =
        fs::canonicalize(opts.dir).map_err(|e| Error::io(&e, format!("cannot read {}", opts.dir.display())))?;
    inside(&opts.dir.join("node_modules"), &real_root)?;
    inside(&entries_dir, &real_root)?;
    let previous = state::read(opts.dir);
    // `links`: each top's, in the order of `tops`.
    let state_of = |entries: Vec<String>, shared: Vec<String>, complete: bool, links: Vec<RootLinks>| {
        let inputs = opts.inputs.as_ref();
        let mut links = links.into_iter();
        let root = links.next().unwrap_or_default();
        State {
            version: 1,
            hash: opts.hash.clone(),
            entries,
            shared,
            complete,
            store: opts.store.dir.display().to_string(),
            production: opts.production,
            tarballs: opts.tarballs.clone(),
            inputs: inputs.map(|i| i.hash.clone()),
            summary: inputs.map(|i| i.summary.clone()),
            root: inputs.map(|_| root),
            workspaces: match inputs {
                Some(_) => tops[1..].iter().map(|t| t.path.clone()).zip(links).collect(),
                None => Vec::new(),
            },
            stamps: inputs.and_then(|i| i.stamps.clone()),
        }
    };
    if let Some(prev) = previous.as_ref().filter(|s| !opts.verify && s.hash == opts.hash && s.complete)
        && let Some(root) = standing(opts.dir, &entries_dir, opts.global.as_deref(), &tops, res, prev, opts.production)
    {
        // Downloads to a store emptied under a tree that still stands: kept as they are.
        opts.store.flush()?;
        // The same tree from other inputs: the state learns them, so the next install is short.
        let learned = opts.inputs.as_ref().is_some_and(|i| prev.inputs.as_ref() != Some(&i.hash));
        if learned || prev.tarballs != opts.tarballs {
            state::write(opts.dir, &state_of(prev.entries.clone(), prev.shared.clone(), true, root))?;
        }
        let stats = Stats { reused: prev.entries.len() + prev.shared.len(), ..Stats::default() };
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
        // One directory name under `.jpm` or the store's `links`, whoever computed it.
        if key.is_empty() || key.starts_with('.') || key.contains(['/', '\\', '\0', ':']) {
            return Err(fail(format!("{id} has an unsafe store key {key:?}")));
        }
        // Settled later: a required package when its entry is built, and in the project layout
        // an optional one when something first needs it.
        let later = opts.fetch.is_some() && (!pkg.optional || opts.global.is_none());
        if !later && !opts.store.has(&pkg.integrity) {
            if !pkg.optional {
                return Err(fail(format!("{id} is not in the store at {}", opts.store.dir.display())));
            }
            dropped.push(id.clone());
            continue;
        }
        let home = sep(&format!("{key}/node_modules/{}", pkg.dir_name()));
        wanted.insert(
            id.clone(),
            Entry {
                pkg,
                key: key.clone(),
                digest: None,
                home,
                shared: opts.global.is_some(),
                build: opts.built.contains(id),
            },
        );
    }
    // A `node_modules` this run makes holds nothing but what it links: those links are made
    // without looking for one there first (see `link_top`).
    let fresh_nm = fs::create_dir(opts.dir.join("node_modules")).is_ok();
    fs::create_dir_all(&entries_dir).map_err(|e| Error::io(&e, format!("cannot create {}", entries_dir.display())))?;
    // An entry that lacks an optional package, or reaches one that does, stays in the project:
    // a global copy would be incomplete for everyone else.
    // So does one being built, and one whose peer is a workspace of this project, and every
    // entry that reaches either.
    let to_dir = |p: &Package| {
        let dir = |(n, v): (&String, &String)| res.packages.get(&format!("{n}@{v}")).is_some_and(|d| d.local.is_some());
        p.peer_dependencies.as_ref().is_some_and(|peers| p.all_deps().iter().any(|e| peers.contains_key(e.0) && dir(e)))
    };
    let peering: Vec<String> = match opts.global {
        Some(_) => wanted.iter().filter(|(_, e)| to_dir(e.pkg)).map(|(id, _)| id.clone()).collect(),
        None => Vec::new(),
    };
    if opts.global.is_some() && !(dropped.is_empty() && opts.built.is_empty() && peering.is_empty()) {
        let mut local: HashSet<String> = opts.built.iter().filter(|id| wanted.contains_key(*id)).cloned().collect();
        local.extend(peering);
        let missing: HashSet<&str> = dropped.iter().map(String::as_str).collect();
        let mut changed = true;
        while changed {
            changed = false;
            for (id, entry) in &wanted {
                if local.contains(id) {
                    continue;
                }
                let lacks = entry.pkg.all_deps().iter().any(|(n, v)| {
                    let dep = format!("{n}@{v}");
                    missing.contains(dep.as_str()) || local.contains(&dep)
                });
                if lacks {
                    local.insert(id.clone());
                    changed = true;
                }
            }
        }
        for id in &local {
            if let Some(e) = wanted.get_mut(id) {
                e.shared = false;
            }
        }
    }
    if let Some(global) = opts.global.as_deref() {
        name_shared(global, &mut wanted, &opts.digests);
    }
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
        real_root: real_root.clone(),
        wanted,
        counts: Counts::default(),
        copy_only: AtomicBool::new(false),
        settled: Mutex::default(),
        fresh_nm,
    };
    let failures: Mutex<Vec<Error>> = Mutex::default();
    // In the graph's order, which is the order an install queues their downloads in.
    // One build per entry: an alias and its real package can be one.
    let mut keys_seen = HashSet::new();
    let ids: Vec<&String> =
        res.packages.keys().filter(|id| linker.wanted.get(*id).is_some_and(|e| keys_seen.insert(&e.key))).collect();
    crate::ui::count(&crate::ui::TO_LINK, ids.len());
    let hoisted = std::thread::scope(|s| {
        // The hoist names each entry by its key alone, so it is made while the entries are built,
        // on a thread of its own: its links are nearly all in one directory, which takes one
        // writer at a time.
        let hoist = s.spawn(|| linker.hoist(&entries_dir.join(HOIST)));
        pool::run(pool::disk_threads() * 2, ids, |id, _| {
            let entry = &linker.wanted[id];
            let placed = match linker.global_of(entry) {
                _ if !linker.present(entry) => Ok(()),
                Some(global) => linker.materialize_global(entry, global),
                None => linker.materialize(entry, present.contains(&entry.key)),
            };
            crate::ui::count(&crate::ui::LINKED, 1);
            if let Err(e) = placed {
                failures.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(e);
            }
        });
        hoist.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    });
    if let Some(e) = failures.into_inner().unwrap_or_default().into_iter().next() {
        return Err(e);
    }
    hoisted?;
    // Downloads no entry took whole, into the store as they are.
    opts.store.flush()?;
    let hook = entries_dir.join(HOOK);
    if linker.wanted.values().any(|e| e.shared) {
        crate::util::write_atomic(&hook, include_bytes!("hoist.cjs"))?;
    } else {
        let _ = fs::remove_file(&hook);
    }
    for top in &tops {
        if let Some(parent) = top.nm.parent() {
            inside(parent, &real_root)?;
        }
        inside(&top.nm, &real_root)?;
    }
    // Each top is a `node_modules` of its own: a workspace's are linked side by side.
    let links: Vec<RootLinks> = pool::map(pool::disk_threads(), tops.iter().collect(), |top| linker.link_top(top))
        .into_iter()
        .collect::<Result<_>>()?;
    linker.sweep_temp();
    let settled = linker.settled.lock().map(|s| s.clone()).unwrap_or_default();
    dropped.extend(settled.iter().filter(|(_, arrived)| !**arrived).map(|(id, _)| id.clone()));
    dropped.sort();
    let names = |shared: bool| {
        let built = |e: &&Entry| settled.get(&e.pkg.key()) != Some(&false);
        let mut out: Vec<String> =
            linker.wanted.values().filter(|e| e.shared == shared).filter(built).map(|e| e.key.clone()).collect();
        out.sort();
        out.dedup();
        out
    };
    state::write(opts.dir, &state_of(names(false), names(true), dropped.is_empty(), links))?;
    Ok(Outcome { stats: linker.counts.stats(), dropped, up_to_date: false })
}

impl Linker<'_> {
    /// The global store, for an entry built there.
    fn global_of(&self, entry: &Entry) -> Option<&Path> {
        self.opts.global.as_deref().filter(|_| entry.shared)
    }

    /// Where an entry's own directory is: under the global store or under the project's `.jpm`.
    fn root_of(&self, entry: &Entry) -> &Path {
        self.global_of(entry).unwrap_or(&self.entries_dir)
    }

    /// Build the entry in the global store unless it is there (checked in full under `verify`).
    /// One already there is taken only when it was built for this subgraph (see `name_shared`).
    fn materialize_global(&self, entry: &Entry, global: &Path) -> Result<()> {
        let fin = global.join(&entry.key);
        let ours = || entry.digest.as_deref().is_none_or(|d| built_for(&fin, d));
        let taken = || fail(format!("{} holds another subgraph's entry: install again", fin.display()));
        if fin.is_dir() && !ours() {
            return Err(taken());
        }
        if !fin.is_dir() {
            let temp = global.join(format!(".tmp-{}", temp_suffix()));
            let (moved, built) = match self.move_in(entry, &temp) {
                Ok(moved) => {
                    let built = self.build(entry, &temp, moved.is_some()).and_then(|()| {
                        if let Some(digest) = &entry.digest {
                            fs::write(temp.join(DIGEST_FILE), digest)
                                .map_err(|e| Error::io(&e, format!("cannot write {}", temp.display())))?;
                        }
                        seal(&temp);
                        fs::rename(&temp, &fin)
                            .map_err(|e| Error::io(&e, format!("cannot place {}", fin.display())).with_code("ELINK"))
                    });
                    (moved, built)
                }
                Err(e) => (None, Err(e)),
            };
            match built {
                Ok(()) => {
                    if moved.is_some() {
                        let at = format!("{}/node_modules/{}", entry.key, entry.pkg.dir_name());
                        self.opts.store.homed(&entry.pkg.integrity, &at)?;
                    }
                    Counts::add(&self.counts.entries, 1);
                }
                // Another install built it first; its entry is as good as ours.
                Err(_) if fin.is_dir() && ours() => {
                    let kept = self.give_back(entry, moved);
                    remove_tree(&temp);
                    kept?;
                    Counts::add(&self.counts.reused, 1);
                }
                Err(e) => {
                    let _ = self.give_back(entry, moved);
                    remove_tree(&temp);
                    return Err(e);
                }
            }
        } else if self.opts.verify && !self.intact(entry)? {
            self.swap_in(entry, &fin, global)?;
        } else {
            Counts::add(&self.counts.reused, 1);
        }
        Ok(())
    }

    /// A global entry's package directory in `temp`, taken whole from the store's staged
    /// download when there is one: moved there with one rename, not a link and a directory per
    /// file. The store then keeps the entry's copy as its own (see `Store::claim`), so only an
    /// entry whose files are the tarball's may take it: not one built, patched or cut down to a
    /// runtime's binary or a directory inside the package. While it holds the claim, this thread
    /// reads nothing else of the store.
    fn move_in(&self, entry: &Entry, temp: &Path) -> Result<Option<PathBuf>> {
        let pkg = entry.pkg;
        if entry.build || pkg.patch.is_some() || pkg.runtime.is_some() || pkg.within().is_some() {
            return Ok(None);
        }
        self.ready(pkg)?;
        let Some(staged) = self.opts.store.claim(&pkg.integrity) else { return Ok(None) };
        let nm = temp.join("node_modules");
        let pkg_dir = nm.join(pkg.dir_name());
        // From the top, each once: `temp` is a new name.
        let scope = pkg_dir.parent().filter(|p| *p != nm);
        let moved = [temp, &nm]
            .into_iter()
            .chain(scope)
            .try_for_each(fs::create_dir)
            .and_then(|()| fs::rename(&staged, &pkg_dir));
        match moved {
            Ok(()) => Ok(Some(pkg_dir)),
            Err(_) => {
                // Built as any other entry, from nothing.
                remove_tree(temp);
                self.opts.store.unclaim(&pkg.integrity, &staged).map(|()| None)
            }
        }
    }

    /// Files `move_in` took for an entry that was not placed, back to the store.
    fn give_back(&self, entry: &Entry, moved: Option<PathBuf>) -> Result<()> {
        let Some(dir) = moved else { return Ok(()) };
        // `seal` may have run: moving a directory out takes write access to it and its parent.
        unseal(&dir);
        if let Some(parent) = dir.parent() {
            unseal(parent);
        }
        self.opts.store.unclaim(&entry.pkg.integrity, &dir)
    }

    /// Rebuild an entry and take its name in one rename, so no reader sees a partial entry.
    fn swap_in(&self, entry: &Entry, fin: &Path, root: &Path) -> Result<()> {
        let temp = root.join(format!(".tmp-{}", temp_suffix()));
        if let Err(e) = self.build(entry, &temp, false) {
            remove_tree(&temp);
            return Err(e);
        }
        if entry.shared {
            if let Some(digest) = &entry.digest
                && let Err(e) = fs::write(temp.join(DIGEST_FILE), digest)
            {
                remove_tree(&temp);
                return Err(Error::io(&e, format!("cannot write {}", temp.display())));
            }
            seal(&temp);
        }
        let retired = root.join(format!(".tmp-{}", temp_suffix()));
        let moved = fs::rename(fin, &retired).is_ok();
        if let Err(e) = fs::rename(&temp, fin) {
            remove_tree(&temp);
            if fin.exists() {
                remove_tree(&retired);
                Counts::add(&self.counts.reused, 1);
                return Ok(());
            }
            if moved {
                let _ = fs::rename(&retired, fin);
            }
            return Err(Error::io(&e, format!("cannot place {}", fin.display())).with_code("ELINK"));
        }
        remove_tree(&retired);
        Counts::add(&self.counts.repaired, 1);
        Ok(())
    }

    /// A dep link's target: every entry sits at the same depth, so from `<entry>/node_modules`
    /// it is always `../../<home>`, one `..` more from under a scope directory. A project entry
    /// reaches a global one by its full path, and a workspace by the way up to it.
    fn dep_target(&self, entry: &Entry, name: &str, dep: Dep) -> String {
        let dep = match dep {
            Dep::Entry(e) => e,
            Dep::Dir(p) => {
                let at = self.root_of(entry).join(&entry.key).join("node_modules").join(name);
                let dir = self.opts.dir.join(p.local.as_deref().unwrap_or_default());
                return relative(at.parent().unwrap_or(&at), &dir).to_string_lossy().into_owned();
            }
        };
        if let Some(global) = self.global_of(dep).filter(|_| !entry.shared) {
            return global.join(&dep.home).to_string_lossy().into_owned();
        }
        let up = format!("..{MAIN_SEPARATOR}");
        format!("{up}{up}{}{}", if name.contains('/') { up.as_str() } else { "" }, dep.home)
    }

    /// An entry's deps that are linked. A self-dep would collide with its own directory: pnpm
    /// leaves it out too, and the package requires itself.
    fn deps_of(&self, pkg: &Package) -> Result<Vec<(String, Dep<'_>)>> {
        let mut out = Vec::new();
        for (name, version) in pkg.all_deps() {
            let id = format!("{name}@{version}");
            // Only a peer reaches a workspace from an entry: a package never names a path.
            if let Some(dir) = self.res.packages.get(&id).filter(|p| p.local.is_some()) {
                if !pkg.peer_dependencies.as_ref().is_some_and(|p| p.contains_key(&name)) {
                    return Err(fail(format!("{}@{} depends on the workspace {name}", pkg.name, pkg.version)));
                }
                out.push((name, Dep::Dir(dir)));
                continue;
            }
            if let Some(dep) = self.wanted.get(&id).filter(|d| name != pkg.dir_name() && self.present(d)) {
                out.push((name, Dep::Entry(dep)));
            }
        }
        Ok(out)
    }

    /// Whether an entry's package is there to link to: always, but for an optional package the
    /// project layout settles as it arrives. One that fails is dropped with a warning, once.
    fn present(&self, entry: &Entry) -> bool {
        if !entry.pkg.optional || self.opts.fetch.is_none() || self.opts.global.is_some() {
            return true;
        }
        let id = entry.pkg.key();
        if let Some(&arrived) = self.settled.lock().unwrap_or_else(PoisonError::into_inner).get(&id) {
            return arrived;
        }
        let arrived = self.ready(entry.pkg);
        let mut settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        if let (Err(e), None) = (&arrived, settled.get(&id)) {
            crate::ui::warn(&format!("skipped optional {id}: {e}"));
        }
        *settled.entry(id).or_insert(arrived.is_ok())
    }

    /// `pkg` in the store, when it may still be arriving.
    fn ready(&self, pkg: &Package) -> Result<()> {
        match self.opts.fetch {
            Some(fetch) if pkg.local.is_none() => fetch(pkg),
            _ => Ok(()),
        }
    }

    fn index(&self, entry: &Entry) -> Result<std::sync::Arc<Index>> {
        self.ready(entry.pkg)?;
        let index = self.opts.store.index(&entry.pkg.integrity).ok_or_else(|| {
            fail(format!("{} is not in the store at {}", entry.pkg.key(), self.opts.store.dir.display()))
        })?;
        // A runtime's entry is its binary alone: the 4,000 files of Node's npm and headers are
        // never run, and would be linked into every project.
        if entry.pkg.runtime.is_some() {
            let files: Vec<FileEntry> =
                index.files.iter().filter(|f| entry.pkg.bin.values().any(|b| *b == f.path)).cloned().collect();
            let unpacked_size = files.iter().map(|f| f.size).sum();
            return Ok(std::sync::Arc::new(Index { files, unpacked_size, suffixed: index.suffixed }));
        }
        // A directory inside a package is its files under that directory, at their paths there.
        if let Some((_, at)) = entry.pkg.within() {
            return Ok(std::sync::Arc::new(index.under(at)));
        }
        Ok(index)
    }

    /// Where a package's files are in the store: a directory inside a package is under it.
    fn files_dir(&self, pkg: &Package) -> Result<PathBuf> {
        let dir = self.opts.store.pkg_dir(&pkg.integrity)?;
        Ok(pkg.within().map_or_else(|| dir.clone(), |(_, at)| dir.join(at)))
    }

    fn materialize(&self, entry: &Entry, present: bool) -> Result<()> {
        let fin = self.entries_dir.join(&entry.key);
        if present {
            // Swept below: a checkout could ship the entry, or a directory in it, as a symlink out.
            let nm = fin.join("node_modules");
            inside(&nm, &self.real_root)?;
            inside(&nm.join(".bin"), &self.real_root)?;
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
            return self.swap_in(entry, &fin, &self.entries_dir);
        }
        let temp = self.temp_name();
        let built = self.build(entry, &temp, false).and_then(|()| {
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
        let nm = self.root_of(entry).join(&entry.key).join("node_modules");
        let pkg_dir = nm.join(entry.pkg.dir_name());
        let index = self.index(entry)?;
        // A built package's files are its scripts' to change, a patched one's are not the store's.
        if !entry.build
            && entry.pkg.patch.is_none()
            && !index.files.iter().all(|f| fs::metadata(pkg_dir.join(&f.path)).is_ok_and(|m| m.len() == f.size))
        {
            return Ok(false);
        }
        let deps = self.deps_of(entry.pkg)?;
        if !deps.iter().all(|(name, dep)| sys::links_to(&nm.join(name), &self.dep_target(entry, name, *dep))) {
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
            } else if !sys::links_to(&bin_dir.join(&bin), &bin_link(&dep, &target)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `moved`: the package's files are in place already (see `move_in`).
    fn build(&self, entry: &Entry, temp: &Path, moved: bool) -> Result<()> {
        let pkg = entry.pkg;
        let nm = temp.join("node_modules");
        let pkg_dir = nm.join(pkg.dir_name());
        if moved {
            Counts::add(&self.counts.linked, self.index(entry)?.files.len());
        } else {
            // Before the directory clone (macOS) as well as the file links.
            self.ready(pkg)?;
            let parent = pkg_dir.parent().unwrap_or(&nm);
            // From the top, each once: `temp` is a new name.
            for dir in [temp, &nm].into_iter().chain(Some(parent).filter(|p| *p != nm)) {
                fs::create_dir(dir)
                    .map_err(|e| Error::io(&e, format!("cannot create {}", dir.display())).with_code("ELINK"))?;
            }
            let src = self.files_dir(pkg)?;
            // A runtime's entry is less than its store directory (see `index`): never a clone.
            let cloned = !entry.build
                && entry.pkg.runtime.is_none()
                && sys::clone_dir(&src, &pkg_dir)
                    .map_err(|e| Error::io(&e, format!("cannot copy {}", src.display())).with_code("ELINK"))?;
            if cloned {
                Counts::add(&self.counts.cloned, 1);
            } else {
                self.place_files(&*self.index(entry)?, &src, &pkg_dir, entry.build)?;
            }
        }
        if let Some(hash) = &pkg.patch {
            let patch = self.opts.patches.iter().find(|p| p.hash == *hash).ok_or_else(|| {
                Error::new(
                    "EPATCH",
                    format!("{}@{} is patched, and no patch of the project has its hash", pkg.name, pkg.version),
                )
            })?;
            crate::patch::apply(&pkg_dir, &patch.text, entry.shared && !entry.build).map_err(|why| {
                Error::new("EPATCH", format!("{} does not apply to {}@{}: {why}", patch.path, pkg.name, pkg.version))
            })?;
        }
        let deps = self.deps_of(pkg)?;
        let own_scope = pkg.dir_name().split_once('/').map(|(s, _)| s);
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
            sys::symlink_dir(&self.dep_target(entry, name, *dep), &at)
                .map_err(|e| Error::io(&e, format!("cannot link {}", at.display())).with_code("ELINK"))?;
        }
        let bins = bins_of(&deps);
        if !bins.is_empty() {
            let bin_dir = nm.join(".bin");
            fs::create_dir_all(&bin_dir).map_err(|e| Error::io(&e, "cannot create .bin").with_code("ELINK"))?;
            let final_nm = self.root_of(entry).join(&entry.key).join("node_modules");
            for (bin, (dep, target)) in bins {
                if WIN {
                    // Relative to where the shim ends up, as `intact` reads it.
                    let file = final_nm.join(&dep).join(&target);
                    let shims = self.shims(&final_nm.join(".bin"), &file, dep_pkg(&deps, &dep), &target)?;
                    for (sfx, text) in shims {
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
    /// `copy`: writable copies, for install scripts to change freely.
    /// `dest` is made here; its parent is there.
    fn place_files(&self, index: &Index, src: &Path, dest: &Path, copy: bool) -> Result<()> {
        let cannot_create = |e: io::Error, at: &Path| Error::io(&e, format!("cannot create {}", at.display()));
        fs::create_dir(dest)
            .or_else(|e| if dest.is_dir() { Ok(()) } else { Err(e) })
            .map_err(|e| cannot_create(e, dest))?;
        // Both held open: each file is linked by its path in the package alone.
        let from_dir = sys::Dir::open(src).map_err(|e| Error::io(&e, format!("cannot read {}", src.display())))?;
        let to_dir = sys::Dir::open(dest).map_err(|e| cannot_create(e, dest))?;
        let mut made: HashSet<String> = HashSet::new();
        for f in &index.files {
            if let Some((dir, _)) = f.path.rsplit_once('/') {
                crate::store::make_dirs(&to_dir, dir, &mut made)
                    .map_err(|e| cannot_create(e, &dest.join(dir)).with_code("ELINK"))?;
            }
        }
        let place = |f: &FileEntry| -> Result<()> {
            let stored: std::borrow::Cow<str> =
                if index.suffixed { index.stored(&f.path).into() } else { f.path.as_str().into() };
            if !copy && !self.copy_only.load(Ordering::Relaxed) {
                match to_dir.link(&from_dir, &stored, &f.path) {
                    Ok(()) => {
                        Counts::add(&self.counts.linked, 1);
                        return Ok(());
                    }
                    // Two names one file on a case-insensitive disk: already there.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::TooManyLinks => {}
                    Err(e) if cannot_link(&e) => self.copy_only.store(true, Ordering::Relaxed),
                    Err(e) => {
                        let to = dest.join(&f.path);
                        return Err(Error::io(&e, format!("cannot link {}", to.display())).with_code("ELINK"));
                    }
                }
            }
            let (from, to) = (src.join(&*stored), dest.join(&f.path));
            match fs::copy(&from, &to) {
                Ok(_) => Counts::add(&self.counts.copied, 1),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::io(&e, format!("cannot copy {}", to.display())).with_code("ELINK")),
            }
            if copy {
                writable(&to, f.exec).map_err(|e| Error::io(&e, format!("cannot write {}", to.display())))?;
            }
            Ok(())
        };
        if index.files.len() < 2 * PLACE_CHUNK {
            return index.files.iter().try_for_each(place);
        }
        // A package of thousands of files (next has 8,000) would take one thread for seconds
        // while the others finish and wait: its files go to every core in chunks, each
        // directory's in one, as a directory takes one new name at a time.
        pool::map(pool::disk_threads(), chunks_by_dir(&index.files, PLACE_CHUNK), |c| c.into_iter().try_for_each(place))
            .into_iter()
            .collect()
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
                self.ready(p)?;
                let target = p.within().map_or_else(|| target.to_string(), |(_, at)| format!("{at}/{target}"));
                self.opts.store.file(&p.integrity, &target).ok().and_then(|f| crate::shim::read_head(&f))
            }
            Some(p) => crate::shim::read_head(&self.opts.dir.join(p.local.as_deref().unwrap_or("")).join(target)),
            None => None,
        };
        crate::shim::shims_of(&relative(bin_dir, file).to_string_lossy(), head.as_deref())
    }

    /// Only direct deps get a top-level name. A registry dep links into `.jpm`; a workspace dep
    /// links to the workspace's own directory. What it linked, for the state. In a `node_modules`
    /// this run made, and the scope and `.bin` directories made in it, the links are made
    /// straight away: nothing is there to read, replace or sweep, and no symlink can lead out.
    fn link_top(&self, top: &Top) -> Result<RootLinks> {
        let nm = &top.nm;
        no_case_twins(top.dependencies.keys(), nm)?;
        let fresh = match fs::create_dir(nm) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.fresh_nm && *nm == self.opts.dir.join("node_modules")
            }
            Err(_) => fs::create_dir_all(nm)
                .map(|()| false)
                .map_err(|e| Error::io(&e, format!("cannot create {}", nm.display())).with_code("ELINK"))?,
        };
        let mut scopes: HashSet<&str> = HashSet::new();
        let real_root = &self.real_root;
        let mut direct: Vec<(String, &Package)> = Vec::new();
        let mut links = BTreeMap::new();
        for (name, version) in &top.dependencies {
            let id = format!("{name}@{version}");
            let Some(pkg) = self.res.packages.get(&id) else { continue };
            let (real, shared) = match (&pkg.local, self.wanted.get(&id)) {
                (Some(path), _) => (self.opts.dir.join(path), false),
                (None, Some(entry)) if self.present(entry) => (self.root_of(entry).join(&entry.home), entry.shared),
                _ => continue, // dropped, or dev under production
            };
            let at = nm.join(name);
            let parent = at.parent().unwrap_or(nm);
            let mut made = fresh;
            if let Some((scope, _)) = name.split_once('/') {
                made = fresh && (scopes.contains(scope) || (fs::create_dir(parent).is_ok() && scopes.insert(scope)));
                if !made {
                    inside(parent, real_root)?;
                    fs::create_dir_all(parent)
                        .map_err(|e| Error::io(&e, "cannot create a scope directory").with_code("ELINK"))?;
                }
            }
            let target = if shared { real.clone() } else { relative(parent, &real) };
            let target = target.to_string_lossy().into_owned();
            // Taken all the same: a concurrent install of this tree.
            if !(made && within(&at, nm).is_ok() && sys::symlink_dir(&target, &at).is_ok()) {
                replace_link(&at, &target, nm, true)?;
            }
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
        // Made, written and swept below: never through a symlink out of the project.
        let fresh_bin = fresh && !bins.is_empty() && fs::create_dir(&bin_dir).is_ok();
        if !fresh_bin {
            inside(&bin_dir, real_root)?;
        }
        if !bins.is_empty() && !fresh_bin {
            fs::create_dir_all(&bin_dir).map_err(|e| Error::io(&e, "cannot create .bin").with_code("ELINK"))?;
        }
        for (bin, (name, target, pkg)) in &bins {
            let file = nm.join(name).join(target);
            if WIN {
                for (sfx, text) in self.shims(&bin_dir, &file, Some(pkg), target)? {
                    let at = bin_dir.join(format!("{bin}{sfx}"));
                    if fresh_bin || fs::read_to_string(&at).ok().as_deref() != Some(text.as_str()) {
                        crate::util::write_atomic(&at, text.as_bytes())?;
                    }
                }
            } else {
                let link = relative(&bin_dir, &file).to_string_lossy().into_owned();
                let at = bin_dir.join(bin);
                if !(fresh_bin && within(&at, &bin_dir).is_ok() && symlink_file(&link, &at).is_ok()) {
                    replace_link(&at, &link, &bin_dir, false)?;
                }
                // A workspace's bin is the project's own file, which a checkout from Windows or
                // an unset bit leaves unrunnable: made executable, as npm and pnpm do. Never one
                // outside the project; the store's are made so as they are unpacked.
                if pkg.local.as_deref().is_some_and(|p| !p.starts_with("..")) {
                    executable(&file);
                }
            }
            Counts::add(&self.counts.bins, 1);
        }
        if !fresh {
            let names: HashSet<String> = direct.into_iter().map(|(n, _)| n).collect();
            self.sweep(nm, &names, "");
            self.sweep(&bin_dir, &bins.keys().cloned().collect(), "");
        }
        Ok(RootLinks { links, bins: bins.keys().cloned().collect() })
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

    /// One entry of every package name in the hidden hoist, the highest. A name the root links
    /// stays out: Node looks here first, so it would hide the root's own (a workspace, a git
    /// dependency), and the root's `node_modules` is the next place Node looks anyway. Links
    /// that are already right stay; the rest converge.
    fn hoist(&self, dir: &Path) -> Result<()> {
        let real_root = &self.real_root;
        let linked = |name: &str, version: &String| {
            let id = format!("{name}@{version}");
            self.wanted.get(&id).is_some_and(|e| self.present(e))
                || self.res.packages.get(&id).is_some_and(|p| p.local.is_some())
        };
        let root: HashSet<&str> =
            self.res.root.dependencies.iter().filter(|(n, v)| linked(n, v)).map(|(n, _)| n.as_str()).collect();
        let rank = |e: &Entry| crate::semver::parse(&e.pkg.version);
        let mut pick: BTreeMap<&str, &Entry> = BTreeMap::new();
        for e in self.wanted.values().filter(|e| !root.contains(e.pkg.name.as_str())) {
            if !self.present(e) {
                continue;
            }
            let better = pick.get(e.pkg.name.as_str()).is_none_or(|have| {
                let (a, b) = (rank(e), rank(have));
                a > b || (a == b && e.key < have.key)
            });
            if better {
                pick.insert(&e.pkg.name, e);
            }
        }
        // Undeclared imports only: of names that differ in case alone, the first in order.
        if sys::FOLDS_CASE {
            let mut seen = HashSet::new();
            pick.retain(|name, _| seen.insert(name.to_lowercase()));
        }
        // A checkout can ship it, or a scope in it, as a symlink out of the project: the links
        // would be made, and others swept, there. One made here just now holds nothing yet.
        inside(dir, real_root)?;
        let fresh = match fs::create_dir(dir) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(_) => fs::create_dir_all(dir)
                .map(|()| false)
                .map_err(|e| Error::io(&e, format!("cannot create {}", dir.display())).with_code("ELINK"))?,
        };
        let keep: HashSet<String> = pick.keys().map(|n| n.to_string()).collect();
        // Each scope directory once, before the links that go in it.
        let scopes: BTreeSet<&str> = pick.keys().filter_map(|n| n.split_once('/').map(|(s, _)| s)).collect();
        for scope in scopes {
            let at = dir.join(scope);
            if fresh {
                fs::create_dir(&at)
            } else {
                inside(&at, real_root)?;
                fs::create_dir(&at).or_else(|e| if at.is_dir() { Ok(()) } else { Err(e) })
            }
            .map_err(|e| Error::io(&e, "cannot create a scope directory").with_code("ELINK"))?;
        }
        for (name, e) in pick {
            let at = dir.join(name);
            let parent = at.parent().unwrap_or(dir);
            let real = self.root_of(e).join(&e.home);
            let target = if e.shared { real } else { relative(parent, &real) };
            let target = target.to_string_lossy();
            // Nothing to replace in a new directory: made straight away.
            let made = fresh && within(&at, dir).is_ok() && sys::symlink_dir(&target, &at).is_ok();
            if !made {
                replace_link(&at, &target, dir, true)?;
            }
        }
        self.sweep(dir, &keep, "");
        Ok(())
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

/// `files` in chunks of about `size`, each directory's files all in one chunk: threads linking
/// into one directory wait on each other. Directories in the order they first appear.
fn chunks_by_dir(files: &[FileEntry], size: usize) -> Vec<Vec<&FileEntry>> {
    let mut dirs: Vec<Vec<&FileEntry>> = Vec::new();
    let mut at: HashMap<&str, usize> = HashMap::new();
    for f in files {
        let dir = f.path.rsplit_once('/').map_or("", |(d, _)| d);
        let i = *at.entry(dir).or_insert_with(|| {
            dirs.push(Vec::new());
            dirs.len() - 1
        });
        dirs[i].push(f);
    }
    let mut chunks: Vec<Vec<&FileEntry>> = Vec::new();
    for dir in dirs {
        match chunks.last_mut() {
            Some(last) if last.len() + dir.len() <= size => last.extend(dir),
            _ => chunks.push(dir),
        }
    }
    chunks
}

fn dep_pkg<'a>(deps: &'a [(String, Dep)], name: &str) -> Option<&'a Package> {
    deps.iter().find(|(n, _)| n == name).map(|(_, d)| d.pkg())
}

/// Bin name -> (dep name, target). Name collisions are last-wins, as npm's are.
fn bins_of(deps: &[(String, Dep)]) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    for (name, dep) in deps {
        for (bin, target) in &dep.pkg().bin {
            out.insert(bin.clone(), (name.clone(), target.clone()));
        }
    }
    out
}

/// A bin link's text from an entry's `.bin`: `../<name>/<target>`.
fn bin_link(name: &str, target: &str) -> String {
    sep(&format!("../{name}/{}", target.trim_end_matches('/')))
}

/// A shared entry is read-only all the way down, its directories as its files already are: no
/// script in one project can add, remove or rename what another project links to.
fn seal(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                seal(&e.path());
            }
        }
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o555));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// One directory `seal` made read-only, writable by its owner again.
fn unseal(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Executable by whoever may read it, through links; a file that is missing or already is,
/// left alone.
fn executable(file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = fs::metadata(file) else { return };
        let mode = meta.permissions().mode();
        let want = mode | ((mode & 0o444) >> 2);
        if meta.is_file() && want != mode {
            let _ = fs::set_permissions(file, fs::Permissions::from_mode(want));
        }
    }
    #[cfg(not(unix))]
    let _ = file;
}

/// A copy the owner may write: the store's files are read-only.
fn writable(file: &Path, exec: bool) -> io::Result<()> {
    let mut perm = fs::metadata(file)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(if exec { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    {
        let _ = exec;
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
    }
    fs::set_permissions(file, perm)
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
fn replace_link(at: &Path, target: &str, within_dir: &Path, dir: bool) -> Result<()> {
    within(at, within_dir)?;
    for attempt in 0..4 {
        if sys::links_to(at, target) {
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

/// Names global entries by the start of their subgraph's digest, `<name>@<version>-<8 chars>`,
/// and a package with no dependencies, which is the same in every project, `<name>@<version>`
/// alone. Every link to an entry spells its name, and one of up to 59 bytes fits in its inode.
/// The name is never trusted alone: an entry keeps its whole digest in `DIGEST_FILE`, and one
/// there under the name with another digest (or none: an older jpm's, or one from elsewhere)
/// is left be, and this subgraph named by more of its digest, as git lengthens a short hash.
///
/// The names are picked with the store's lock held shared, as other installs may be picking
/// theirs: two that pick one name for two subgraphs at once (which takes two digests that start
/// alike) race to rename their entry into place, and the loser stops with an error rather than
/// link to the winner's. Run again, it picks a longer name.
fn name_shared(global: &Path, wanted: &mut HashMap<String, Entry>, digests: &HashMap<String, String>) {
    // Tests set how much of the digest names show; none makes every name collide.
    let shown = std::env::var("JPM_DIGEST_SHOWN").ok().and_then(|v| v.parse().ok()).unwrap_or(DIGEST_SHOWN);
    let mut named: HashMap<String, (String, String)> = HashMap::new();
    for (id, e) in wanted.iter_mut().filter(|(_, e)| e.shared) {
        // `<name>@<version>-<digest>`, as `keys::store_keys` spells it: the name and version.
        let Some(at) = e.key.len().checked_sub(23).filter(|at| e.key.as_bytes()[*at] == b'-') else { continue };
        let Some(digest) = digests.get(id) else { continue };
        let base = e.key[..at].to_string();
        let (name, digest) = named
            .entry(e.key.clone())
            .or_insert_with(|| {
                let p = e.pkg;
                // Nothing below it or beside it, and its files the tarball's own: the same entry
                // in every project.
                let leaf = p.all_deps().is_empty()
                    && p.peer_dependencies.as_ref().is_none_or(|d| d.is_empty())
                    && p.patch.is_none()
                    && p.within().is_none()
                    && !e.build;
                let lengths = (shown.clamp(1, digest.len())..digest.len()).step_by(2).chain([digest.len()]);
                // None shown: every name as a leaf's, which tests use to make names collide.
                let mut tries = (leaf || shown == 0)
                    .then(|| base.clone())
                    .into_iter()
                    .chain(lengths.map(|n| format!("{base}-{}", &digest[..n])));
                let name = tries.find(|name| {
                    let at = global.join(name);
                    !at.exists() || built_for(&at, digest)
                });
                (name.unwrap_or_else(|| e.key.clone()), digest.clone())
            })
            .clone();
        e.home = sep(&format!("{name}/node_modules/{}", e.pkg.dir_name()));
        e.key = name;
        e.digest = Some(digest);
    }
}

/// Whether the global entry at `at` was built for the subgraph with this digest.
fn built_for(at: &Path, digest: &str) -> bool {
    fs::read_to_string(at.join(DIGEST_FILE)).is_ok_and(|d| d == digest)
}

/// `at` names a place under `dir`: no `..` climbs out of it.
fn within(at: &Path, dir: &Path) -> Result<()> {
    if !at.starts_with(dir) || at.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(fail(format!("refusing to link outside {}: {}", dir.display(), at.display())));
    }
    Ok(())
}

/// A top whose directory, `node_modules` or scope directory is a symlink out of the project,
/// as a hostile checkout can arrange, would have the sweep delete there.
pub fn inside(path: &Path, real_root: &Path) -> Result<()> {
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
    global: Option<&Path>,
    tops: &[Top],
    res: &Resolution,
    st: &State,
    production: bool,
) -> Option<Vec<RootLinks>> {
    let mut found = Vec::with_capacity(tops.len());
    for top in tops {
        found.push(standing_top(dir, global, top, res, production)?);
    }
    let present: HashSet<String> = fs::read_dir(entries_dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let shared = st.shared.is_empty() || global.is_some_and(|g| st.shared.iter().all(|k| g.join(k).is_dir()));
    (shared && entries_standing(st, &present)).then_some(found)
}

fn standing_top(dir: &Path, global: Option<&Path>, top: &Top, res: &Resolution, production: bool) -> Option<RootLinks> {
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
                if !sys::links_to(&at, &relative(at.parent()?, &dir.join(path)).to_string_lossy()) {
                    return None;
                }
            }
            None => {
                // Relative to the link (unix) or absolute (a junction).
                let local = dir.join("node_modules").join(".jpm");
                let store = relative(at.parent()?, &local);
                // An alias's entry holds its package under the real name.
                let tail = Path::new("node_modules").join(pkg.map_or(name.as_str(), Package::dir_name));
                let to_path = Path::new(&to);
                let within = to_path.starts_with(&store)
                    || to_path.starts_with(&local)
                    || global.is_some_and(|g| to_path.starts_with(g));
                if !within || !Path::new(&to).ends_with(&tail) {
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

/// The no-op check, read off the state alone: every recorded link of the root and each workspace
/// pointing where it was made to, every bin placed, every entry a directory. No graph needed.
pub fn tree_standing(dir: &Path, st: &State) -> bool {
    let nm = dir.join("node_modules");
    let Some(root) = st.root.as_ref().filter(|_| st.complete) else { return false };
    let shared = !st.shared.is_empty();
    if !top_standing(&nm, root, shared)
        || !st.workspaces.iter().all(|(path, top)| top_standing(&dir.join(path).join("node_modules"), top, shared))
    {
        return false;
    }
    let Ok(entries) = fs::read_dir(nm.join(".jpm")) else { return false };
    let present: HashSet<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries_standing(st, &present)
}

/// One top's recorded links and bins, still in `nm`.
fn top_standing(nm: &Path, top: &RootLinks, shared: bool) -> bool {
    let bin_dir = nm.join(".bin");
    top.links.iter().all(|(name, target)| sys::links_to(&nm.join(name), target))
        && top.bins.iter().all(|b| fs::symlink_metadata(bin_dir.join(if WIN { format!("{b}.cmd") } else { b.clone() })).is_ok())
        // Links into the global store stand only while their entries do: a store can be wiped
        // or pruned. The direct ones are enough: an entry's name covers everything below it, so
        // a prune that keeps it keeps its dependencies too.
        && (!shared || top.links.keys().all(|name| nm.join(name).is_dir()))
}

/// Every entry built in the project is there, and so is the hoist: a tree from before there was
/// one gets it on its next install.
fn entries_standing(st: &State, present: &HashSet<String>) -> bool {
    st.entries.iter().all(|k| present.contains(k))
        && ((st.entries.is_empty() && st.shared.is_empty()) || present.contains(HOIST))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_keep_each_directory_whole() {
        let f = |p: &str| FileEntry { path: p.into(), size: 0, exec: false };
        let files = [f("a"), f("lib/x"), f("b"), f("lib/y"), f("lib/sub/z"), f("c"), f("d"), f("e/1")];
        let chunks = chunks_by_dir(&files, 3);
        let paths: Vec<Vec<&str>> = chunks.iter().map(|c| c.iter().map(|f| f.path.as_str()).collect()).collect();
        // The top's four files stay together past the size; the rest fill chunks up to it.
        assert_eq!(paths, [vec!["a", "b", "c", "d"], vec!["lib/x", "lib/y", "lib/sub/z"], vec!["e/1"]]);
        assert!(chunks_by_dir(&[], 3).is_empty());
    }
}
