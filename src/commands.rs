//! What each command does, without argv parsing or result formatting (that is `cli.rs`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};

use crate::json::{self, Object, Value};

use crate::config::{Config, Flags, read_config};
use crate::error::{Error, Result};
use crate::graph::{Package, Resolution, filter_platform, runs_on, unmet_peers};
use crate::lock::{self, LOCKFILE, Lockfile};
use crate::manifest::Manifest;
use crate::project::{self, Added, Found, RootManifest, Workspace};
use crate::registry::{Registry, base_for};
use crate::resolve;
use crate::semver;
use crate::spec::{self, Kind};
use crate::state::{self, Stamp, Stamps, stamp_of};
use crate::store::{Index, Store, Tarball, store_dir};
use crate::sys::Platform;
use crate::ui::{self, info, warn};
use crate::{build, foreign, gc, link, pool, run};

/// Which workspaces a command acts on.
#[derive(Debug, Clone)]
pub enum Select {
    All,
    Some(Vec<String>),
}

#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub dir: Option<PathBuf>,
    pub flags: Flags,
    pub store: Option<PathBuf>,
    pub production: bool,
    pub verify: bool,
    pub frozen: bool,
    pub group: Option<&'static str>,
    pub exact: bool,
    pub workspaces: Option<Select>,
    pub if_present: bool,
    pub include_root: bool,
    /// Run no install or lifecycle scripts.
    pub ignore_scripts: bool,
}

#[derive(Debug, Default)]
pub struct InstallResult {
    pub packages: usize,
    pub workspaces: usize,
    pub other_platforms: usize,
    pub up_to_date: bool,
    pub missing_optional: Vec<String>,
    pub stats: link::Stats,
    /// Packages whose install scripts ran.
    pub built: usize,
    /// Packages with install scripts that did not run, as `name@version`.
    pub unbuilt: Vec<String>,
}

impl InstallResult {
    /// What `--json` prints, after any `changes` to package.json.
    pub fn to_object(&self, mut out: Object) -> Object {
        out.insert("packages", self.packages.into());
        out.insert("workspaces", self.workspaces.into());
        out.insert("otherPlatforms", self.other_platforms.into());
        for (k, v) in self.stats.to_object().iter() {
            out.insert(k.clone(), v.clone());
        }
        out.insert("dropped", Value::from(self.missing_optional.clone()));
        out.insert("built", self.built.into());
        out.insert("unbuilt", Value::from(self.unbuilt.clone()));
        out.insert("upToDate", self.up_to_date.into());
        out
    }
}

/// One command's options, and what it found out about the project on the way.
struct Ctx {
    opts: Opts,
    dedupe: bool,
    root: Option<PathBuf>,
    found: Option<Found>,
    inside: Option<Workspace>,
    config: Option<Config>,
    /// `jpm.lock`, or another manager's file.
    source: Option<(PathBuf, Option<&'static str>)>,
    /// Another manager's lockfile as read, stamped first.
    foreign_read: Option<(String, Option<Stamp>)>,
    binless: Vec<String>,
    /// The foreign lockfile read never says which packages have install scripts.
    scriptless: bool,
    /// Each local tarball's stamp from just before this command checked or read it.
    stamped: Mutex<BTreeMap<String, Stamp>>,
}

struct Project {
    dir: PathBuf,
    manifest: RootManifest,
    workspaces: Vec<Workspace>,
}

/// An edited package.json on its way through an install, written once the install can use it.
struct Edit {
    file: PathBuf,
    raw: String,
    doc: Object,
    project: Project,
}

fn fail(code: &'static str, message: impl Into<String>) -> Error {
    Error::new(code, message)
}

impl Ctx {
    fn new(opts: Opts, dedupe: bool) -> Self {
        Self {
            opts,
            dedupe,
            root: None,
            found: None,
            inside: None,
            config: None,
            source: None,
            foreign_read: None,
            binless: Vec::new(),
            scriptless: false,
            stamped: Mutex::default(),
        }
    }

    /// The root and its `.npmrc`, read first by every command but `run`.
    fn open(opts: Opts, dedupe: bool) -> Result<Self> {
        let mut ctx = Self::new(opts, dedupe);
        ctx.opened()?;
        Ok(ctx)
    }

    fn opened(&mut self) -> Result<()> {
        let root = self.project_dir();
        self.config = Some(read_config(&root, &self.opts.flags)?);
        // One .npmrc for the tree, or two workspaces could install one lockfile two ways.
        if let Some(ws) = &self.inside {
            let own = ws.dir.join(".npmrc");
            if own.exists() {
                warn(&format!("ignoring {}: .npmrc is read from {}", own.display(), root.display()));
            }
        }
        Ok(())
    }

    fn config(&self) -> &Config {
        static DEFAULT: std::sync::OnceLock<Config> = std::sync::OnceLock::new();
        self.config.as_ref().unwrap_or_else(|| DEFAULT.get_or_init(Config::default))
    }

    /// `dir` as given, else npm's walk up from cwd.
    fn project_dir(&mut self) -> PathBuf {
        if let Some(root) = &self.root {
            return root.clone();
        }
        let root = match &self.opts.dir {
            Some(d) => std::path::absolute(d).unwrap_or_else(|_| d.clone()),
            None => {
                let found = project::find_root(&std::env::current_dir().unwrap_or_default());
                let dir = found.dir.clone();
                self.inside = found.workspace.clone();
                self.found = Some(found);
                dir
            }
        };
        self.root = Some(root.clone());
        root
    }

    fn load_project(&mut self) -> Result<Project> {
        let dir = self.project_dir();
        let manifest = match self.found.as_ref().and_then(|f| f.manifest.clone()) {
            Some(m) => m,
            None => project::read_manifest(&dir.join("package.json"))?,
        };
        let workspaces = match self.found.as_ref().and_then(|f| f.workspaces.clone()) {
            Some(w) => w,
            None => project::find_workspaces(&dir, &manifest)?,
        };
        Ok(Project { dir, manifest, workspaces })
    }

    fn store(&self, verify: bool) -> Store {
        let c = self.config();
        Store::new(store_dir(self.opts.store.as_deref()), c.auth.clone(), c.offline, verify)
    }

    fn registry(&self, store: &Store) -> Registry {
        Registry::new(self.config(), Some(&store.metadata_dir()))
    }

    fn base_for(&self) -> impl Fn(&str) -> String + '_ {
        let c = self.config();
        move |name: &str| base_for(&c.registry, &c.scopes, name).to_string()
    }

    /// Which lockfile the project installs from.
    fn lock_source(&mut self, dir: &Path) -> Result<(PathBuf, Option<&'static str>)> {
        if let Some(s) = &self.source {
            return Ok(s.clone());
        }
        if dir.join(LOCKFILE).exists() {
            let s = (dir.join(LOCKFILE), None);
            self.source = Some(s.clone());
            return Ok(s);
        }
        let found: Vec<&'static str> = foreign::FOREIGN.iter().copied().filter(|f| dir.join(f).exists()).collect();
        if found.len() > 1 {
            return Err(fail(
                "ELOCK",
                format!("{} both lock {}: delete all but one", found.join(" and "), dir.display()),
            ));
        }
        let s = match found.first() {
            Some(f) => (dir.join(f), Some(*f)),
            None => (dir.join(LOCKFILE), None),
        };
        self.source = Some(s.clone());
        Ok(s)
    }

    fn lock_text(&mut self, dir: &Path) -> Option<String> {
        if let Some((text, _)) = &self.foreign_read {
            return Some(text.clone());
        }
        let (path, _) = self.lock_source(dir).ok()?;
        std::fs::read_to_string(path).ok()
    }

    fn settings(&self) -> String {
        let c = self.config();
        let store = store_dir(self.opts.store.as_deref());
        let scopes = json::str_map(&c.scopes);
        let hosts = Value::Array(vec![c.registry.as_str().into(), scopes]);
        let platform = Platform::current().to_value();
        json::to_string(&Value::Array(vec![
            self.opts.production.into(),
            store.display().to_string().into(),
            self.wants_global().into(),
            self.ignore_scripts().into(),
            hosts,
            platform,
        ]))
    }

    fn ignore_scripts(&self) -> bool {
        self.opts.ignore_scripts || self.config().ignore_scripts
    }

    /// The global virtual store is on unless the config says `global-store=false` or this runs
    /// in a container, whose project mount would not see the store's links.
    fn wants_global(&self) -> bool {
        let env = std::env::var("JPM_GLOBAL_STORE").ok().map(|v| !matches!(v.as_str(), "0" | "false" | "off"));
        let setting = self.opts.flags.global_store.or(env).or(self.config().global_store);
        setting.unwrap_or_else(|| !Path::new("/.dockerenv").exists() && !Path::new("/run/.containerenv").exists())
    }

    fn stamps(&mut self, dir: &Path) -> Option<Stamps> {
        let lock = match &self.foreign_read {
            Some((_, stamp)) => stamp.clone(),
            None => stamp_of(&self.lock_source(dir).ok()?.0),
        }?;
        let manifest = stamp_of(&dir.join("package.json"))?;
        Some(Stamps { lock, manifest, settings: self.settings() })
    }

    fn inputs_hash(&self, project: &Project, lock_text: &str) -> String {
        state::inputs_hash(lock_text, &project.manifest.doc, &self.settings())
    }
}

// --- install --------------------------------------------------------------------------------

pub fn install(opts: Opts) -> Result<InstallResult> {
    let mut ctx = Ctx::open(opts, false)?;
    install_tree(&mut ctx, None, None)
}

/// Resolve every range again, preferring locked versions, then install.
pub fn dedupe(mut opts: Opts) -> Result<InstallResult> {
    opts.frozen = false;
    let mut ctx = Ctx::open(opts, true)?;
    install_tree(&mut ctx, None, None)
}

fn install_tree(ctx: &mut Ctx, edit: Option<Edit>, loaded: Option<Project>) -> Result<InstallResult> {
    let (project, edit) = match edit {
        Some(mut e) => (
            std::mem::replace(
                &mut e.project,
                Project { dir: PathBuf::new(), manifest: RootManifest::default(), workspaces: Vec::new() },
            ),
            Some(e),
        ),
        None => (
            match loaded {
                Some(p) => p,
                None => ctx.load_project()?,
            },
            None,
        ),
    };
    let dir = project.dir.clone();
    let previous = if ctx.opts.verify { None } else { state::read(&dir) };
    // The same inputs, with the tree still standing: a no-op that never reads the graph.
    // Only from jpm.lock itself (or frozen): any other lockfile is to be brought over first.
    let source = ctx.lock_source(&dir)?.0;
    let own = ctx.opts.frozen || (source.file_name().is_some_and(|n| n == LOCKFILE) && lock::is_current(&source));
    if let Some(st) = previous
        .as_ref()
        .filter(|s| own && s.inputs.is_some() && edit.is_none() && !ctx.dedupe && project.workspaces.is_empty())
    {
        let stamps = ctx.stamps(&dir);
        let stamped = stamps.as_ref().zip(st.stamps.as_ref()).is_some_and(|(a, b)| a == b);
        let matched = stamped || ctx.lock_text(&dir).is_some_and(|t| Some(ctx.inputs_hash(&project, &t)) == st.inputs);
        let files_same = st.tarballs.as_ref().is_some_and(|files| same_files(&dir, files));
        if matched && files_same && link::tree_standing(&dir, st) {
            if !stamped && stamps.is_some() {
                let mut st = st.clone();
                st.stamps = stamps;
                let _ = state::write(&dir, &st);
            }
            // A copied project registers on its first install, even one with nothing to do.
            ctx.store(false).register(&dir);
            let summary = st.summary.clone().unwrap_or_default();
            for w in &summary.warnings {
                warn(w);
            }
            return Ok(InstallResult {
                packages: summary.packages,
                other_platforms: summary.other_platforms,
                up_to_date: true,
                stats: link::Stats { reused: st.entries.len() + st.shared.len(), ..link::Stats::default() },
                ..InstallResult::default()
            });
        }
    }
    ui::phase("start");
    let store = ctx.store(ctx.opts.verify);
    let _hold = store.hold(false);
    let platform = Platform::current();
    let (tx, rx) = mpsc::channel::<(Tarball, String)>();
    let rx = Mutex::new(rx);
    let prefetching = !ctx.opts.production && !ctx.dedupe;
    // Set when the plan fails: what is still queued is not downloaded.
    let stop = AtomicBool::new(false);
    let lock = std::thread::scope(|scope| -> Result<Lockfile> {
        if prefetching {
            for _ in 0..pool::network_threads() {
                scope.spawn(|| {
                    loop {
                        let job = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                        let Ok((tarball, integrity)) = job else { return };
                        if stop.load(Ordering::Relaxed) {
                            continue;
                        }
                        // A failure here is nothing: the fill asks again, and that one is reported.
                        let _ = store.ensure(&tarball, &integrity);
                    }
                });
            }
        }
        let skipped: Mutex<BTreeMap<String, bool>> = Mutex::default();
        let tx = Mutex::new(tx);
        let on_pick = |pkg: &Package, from: &str| {
            let mut skipped = skipped.lock().unwrap_or_else(PoisonError::into_inner);
            let skip = skipped.get(from).copied().unwrap_or(false)
                || !runs_on(pkg.os.as_ref(), pkg.cpu.as_ref(), pkg.libc.as_ref(), &platform);
            skipped.insert(pkg.key(), skip);
            if !skip && !pkg.integrity.is_empty() {
                let _ = tx
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .send((tarball_of(&dir, &pkg.resolved, pkg.source.as_deref()), pkg.integrity.clone()));
            }
        };
        let walk_pick: Option<&resolve::OnPick> = if prefetching { Some(&on_pick) } else { None };
        let planned = plan(ctx, &project, &store, walk_pick, previous.as_ref().and_then(|s| s.tarballs.clone()))
            // A required package that cannot run here fails now, not once the prefetch is done.
            .and_then(|lock| filter_platform(lock::from_lockfile(&lock, &ctx.base_for()), &platform).map(|_| lock));
        if planned.is_err() {
            stop.store(true, Ordering::Relaxed);
        }
        ui::phase("planned");
        drop(tx);
        planned
    })?;
    ui::phase("prefetched");
    // Only now: a package.json naming a tree the registry cannot resolve is never written.
    if let Some(edit) = &edit {
        save_manifest(edit)?;
    }
    // What is needed of the lockfile itself, before it is taken apart into the graph.
    let workspaces = lock.workspaces.len();
    let locked = lock.packages.len();
    let lock_hash = lock::content_hash(&lock);
    let tarballs = files_of(ctx, &lock);
    let global = global_store(ctx, &store);
    // Shared entries are named by keys computed here, over the graph this platform installs:
    // a lockfile could claim another project's key and plant an entry every project trusts, and
    // an entry built without a package another platform needs must not share its name.
    let recorded = if global.is_some() { None } else { lock::recorded_keys(&lock) };
    let checked = lock::into_resolution(lock, &ctx.base_for());
    let keys = global.is_none().then(|| recorded.unwrap_or_else(|| crate::keys::store_keys(&checked.packages)));
    let resolution = filter_platform(checked, &platform)?;
    let keys = keys.unwrap_or_else(|| crate::keys::store_keys(&resolution.packages));
    for w in &resolution.warnings {
        warn(w);
    }
    if ctx.opts.verify {
        for unmet in unmet_peers(&resolution) {
            warn(&format!("unmet peer — {unmet}"));
        }
    }
    let elsewhere = locked.saturating_sub(resolution.packages.len() - workspaces);
    let mut resolution = resolution;
    if !ctx.binless.is_empty() {
        read_bins(&mut resolution, &store, &ctx.binless, &dir)?;
    }
    let wanted: Vec<&Package> =
        resolution.packages.values().filter(|p| p.local.is_none() && !(ctx.opts.production && p.dev)).collect();
    let hash = state::state_hash(&lock_hash, ctx.opts.production, &store.dir, global.is_some(), &platform);
    let settled = previous.as_ref().is_some_and(|s| s.hash == hash);
    if !settled {
        fill(&store, &wanted, &dir)?;
    }
    ui::phase("filled");
    let inputs = if project.workspaces.is_empty() {
        ctx.lock_text(&dir).map(|text| link::Inputs {
            hash: ctx.inputs_hash(&project, &text),
            summary: state::Summary {
                packages: wanted.len(),
                other_platforms: elsewhere,
                warnings: resolution.warnings.clone(),
            },
            stamps: ctx.stamps(&dir),
        })
    } else {
        None
    };
    let packages = wanted.len();
    let scripts = !ctx.ignore_scripts();
    let mut chosen =
        if scripts { build::chosen(&resolution, &build::trusted(&project.manifest)) } else { HashSet::new() };
    // Only the package the registry serves under that name and version, or a tarball package.json
    // names: a lockfile edit pointing an approved package at another tarball, or an alias
    // wearing a trusted name, runs nothing.
    let base = ctx.base_for();
    chosen.retain(|id| {
        let p = &resolution.packages[id];
        let own = p.source.is_some() || p.resolved == crate::registry::tarball_url(&base(&p.name), &p.name, &p.version);
        if !own {
            warn(&format!("{id} is approved, but its tarball is not the registry's; its install scripts do not run"));
        }
        own
    });
    let build_keys: HashMap<String, String> =
        chosen.iter().filter_map(|id| Some((id.clone(), keys.get(id)?.clone()))).collect();
    let options = link::Options {
        dir: &dir,
        store: &store,
        production: ctx.opts.production,
        verify: ctx.opts.verify,
        hash: hash.clone(),
        keys,
        global,
        built: chosen.clone(),
        inputs,
        tarballs: Some(tarballs.clone()),
    };
    let outcome = match link::link(&resolution, &options) {
        Err(e) if e.code == "ELINK" && e.message.contains("is not in the store") => {
            // The store lost content between the fill and the link: fill again, checking every file.
            let again = ctx.store(true);
            fill(&again, &wanted, &dir)?;
            link::link(&resolution, &link::Options { store: &again, ..options })?
        }
        other => other?,
    };
    store.register(&dir);
    ui::phase("linked");
    let built = if build_keys.is_empty() { 0 } else { build::run_packages(&dir, &resolution, &build_keys)? };
    // The project's own scripts, on an install that changed the tree, as npm runs them.
    if scripts && edit.is_none() && !outcome.up_to_date {
        let mut tops = vec![(dir.as_path(), &project.manifest)];
        tops.extend(project.workspaces.iter().map(|w| (w.dir.as_path(), &w.manifest)));
        build::run_lifecycle(&tops)?;
    }
    let installed = |id: &str| {
        resolution.packages.get(id).is_some_and(|p| !(ctx.opts.production && p.dev))
            && !outcome.dropped.iter().any(|d| d == id)
    };
    let unbuilt = build::skipped(&resolution, &chosen, &installed);
    Ok(InstallResult {
        packages,
        workspaces,
        other_platforms: elsewhere,
        up_to_date: outcome.up_to_date,
        missing_optional: outcome.dropped,
        stats: outcome.stats,
        built,
        unbuilt,
    })
}

pub struct Approved {
    /// Lockfile keys newly approved.
    pub approved: Vec<String>,
    /// Packages whose install scripts still do not run.
    pub pending: Vec<String>,
    /// The install that ran the scripts, when anything was approved.
    pub install: Option<InstallResult>,
}

/// `jpm approve <name>...`: trust the names in package.json (`trustedDependencies`), approve
/// their locked versions' install scripts in jpm.lock, and install, which runs them. A later
/// version waits for another approval. Without names, what waits for one.
pub fn approve(names: &[String], opts: Opts) -> Result<Approved> {
    install_tree(&mut Ctx::open(opts.clone(), false)?, None, None)?;
    let dir = Ctx::open(opts.clone(), false)?.project_dir();
    let missing = || fail("ELOCK", format!("no {LOCKFILE} in {}", dir.display()));
    let (mut lock, _) = lock::read_lockfile(&dir)?.ok_or_else(missing)?;
    let file = dir.join("package.json");
    let raw = std::fs::read_to_string(&file).map_err(|e| Error::io(&e, format!("cannot read {}", file.display())))?;
    let mut doc = RootManifest::parse(&raw, &file)?.doc;
    if names.is_empty() {
        let trusted = build::trusted(&RootManifest::parse(&raw, &file)?);
        let pending = lock
            .packages
            .iter()
            .filter(|(key, e)| {
                e.scripts && !(e.build && crate::graph::split_key(key).is_some_and(|(n, _)| trusted.contains(n)))
            })
            .map(|(key, _)| key.clone())
            .collect();
        return Ok(Approved { approved: Vec::new(), pending, install: None });
    }
    let mut approved = Vec::new();
    for name in names {
        let mut found = false;
        for (key, e) in &mut lock.packages {
            if e.scripts && crate::graph::split_key(key).is_some_and(|(n, _)| n == name) {
                // An alias, or a tarball from elsewhere, is not the package the name says.
                if let Some(from) = &e.resolved {
                    return Err(fail(
                        "ENOSCRIPTS",
                        format!("{key} comes from {from}, not the registry; jpm will not approve it"),
                    ));
                }
                found = true;
                if !e.build {
                    e.build = true;
                    approved.push(key.clone());
                }
            }
        }
        if !found {
            return Err(fail("ENOSCRIPTS", format!("{name} has no install scripts in {LOCKFILE}")));
        }
    }
    // An approved package is an entry of its own, and so is all that reaches it.
    for e in lock.packages.values_mut() {
        e.subgraph = None;
    }
    lock::write_lockfile(&dir, &mut lock)?;
    let mut trusted: Vec<String> = doc
        .get("trustedDependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    for name in names {
        if !trusted.contains(name) {
            trusted.push(name.clone());
        }
    }
    doc.insert("trustedDependencies", Value::from(trusted));
    let text = project::format_manifest(&doc, &raw);
    std::fs::write(&file, text).map_err(|e| Error::io(&e, format!("cannot write {}", file.display())))?;
    let install = install_tree(&mut Ctx::open(opts, false)?, None, None)?;
    Ok(Approved { approved, pending: install.unbuilt.clone(), install: Some(install) })
}

/// The global virtual store's entry directory, when it is wanted and the store can be written.
fn global_store(ctx: &Ctx, store: &Store) -> Option<PathBuf> {
    if !ctx.wants_global() {
        return None;
    }
    let dir = store.links_dir();
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Every wanted package in the store. An optional one that fails is skipped with a warning.
fn fill(store: &Store, wanted: &[&Package], dir: &Path) -> Result<()> {
    let results = pool::map(pool::network_threads(), wanted.to_vec(), |p| {
        (p, store.ensure(&tarball_of(dir, &p.resolved, p.source.as_deref()), &p.integrity))
    });
    for (p, r) in results {
        let Err(e) = r else { continue };
        if !p.optional && p.source.is_some() {
            return Err(stale(e, p.source.as_deref().unwrap_or("")));
        }
        // Offline, a missing optional fails too: skipped, it would not be fetched again.
        if !p.optional || e.code == "EOFFLINE" {
            return Err(e);
        }
        warn(&format!("skipped optional {}@{}: {e}", p.name, p.version));
    }
    Ok(())
}

/// Where the store reads a package: a local tarball as a file, anything else by url.
fn tarball_of(dir: &Path, resolved: &str, source: Option<&str>) -> Tarball {
    match source.and_then(|s| s.strip_prefix("file:")) {
        Some(path) => Tarball::File(dir.join(path)),
        None => Tarball::Url(resolved.to_string()),
    }
}

/// A tarball dependency whose bytes are not the ones the lockfile pinned.
fn stale(e: Error, source: &str) -> Error {
    if e.code != "EINTEGRITY" {
        return e;
    }
    fail(
        "EINTEGRITY",
        format!("{source} changed since {LOCKFILE} locked it ({e}); remove it and add it again to lock the new one"),
    )
}

/// Each local tarball the lockfile names, with the stamp this command took before checking it.
fn files_of(ctx: &Ctx, lock: &Lockfile) -> BTreeMap<String, Option<Stamp>> {
    let stamped = ctx.stamped.lock().unwrap_or_else(PoisonError::into_inner);
    local_sources(lock).into_values().map(|s| (s.clone(), stamped.get(&s).cloned())).collect()
}

fn same_files(dir: &Path, files: &BTreeMap<String, Option<Stamp>>) -> bool {
    files.iter().all(|(source, stamp)| {
        let at = dir.join(source.trim_start_matches("file:"));
        stamp.is_some() && stamp_of(&at) == *stamp
    })
}

/// The lockfile's local tarballs: key -> source.
fn local_sources(lock: &Lockfile) -> BTreeMap<String, String> {
    lock.packages
        .keys()
        .filter_map(|k| k.find("@file:").filter(|at| *at > 0).map(|at| (k.clone(), k[at + 1..].to_string())))
        .collect()
}

/// pnpm records only `hasBin`: those bins are read out of the store before the state hash.
fn read_bins(res: &mut Resolution, store: &Store, keys: &[String], dir: &Path) -> Result<()> {
    for key in keys {
        let Some(p) = res.packages.get_mut(key) else { continue };
        if let Err(e) = store.ensure(&tarball_of(dir, &p.resolved, p.source.as_deref()), &p.integrity) {
            if p.optional {
                continue;
            }
            return Err(e);
        }
        let Ok(file) = store.file(&p.integrity, "package.json") else { continue };
        if let Ok(text) = std::fs::read_to_string(file)
            && let Ok(m) = Manifest::from_json(&text)
        {
            p.bin = m.bins();
        }
    }
    Ok(())
}

/// The lockfile to install from. `frozen` reads it and never writes it.
fn plan(
    ctx: &mut Ctx,
    project: &Project,
    store: &Store,
    on_pick: Option<&resolve::OnPick>,
    recorded: Option<BTreeMap<String, Option<Stamp>>>,
) -> Result<Lockfile> {
    let dir = &project.dir;
    let (_, foreign_file) = ctx.lock_source(dir)?;
    if let Some(file) = foreign_file {
        // Frozen is CI: read in memory, write nothing. Otherwise jpm.lock takes over.
        return if ctx.opts.frozen {
            foreign_lock(ctx, project, store, file, on_pick)
        } else {
            import(ctx, project, store, file, on_pick)
        };
    }
    let existing = if ctx.opts.frozen { lock::read_lockfile(dir)?.map(|(l, _)| l) } else { current_lock(dir) };
    let reader = |source: &str, pinned: Option<&str>| read_tarball(ctx, store, dir, source, pinned);
    let moved = match &existing {
        Some(l) => moved_tarballs(ctx, dir, l, &reader, recorded.unwrap_or_default())?,
        None => Vec::new(),
    };
    if let Some(l) = &existing
        && moved.is_empty()
        && lock::same_tree(l, &project.manifest, &project.workspaces)
        && !ctx.dedupe
    {
        let mut l = l.clone();
        // upm's JSON, an older jpm.lock or a hand edit: written again in jpm's format, hash and all.
        if l.hash.is_none() && !ctx.opts.frozen {
            lock::write_lockfile(dir, &mut l)?;
            ctx.source = None;
            info(&format!("wrote {} in jpm's lockfile format", dir.join(LOCKFILE).display()));
        }
        return Ok(l);
    }
    if ctx.opts.frozen {
        let why = match &existing {
            None => "is missing".to_string(),
            Some(l) if !moved.is_empty() => {
                let sources = local_sources(l);
                let changed: Vec<&str> = moved.iter().filter_map(|k| sources.get(k).map(String::as_str)).collect();
                format!("is out of date: {} changed since it was locked", changed.join(", "))
            }
            Some(_) => "is out of date with package.json".into(),
        };
        return Err(fail("ELOCK", format!("{} {why}", dir.join(LOCKFILE).display())));
    }
    let registry = ctx.registry(store);
    resolve_lock(ctx, project, existing, &registry, &reader, on_pick, &moved, true, None)
}

/// Another manager's lockfile becomes `jpm.lock`. When it describes package.json exactly it is
/// carried over as is, no registry asked; otherwise (out of date, workspaces, an older format)
/// the tree is resolved with the versions it names preferred wherever the ranges allow them.
fn import(
    ctx: &mut Ctx,
    project: &Project,
    store: &Store,
    file: &'static str,
    on_pick: Option<&resolve::OnPick>,
) -> Result<Lockfile> {
    let dir = &project.dir;
    let exact = foreign_lock(ctx, project, store, file, on_pick);
    let text = ctx.foreign_read.take().map(|(t, _)| t).unwrap_or_default();
    ctx.source = None;
    let lock = match exact {
        Ok(mut lock) => {
            fill_bins(ctx, &mut lock, store, dir)?;
            lock::write_lockfile(dir, &mut lock)?;
            info(&format!("wrote {} from {file} with the same versions; {file} is no longer read", LOCKFILE));
            lock
        }
        Err(why) => {
            info(&format!("{}; resolving with its versions preferred", why.message));
            let prefer = resolve::Prefer {
                legacy_peers: yarn_1(file, &text),
                ..foreign::prefer(file, &text).unwrap_or_default()
            };
            let reader = |source: &str, pinned: Option<&str>| read_tarball(ctx, store, dir, source, pinned);
            let registry = ctx.registry(store);
            let lock = resolve_lock(ctx, project, None, &registry, &reader, on_pick, &[], true, Some(&prefer))?;
            info(&format!("{file} is no longer read; it can be deleted"));
            lock
        }
    };
    ctx.binless.clear();
    ctx.scriptless = false;
    ctx.source = None;
    Ok(lock)
}

/// What a converted lockfile leaves out, read from the packages once they are in the store:
/// the bins pnpm marks only as `hasBin`, and which packages have install scripts, which bun.lock
/// never says (a `preinstall`, `install` or `postinstall`, or a `binding.gyp`, as the registry
/// decides `hasInstallScript`). Only what installs on this platform is fetched, in parallel, as
/// the install would next.
fn fill_bins(ctx: &Ctx, lock: &mut Lockfile, store: &Store, dir: &Path) -> Result<()> {
    let base = ctx.base_for();
    let mut keys = ctx.binless.clone();
    if ctx.scriptless {
        let here = filter_platform(lock::from_lockfile(lock, &base), &Platform::current())?;
        keys.extend(
            here.packages.iter().filter(|(_, p)| p.local.is_none() && p.source.is_none()).map(|(k, _)| k.clone()),
        );
        keys.sort();
        keys.dedup();
    }
    let jobs: Vec<(String, Tarball, String)> = keys
        .iter()
        .filter_map(|key| {
            let (name, version) = crate::graph::split_key(key)?;
            let e = lock.packages.get(key)?;
            let url = e.resolved.clone().unwrap_or_else(|| crate::registry::tarball_url(&base(name), name, version));
            Some((key.clone(), tarball_of(dir, &url, None), e.integrity.clone()))
        })
        .collect();
    let fetched = pool::map(pool::network_threads(), jobs, |(key, tarball, integrity)| {
        let got = store.ensure(&tarball, &integrity);
        (key, got)
    });
    for (key, got) in fetched {
        let binless = ctx.binless.contains(&key);
        let index = match got {
            Ok(index) => index,
            // Not needed for its bins: the install that follows reports it, or skips it if optional.
            Err(_) if !binless => continue,
            Err(e) => return Err(e),
        };
        let Some(entry) = lock.packages.get_mut(&key) else { continue };
        let text = std::fs::read_to_string(store.file(&entry.integrity, "package.json")?).unwrap_or_default();
        let manifest = Manifest::from_json(&text).ok();
        if binless && let Some(m) = &manifest {
            entry.bin = m.bins();
        }
        if ctx.scriptless {
            entry.scripts = manifest.is_some_and(|m| m.scripts) || index.files.iter().any(|f| f.path == "binding.gyp");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_lock(
    ctx: &Ctx,
    project: &Project,
    existing: Option<Lockfile>,
    registry: &Registry,
    reader: &resolve::TarballReader,
    on_pick: Option<&resolve::OnPick>,
    moved: &[String],
    write: bool,
    prefer: Option<&resolve::Prefer>,
) -> Result<Lockfile> {
    let base = ctx.base_for();
    let mut locked = existing.as_ref().map(|l| lock::from_lockfile(l, &base));
    if let Some(l) = &mut locked {
        for key in moved {
            l.packages.remove(key);
        }
    }
    let workspaces: Vec<(String, RootManifest)> =
        project.workspaces.iter().map(|w| (w.path.clone(), w.manifest.clone())).collect();
    let options = |locked| resolve::Options {
        registry,
        locked,
        dedupe: ctx.dedupe,
        workspaces: workspaces.clone(),
        tarball: Some(reader),
        on_pick,
        prefer,
        legacy_peers: ctx.config().legacy_peer_deps || prefer.is_some_and(|p| p.legacy_peers),
        threads: pool::network_threads(),
    };
    let mut resolution = resolve::resolve(&project.manifest, &options(locked.as_ref()))?;
    // Another pass lets kept ranges move onto versions a new range brought in.
    if ctx.dedupe {
        let mut size = usize::MAX;
        while resolution.packages.len() < size {
            size = resolution.packages.len();
            let previous = resolution;
            resolution =
                resolve::resolve(&project.manifest, &resolve::Options { locked: Some(&previous), ..options(None) })?;
        }
    }
    for w in &resolution.warnings {
        warn(w);
    }
    // An approval stays with its version and bytes, however the walk reached them.
    if let Some(existing) = &existing {
        for (key, p) in &mut resolution.packages {
            if let Some(e) = existing.packages.get(key) {
                p.build |= p.scripts && e.build && e.integrity == p.integrity;
            }
        }
    }
    let mut lock = lock::to_lockfile(&resolution, &base);
    if let Some(existing) = &existing {
        if lock::format_lockfile(&lock)? == lock::format_lockfile(existing)? {
            if ctx.dedupe {
                info("nothing to dedupe");
            }
            return Ok(existing.clone());
        }
        if ctx.dedupe {
            let dropped = existing.packages.len().saturating_sub(lock.packages.len());
            if dropped > 0 {
                info(&format!("dropped {dropped} packages"));
            }
        }
    }
    if write {
        lock::write_lockfile(&project.dir, &mut lock)?;
        info(&format!("wrote {} — {}", project.dir.join(LOCKFILE).display(), counts(&lock)));
    }
    Ok(lock)
}

/// A broken lockfile does not stop a resolve: writing a good one is the job.
fn current_lock(dir: &Path) -> Option<Lockfile> {
    match lock::read_lockfile(dir) {
        Ok(found) => found.map(|(l, _)| l),
        Err(e) => {
            warn(&format!("ignoring {LOCKFILE}: {e}"));
            None
        }
    }
}

/// A tarball dependency's package.json, with `dist` naming the source and its bytes' integrity.
fn read_tarball(ctx: &Ctx, store: &Store, dir: &Path, source: &str, pinned: Option<&str>) -> Result<Arc<Manifest>> {
    let at = tarball_of(dir, source, Some(source));
    let stamp = match (&at, pinned) {
        (Tarball::File(path), None) => stamp_of(path),
        _ => None,
    };
    let (index, integrity): (Arc<Index>, String) = match pinned {
        Some(p) => (store.ensure(&at, p).map_err(|e| stale(e, source))?, p.to_string()),
        None => store.adopt(&at).map_err(|e| stale(e, source))?,
    };
    if let Some(stamp) = stamp {
        ctx.stamped.lock().unwrap_or_else(PoisonError::into_inner).insert(source.to_string(), stamp);
    }
    if !index.files.iter().any(|f| f.path == "package.json") {
        return Err(fail("EMANIFEST", format!("{source} has no package.json")));
    }
    let text = std::fs::read_to_string(store.file(&integrity, "package.json")?)
        .map_err(|e| Error::io(&e, format!("cannot read the package.json of {source}")))?;
    let where_ = format!("package.json of {source}");
    // Written by hand, not checked by a registry.
    RootManifest::parse(&text, Path::new(&where_))?;
    let mut m = Manifest::from_json(&text).map_err(|e| e.context(&where_))?;
    let exact = semver::parse(&m.version).map(|v| v.text);
    let Some(exact) = exact else { return Err(fail("EMANIFEST", format!("{where_} has no valid version"))) };
    m.version = exact;
    m.dist.tarball = Some(source.to_string());
    m.dist.integrity = Some(integrity);
    m.full = true;
    Ok(Arc::new(m))
}

/// The lockfile's local tarballs whose file no longer holds the bytes it pinned.
fn moved_tarballs(
    ctx: &Ctx,
    dir: &Path,
    lock: &Lockfile,
    read: &resolve::TarballReader,
    recorded: BTreeMap<String, Option<Stamp>>,
) -> Result<Vec<String>> {
    let mut moved = Vec::new();
    for (key, source) in local_sources(lock) {
        let Some(stamp) = stamp_of(&dir.join(source.trim_start_matches("file:"))) else { continue };
        if recorded.get(&source).and_then(Clone::clone).as_ref() == Some(&stamp) {
            ctx.stamped.lock().unwrap_or_else(PoisonError::into_inner).insert(source.clone(), stamp);
            continue;
        }
        let read = read(&source, None)?;
        if read.dist.integrity.as_deref() != Some(lock.packages[&key].integrity.as_str()) {
            info(&format!("{source} changed since {LOCKFILE} locked it"));
            moved.push(key);
        }
    }
    moved.sort();
    Ok(moved)
}

fn foreign_lock(
    ctx: &mut Ctx,
    project: &Project,
    store: &Store,
    file: &'static str,
    on_pick: Option<&resolve::OnPick>,
) -> Result<Lockfile> {
    let path = project.dir.join(file);
    let stamp = stamp_of(&path);
    let text =
        std::fs::read_to_string(&path).map_err(|e| Error::io(&e, format!("cannot read {file}")).with_code("ELOCK"))?;
    ctx.foreign_read = Some((text.clone(), stamp));
    if file == "yarn.lock" {
        // It names too little to link from, so the registry fills in the rest: every range
        // gets the version yarn gave it, and a range it does not name means it is out of date.
        let prefer = resolve::Prefer { only: true, legacy_peers: yarn_1(file, &text), ..foreign::prefer(file, &text)? };
        let ctx = &*ctx;
        let reader = |source: &str, pinned: Option<&str>| read_tarball(ctx, store, &project.dir, source, pinned);
        let registry = ctx.registry(store);
        return resolve_lock(ctx, project, None, &registry, &reader, on_pick, &[], false, Some(&prefer)).map_err(|e| {
            if e.code == "ELOCK" {
                fail("ELOCK", format!("yarn.lock is out of date with package.json: {}", e.message))
            } else {
                e
            }
        });
    }
    let has_workspaces = project.manifest.workspaces.is_some() || !project.workspaces.is_empty();
    let loaded = foreign::load(file, &text, &project.manifest, has_workspaces, &ctx.base_for())?;
    for w in &loaded.warnings {
        warn(w);
    }
    ctx.binless = loaded.binless;
    ctx.scriptless = loaded.scriptless;
    Ok(loaded.lock)
}

/// yarn.lock from yarn 1, which has no `__metadata` and never installs peers.
fn yarn_1(file: &str, text: &str) -> bool {
    file == "yarn.lock" && !text.lines().any(|l| l == "__metadata:")
}

pub fn counts(lock: &Lockfile) -> String {
    let res = lock::from_lockfile(lock, &|_| String::new());
    let all: Vec<&Package> = res.packages.values().filter(|p| p.local.is_none()).collect();
    let optional = all.iter().filter(|p| p.optional).count();
    let dev = all.iter().filter(|p| p.dev).count();
    let n = lock.workspaces.len();
    let ws = if n > 0 { format!(", {n} workspace{}", if n == 1 { "" } else { "s" }) } else { String::new() };
    format!("{} packages, {optional} optional, {dev} dev{ws}", all.len())
}

// --- add and remove -------------------------------------------------------------------------

/// The package.json `add` and `remove` edit: the workspace picked, else the one cwd is in,
/// else the root's.
fn edit_target(ctx: &mut Ctx, command: &str) -> Result<Edit> {
    let mut project = ctx.load_project()?;
    let mut workspace = ctx.inside.clone();
    if let Some(select) = &ctx.opts.workspaces {
        let picked = select_workspaces(select, &project.dir, &project.workspaces)?;
        match picked.as_slice() {
            [] => return Err(fail("EWORKSPACE", format!("{command} found no workspace to edit"))),
            [one] => workspace = Some(one.clone()),
            many => {
                let names: Vec<&str> = many.iter().map(|w| w.name.as_str()).collect();
                return Err(fail(
                    "EWORKSPACE",
                    format!("{command} edits one package.json, and workspaces picks {}", names.join(", ")),
                ));
            }
        }
    }
    let dir = workspace.as_ref().map_or(project.dir.clone(), |w| w.dir.clone());
    let file = dir.join("package.json");
    let raw = std::fs::read_to_string(&file)
        .map_err(|e| Error::io(&e, format!("cannot read {}", file.display())).with_code("EMANIFEST"))?;
    let manifest = RootManifest::parse(&raw, &file)?;
    let doc = manifest.doc.clone();
    match &workspace {
        Some(w) => {
            if let Some(found) = project.workspaces.iter_mut().find(|x| x.path == w.path) {
                found.manifest = manifest;
            }
        }
        None => project.manifest = manifest,
    }
    Ok(Edit { file, raw, doc, project })
}

/// Apply the edited document to the project the install reads.
fn apply(edit: &mut Edit) -> Result<()> {
    let m = RootManifest::from_doc(edit.doc.clone(), &edit.file)?;
    let dir = edit.file.parent().map(Path::to_path_buf).unwrap_or_default();
    match edit.project.workspaces.iter_mut().find(|w| w.dir == dir) {
        Some(w) => w.manifest = m,
        None => edit.project.manifest = m,
    }
    Ok(())
}

fn save_manifest(edit: &Edit) -> Result<()> {
    let text = project::format_manifest(&edit.doc, &edit.raw);
    if text == edit.raw {
        return Ok(());
    }
    std::fs::write(&edit.file, text)
        .map_err(|e| Error::io(&e, format!("cannot write {}", edit.file.display())).with_code("EMANIFEST"))
}

pub struct AddResult {
    pub added: Vec<Added>,
    pub install: InstallResult,
}

pub fn add(specs: &[String], opts: Opts) -> Result<AddResult> {
    if specs.is_empty() {
        return Err(fail("EOPTION", "add needs at least one spec"));
    }
    let group = opts.group.unwrap_or("dependencies");
    let bare: Vec<Option<String>> = specs.iter().map(|s| spec::bare_tarball(s)).collect::<Result<_>>()?;
    let parsed: Vec<Option<spec::Spec>> = specs
        .iter()
        .zip(&bare)
        .map(|(s, b)| if b.is_none() { spec::parse_spec(s).map(Some) } else { Ok(None) })
        .collect::<Result<_>>()?;
    let mut ctx = Ctx::open(opts, false)?;
    let exact = ctx.opts.exact || ctx.config().save_exact;
    let mut edit = edit_target(&mut ctx, "add")?;
    let local: BTreeMap<String, String> =
        edit.project.workspaces.iter().map(|w| (w.name.clone(), w.version.clone())).collect();
    let store = ctx.store(false);
    let registry = ctx.registry(&store);
    let mut added: Vec<Added> = Vec::new();
    for ((raw, spec), bare) in specs.iter().zip(&parsed).zip(&bare) {
        let tarball = spec.as_ref().is_none_or(|s| s.kind == Kind::Tarball);
        if tarball {
            let fetch_spec =
                from_cwd(&edit.file, bare.as_deref().or(spec.as_ref().map(|s| s.fetch_spec.as_str())).unwrap_or(""));
            let name = match spec {
                Some(s) => s.name.clone(),
                None => {
                    let base =
                        crate::util::relative(&edit.project.dir, edit.file.parent().unwrap_or(&edit.project.dir));
                    let source = spec::tarball_source(&fetch_spec, &base.to_string_lossy().replace('\\', "/"));
                    let m = read_tarball(&ctx, &store, &edit.project.dir, &source, None)?;
                    if m.name.is_empty() {
                        return Err(fail(
                            "EINVALIDSPEC",
                            format!("{raw} has no name in its package.json: add it as <name>@{raw}"),
                        ));
                    }
                    m.name.clone()
                }
            };
            let range = spec::parse_dep(&name, &fetch_spec)?.fetch_spec;
            added.push(Added { name, range, group });
            continue;
        }
        let Some(spec) = spec else { continue };
        let version = match local.get(&spec.fetch_name).filter(|v| project::links_to(spec, v)) {
            Some(v) => v.clone(),
            None => registry.pick(spec, None, false)?.version.clone(),
        };
        added.push(Added { name: spec.name.clone(), range: project::save_range(spec, &version, exact), group });
    }
    for (i, d) in added.iter().enumerate() {
        if added[..i].iter().any(|o| o.name == d.name) {
            return Err(fail("EINVALIDSPEC", format!("{} is given more than once", d.name)));
        }
    }
    project::add_deps(&mut edit.doc, &added);
    apply(&mut edit)?;
    for d in &added {
        info(&format!("+ {}@{} in {}", d.name, d.range, d.group));
    }
    let install = install_tree(&mut ctx, Some(edit), None)?;
    Ok(AddResult { added, install })
}

/// A path `add` is given is the shell's, read from cwd; the package.json keeps it from its own
/// directory.
fn from_cwd(file: &Path, fetch_spec: &str) -> String {
    let Some(path) = fetch_spec.strip_prefix("file:") else { return fetch_spec.to_string() };
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let at = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
    let (Some(at_dir), Some(name)) = (at.parent(), at.file_name()) else { return fetch_spec.to_string() };
    let base = file.parent().unwrap_or(Path::new("."));
    let rel = crate::util::relative(&real(base), &real(at_dir)).join(name);
    format!("file:{}", rel.to_string_lossy().replace('\\', "/"))
}

pub fn remove(names: &[String], opts: Opts) -> Result<(Vec<String>, InstallResult)> {
    if names.is_empty() {
        return Err(fail("EOPTION", "remove needs at least one name"));
    }
    let mut ctx = Ctx::open(opts, false)?;
    let mut edit = edit_target(&mut ctx, "remove")?;
    let mut removed: Vec<String> = Vec::new();
    for n in names {
        if !removed.contains(n) {
            removed.push(n.clone());
        }
    }
    let missing = project::remove_deps(&mut edit.doc, &removed);
    if !missing.is_empty() {
        return Err(fail("ENODEP", format!("not a dependency in {}: {}", edit.file.display(), missing.join(", "))));
    }
    apply(&mut edit)?;
    for n in &removed {
        info(&format!("- {n}"));
    }
    let result = install_tree(&mut ctx, Some(edit), None)?;
    Ok((removed, result))
}

// --- lock, fetch, resolve, prune ------------------------------------------------------------

/// The lockfile of the whole graph, every platform's builds and dev packages included.
pub fn lock_command(opts: Opts, write: bool) -> Result<Lockfile> {
    let mut ctx = Ctx::open(opts, false)?;
    let project = ctx.load_project()?;
    let dir = project.dir.clone();
    let store = ctx.store(false);
    if let (_, Some(file)) = ctx.lock_source(&dir)? {
        // `--json` shows it without writing anything; otherwise jpm.lock takes over.
        return if write {
            import(&mut ctx, &project, &store, file, None)
        } else {
            foreign_lock(&mut ctx, &project, &store, file, None)
        };
    }
    let existing = current_lock(&dir);
    let reader = |source: &str, pinned: Option<&str>| read_tarball(&ctx, &store, &dir, source, pinned);
    let moved = match &existing {
        Some(l) => moved_tarballs(&ctx, &dir, l, &reader, BTreeMap::new())?,
        None => Vec::new(),
    };
    if let Some(l) = &existing
        && moved.is_empty()
        && lock::same_tree(l, &project.manifest, &project.workspaces)
    {
        let mut l = l.clone();
        if l.hash.is_none() && write {
            lock::write_lockfile(&dir, &mut l)?;
            info(&format!("wrote {} in jpm's lockfile format", dir.join(LOCKFILE).display()));
        }
        info(&format!("{LOCKFILE} is up to date — {}", counts(&l)));
        return Ok(l);
    }
    let registry = ctx.registry(&store);
    resolve_lock(&ctx, &project, existing, &registry, &reader, None, &moved, write, None)
}

#[derive(Debug)]
pub struct Fetched {
    pub name: String,
    pub version: String,
    pub cached: bool,
    pub files: usize,
    pub bytes: u64,
}

/// Fill the store with every package the lockfile names for this platform. No linking.
pub fn fetch_lockfile(opts: Opts) -> Result<Vec<Fetched>> {
    let mut ctx = Ctx::open(opts, false)?;
    let dir = ctx.project_dir();
    let lock = match ctx.lock_source(&dir)? {
        (_, Some(file)) => {
            let project = ctx.load_project()?;
            let store = ctx.store(false);
            foreign_lock(&mut ctx, &project, &store, file, None)?
        }
        _ => lock::read_lockfile(&dir)?
            .map(|(l, _)| l)
            .ok_or_else(|| fail("ELOCK", format!("no {LOCKFILE} in {}", dir.display())))?,
    };
    let store = ctx.store(false);
    let _hold = store.hold(false);
    let res = filter_platform(lock::from_lockfile(&lock, &ctx.base_for()), &Platform::current())?;
    for w in &res.warnings {
        warn(w);
    }
    let wanted: Vec<&Package> =
        res.packages.values().filter(|p| p.local.is_none() && !(ctx.opts.production && p.dev)).collect();
    let results = pool::map(pool::network_threads(), wanted, |p| {
        (p, store.ensure(&tarball_of(&dir, &p.resolved, p.source.as_deref()), &p.integrity))
    });
    let mut out = Vec::new();
    for (p, r) in results {
        match r {
            Ok(index) => out.push(fetched(&p.name, &p.version, !store.was_fetched(&p.integrity), &index)),
            Err(e) if p.optional => warn(&format!("skipped optional {}@{}: {e}", p.name, p.version)),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

impl Fetched {
    pub fn to_value(&self) -> Value {
        json::obj([
            ("name", (&self.name).into()),
            ("version", (&self.version).into()),
            ("cached", self.cached.into()),
            ("files", self.files.into()),
            ("bytes", self.bytes.into()),
        ])
    }
}

impl Pruned {
    pub fn to_value(&self) -> Value {
        json::obj([
            ("entries", self.entries.as_ref().map_or(Value::Null, gc::Swept::to_value)),
            ("shared", self.shared.to_value()),
            ("store", self.store.to_value()),
        ])
    }
}

fn fetched(name: &str, version: &str, cached: bool, index: &Index) -> Fetched {
    Fetched { name: name.into(), version: version.into(), cached, files: index.files.len(), bytes: index.unpacked_size }
}

/// What each spec resolves to on the registry, in order.
pub fn resolve_specs(specs: &[String], opts: Opts) -> Result<Vec<Arc<Manifest>>> {
    let ctx = Ctx::open(opts, false)?;
    let store = ctx.store(false);
    pick_all(&ctx, &store, specs)
}

fn pick_all(ctx: &Ctx, store: &Store, specs: &[String]) -> Result<Vec<Arc<Manifest>>> {
    if specs.is_empty() {
        return Err(fail("EOPTION", "needs at least one spec"));
    }
    let parsed: Vec<spec::Spec> = specs.iter().map(|s| spec::parse_spec(s)).collect::<Result<_>>()?;
    if let Some(t) = parsed.iter().find(|s| s.kind == Kind::Tarball) {
        return Err(fail("EINVALIDSPEC", format!("{} is a tarball, not a registry spec", t.raw)));
    }
    let registry = ctx.registry(store);
    pool::map(pool::network_threads(), parsed, |s| registry.pick(&s, None, false)).into_iter().collect()
}

/// Resolve each spec and add its tarball to the store.
pub fn fetch_specs(specs: &[String], opts: Opts) -> Result<Vec<Fetched>> {
    let ctx = Ctx::open(opts, false)?;
    let store = ctx.store(false);
    let _hold = store.hold(false);
    let picked = pick_all(&ctx, &store, specs)?;
    let results = pool::map(pool::network_threads(), picked, |m| {
        let r = m.integrity().and_then(|i| {
            let index = store.ensure(&Tarball::Url(m.dist.tarball.clone().unwrap_or_default()), &i)?;
            Ok((index, i))
        });
        (m, r)
    });
    results
        .into_iter()
        .map(|(m, r)| r.map(|(index, i)| fetched(&m.name, &m.version, !store.was_fetched(&i), &index)))
        .collect()
}

#[derive(Debug)]
pub struct Pruned {
    pub entries: Option<gc::Swept>,
    pub shared: gc::Swept,
    pub store: gc::Swept,
}

pub fn prune(opts: Opts) -> Result<Pruned> {
    let mut ctx = Ctx::open(opts, false)?;
    let dir = ctx.project_dir();
    let store = ctx.store(false);
    let hold = store.hold(true);
    let entries = state::read(&dir).map(|s| gc::sweep_entries(&dir, &s.entries.into_iter().collect()));
    if entries.is_some() {
        store.register(&dir);
    }
    if hold.is_none() {
        return Ok(Pruned { entries, shared: gc::Swept::default(), store: gc::Swept::default() });
    }
    let (shared, used) = gc::mark(&store);
    let shared = gc::sweep_shared(&store.links_dir(), &shared);
    Ok(Pruned { entries, shared, store: gc::prune_store(&store.pkg_root(), &store.tmp_dir(), &used) })
}

// --- run and exec ---------------------------------------------------------------------------

pub struct ScriptPackage {
    pub name: String,
    pub path: String,
    pub dir: PathBuf,
    pub file: PathBuf,
    pub manifest: RootManifest,
}

/// cwd's own package.json (or `dir`'s); under `workspaces`, each workspace picked, in run order.
pub fn packages(opts: &Opts) -> Result<Vec<ScriptPackage>> {
    let Some(select) = &opts.workspaces else {
        let dir = std::path::absolute(opts.dir.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default()))
            .unwrap_or_default();
        let file = dir.join("package.json");
        let manifest = project::read_manifest(&file)?;
        let name = manifest.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| basename(&dir));
        return Ok(vec![ScriptPackage { name, path: ".".into(), dir, file, manifest }]);
    };
    let mut ctx = Ctx::new(opts.clone(), false);
    let project = ctx.load_project()?;
    let picked = select_workspaces(select, &project.dir, &project.workspaces)?;
    let (order, cycles) = run_order(&project.workspaces);
    for cycle in cycles {
        if cycle.iter().any(|w| picked.iter().any(|p| p.path == w.path)) {
            let names: Vec<&str> = cycle.iter().map(|w| w.name.as_str()).collect();
            warn(&format!("workspaces {} depend on each other; running them as declared", names.join(", ")));
        }
    }
    let mut out = Vec::new();
    if opts.include_root {
        let name = project.manifest.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| basename(&project.dir));
        out.push(ScriptPackage {
            name,
            path: ".".into(),
            file: project.dir.join("package.json"),
            dir: project.dir.clone(),
            manifest: project.manifest.clone(),
        });
    }
    for w in order.into_iter().filter(|w| picked.iter().any(|p| p.path == w.path)) {
        out.push(ScriptPackage {
            name: w.name,
            path: w.path,
            file: w.dir.join("package.json"),
            dir: w.dir,
            manifest: w.manifest,
        });
    }
    Ok(out)
}

fn basename(dir: &Path) -> String {
    dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Every workspace after the ones it depends on (by `workspace:` or a fitting range), otherwise
/// as declared. A cycle comes out together, as declared, and is reported.
fn run_order(all: &[Workspace]) -> (Vec<Workspace>, Vec<Vec<Workspace>>) {
    let depends = |ws: &Workspace, dep: &Workspace| {
        [&ws.manifest.dependencies, &ws.manifest.dev_dependencies, &ws.manifest.optional_dependencies].iter().any(|g| {
            g.iter().any(|(n, r)| {
                spec::parse_dep(n, r).is_ok_and(|s| s.fetch_name == dep.name && project::links_to(&s, &dep.version))
            })
        })
    };
    let n = all.len();
    let (mut index, mut low) = (vec![usize::MAX; n], vec![0; n]);
    let (mut stack, mut on) = (Vec::new(), vec![false; n]);
    let (mut order, mut cycles) = (Vec::new(), Vec::new());
    let mut counter = 0;
    #[allow(clippy::too_many_arguments)]
    fn visit(
        v: usize,
        all: &[Workspace],
        depends: &dyn Fn(&Workspace, &Workspace) -> bool,
        index: &mut [usize],
        low: &mut [usize],
        stack: &mut Vec<usize>,
        on: &mut [bool],
        counter: &mut usize,
        order: &mut Vec<Workspace>,
        cycles: &mut Vec<Vec<Workspace>>,
    ) {
        index[v] = *counter;
        low[v] = *counter;
        *counter += 1;
        stack.push(v);
        on[v] = true;
        for d in 0..all.len() {
            if d == v || !depends(&all[v], &all[d]) {
                continue;
            }
            if index[d] == usize::MAX {
                visit(d, all, depends, index, low, stack, on, counter, order, cycles);
                low[v] = low[v].min(low[d]);
            } else if on[d] {
                low[v] = low[v].min(index[d]);
            }
        }
        if low[v] != index[v] {
            return;
        }
        let at = stack.iter().position(|x| *x == v).unwrap_or(0);
        let mut members: Vec<usize> = stack.split_off(at);
        for m in &members {
            on[*m] = false;
        }
        members.sort_unstable();
        let group: Vec<Workspace> = members.iter().map(|m| all[*m].clone()).collect();
        if group.len() > 1 {
            cycles.push(group.clone());
        }
        order.extend(group);
    }
    for v in 0..n {
        if index[v] == usize::MAX {
            visit(v, all, &depends, &mut index, &mut low, &mut stack, &mut on, &mut counter, &mut order, &mut cycles);
        }
    }
    (order, cycles)
}

/// The workspaces an option names: a name, a path from the root or cwd, or a directory above
/// some. Every entry has to find one.
fn select_workspaces(select: &Select, root: &Path, all: &[Workspace]) -> Result<Vec<Workspace>> {
    let Select::Some(list) = select else { return Ok(all.to_vec()) };
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut picked: HashSet<String> = HashSet::new();
    for arg in list {
        let dirs = [normalize(&root.join(arg)), normalize(&cwd.join(arg))];
        let exact: Vec<&Workspace> =
            all.iter().filter(|w| w.name == *arg || dirs.contains(&normalize(&w.dir))).collect();
        let under: Vec<&Workspace> = all
            .iter()
            .filter(|w| dirs.iter().any(|d| normalize(&w.dir).starts_with(d) && normalize(&w.dir) != *d))
            .collect();
        let hits = if exact.is_empty() { under } else { exact };
        if hits.is_empty() {
            return Err(fail("EWORKSPACE", format!("no workspace is named or at {arg}")));
        }
        picked.extend(hits.into_iter().map(|w| w.path.clone()));
    }
    Ok(all.iter().filter(|w| picked.contains(&w.path)).cloned().collect())
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[derive(Debug)]
pub struct ScriptResult {
    pub name: String,
    pub path: String,
    pub file: PathBuf,
    pub code: Option<i32>,
    pub missing: bool,
}

/// One package.json script, or one per workspace picked. `replace`: a single script may take
/// over this process, so signals and the exit code are the script's own.
pub fn run_script(script: &str, args: &[String], opts: &Opts, replace: bool) -> Result<(i32, Vec<ScriptResult>)> {
    let logged = opts.workspaces.is_some();
    let tops = packages(opts)?;
    let found = tops.iter().any(|t| t.manifest.scripts(&t.file).is_ok_and(|s| s.contains_key(script)));
    if found {
        install_first(opts)?;
    }
    let mut results = Vec::new();
    let single = tops.len() == 1;
    for top in tops {
        let scripts = top.manifest.scripts(&top.file)?;
        let Some(command) = scripts.get(script).and_then(Value::as_str) else {
            if !opts.if_present && logged {
                warn(&format!("missing script \"{script}\" in {}", top.file.display()));
            }
            results.push(ScriptResult { name: top.name, path: top.path, file: top.file, code: None, missing: true });
            continue;
        };
        let bins = run::bin_dirs(&top.dir);
        let batch = cfg!(windows)
            && !args.is_empty()
            && crate::shim::is_batch(&crate::shim::first_word(command), &top.dir, &bins);
        let line = run::shell_line(command, args, batch);
        if !ui::quiet() {
            let at = if logged { format!("{}: ", top.name) } else { String::new() };
            eprintln!("{}", ui::paint(ui::GRAY, &format!("> {at}{script}\n> {line}"), false));
        }
        let mut cmd = run::shell(&line, &top.dir, &bins);
        let version = top.manifest.version.clone().unwrap_or_default();
        run::script_env(&mut cmd, &top.file, script, command, top.manifest.name.as_deref().unwrap_or(""), &version);
        let code = if replace && single && !logged {
            crate::sys::exec(&mut cmd).map_err(|e| run::start_error(&e, &cmd))?
        } else {
            run::wait(&mut cmd)?
        };
        results.push(ScriptResult { name: top.name, path: top.path, file: top.file, code: Some(code), missing: false });
    }
    let failed: Vec<&ScriptResult> =
        results.iter().filter(|r| if r.missing { !opts.if_present } else { r.code != Some(0) }).collect();
    if logged {
        for r in &failed {
            warn(&format!("{script} failed in {} ({}) with code {}", r.name, r.path, r.code.unwrap_or(1)));
        }
    }
    let code = failed.first().map_or(0, |r| r.code.unwrap_or(1));
    Ok((code, results))
}

/// `run`'s install: of the tree its packages are in, as that tree was last installed.
fn install_first(opts: &Opts) -> Result<()> {
    let start = std::path::absolute(opts.dir.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default()))
        .unwrap_or_default();
    let found = project::find_root(&start);
    let root = found.dir.clone();
    let previous = state::read(&root);
    let mut install = opts.clone();
    install.dir = Some(root.clone());
    install.workspaces = None;
    install.production = previous.as_ref().is_some_and(|s| s.production);
    if install.store.is_none() {
        install.store = previous.as_ref().map(|s| PathBuf::from(&s.store));
    }
    let mut ctx = Ctx::new(install, false);
    ctx.root = Some(root);
    ctx.inside = found.workspace.clone();
    ctx.found = Some(found);
    ctx.opened()?;
    let project = ctx.load_project()?;
    // No lockfile or node_modules for a project that never needed one.
    if previous.is_none() && !project.manifest.declares() && project.workspaces.is_empty() {
        return Ok(());
    }
    let result = install_tree(&mut ctx, None, Some(project))?;
    for id in &result.missing_optional {
        warn(&format!("{id} is missing from the store"));
    }
    if !result.up_to_date {
        info(&format!("installed {} packages", result.packages));
    }
    Ok(())
}

pub struct ExecOpts {
    pub opts: Opts,
    pub args: Vec<String>,
    /// Registry packages to install first; `command` is then a command line word.
    pub packages: Option<Vec<String>>,
    /// `command` is a shell line, run as written.
    pub call: bool,
}

/// A package's bin, as npx runs one: a local bin when the name has one, else installed into a
/// project of its own under the exec home, one per set of versions and registries.
/// npm's own commands (publish, login, view...), handed to the npm on PATH as they are. Never an
/// npm from a project or its dependencies' bins, which would see the credentials these handle,
/// and never one installed on the fly from a registry a project's .npmrc chose.
pub fn npm(command: &str, args: &[String], dir: Option<&Path>) -> Result<i32> {
    let npm = run::which("npm")
        .ok_or_else(|| fail("ENOENT", format!("npm is not on PATH; jpm hands `{command}` to npm as it is")))?;
    let mut cmd = std::process::Command::new(npm);
    cmd.arg(command).args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    // Or npm's version and init, run in a workspace, would install the tree their own way.
    cmd.env("npm_config_workspaces_update", "false");
    crate::sys::exec(&mut cmd).map_err(|err| Error::io(&err, "cannot start npm"))
}

pub fn exec(command: &str, e: ExecOpts) -> Result<i32> {
    if e.call && !e.args.is_empty() {
        return Err(fail("EOPTION", "exec takes a call line or args, not both"));
    }
    let cwd = std::path::absolute(e.opts.dir.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default()))
        .unwrap_or_default();
    let run_line = |line: &str, dirs: Vec<PathBuf>| -> Result<i32> {
        let mut all = dirs;
        all.extend(run::bin_dirs(&cwd));
        let mut cmd = run::shell(line, &cwd, &all);
        crate::sys::exec(&mut cmd).map_err(|err| run::start_error(&err, &cmd))
    };
    let spawn = |words: &[String], dirs: Vec<PathBuf>| -> Result<i32> {
        let head: Vec<String> = words.iter().map(|w| run::quote(w, cfg!(windows), false)).collect();
        let first: Vec<PathBuf> = dirs.iter().cloned().chain(run::bin_dirs(&cwd)).collect();
        let batch = cfg!(windows) && !e.args.is_empty() && crate::shim::is_batch(&words[0], &cwd, &first);
        run_line(&run::shell_line(&head.join(" "), &e.args, batch), dirs)
    };
    if e.call && e.packages.is_none() {
        return run_line(command, Vec::new());
    }
    if e.packages.is_none()
        && let Some(local) = self_bin(&cwd, command).or_else(|| local_bin(&cwd, command))
    {
        return spawn(&local, Vec::new());
    }
    let own = if e.packages.is_none() { Some(spec::parse_spec(command)?) } else { None };
    if e.packages.as_ref().is_some_and(Vec::is_empty) {
        return Err(fail("EOPTION", "exec lists no package to install"));
    }
    let quiet = ui::quiet();
    let mut ctx = Ctx::open(e.opts.clone(), false)?;
    let specs = e.packages.clone().unwrap_or_else(|| vec![command.to_string()]);
    ui::set_quiet(true); // the install's progress is about a directory nobody chose
    let installed = (|| {
        let (dir, names) = exec_project(&mut ctx, &specs)?;
        let result = install_tree(&mut ctx, None, None)?;
        Ok::<_, Error>((dir, names, result))
    })();
    ui::set_quiet(quiet);
    let (dir, names, result) = installed?;
    if !result.up_to_date {
        info(&format!("installed {}", names.join(", ")));
    }
    let bins = vec![dir.join("node_modules").join(".bin")];
    if e.call {
        return run_line(command, bins);
    }
    let bin = match &own {
        Some(s) => {
            let file = dir.join("node_modules").join(&s.name).join("package.json");
            let doc = json::parse(&std::fs::read_to_string(&file).unwrap_or_default()).unwrap_or(Value::Null);
            pick_bin(&doc, &s.fetch_name)?
        }
        None => command.to_string(),
    };
    spawn(&[bin], bins)
}

/// Where the specs install, made the context's root; the config stays the one already read.
fn exec_project(ctx: &mut Ctx, specs: &[String]) -> Result<(PathBuf, Vec<String>)> {
    let parsed: Vec<spec::Spec> = specs.iter().map(|s| spec::parse_spec(s)).collect::<Result<_>>()?;
    if let Some(l) = parsed.iter().find(|s| matches!(s.kind, Kind::Workspace | Kind::Tarball)) {
        return Err(fail("EINVALIDSPEC", format!("exec installs registry packages, not {}", l.raw)));
    }
    let store = ctx.store(false);
    let loose: Vec<String> = parsed.iter().filter(|s| s.kind != Kind::Version).map(|s| s.raw.clone()).collect();
    let picked = if loose.is_empty() { Vec::new() } else { pick_all(ctx, &store, &loose)? };
    let mut deps: BTreeMap<String, String> = BTreeMap::new();
    let mut loose_i = 0;
    for s in &parsed {
        if deps.contains_key(&s.name) {
            return Err(fail("EINVALIDSPEC", format!("{} is given more than once", s.name)));
        }
        let version = if s.kind == Kind::Version {
            semver::parse(&s.fetch_spec).map(|v| v.text).unwrap_or_default()
        } else {
            loose_i += 1;
            picked[loose_i - 1].version.clone()
        };
        let range = if s.name == s.fetch_name { version } else { format!("npm:{}@{version}", s.fetch_name) };
        deps.insert(s.name.clone(), range);
    }
    let text = json::to_pretty(&json::obj([("private", true.into()), ("dependencies", json::str_map(&deps))]), "  ");
    let c = ctx.config();
    let key = crate::util::short_hash(&json::to_string(&Value::Array(vec![
        c.registry.as_str().into(),
        json::str_map(&c.scopes),
        text.as_str().into(),
    ])));
    let root = ctx.project_dir();
    let dir = exec_home(&root).join(key);
    let file = dir.join("package.json");
    if std::fs::read_to_string(&file).ok().as_deref() != Some(text.as_str()) {
        std::fs::create_dir_all(&dir).map_err(|err| Error::io(&err, format!("cannot create {}", dir.display())))?;
        crate::util::write_atomic(&file, text.as_bytes())?;
    }
    ctx.root = Some(dir.clone());
    ctx.found = None;
    ctx.inside = None;
    ctx.source = None;
    Ok((dir, deps.into_iter().map(|(n, r)| format!("{n}@{r}")).collect()))
}

/// The project's `node_modules/.jpm/.exec` when it has a tree, else `~/.jpm/exec`.
fn exec_home(root: &Path) -> PathBuf {
    if root.join("node_modules").is_dir() && root.join("package.json").is_file() {
        return root.join("node_modules").join(".jpm").join(".exec");
    }
    crate::config::home().join(".jpm").join("exec")
}

/// The command as a bin of the nearest package.json above `dir`: `npx my-cli` inside my-cli.
fn self_bin(dir: &Path, command: &str) -> Option<Vec<String>> {
    for at in dir.ancestors() {
        let file = at.join("package.json");
        if !file.is_file() {
            continue;
        }
        let doc = json::parse(&std::fs::read_to_string(&file).ok()?).ok()?;
        let bins = crate::bin::normalize(doc.get("name").and_then(Value::as_str), doc.get("bin"));
        let target = at.join(bins.get(command)?);
        let runs = !cfg!(windows) && is_exec(&target);
        let target = target.to_string_lossy().into_owned();
        return Some(if runs { vec![target] } else { vec!["node".into(), target] });
    }
    None
}

fn is_exec(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// The bin a command runs where it is installed, nearest first: a bin of that name, or the bin of
/// the package the spec names where the installed version fits.
fn local_bin(dir: &Path, command: &str) -> Option<Vec<String>> {
    let one_segment = !command.contains(['/', '\\']) && command != "." && command != "..";
    let spec = spec::parse_spec(command).ok();
    let shim =
        |bins: &Path, name: &str| bins.join(if cfg!(windows) { format!("{name}.cmd") } else { name.to_string() });
    for bins in run::bin_dirs(dir) {
        if one_segment && shim(&bins, command).is_file() {
            return Some(vec![shim(&bins, command).to_string_lossy().into_owned()]);
        }
        let Some(s) = &spec else { continue };
        let pkg_file = bins.parent()?.join(&s.name).join("package.json");
        let Some(doc) = std::fs::read_to_string(&pkg_file).ok().and_then(|t| json::parse(&t).ok()) else {
            continue;
        };
        let version = doc.get("version").and_then(Value::as_str);
        let fits = s.raw == s.name
            || (matches!(s.kind, Kind::Version | Kind::Range)
                && s.name == s.fetch_name
                && version.is_some_and(|v| semver::satisfies(v, &s.fetch_spec)));
        if !fits {
            continue;
        }
        let Ok(own) = pick_bin(&doc, &s.name) else { continue };
        if shim(&bins, &own).is_file() {
            return Some(vec![shim(&bins, &own).to_string_lossy().into_owned()]);
        }
    }
    None
}

/// As npm picks: the one bin, or several that are one file; else the one named after the
/// package without its scope.
fn pick_bin(doc: &Value, name: &str) -> Result<String> {
    let bins = crate::bin::normalize(Some(doc.get("name").and_then(Value::as_str).unwrap_or(name)), doc.get("bin"));
    let targets: HashSet<&String> = bins.values().collect();
    if targets.len() == 1 {
        return Ok(bins.keys().next().cloned().unwrap_or_default());
    }
    let short = name.rsplit('/').next().unwrap_or(name);
    if bins.contains_key(short) {
        return Ok(short.to_string());
    }
    let why = if bins.is_empty() {
        "has no bin".to_string()
    } else {
        format!("has bins {} and none is {short}", bins.keys().cloned().collect::<Vec<_>>().join(", "))
    };
    Err(fail("ENOBIN", format!("{name} {why}")))
}

/// Whether `jpm <name>` names a bin installed above `dir`.
pub fn installed_bin(dir: &Path, name: &str) -> bool {
    self_bin(dir, name).is_some() || local_bin(dir, name).is_some()
}
