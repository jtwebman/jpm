//! Walk the root package.json and its workspaces into a flat, deterministic set of packages.
//! No hoisting and no placement: the linker's layout makes both unnecessary.
//!
//! Each edge is a job on a thread pool: pick a version (blocking on the registry), record the
//! package, queue its own edges. A failed pick marks the package that asked dead; `prune` then
//! drops dead packages up to the nearest optional edge. Peers are settled against the finished
//! walk, round by round until nothing new is fetched.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::{Error, Result};
use crate::graph::{Deps, Package, PeerKind, Peers, Resolution, Root};
use crate::manifest::Manifest;
use crate::pool::{self, Queue};
use crate::project::{self, RootManifest, declared_peers, local_path, local_shape};
use crate::registry::Registry;
use crate::rules::{self, Override};
use crate::semver;
use crate::spec::{self, Kind, Spec};

const ROOT: &str = "";

pub type TarballReader<'a> = dyn Fn(&str, Option<&str>) -> Result<Arc<Manifest>> + Sync + 'a;
pub type OnPick<'a> = dyn Fn(&Package, &str) + Sync + 'a;

pub struct Options<'a> {
    pub registry: &'a Registry,
    /// The previous resolution: an edge whose range a locked version satisfies keeps it.
    pub locked: Option<&'a Resolution>,
    /// Walk every package afresh, preferring the highest locked version a range allows.
    pub dedupe: bool,
    /// The workspaces, each a top like the root, as `(path, manifest)`.
    pub workspaces: Vec<(String, RootManifest)>,
    /// The directories the tops depend on by path.
    pub dirs: Vec<Dir>,
    /// Reads a tarball dependency's package.json, given its source and the integrity it is
    /// pinned to, if any. `dist.integrity` in what comes back is its bytes' integrity.
    pub tarball: Option<&'a TarballReader<'a>>,
    /// Told each package as the walk picks it, before its dependencies are walked.
    pub on_pick: Option<&'a OnPick<'a>>,
    /// Another manager's lockfile being brought over, so its choices survive where they fit.
    pub prefer: Option<&'a Prefer>,
    /// `legacy-peer-deps`: a peer is linked to what the tree has, and never added.
    pub legacy_peers: bool,
    /// pnpm's `block-exotic-subdeps`: only a top may take a git or tarball-url package.
    pub block_exotic: bool,
    pub threads: usize,
}

/// A directory a top depends on (`link:` or `file:`), at its root-relative path. A `file:`
/// directory inside the project is a top, as a workspace is: its dependencies install in its own
/// `node_modules`. A `link:` one, or one outside the project, is only linked: nothing is written
/// there, and its dependencies are its own.
#[derive(Debug, Clone)]
pub struct Dir {
    pub path: String,
    /// What the first top to depend on it calls it: a top is keyed by one name.
    pub name: String,
    pub top: bool,
    /// Its package.json, if it has one (a top must).
    pub manifest: Option<RootManifest>,
}

#[derive(Debug, Default)]
pub struct Prefer {
    /// Registry name -> the versions the file names.
    pub versions: HashMap<String, Vec<String>>,
    /// `name@range` -> the version the file resolved that very range to (yarn keys by range).
    pub ranges: HashMap<String, String>,
    /// Every registry range must be one of `ranges`: a frozen install from yarn.lock.
    pub only: bool,
    /// The file's manager never installs peers (yarn 1), so the resolve adds none.
    pub legacy_peers: bool,
}

#[derive(Debug, Clone)]
struct Edge {
    name: String,
    version: String,
    optional: bool,
}

struct Job {
    from: String,
    name: String,
    range: String,
    optional: bool,
    /// Skips the lockfile: a new consumer's unmet peer is fetched as a fresh resolve would.
    fresh: bool,
    /// A peer's fetch: with no version to fetch, it may settle on what its scope has.
    peer: bool,
}

/// A peer found in its consumer's scope: an edge to link, or an alias's version to fetch as the
/// package itself.
enum Scoped {
    Link(String),
    Fetch(String),
}

struct Top {
    manifest: RootManifest,
    prod: HashSet<String>,
}

#[derive(Default)]
struct State {
    records: HashMap<String, Package>,
    edges: HashMap<String, Vec<Edge>>,
    started: HashSet<String>,
    dead: HashMap<String, Error>,
    soft_peers: HashMap<String, Vec<(String, String)>>,
    hard_peers: Vec<(String, String, String)>,
    warnings: BTreeSet<String>,
    /// Ends the walk: yarn.lock lacks a range a frozen install needs.
    fatal: Option<Error>,
    /// Peers no version satisfies, as (consumer, name, range, why): settled once a round's
    /// fetches are all in, so what the scope has then does not hang on which thread came first.
    unfetched: Vec<(String, String, String, Error)>,
}

struct Walk<'a> {
    opts: &'a Options<'a>,
    state: Mutex<State>,
    tops: HashMap<String, Top>,
    /// Workspace name -> its record.
    local: HashMap<String, Package>,
    /// The root, named and not listed as a workspace: what `workspace:` finds for its name.
    root_local: Option<Package>,
    /// Registry packages of the lock, tarballs left out, by name.
    locked_versions: HashMap<String, Vec<String>>,
    picks: Memo<Arc<Manifest>>,
    libcs: Memo<Option<Vec<String>>>,
    runtimes: Memo<Package>,
    /// The tops' own registry edges, overrides applied, by the package they fetch.
    direct: HashMap<String, Vec<Spec>>,
}

/// Values computed once however many threads ask.
type Memo<V> = Mutex<HashMap<String, Arc<std::sync::OnceLock<Result<V>>>>>;

/// `block-exotic-subdeps` refusing a package's own git or tarball-url dependency.
pub fn exotic(from: &str, raw: &str) -> Error {
    Error::new(
        "EEXOTIC",
        format!(
            "{from} depends on {raw}: with block-exotic-subdeps, only the project may take a git or tarball-url package"
        ),
    )
}

fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn resolve(manifest: &RootManifest, opts: &Options) -> Result<Resolution> {
    let mut tops = HashMap::new();
    tops.insert(ROOT.to_string(), Top { prod: manifest.prod(), manifest: manifest.clone() });
    let mut local = HashMap::new();
    let mut state = State::default();
    for (path, m) in &opts.workspaces {
        let found = local_record(path, m)?;
        let key = found.key();
        tops.insert(key.clone(), Top { prod: m.prod(), manifest: m.clone() });
        state.started.insert(key.clone());
        state.records.insert(key, found.clone());
        // Of two with one name, the first is the one found by it (nothing links to it by name:
        // `find_workspaces` refuses that).
        local.entry(found.name.clone()).or_insert(found);
    }
    // The root listed as a workspace of its own: linked to by name, walked only as the root.
    if project::lists_root(manifest)
        && let Ok(found) = local_record(project::ROOT_PATH, manifest)
    {
        let found = Package { specs: None, peer_dependencies: None, peers: None, ..found };
        state.started.insert(found.key());
        state.records.insert(found.key(), found.clone());
        local.insert(found.name.clone(), found);
    }
    // Not listed, a named root is still what `workspace:` finds for its name, as pnpm and yarn
    // berry have it (hono's and nitro's examples link the root so); a range never links to it.
    let root_local = manifest
        .name
        .as_ref()
        .filter(|n| !n.is_empty() && !local.contains_key(*n))
        .and_then(|_| local_record(project::ROOT_PATH, manifest).ok())
        .map(|found| Package { specs: None, peer_dependencies: None, peers: None, ..found });
    // A `file:` directory inside the project is a top, as a workspace is, never linked by name.
    for dir in opts.dirs.iter().filter(|d| d.top) {
        let m = dir.manifest.clone().unwrap_or_default();
        let found = dir_record(dir, &m)?;
        let key = found.key();
        tops.insert(key.clone(), Top { prod: m.prod(), manifest: m });
        state.started.insert(key.clone());
        state.records.insert(key, found);
    }
    let mut locked_versions: HashMap<String, Vec<String>> = HashMap::new();
    for p in opts.locked.iter().flat_map(|l| l.packages.values()) {
        if p.local.is_none() && p.source.is_none() {
            locked_versions.entry(p.name.clone()).or_default().push(p.version.clone());
        }
    }
    let mut direct: HashMap<String, Vec<Spec>> = HashMap::new();
    for (key, top) in &tops {
        for (name, range, _) in top.manifest.edges() {
            let range = match rules::find(&manifest.overrides, crate::graph::split_key(key), &name, &range) {
                Some(None) => continue,
                Some(Some(r)) => r.to_string(),
                None => range,
            };
            let Ok(own) = spec::parse_dep(&name, &range) else { continue };
            // Not an alias: npm and yarn keep a dependency off the version a root alias pins (berry's
            // basic.test.js), though pnpm takes it.
            let plain = own.fetch_name == own.name && !local.contains_key(&own.name);
            if plain && matches!(own.kind, Kind::Version | Kind::Range | Kind::Tag) {
                direct.entry(own.fetch_name.clone()).or_default().push(own);
            }
        }
    }
    let walk = Walk {
        opts,
        state: Mutex::new(state),
        tops,
        local,
        root_local,
        locked_versions,
        picks: Mutex::default(),
        libcs: Mutex::default(),
        runtimes: Mutex::default(),
        direct,
    };
    walk.run()
}

impl Walk<'_> {
    fn run(&self) -> Result<Resolution> {
        let mut jobs = Vec::new();
        {
            let mut s = lock(&self.state);
            for (key, top) in &self.tops {
                s.edges.insert(key.clone(), Vec::new());
                for (name, range, optional) in top.manifest.edges() {
                    jobs.push(Job { from: key.clone(), name, range, optional, fresh: false, peer: false });
                }
                if key != ROOT {
                    let peers = s.records[key].peers.clone().unwrap_or_default();
                    settle(&mut s, key, true, &peers, top.manifest.peer_dependencies.as_ref(), self.overrides());
                }
            }
        }
        self.drain(jobs)?;
        self.prune()?;
        self.settle_peers()?;
        self.prune()?;
        self.wire_soft_peers();
        Ok(self.finish())
    }

    fn drain(&self, jobs: Vec<Job>) -> Result<()> {
        pool::run(self.opts.threads, jobs, |job, queue| self.edge(job, queue));
        lock(&self.state).fatal.take().map_or(Ok(()), Err)
    }

    fn edge(&self, job: Job, queue: &Queue<Job>) {
        let Job { from, name, range, optional, fresh, peer } = job;
        if lock(&self.state).fatal.is_some() {
            return;
        }
        if let Err(error) = self.try_edge(&from, &name, &range, optional, fresh, queue) {
            // Offline, a skipped optional would be locked out for good, where online it is fetched.
            let mut s = lock(&self.state);
            if peer && matches!(error.code, "ETARGET" | "ENOVERSIONS") {
                s.unfetched.push((from, name, range, error));
                return;
            }
            if !optional || error.code == "EOFFLINE" {
                let who = if from.is_empty() { "root" } else { &from };
                let error =
                    Error::new(error.code, format!("{} — resolving {name}@{range} (required by {who})", error.message));
                // Out of date is out of date: the rest of the walk would only download more.
                if error.code == "ELOCK" && self.opts.prefer.is_some_and(|p| p.only) {
                    s.fatal.get_or_insert(error);
                    return;
                }
                s.dead.entry(from).or_insert(error);
            } else {
                let who = if from.is_empty() { "root".to_string() } else { from };
                s.warnings.insert(format!("skipped optional {name}@{range} of {who}: {}", error.message));
            }
        }
    }

    fn try_edge(
        &self,
        from: &str,
        name: &str,
        range: &str,
        optional: bool,
        fresh: bool,
        queue: &Queue<Job>,
    ) -> Result<()> {
        let over = self.overridden(from, name, range);
        let range = match &over {
            Some(None) => return Ok(()),
            Some(Some(r)) if !self.tops.contains_key(from) && to_workspace(name, r) => {
                lock(&self.state).warnings.insert(workspace_override(name, r));
                range
            }
            Some(Some(r)) => r.as_str(),
            None => range,
        };
        let spec = spec::parse_dep(name, range)?;
        if spec.kind == Kind::Workspace && !self.tops.contains_key(from) {
            return Err(Error::new(
                "EWORKSPACE",
                format!("only the root and workspaces link to workspaces, so not {from}"),
            ));
        }
        // A git or tarball source the project's overrides chose is not the package's own.
        if matches!(spec.kind, Kind::Git | Kind::Tarball)
            && self.opts.block_exotic
            && !self.tops.contains_key(from)
            && over.is_none()
        {
            return Err(exotic(from, &spec.raw));
        }
        let push = |version: String| {
            if let Some(list) = lock(&self.state).edges.get_mut(from) {
                list.push(Edge { name: name.to_string(), version, optional });
            }
        };
        if spec.kind == Kind::Tarball {
            // An override's path is the root's, whoever's edge it replaces.
            let source = self.source_of(&spec.fetch_spec, if over.is_some() { ROOT } else { from })?;
            let key = format!("{}@{source}", spec.name);
            let pinned = self.opts.locked.and_then(|l| l.packages.get(&key)).map(|p| p.integrity.clone());
            if pinned.is_some() && !fresh && !self.opts.dedupe {
                self.visit_locked(from, &key);
            } else {
                let m = self.read(&source, pinned.as_deref())?;
                self.visit(from, &spec.name, &m, Some(&source), None, queue)?;
            }
            push(source);
            return Ok(());
        }
        if spec.kind == Kind::Directory {
            push(self.dir(from, &spec)?);
            return Ok(());
        }
        if spec.kind == Kind::Runtime {
            if !self.tops.contains_key(from) {
                lock(&self.state)
                    .warnings
                    .insert(format!("{from} declares {name}@{range}; only the root and workspaces install a runtime"));
                return Ok(());
            }
            push(self.runtime(from, &spec, fresh)?);
            return Ok(());
        }
        if spec.kind == Kind::Git {
            // The locked commit while the spec that chose it stands: a branch is not followed
            // until package.json names another ref.
            // The same repository, at the pinned commit if the spec pins one: never another the
            // lockfile names in its place.
            let kept = self.kept_commit(from, name, range).filter(|e| !fresh && spec::names_source(&spec, "", e));
            let source = match kept {
                Some(source) => {
                    self.visit_locked(from, &format!("{name}@{source}"));
                    source
                }
                None => {
                    let m = self.read(&spec.fetch_spec, None)?;
                    let source = m.dist.tarball.clone().unwrap_or_default();
                    self.visit(from, &spec.name, &m, Some(&source), None, queue)?;
                    source
                }
            };
            push(source);
            return Ok(());
        }
        if self.tops.contains_key(from)
            && let Some(ws) = self.local_for(&spec, from)?
        {
            push(ws.edge_version());
            return Ok(());
        }
        // An alias is keyed by the package it installs, not only by the name it takes.
        let alias = (spec.fetch_name != spec.name).then_some(spec.fetch_name.as_str());
        let edge = |version: &str| alias.map_or_else(|| version.to_string(), |a| crate::graph::alias_edge(a, version));
        let kept = if fresh || self.opts.dedupe { None } else { self.kept(&spec) };
        if let Some(version) = kept {
            self.visit_locked(from, &format!("{}@{}", spec.name, edge(&version)));
            push(edge(&version));
            return Ok(());
        }
        let m = self.pick(&spec, fresh, self.tops.contains_key(from))?;
        m.integrity()?;
        let key = format!("{}@{}", spec.name, edge(&m.version));
        let libc = needs_libc(&m);
        let first = self.visit(from, &spec.name, &m, None, alias, queue)?;
        if libc {
            // The read the walk above needs is this edge's to fail on.
            let read = self.libc_of(&m)?;
            let mut s = lock(&self.state);
            if let Some(record) = s.records.get_mut(&key) {
                if record.libc.is_none() {
                    record.libc = read;
                }
                if let (true, Some(on_pick)) = (first, self.opts.on_pick) {
                    on_pick(record, from);
                }
            }
        }
        push(edge(&m.version));
        Ok(())
    }

    fn overrides(&self) -> &[Override] {
        &self.tops[ROOT].manifest.overrides
    }

    /// What the root's overrides make of an edge: `None` leaves it, `Some(None)` takes it out.
    fn overridden(&self, from: &str, name: &str, range: &str) -> Option<Option<String>> {
        rules::find(self.overrides(), crate::graph::split_key(from), name, range).map(|v| v.map(str::to_string))
    }

    /// Memoized on the fetched name and range, so two aliases of one package share a pick. A
    /// package's edge (not a top's) takes the version a top's own edge to that package gets
    /// where its range allows it, as pnpm and npm dedupe it: a root pinning 1.0.0 keeps a
    /// dependency's ^1 off 1.1.0.
    fn pick(&self, spec: &Spec, fresh: bool, top: bool) -> Result<Arc<Manifest>> {
        let key = format!(
            "{}{}{}@{}",
            if fresh { "!" } else { "" },
            if top { "^" } else { "" },
            spec.fetch_name,
            spec.fetch_spec
        );
        let cell = self.picks.lock().unwrap_or_else(PoisonError::into_inner).entry(key).or_default().clone();
        cell.get_or_init(|| {
            // An exact version or the locked version dedupe prefers is asked for by version.
            let exact = (spec.kind == Kind::Version).then(|| semver::parse(&spec.fetch_spec).map(|v| v.text)).flatten();
            if exact.is_none() && self.opts.prefer.is_some_and(|p| p.only) && self.ranged(spec).is_none() {
                return Err(Error::new("ELOCK", format!("it has no {}@{}", spec.fetch_name, spec.fetch_spec)));
            }
            let kept = if self.opts.dedupe && !fresh { self.kept(spec) } else { None };
            let preferred = self.preferred(spec);
            let direct = if top || exact.is_some() { None } else { self.direct(spec) };
            let wanted = exact.or_else(|| kept.clone()).or_else(|| preferred.clone()).or_else(|| direct.clone());
            // A version a lockfile names was taken before: the release age is for new picks, and
            // a top's pick has met it already.
            let exempt = wanted.is_some() && (wanted == kept || wanted == preferred || wanted == direct);
            self.opts.registry.pick(spec, wanted.as_deref(), exempt)
        })
        .clone()
    }

    /// The newest version a top's own registry edge to this package gets that `spec` allows.
    fn direct(&self, spec: &Spec) -> Option<String> {
        if spec.kind != Kind::Range {
            return None;
        }
        let mut best: Option<semver::Version> = None;
        for own in self.direct.get(&spec.fetch_name).into_iter().flatten() {
            if own.fetch_spec == spec.fetch_spec {
                continue;
            }
            // As the top's edge takes it: the locked version while it fits, else a pick.
            let kept = if self.opts.dedupe { None } else { self.kept(own) };
            let Some(version) = kept.or_else(|| self.pick(own, false, true).ok().map(|m| m.version.clone())) else {
                continue;
            };
            let v = semver::parse(&version).filter(|v| semver::satisfies_version(v, &spec.fetch_spec, false));
            if v.is_some() && v > best {
                best = v;
            }
        }
        best.map(|v| v.text)
    }

    /// What the file resolved this very range to, else the highest version it names that the
    /// range allows; a tag only by the first, as the tag named it then.
    fn preferred(&self, spec: &Spec) -> Option<String> {
        if let Some(v) = self.ranged(spec) {
            return Some(v);
        }
        if spec.kind == Kind::Tag {
            return None;
        }
        let versions = self.opts.prefer?.versions.get(&spec.fetch_name)?;
        semver::max_satisfying(versions.iter().map(String::as_str), &spec.fetch_spec).map(str::to_string)
    }

    fn ranged(&self, spec: &Spec) -> Option<String> {
        let v = self.opts.prefer?.ranges.get(&format!("{}@{}", spec.fetch_name, spec.fetch_spec))?;
        (spec.kind == Kind::Tag || semver::satisfies(v, &spec.fetch_spec)).then(|| v.clone())
    }

    /// The abbreviated document leaves `libc` out, so every linux build costs a read of the full
    /// manifest; never guessed from the name.
    fn libc_of(&self, m: &Manifest) -> Result<Option<Vec<String>>> {
        let key = format!("{}@{}", m.name, m.version);
        let cell = self.libcs.lock().unwrap_or_else(PoisonError::into_inner).entry(key).or_default().clone();
        cell.get_or_init(|| Ok(self.opts.registry.manifest(&m.name, &m.version)?.libc.clone())).clone()
    }

    fn read(&self, source: &str, pinned: Option<&str>) -> Result<Arc<Manifest>> {
        let Some(read) = self.opts.tarball else {
            return Err(Error::new("EINVALIDSPEC", format!("nothing reads tarballs here, so not {source}")));
        };
        let cell =
            self.picks.lock().unwrap_or_else(PoisonError::into_inner).entry(source.to_string()).or_default().clone();
        cell.get_or_init(|| read(source, pinned)).clone()
    }

    /// A path is read from the package.json that declares it, so only a top may have one.
    fn source_of(&self, fetch_spec: &str, from: &str) -> Result<String> {
        if !fetch_spec.starts_with("file:") && !fetch_spec.starts_with("link:") {
            return Ok(fetch_spec.to_string());
        }
        let base = if from == ROOT {
            Some(String::new())
        } else {
            self.tops.get(from).and_then(|_| lock(&self.state).records.get(from).and_then(|r| r.local.clone()))
        };
        let Some(base) = base else {
            return Err(Error::new("EINVALIDSPEC", "only the root and workspaces may depend on a path"));
        };
        Ok(spec::source_at(fetch_spec, &base))
    }

    /// What a top's edge was locked to, while the top still declares it as it did then. Only a
    /// top: a package's own edges are replayed whole with it (`visit_locked`), or walked afresh.
    fn kept_commit(&self, from: &str, name: &str, range: &str) -> Option<String> {
        let locked = self.opts.locked?;
        let (specs, edge) = if from == ROOT {
            (locked.root.specs.as_ref(), locked.root.dependencies.get(name))
        } else {
            let p = locked.packages.get(from).filter(|_| self.tops.contains_key(from))?;
            (p.specs.as_ref(), p.dependencies.get(name).or_else(|| p.optional_dependencies.get(name)))
        };
        let declared = specs?.groups().any(|(_, g)| g.and_then(|g| g.get(name)).is_some_and(|r| r == range));
        let edge = edge.filter(|e| declared && locked.packages.contains_key(&format!("{name}@{e}")))?;
        Some(edge.clone())
    }

    /// A runtime edge's version, `runtime:<version>`. The locked version stays while the top
    /// declares the same range, or while the new range allows it; then a version another
    /// manager's lockfile names; else the newest the range allows.
    fn runtime(&self, from: &str, spec: &Spec, fresh: bool) -> Result<String> {
        let (name, range) = (spec.name.as_str(), spec.fetch_spec.as_str());
        let in_range = |versions: &mut dyn Iterator<Item = &str>| {
            let list: Vec<&str> = versions.filter_map(|v| v.strip_prefix(crate::runtime::PROTOCOL)).collect();
            semver::max_satisfying(list, if range.is_empty() { "*" } else { range }).map(str::to_string)
        };
        if !fresh {
            if let Some(source) = self.kept_commit(from, name, &spec.raw[name.len() + 1..]) {
                self.visit_locked(from, &format!("{name}@{source}"));
                return Ok(source);
            }
            let locked = self.opts.locked.iter().flat_map(|l| l.packages.values()).filter(|p| p.name == name);
            if let Some(v) = in_range(&mut locked.filter_map(|p| p.source.as_deref())) {
                let source = format!("{}{v}", crate::runtime::PROTOCOL);
                self.visit_locked(from, &format!("{name}@{source}"));
                return Ok(source);
            }
        }
        let preferred = self.opts.prefer.and_then(|p| in_range(&mut p.versions.get(name)?.iter().map(String::as_str)));
        let memo = format!("{}{name}@{range}", crate::runtime::PROTOCOL);
        let cell = self.runtimes.lock().unwrap_or_else(PoisonError::into_inner).entry(memo).or_default().clone();
        let found = cell
            .get_or_init(|| crate::runtime::resolve(name, range, preferred.as_deref(), self.opts.registry))
            .clone()?;
        let key = found.key();
        let mut s = lock(&self.state);
        if s.started.insert(key.clone()) {
            if let Some(on_pick) = self.opts.on_pick {
                on_pick(&found, from);
            }
            s.edges.insert(key.clone(), Vec::new());
            s.records.insert(key, found.clone());
            crate::ui::count(&crate::ui::RESOLVED, 1);
        }
        Ok(found.edge_version())
    }

    /// A directory edge's version, `link:<path>`: the top there when it goes by this name, else
    /// a record of the directory, linked as it is.
    fn dir(&self, from: &str, spec: &Spec) -> Result<String> {
        let source = self.source_of(&spec.fetch_spec, from)?;
        let path = &source[5..]; // `link:` or `file:`
        if path.is_empty() {
            return Err(Error::new("EINVALIDSPEC", "a package cannot depend on the project's own directory"));
        }
        let version = format!("link:{path}");
        if self.tops.contains_key(&format!("{}@{version}", spec.name)) {
            return Ok(version);
        }
        let m = self.opts.dirs.iter().find(|d| d.path == path).and_then(|d| d.manifest.as_ref());
        let found = Package {
            name: spec.name.clone(),
            version: m
                .and_then(|m| m.version.clone())
                .filter(|v| semver::is_exact(v))
                .unwrap_or_else(|| "0.0.0".into()),
            local: Some(path.to_string()),
            linked: true,
            bin: m.map(RootManifest::bins).unwrap_or_default(),
            ..Package::default()
        };
        let mut s = lock(&self.state);
        if spec.fetch_spec.starts_with("file:") && (path == ".." || path.starts_with("../")) {
            s.warnings.insert(format!(
                "{source} is outside the project: it is linked, and its dependencies are its own to install"
            ));
        }
        if s.started.insert(found.key()) {
            s.edges.insert(found.key(), Vec::new());
            s.records.insert(found.key(), found);
        }
        Ok(version)
    }

    /// The locked version an edge can keep: one the lockfile has under this very key, the
    /// package the spec asks for (an alias's key names it). Never for a tag. For an alias keyed
    /// before aliases had keys of their own (`name@version`), when its tarball is the one the
    /// registry serves for the aliased name.
    fn kept(&self, spec: &Spec) -> Option<String> {
        if spec.kind == Kind::Tag {
            return None;
        }
        let locked = self.opts.locked?;
        let versions = self.locked_versions.get(&spec.name)?;
        let alias = spec.fetch_name != spec.name;
        let same = |v: &&String| {
            let own = if alias { crate::graph::alias_edge(&spec.fetch_name, v) } else { v.to_string() };
            locked.packages.get(&format!("{}@{own}", spec.name)).is_some_and(|p| p.alias.is_none() || alias)
        };
        let list: Vec<&str> = versions.iter().filter(same).map(String::as_str).collect();
        semver::max_satisfying(list, &spec.fetch_spec).map(str::to_string)
    }

    /// The workspace an edge from a top lands on, if any.
    fn local_for(&self, spec: &Spec, from: &str) -> Result<Option<Package>> {
        let found = self.local.get(&spec.fetch_name);
        let own = found.is_some_and(|f| f.key() == from);
        let fail = |m: String| Err(Error::new("EWORKSPACE", m));
        if spec.kind == Kind::Workspace {
            let root = self.root_local.as_ref().filter(|r| found.is_none() && r.name == spec.fetch_name);
            let Some(found) = found.or(root) else {
                return fail(format!("no workspace package named {}", spec.fetch_name));
            };
            // A workspace on itself (mui's `@mui/types`) links to its own directory, as pnpm links
            // it; the root, which no workspace path names, cannot.
            if root.is_some() && from == ROOT {
                return fail(format!("workspace {} cannot depend on itself", spec.name));
            }
            if root.is_some() {
                // Recorded once a workspace links it, as a root listed among its workspaces is.
                let mut s = lock(&self.state);
                if s.started.insert(found.key()) {
                    s.records.insert(found.key(), found.clone());
                }
            }
            if !fits(&found.version, &spec.fetch_spec) {
                return fail(format!(
                    "no workspace version of {} satisfies {} (have {})",
                    spec.fetch_name, spec.fetch_spec, found.version
                ));
            }
            if spec.fetch_name != spec.name {
                // pnpm's `workspace:<name>@<range>` (prisma's `prisma`): the workspace linked under
                // another name, as a `link:` directory is.
                let alias = Package {
                    name: spec.name.clone(),
                    version: found.version.clone(),
                    local: found.local.clone(),
                    linked: true,
                    bin: found.bin.clone(),
                    ..Package::default()
                };
                let mut s = lock(&self.state);
                if s.started.insert(alias.key()) {
                    s.edges.insert(alias.key(), Vec::new());
                    s.records.insert(alias.key(), alias.clone());
                }
                return Ok(Some(alias));
            }
            return Ok(Some(found.clone()));
        }
        let Some(found) = found.filter(|_| !own && spec.kind != Kind::Tag && spec.fetch_name == spec.name) else {
            return Ok(None);
        };
        if fits(&found.version, &spec.fetch_spec) {
            return Ok(Some(found.clone()));
        }
        let who = if from.is_empty() { "root" } else { from };
        lock(&self.state).warnings.insert(format!(
            "workspace {}@{} does not satisfy {} from {who}; using the registry",
            spec.name, found.version, spec.fetch_spec
        ));
        Ok(None)
    }

    /// Record a picked package and queue its edges, unless it is already being walked. A key
    /// is one package: `x@1.0.0` reached as the real `x` and as `npm:other@1.0.0` under the
    /// name `x` would otherwise let whichever came first stand in for the other everywhere.
    fn visit(
        &self,
        from: &str,
        name: &str,
        m: &Manifest,
        source: Option<&str>,
        alias: Option<&str>,
        queue: &Queue<Job>,
    ) -> Result<bool> {
        let mut found = record(name, m, source);
        found.alias = alias.map(str::to_string);
        let key = found.key();
        let mut s = lock(&self.state);
        if !s.started.insert(key.clone()) {
            let integrity = m.integrity().unwrap_or_default();
            if let Some(held) = s.records.get(&key).filter(|p| p.local.is_none() && p.integrity != integrity) {
                let (held, other) = (&held.resolved, m.dist.tarball.as_deref().unwrap_or(&m.name));
                return Err(Error::new(
                    "ECONFLICT",
                    format!("{key} is two different packages ({held} and {other}); jpm keeps one per name and version"),
                ));
            }
            return Ok(false);
        }
        s.edges.insert(key.clone(), Vec::new());
        // A dependency that is a peer too is a peer, as npm and pnpm take it: the MCP sdk's zod
        // is the one its parent has, not the tree's newest. An optional one is a dependency, as
        // pnpm installs it: an optional peer is only wired to what is there, and the package
        // would lose a dependency it asked for.
        let mut peers = declared_peers(&Deps::new(), &m.optional_dependencies, Some(&m.peer_dependencies), &|n| {
            m.is_optional_peer(n)
        });
        peers.retain(|n, kind| *kind == PeerKind::Required || !m.dependencies.contains_key(n));
        if !peers.is_empty() {
            found.peers = Some(peers.clone());
        }
        // A linux build whose libc is still unread is announced once it is in.
        if !(source.is_none() && needs_libc(m))
            && let Some(on_pick) = self.opts.on_pick
        {
            on_pick(&found, from);
        }
        s.records.insert(key.clone(), found);
        crate::ui::count(&crate::ui::RESOLVED, 1);
        for (n, r) in &m.dependencies {
            if !m.optional_dependencies.contains_key(n) && !peers.contains_key(n) {
                queue.push(Job {
                    from: key.clone(),
                    name: n.clone(),
                    range: r.clone(),
                    optional: false,
                    fresh: false,
                    peer: false,
                });
            }
        }
        for (n, r) in &m.optional_dependencies {
            queue.push(Job {
                from: key.clone(),
                name: n.clone(),
                range: r.clone(),
                optional: true,
                fresh: false,
                peer: false,
            });
        }
        settle(&mut s, &key, false, &peers, Some(&m.peer_dependencies), self.overrides());
        Ok(true)
    }

    /// A locked package and everything under its own edges. Its peer edges are not replayed:
    /// they are settled against the tree at hand.
    fn visit_locked(&self, from: &str, key: &str) {
        let Some(locked) = self.opts.locked else { return };
        let mut s = lock(&self.state);
        let mut stack = vec![(from.to_string(), key.to_string())];
        while let Some((from, key)) = stack.pop() {
            let Some(pkg) = locked.packages.get(&key) else { continue };
            if !s.started.insert(key.clone()) {
                continue;
            }
            let peers = pkg.peers.clone().unwrap_or_default();
            let mut found = pkg.clone();
            found.dependencies = Deps::new();
            found.optional_dependencies = Deps::new();
            found.optional = true;
            found.dev = true;
            if let Some(on_pick) = self.opts.on_pick {
                on_pick(&found, &from);
            }
            s.records.insert(key.clone(), found);
            crate::ui::count(&crate::ui::RESOLVED, 1);
            let mut list = Vec::new();
            for (optional, map) in [(false, &pkg.dependencies), (true, &pkg.optional_dependencies)] {
                for (name, version) in map {
                    if peers.contains_key(name) {
                        continue;
                    }
                    list.push(Edge { name: name.clone(), version: version.clone(), optional });
                    stack.push((key.clone(), format!("{name}@{version}")));
                }
            }
            s.edges.insert(key.clone(), list);
            let top = self.tops.contains_key(&key);
            settle(&mut s, &key, top, &peers, pkg.peer_dependencies.as_ref(), self.overrides());
        }
    }

    /// Everything a top's non-dev edges reach.
    fn shipped(&self, s: &State) -> HashSet<String> {
        crawl(&s.edges, self.tops.keys(), &|e, from| self.tops.get(from).is_none_or(|t| t.prod.contains(&e.name)))
    }

    /// A required peer resolves against the tree first, so a plugin reuses the host already
    /// there. Only an unmet peer is fetched, and a fetch can bring peers of its own: a fixpoint.
    fn settle_peers(&self) -> Result<()> {
        loop {
            // Unmet, by pool and name: a dev-only consumer never narrows what a shipped one gets.
            let mut unmet: Vec<(bool, Vec<(String, Job)>)> = Vec::new();
            let mut aliased = Vec::new();
            {
                let mut s = lock(&self.state);
                let mut todo = std::mem::take(&mut s.hard_peers);
                if todo.is_empty() {
                    return Ok(());
                }
                todo.sort();
                let mut up = parent_index(&s);
                let shipped = self.shipped(&s);
                let have = by_name(&s.records, &|k| !s.dead.contains_key(k));
                let shipped_have = by_name(&s.records, &|k| !s.dead.contains_key(k) && shipped.contains(k));
                for (from, name, range) in todo {
                    let skip = s.dead.contains_key(&from)
                        || s.edges.get(&from).is_none_or(|l| l.iter().any(|e| e.name == name));
                    if skip {
                        continue;
                    }
                    // A shipped consumer takes a shipped copy first, else a dev one, which then ships:
                    // never a second copy of what the tree has (two Reacts break hooks).
                    // What its scope has comes before the rest of the tree, out of the peer's range
                    // too, as pnpm, yarn and bun link it: its parent's copy, never a second one.
                    let pool = if shipped.contains(&from) { &shipped_have } else { &have };
                    let found = self
                        .parents_peer(&s, &up, &from, &name, &range, &have)
                        .map(Scoped::Link)
                        .or_else(|| self.scoped(&mut s, &up, &from, &name, &range))
                        .or_else(|| self.settle_on(&s, &from, &name, &range, pool).map(Scoped::Link))
                        .or_else(|| self.settle_on(&s, &from, &name, &range, &have).map(Scoped::Link));
                    match found {
                        Some(Scoped::Link(best)) => {
                            up.entry(format!("{name}@{best}")).or_default().push(from.clone());
                            if let Some(list) = s.edges.get_mut(&from) {
                                list.push(Edge { name, version: best, optional: false });
                            }
                            continue;
                        }
                        // An alias's package, as itself: the same version under its own name.
                        Some(Scoped::Fetch(version)) if !self.opts.legacy_peers => {
                            aliased.push(Job { from, name, range: version, optional: false, fresh: false, peer: true });
                            continue;
                        }
                        _ => {}
                    }
                    if self.opts.legacy_peers {
                        let who = if from.is_empty() { "root" } else { &from };
                        s.warnings
                            .insert(format!("unmet peer {name}@{range} of {who}: nothing in the tree provides it"));
                        continue;
                    }
                    // Nothing in the tree: the version this consumer was locked with, if it still fits.
                    let own = self.locked_peer(&from, &name);
                    let again = own.as_deref().filter(|o| {
                        semver::satisfies(o, &range)
                            && !have.get(&name).is_some_and(|l| l.iter().any(|k| s.records[k].version == *o))
                    });
                    let fresh = again.is_none();
                    let ask = again.map_or_else(|| range.clone(), str::to_string);
                    let ships = shipped.contains(&from);
                    let job = (range, Job { from, name, range: ask, optional: false, fresh, peer: true });
                    match unmet.iter_mut().find(|(p, g)| *p == ships && g[0].1.name == job.1.name) {
                        Some((_, group)) => group.push(job),
                        None => unmet.push((ships, vec![job])),
                    }
                }
            }
            let mut jobs = aliased;
            // ponytail: one group at a time; a pool if many groups ever wait on the registry.
            for (_, mut group) in unmet {
                self.share_peer(&mut group);
                jobs.extend(group.into_iter().map(|(_, j)| j));
            }
            self.drain(jobs)?;
            let again = self.settle_unfetched();
            self.drain(again)?;
        }
    }

    /// A peer no version satisfies takes what its scope has, as pnpm links it, rather than fail:
    /// registry-mock's deadlock.b wants deadlock.c 2.0.0, and its parent has 1.0.0. With nothing
    /// there, its consumer fails as before. Returns the aliases' packages to fetch.
    fn settle_unfetched(&self) -> Vec<Job> {
        let mut s = lock(&self.state);
        let mut todo = std::mem::take(&mut s.unfetched);
        todo.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        let up = parent_index(&s);
        let mut jobs = Vec::new();
        for (from, name, range, error) in todo {
            let who = if from.is_empty() { "root".to_string() } else { from.clone() };
            match self.scope_peer(&s, &up, &from, &name, &range).map(|(found, _)| found) {
                Some(Scoped::Link(version)) => {
                    let have =
                        s.records.get(&format!("{name}@{version}")).map_or(version.clone(), |p| p.version.clone());
                    s.warnings.insert(format!(
                        "{who} needs peer {name}@{range}, which no version satisfies; linked to {name}@{have}"
                    ));
                    if let Some(list) = s.edges.get_mut(&from) {
                        list.push(Edge { name, version, optional: false });
                    }
                }
                Some(Scoped::Fetch(version)) => {
                    s.warnings.insert(format!(
                        "{who} needs peer {name}@{range}, which no version satisfies; linked to {name}@{version}"
                    ));
                    jobs.push(Job { from, name, range: version, optional: false, fresh: false, peer: false });
                }
                None => {
                    let error = Error::new(
                        error.code,
                        format!("{} — resolving {name}@{range} (required by {who})", error.message),
                    );
                    s.dead.entry(from).or_insert(error);
                }
            }
        }
        jobs
    }

    /// Consumers that miss the same peer share the newest of what each would get alone that
    /// fits them all: typescript-eslint caps typescript where ts-api-utils does not, and a copy
    /// each hands them two compilers. The picks are the ones their edges make anyway. With no
    /// such version each keeps its own; on a tie a locked version wins, so the record is the lock's.
    fn share_peer(&self, group: &mut [(String, Job)]) {
        if group.len() < 2 {
            return;
        }
        let answers: Vec<Option<String>> = group
            .iter()
            .map(|(_, j)| {
                if !j.fresh {
                    return Some(j.range.clone());
                }
                spec::parse_dep(&j.name, &j.range)
                    .and_then(|s| self.pick(&s, true, false))
                    .ok()
                    .map(|m| m.version.clone())
            })
            .collect();
        let fits_all = |v: &str| group.iter().zip(&answers).all(|((r, _), a)| a.is_none() || semver::satisfies(v, r));
        let mut best: Option<(usize, Option<semver::Version>)> = None;
        for (i, v) in answers.iter().enumerate() {
            let Some(v) = v.as_deref().filter(|v| fits_all(v)) else { continue };
            let version = semver::parse(v);
            if best.as_ref().is_none_or(|(_, b)| version > *b || (version == *b && !group[i].1.fresh)) {
                best = Some((i, version));
            }
        }
        let Some((i, _)) = best else { return };
        let (range, fresh) = (group[i].1.range.clone(), group[i].1.fresh);
        for ((_, j), answer) in group.iter_mut().zip(&answers) {
            if answer.is_some() {
                j.range = range.clone();
                j.fresh = fresh;
            }
        }
    }

    fn locked_peer(&self, from: &str, name: &str) -> Option<String> {
        self.opts.locked?.packages.get(from)?.dependencies.get(name).cloned()
    }

    /// The version a peer settles on out of `pool`. A top takes a fitting workspace first.
    fn settle_on(
        &self,
        s: &State,
        from: &str,
        name: &str,
        range: &str,
        pool: &HashMap<String, Vec<String>>,
    ) -> Option<String> {
        let found: Vec<&Package> = pool.get(name).into_iter().flatten().filter_map(|k| s.records.get(k)).collect();
        if self.tops.contains_key(from)
            && let Some(ws) = found.iter().find(|p| p.local.is_some() && fits(&p.version, range))
        {
            return Some(ws.edge_version());
        }
        let packages: Vec<&Package> = found.into_iter().filter(|p| p.local.is_none()).collect();
        // Then the root's own copy that fits, as npm's and bun's hoisted copy is: opencode's zod
        // 4.1.8, not the 4.4.3 that astro pins somewhere below.
        let root = s.edges.get(ROOT).and_then(|l| l.iter().find(|e| e.name == name));
        if let Some(p) = root.and_then(|e| packages.iter().find(|p| p.edge_version() == e.version))
            && semver::satisfies(&p.version, range)
        {
            return Some(p.edge_version());
        }
        let best = semver::max_satisfying(packages.iter().map(|p| p.version.as_str()), range)?;
        let mut same: Vec<&&Package> = packages.iter().filter(|p| p.version == best).collect();
        same.sort_by_key(|p| p.key());
        if same.len() < 2 {
            return same.first().map(|p| p.edge_version());
        }
        // Of two copies of the version, the one a top links by this name wins.
        let linked = |p: &&&Package| {
            let v = p.edge_version();
            self.tops.keys().any(|t| s.edges.get(t).is_some_and(|l| l.iter().any(|e| e.name == name && e.version == v)))
        };
        let chosen = same.iter().copied().find(linked).unwrap_or(same[0]);
        Some(chosen.edge_version())
    }

    /// As pnpm: what the consumer's parents have by that name comes first, dev or not, so tsup
    /// under a root with typescript 5 gets 5, not a playground's 6. Then a parent that is itself
    /// the peer: a plugin its host depends on gets that host, not the root's other version.
    // ponytail: a scan of every edge per peer; an index of parents if big trees slow down.
    fn parents_peer(
        &self,
        s: &State,
        up: &Parents,
        from: &str,
        name: &str,
        range: &str,
        have: &HashMap<String, Vec<String>>,
    ) -> Option<String> {
        let parents: Vec<&String> = up.get(from).into_iter().flatten().collect();
        let theirs: HashSet<&str> = parents
            .iter()
            .filter_map(|k| s.edges.get(*k)?.iter().find(|e| e.name == name))
            .map(|e| e.version.as_str())
            .collect();
        let pool = |keep: &dyn Fn(&String) -> bool| -> HashMap<String, Vec<String>> {
            let keys = have.get(name).into_iter().flatten().filter(|k| keep(k)).cloned().collect();
            HashMap::from([(name.to_string(), keys)])
        };
        let near = pool(&|k| s.records.get(k).is_some_and(|p| theirs.contains(p.edge_version().as_str())));
        self.settle_on(s, from, name, range, &near)
            .or_else(|| self.settle_on(s, from, name, range, &pool(&|k| parents.contains(&k))))
    }

    /// What the consumer's scope has for a peer, as pnpm looks: its parents' dependencies (or a
    /// parent that is the peer), then their parents', up to the tops, then the root's. The nearest
    /// level that has one wins: there, a package by that name, else the newest alias of that
    /// package (a root's `peer-b: npm:peer-a@1` gives peer-a), linked as the package itself; the
    /// newest in the peer's range, else the newest out of it (`false`), as pnpm links it.
    fn scope_peer(&self, s: &State, up: &Parents, from: &str, name: &str, range: &str) -> Option<(Scoped, bool)> {
        let live = |k: &str| s.records.get(k).filter(|_| !s.dead.contains_key(k));
        let newest = |versions: &mut Vec<(&str, String)>| {
            versions.sort_by_key(|(v, _)| semver::parse(v));
            let fitting = versions.iter().rev().find(|(v, _)| semver::satisfies(v, range));
            fitting.or_else(|| versions.last()).map(|(v, edge)| (edge.clone(), semver::satisfies(v, range)))
        };
        let mut seen: HashSet<&str> = HashSet::from([from]);
        let mut level: Vec<&str> = vec![from];
        loop {
            let below = std::mem::take(&mut level);
            for k in below {
                level.extend(up.get(k).into_iter().flatten().map(String::as_str).filter(|p| seen.insert(p)));
            }
            let last = level.is_empty();
            if last {
                level.push(ROOT);
            }
            let edges: Vec<&Edge> = level.iter().filter_map(|k| s.edges.get(*k)).flatten().collect();
            let mut named: Vec<(&str, String)> = edges
                .iter()
                .filter(|e| e.name == name)
                .filter_map(|e| live(&format!("{}@{}", e.name, e.version)))
                .chain(level.iter().filter_map(|k| live(k)).filter(|p| p.name == name))
                .map(|p| (p.version.as_str(), p.edge_version()))
                .collect();
            if let Some((edge, fits)) = newest(&mut named) {
                return Some((Scoped::Link(edge), fits));
            }
            let mut aliases: Vec<(&str, String)> = edges
                .iter()
                .filter_map(|e| crate::graph::split_alias(&e.version))
                .filter(|(real, _)| *real == name)
                .map(|(_, v)| (v, v.to_string()))
                .collect();
            if let Some((v, fits)) = newest(&mut aliases) {
                let found = if live(&format!("{name}@{v}")).is_some() { Scoped::Link(v) } else { Scoped::Fetch(v) };
                return Some((found, fits));
            }
            if last {
                return None;
            }
        }
    }

    /// `scope_peer` for a peer the tree settles, out of its range with a warning. Not a top's own
    /// peer: that is installed in its range, as pnpm installs an importer's.
    fn scoped(&self, s: &mut State, up: &Parents, from: &str, name: &str, range: &str) -> Option<Scoped> {
        let (found, fits) = self.scope_peer(s, up, from, name, range)?;
        if !fits {
            if self.tops.contains_key(from) {
                return None;
            }
            let have = match &found {
                Scoped::Link(v) => s.records.get(&format!("{name}@{v}")).map_or(v.as_str(), |p| p.version.as_str()),
                Scoped::Fetch(v) => v.as_str(),
            };
            let who = if from.is_empty() { "root" } else { from };
            let line = format!("unmet peer {name}@{range} of {who}: linked to the {name}@{have} above it");
            s.warnings.insert(line);
        }
        Some(found)
    }

    /// An optional peer never installs anything, but a consumer sees a version already here.
    fn wire_soft_peers(&self) {
        let mut s = lock(&self.state);
        let mut up = parent_index(&s);
        let shipped = self.shipped(&s);
        let all = by_name(&s.records, &|_| true);
        let prod = by_name(&s.records, &|k| shipped.contains(k));
        let soft: Vec<(String, Vec<(String, String)>)> =
            s.soft_peers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (key, peers) in soft {
            let pool = if shipped.contains(&key) { &prod } else { &all };
            for (name, range) in peers {
                let Some(list) = s.edges.get(&key) else { break };
                if list.iter().any(|e| e.name == name) {
                    continue;
                }
                let best = self.parents_peer(&s, &up, &key, &name, &range, &all).or_else(|| {
                    match self.scoped(&mut s, &up, &key, &name, &range) {
                        Some(Scoped::Link(v)) => Some(v),
                        _ => None,
                    }
                });
                if let Some(best) = best.or_else(|| self.settle_on(&s, &key, &name, &range, pool))
                    && let Some(list) = s.edges.get_mut(&key)
                {
                    up.entry(format!("{name}@{best}")).or_default().push(key.clone());
                    list.push(Edge { name, version: best, optional: true });
                }
            }
        }
    }

    /// Drop the edges to dead packages: an optional parent warns, a required one dies too,
    /// until nothing points at anything unusable. A top has nothing to fall back on.
    fn prune(&self) -> Result<()> {
        let mut s = lock(&self.state);
        if let Some(why) = s.dead.iter().find(|(k, _)| self.tops.contains_key(*k)).map(|(_, e)| e.clone()) {
            return Err(why);
        }
        let mut changed = true;
        while changed {
            changed = false;
            let keys: Vec<String> = s.edges.keys().filter(|k| !s.dead.contains_key(*k)).cloned().collect();
            for key in keys {
                let list = s.edges[&key].clone();
                let mut keep = Vec::with_capacity(list.len());
                for e in list {
                    let child = format!("{}@{}", e.name, e.version);
                    if !s.dead.contains_key(&child) && s.records.contains_key(&child) {
                        keep.push(e);
                        continue;
                    }
                    changed = true;
                    let why = s
                        .dead
                        .get(&child)
                        .cloned()
                        .unwrap_or_else(|| Error::new("ERESOLVE", format!("{child} was not resolved")));
                    let who = if key.is_empty() { "root" } else { &key };
                    if !e.optional && self.tops.contains_key(&key) {
                        return Err(Error::new(
                            why.code,
                            format!("{} — resolving {}@{} (required by {who})", why.message, e.name, e.version),
                        ));
                    }
                    if e.optional {
                        let line = format!("skipped optional {}@{} of {who}: {}", e.name, e.version, why.message);
                        s.warnings.insert(line);
                    } else {
                        s.dead.insert(key.clone(), why);
                        break;
                    }
                }
                if !s.dead.contains_key(&key) {
                    s.edges.insert(key, keep);
                }
            }
        }
        let dead: Vec<String> = s.dead.keys().cloned().collect();
        for key in dead {
            s.edges.remove(&key);
            s.records.remove(&key);
        }
        Ok(())
    }

    fn finish(&self) -> Resolution {
        let s = lock(&self.state);
        let reachable = crawl(&s.edges, self.tops.keys(), &|_, _| true);
        let required = crawl(&s.edges, self.tops.keys(), &|e, _| !e.optional);
        let shipped = self.shipped(&s);
        let mut packages = BTreeMap::new();
        for key in &reachable {
            let Some(found) = s.records.get(key) else { continue };
            let mut p = found.clone();
            p.dependencies = Deps::new();
            p.optional_dependencies = Deps::new();
            for e in s.edges.get(key).into_iter().flatten() {
                let map = if e.optional { &mut p.optional_dependencies } else { &mut p.dependencies };
                map.insert(e.name.clone(), e.version.clone());
            }
            p.optional = !required.contains(key);
            p.dev = !shipped.contains(key);
            packages.insert(key.clone(), p);
        }
        let root_manifest = &self.tops[ROOT].manifest;
        let dependencies =
            s.edges.get(ROOT).into_iter().flatten().map(|e| (e.name.clone(), e.version.clone())).collect();
        Resolution {
            root: Root {
                name: root_manifest.name.clone(),
                version: root_manifest.version.clone(),
                specs: root_manifest.specs(),
                dependencies,
                workspaces: root_manifest.workspaces.clone(),
                overrides: root_manifest.overrides.clone(),
            },
            packages,
            warnings: s.warnings.iter().cloned().collect(),
        }
    }
}

/// Each package's parents: what has an edge to it, as a dependency or a peer.
type Parents = HashMap<String, Vec<String>>;

fn parent_index(s: &State) -> Parents {
    let mut up: Parents = HashMap::with_capacity(s.records.len());
    for (from, list) in &s.edges {
        for e in list {
            up.entry(format!("{}@{}", e.name, e.version)).or_default().push(from.clone());
        }
    }
    up
}

/// Register a package's peers to settle after the walk: required ones become edges, optional
/// ones are wired only to what is there. Overrides apply to a peer's range too, but one to a
/// workspace or a directory only for a `top` (see `workspace_override`).
fn settle(s: &mut State, key: &str, top: bool, peers: &Peers, ranges: Option<&Deps>, overrides: &[Override]) {
    let mut soft = Vec::new();
    for (name, kind) in peers {
        let mut written = ranges.and_then(|r| r.get(name)).cloned().unwrap_or_default();
        match rules::find(overrides, crate::graph::split_key(key), name, &written) {
            Some(None) => continue,
            Some(Some(r)) if !top && to_workspace(name, r) => {
                s.warnings.insert(workspace_override(name, r));
            }
            Some(Some(r)) => written = r.to_string(),
            None => {}
        }
        let Some(range) = peer_range(name, &written) else {
            let who = if key.is_empty() { "root" } else { key };
            s.warnings.insert(format!("{who} declares peer {name}@{written}, which is not a range; left unmet"));
            continue;
        };
        match kind {
            PeerKind::Optional => soft.push((name.clone(), range)),
            PeerKind::Required => s.hard_peers.push((key.to_string(), name.clone(), range)),
        }
    }
    s.soft_peers.insert(key.to_string(), soft);
}

/// Whether an override's value sends `name` into the project: a workspace, or a directory
/// (nitro's `oxc-parser: link:./shims/oxc-parser`).
fn to_workspace(name: &str, value: &str) -> bool {
    spec::parse_dep(name, value).is_ok_and(|s| matches!(s.kind, Kind::Workspace | Kind::Directory))
}

/// An override into the project holds for the root and the workspaces only. No registry package
/// links into a project, as its entry may be shared by every project: there the override gives
/// way to the range the package asked for, as a dependency or a peer.
fn workspace_override(name: &str, value: &str) -> String {
    format!(
        "overrides send {name} to {value}: jpm links only the root and workspaces to it, and packages from the registry get {name} from the registry"
    )
}

/// A peer range as written, or the `||` alternatives of it that are ranges (`>=3 || insiders`
/// is `>=3`); `None` when none is.
fn peer_range(name: &str, range: &str) -> Option<String> {
    if spec::parse_dep(name, range).is_ok() {
        return Some(range.to_string());
    }
    let kept: Vec<&str> =
        range.split("||").map(str::trim).filter(|r| !r.is_empty() && semver::valid_range(r)).collect();
    (!kept.is_empty()).then(|| kept.join(" || "))
}

/// Package name -> the keys of its records `keep` accepts.
fn by_name(records: &HashMap<String, Package>, keep: &dyn Fn(&str) -> bool) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for (key, p) in records {
        if keep(key) {
            out.entry(p.name.clone()).or_default().push(key.clone());
        }
    }
    out
}

/// Every top but the root, and everything the tops reach through the edges `keep` accepts.
fn crawl<'a>(
    edges: &HashMap<String, Vec<Edge>>,
    tops: impl Iterator<Item = &'a String>,
    keep: &dyn Fn(&Edge, &str) -> bool,
) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut queue: Vec<String> = Vec::new();
    for top in tops {
        if top != ROOT {
            seen.insert(top.clone());
        }
        queue.push(top.clone());
    }
    while let Some(key) = queue.pop() {
        for e in edges.get(&key).into_iter().flatten() {
            if !keep(e, &key) {
                continue;
            }
            let child = format!("{}@{}", e.name, e.version);
            if seen.insert(child.clone()) {
                queue.push(child);
            }
        }
    }
    seen
}

/// Only a linux build that does not say its libc needs the full manifest's word on it.
fn needs_libc(m: &Manifest) -> bool {
    if m.libc.is_some() || m.full || (m.os.is_none() && m.cpu.is_none()) {
        return false;
    }
    m.os.as_ref().is_none_or(|os| crate::graph::runs_on(Some(os), None, None, &linux()))
}

fn linux() -> crate::sys::Platform {
    crate::sys::Platform { os: "linux".into(), cpu: String::new(), libc: None }
}

/// `*` takes any version, a prerelease too.
fn fits(version: &str, range: &str) -> bool {
    range == "*" || semver::satisfies(version, range)
}

fn record(name: &str, m: &Manifest, source: Option<&str>) -> Package {
    Package {
        name: name.to_string(),
        version: m.version.clone(),
        resolved: source.map_or_else(|| m.dist.tarball.clone().unwrap_or_default(), str::to_string),
        integrity: m.integrity().unwrap_or_default(),
        source: source.map(str::to_string),
        optional: true,
        dev: true,
        bin: m.bins(), // an alias renames the package, never its bins
        os: m.os.clone(),
        cpu: m.cpu.clone(),
        libc: m.libc.clone(),
        peer_dependencies: (!m.peer_dependencies.is_empty()).then(|| m.peer_dependencies.clone()),
        scripts: m.scripts,
        ..Package::default()
    }
}

/// A directory's version: its package.json's, else `0.0.0`.
pub fn dir_version(m: &RootManifest) -> String {
    m.version.clone().filter(|v| !v.is_empty()).unwrap_or_else(|| "0.0.0".into())
}

/// A `file:` directory walked as a top: a workspace named by the dependency on it.
fn dir_record(dir: &Dir, m: &RootManifest) -> Result<Package> {
    let version = dir_version(m);
    if !local_path(&dir.path) || !semver::is_exact(&version) {
        return Err(Error::new("EWORKSPACE", format!("file:{} has an invalid version ({version})", dir.path)));
    }
    let shape = local_shape(m);
    Ok(Package {
        name: dir.name.clone(),
        version,
        local: Some(dir.path.clone()),
        specs: shape.specs,
        bin: shape.bin,
        peer_dependencies: shape.peer_dependencies,
        peers: shape.peers,
        ..Package::default()
    })
}

/// A workspace as a package: named and versioned by its manifest, placed by its path.
fn local_record(path: &str, m: &RootManifest) -> Result<Package> {
    if !local_path(path) {
        return Err(Error::new(
            "EWORKSPACE",
            format!("workspace path {path} is not a relative path inside the project"),
        ));
    }
    let name = m.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| project::unnamed(path));
    // npm installs a workspace versioned `latest` (puppeteer's test package), or not at all.
    let version = m.version.clone().filter(|v| semver::is_exact(v)).unwrap_or_else(|| "0.0.0".into());
    if spec::parse_dep(&name, &version).is_err() {
        return Err(Error::new(
            "EWORKSPACE",
            format!("workspace at {path} has an invalid name or version ({name}@{version})"),
        ));
    }
    let shape = local_shape(m);
    Ok(Package {
        name,
        version,
        local: Some(path.to_string()),
        specs: shape.specs,
        bin: shape.bin,
        peer_dependencies: shape.peer_dependencies,
        peers: shape.peers,
        ..Package::default()
    })
}
