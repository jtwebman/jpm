//! `node-linker=hoisted`: `node_modules` as npm lays it out. Each package is a real directory,
//! as high in the tree as it can go without changing what anything else there resolves, and
//! nested under what needs it where two versions of one name meet. Its files are linked out of
//! the store, as an entry's are; a package whose install scripts run, or that is patched, gets
//! copies. Never in the global store: Electron's packers, tsc's declaration emit and scripts
//! written for npm's paths read packages where npm puts them.
//!
//! The state records where each package went, so a repeat install checks only that those are
//! there, and a changed one replaces only what moved.

use super::*;

/// Where each package goes: a path from the project, `/` separated, to the package's id. A
/// workspace or a linked directory is a link there; anything else is the package's files.
/// `lockfile_root`: the version the project's npm or bun lockfile puts at the root, by name.
pub(super) fn plan(
    res: &Resolution,
    tops: &[Top],
    skip: &HashSet<String>,
    lockfile_root: &HashMap<String, String>,
) -> BTreeMap<String, String> {
    let mut p = Planner { prefer: root_choice(res, tops, lockfile_root), ..Planner::default() };
    // Each top's `node_modules`, then those of the tops it sits inside, nearest first: where
    // Node looks from a workspace.
    let nm_of = |path: &str| if path.is_empty() { "node_modules".to_string() } else { format!("{path}/node_modules") };
    let chain = |path: &str| -> Vec<String> {
        let mut out = vec![nm_of(path)];
        let mut above: Vec<&Top> = tops
            .iter()
            .filter(|t| t.path != path && (t.path.is_empty() || path.starts_with(&format!("{}/", t.path))))
            .collect();
        above.sort_by_key(|t| Reverse(t.path.len()));
        out.extend(above.iter().map(|t| nm_of(&t.path)));
        out
    };
    let edges = |deps: &mut dyn Iterator<Item = (&String, &String)>, own: Option<&str>| -> Vec<(String, String)> {
        deps.filter(|(n, _)| Some(n.as_str()) != own)
            .map(|(n, v)| (n.clone(), format!("{n}@{v}")))
            .filter(|(_, id)| res.packages.contains_key(id) && !skip.contains(id))
            .collect()
    };
    // Every workspace at the root, as npm links them, where the root does not name another
    // package so.
    let root = &tops[0];
    for t in &tops[1..] {
        let Some((id, ws)) = res.packages.iter().find(|(_, p)| p.local.as_deref() == Some(t.path.as_str())) else {
            continue;
        };
        if !root.dependencies.contains_key(&ws.name) {
            p.put("node_modules", &ws.name, id);
        }
    }
    let mut queue: VecDeque<(Vec<String>, Edges)> = VecDeque::new();
    for t in tops {
        queue.push_back((chain(&t.path), edges(&mut t.dependencies.iter(), None)));
    }
    while let Some((chain, deps)) = queue.pop_front() {
        for (name, id) in deps {
            let Some((at, level)) = p.edge(&chain, &name, &id) else { continue };
            let pkg = &res.packages[&id];
            if pkg.local.is_some() {
                continue; // a workspace's own dependencies are its top's; a linked directory's its own
            }
            let mut below = vec![format!("{at}/node_modules")];
            below.extend(chain[level..].iter().cloned());
            queue.push_back((below, edges(&mut pkg.all_deps().iter(), Some(pkg.dir_name()))));
        }
    }
    p.placed
}

/// A package's edges, name and id.
type Edges = Vec<(String, String)>;

/// Which copy of each name the root's `node_modules` holds when the root does not depend on
/// it: the one the project's lockfile put there, else the one most packages depend on (the
/// newest of a tie), as npm's and yarn's hoisting leave it. Any other copy nests under what
/// needs it, however early the walk meets it.
fn root_choice(res: &Resolution, tops: &[Top], lockfile_root: &HashMap<String, String>) -> HashMap<String, String> {
    let mut uses: HashMap<String, usize> = HashMap::new();
    let edges =
        res.packages.values().flat_map(|p| p.all_deps()).chain(tops.iter().flat_map(|t| t.dependencies.clone()));
    for (name, version) in edges {
        *uses.entry(format!("{name}@{version}")).or_default() += 1;
    }
    let mut best: HashMap<String, (usize, Option<crate::semver::Version>, String)> = HashMap::new();
    for (id, n) in uses {
        let Some(p) = res.packages.get(&id) else { continue };
        let name =
            crate::graph::split_key(crate::graph::split_peers(&id).0).map_or(p.name.clone(), |(n, _)| n.to_string());
        let rank = (n, crate::semver::parse(&p.version), id.clone());
        if best.get(&name).is_none_or(|b| (rank.0, &rank.1) > (b.0, &b.1)) {
            best.insert(name, rank);
        }
    }
    let mut out: HashMap<String, String> = best.into_iter().map(|(name, (_, _, id))| (name, id)).collect();
    for (name, version) in lockfile_root {
        let id = format!("{name}@{version}");
        if res.packages.contains_key(&id) {
            out.insert(name.clone(), id);
        }
    }
    out
}

#[derive(Default)]
struct Planner {
    /// The copy the root holds of each name (`root_choice`).
    prefer: HashMap<String, String>,
    /// Each `node_modules`: name -> id.
    dirs: HashMap<String, BTreeMap<String, String>>,
    /// Each `node_modules`: the names something below it resolves past it, from higher up. One
    /// placed there would take their place.
    passes: HashMap<String, HashSet<String>>,
    placed: BTreeMap<String, String>,
}

impl Planner {
    fn put(&mut self, nm: &str, name: &str, id: &str) {
        self.dirs.entry(nm.to_string()).or_default().insert(name.to_string(), id.to_string());
        self.placed.insert(format!("{nm}/{name}"), id.to_string());
    }

    /// An edge from what resolves from `chain` (its own `node_modules` first): `None` when the
    /// package is there already, else where it went and which level of `chain` that is.
    fn edge(&mut self, chain: &[String], name: &str, id: &str) -> Option<(String, usize)> {
        let mut free = None;
        for (i, nm) in chain.iter().enumerate() {
            match self.dirs.get(nm).and_then(|d| d.get(name)) {
                Some(found) if found == id => {
                    self.pass(&chain[..i], name);
                    return None;
                }
                Some(_) => break,
                None => free = Some(i),
            }
        }
        // As high as it goes, but not where it would hide another copy something below finds.
        // The root's slot is the chosen copy's (`root_choice`), but for the root's own.
        let reserved = |i: usize| i > 0 && chain[i] == "node_modules" && self.prefer.get(name).is_some_and(|p| p != id);
        let highest = free?;
        let level = (1..=highest)
            .rev()
            .find(|&i| !reserved(i) && !self.passes.get(&chain[i]).is_some_and(|p| p.contains(name)))
            .unwrap_or(0);
        self.put(&chain[level], name, id);
        self.pass(&chain[..level], name);
        Some((format!("{}/{name}", chain[level]), level))
    }

    fn pass(&mut self, levels: &[String], name: &str) {
        for nm in levels {
            self.passes.entry(nm.clone()).or_default().insert(name.to_string());
        }
    }
}

/// `link`, for the hoisted layout.
pub(super) fn link(res: &Resolution, opts: &Options) -> Result<Outcome> {
    let tops = tops_of(opts.dir, res);
    let real_root =
        fs::canonicalize(opts.dir).map_err(|e| Error::io(&e, format!("cannot read {}", opts.dir.display())))?;
    let nm = opts.dir.join("node_modules");
    for top in &tops {
        if let Some(parent) = top.nm.parent() {
            inside(parent, &real_root)?;
        }
        inside(&top.nm, &real_root)?;
    }
    // Installs of the project take turns, as the isolated layout's do (see `Turn`): Rocket.Chat's
    // and cal.com's postinstall start one in each workspace at once.
    fs::create_dir_all(&nm).map_err(|e| Error::io(&e, format!("cannot create {}", nm.display())))?;
    let turn = Turn::take(&nm);
    // Under `--verify`, nothing found is trusted: laid out again from the store.
    let previous = state::read(opts.dir).filter(|s| s.hoisted && !opts.verify);
    if let Some(prev) = previous.as_ref().filter(|s| !opts.verify && s.hash == opts.hash && s.complete)
        && placed_standing(opts.dir, &prev.placed)
    {
        opts.store.flush()?;
        if opts.inputs.as_ref().is_some_and(|i| prev.inputs.as_ref() != Some(&i.hash)) || prev.tarballs != opts.tarballs
        {
            let mut st = prev.clone();
            st.inputs = opts.inputs.as_ref().map(|i| i.hash.clone());
            st.summary = opts.inputs.as_ref().map(|i| i.summary.clone());
            st.stamps = opts.inputs.as_ref().and_then(|i| i.stamps.clone());
            st.tarballs = opts.tarballs.clone();
            state::write(opts.dir, &st)?;
        }
        let stats = Stats { reused: prev.placed.len(), ..Stats::default() };
        return Ok(Outcome { up_to_date: true, stats, turn, ..Outcome::default() });
    }
    // A tree another layout made, or none recorded: every top's node_modules from nothing, but
    // the turn's file, which another install may be waiting on.
    if previous.is_none() || opts.clean {
        for top in &tops {
            for e in fs::read_dir(&top.nm).into_iter().flatten().flatten() {
                if e.file_name() != TURN {
                    let _ = remove_link(&e.path());
                }
            }
        }
    }
    state::clear(opts.dir);

    // Left out: dev packages for production, and optional packages that cannot be had.
    let mut skip: HashSet<String> = HashSet::new();
    let mut dropped = Vec::new();
    for (id, p) in &res.packages {
        if p.local.is_some() {
            continue;
        }
        if opts.production && p.dev {
            skip.insert(id.clone());
        } else if p.optional && !ready(opts, p) {
            skip.insert(id.clone());
            dropped.push(id.clone());
        }
    }
    let placed = plan(res, &tops, &skip, opts.placed);

    // What was placed before and stands as it is: the same package, nothing above it moved, and
    // one whose scripts now run already built there. One not yet built goes again, as a copy
    // its scripts may write to.
    let (old, was_built) = previous.map(|s| (s.placed, s.built)).unwrap_or_default();
    let unbuilt = |at: &String, id: &String| opts.built.contains(id) && !was_built.contains(at);
    let mut gone: Vec<&String> =
        old.iter().filter(|(at, id)| placed.get(*at) != Some(id) || unbuilt(at, id)).map(|(at, _)| at).collect();
    gone.sort_by_key(|at| Reverse(at.len()));
    let counts = Counts::default();
    for at in &gone {
        // Never through a link out of the project, which a checkout can leave where a package was.
        let path = opts.dir.join(at);
        within(&path, opts.dir)?;
        if let Some(parent) = path.parent() {
            inside(parent, &real_root)?;
        }
        if remove_link(&path).is_ok() {
            Counts::add(&counts.removed, 1);
        }
    }
    let moved = |at: &str| gone.iter().any(|g| at.starts_with(&format!("{g}/")));
    // Still what was placed: a package's own directory, a workspace's link. Never a link where
    // a package's files should be, which a checkout's state could vouch for.
    let kept = |at: &str, id: &String| {
        let meta = fs::symlink_metadata(opts.dir.join(at));
        match res.packages[id].local {
            Some(_) => meta.is_ok_and(|m| m.file_type().is_symlink() || m.is_dir()),
            None => meta.is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()),
        }
    };
    let todo: Vec<(&String, &String)> = placed
        .iter()
        .filter(|(at, id)| old.get(*at) != Some(id) || unbuilt(at, id) || moved(at) || !kept(at, id))
        .collect();
    Counts::add(&counts.reused, placed.len() - todo.len());

    // Parents before what is under them; each level's packages at once.
    let depth = |at: &str| at.matches("/node_modules/").count();
    let deepest = todo.iter().map(|(at, _)| depth(at)).max().unwrap_or(0);
    let copy_only = AtomicBool::new(false);
    let failed: Mutex<Vec<String>> = Mutex::default();
    for level in 0..=deepest {
        let these: Vec<(&String, &String)> = todo.iter().filter(|(at, _)| depth(at) == level).copied().collect();
        let results = pool::map(pool::disk_threads(), these, |(at, id)| {
            let pkg = &res.packages[id];
            match place(opts, &real_root, &counts, &copy_only, at, pkg) {
                Err(e) if pkg.optional => {
                    crate::ui::warn(&format!("skipped optional {id}: {e}"));
                    failed.lock().unwrap_or_else(PoisonError::into_inner).push(id.clone());
                    Ok(())
                }
                other => other,
            }
        });
        results.into_iter().collect::<Result<Vec<()>>>()?;
        crate::ui::count(&crate::ui::LINKED, todo.len());
    }
    dropped.extend(failed.into_inner().unwrap_or_default());

    // Each node_modules's `.bin`, made again: the packages placed in it, the top's own first.
    let mut dirs: BTreeMap<String, Vec<(&str, &String)>> = BTreeMap::new();
    for (at, id) in &placed {
        if let Some((nm, name)) = split_place(at) {
            dirs.entry(nm.to_string()).or_default().push((name, id));
        }
    }
    for top in &tops {
        let rel = if top.path.is_empty() { "node_modules".to_string() } else { format!("{}/node_modules", top.path) };
        dirs.entry(rel).or_default();
    }
    for (nm_rel, here) in &dirs {
        let own = tops.iter().find(|t| {
            let rel = if t.path.is_empty() { "node_modules".to_string() } else { format!("{}/node_modules", t.path) };
            rel == *nm_rel
        });
        bins(res, opts, &counts, nm_rel, here, own.map(|t| &t.dependencies))?;
    }

    // What tools of the other managers read: nx's `.modules.yaml`, yarn's state file.
    let modules = nm.join(".modules.yaml");
    if opts.dir.join("pnpm-lock.yaml").is_file() && fs::symlink_metadata(&modules).is_err() {
        crate::util::write_atomic(&modules, b"hoistedDependencies: {}\n")?;
    }
    if let Ok(text) = fs::read_to_string(opts.dir.join("yarn.lock"))
        && text.lines().any(|l| l == "__metadata:")
    {
        let mut at: HashMap<String, Vec<String>> = HashMap::new();
        for (place, id) in &placed {
            let p = &res.packages[id];
            let real = p.alias.as_deref().unwrap_or(&p.name);
            at.entry(format!("{real}@{}", p.version)).or_default().push(place.clone());
        }
        crate::util::write_atomic(&nm.join(".yarn-state.yml"), crate::foreign::yarn_state(&text, &at).as_bytes())?;
    }

    let built: Vec<(String, PathBuf)> = todo
        .iter()
        .filter(|(_, id)| opts.built.contains(*id) && !dropped.contains(id))
        .map(|(at, id)| ((*id).clone(), opts.dir.join(at)))
        .collect();
    let inputs = opts.inputs.as_ref();
    dropped.sort();
    dropped.dedup();
    let complete = dropped.is_empty();
    Counts::add(&counts.entries, todo.len());
    let todo_at: HashSet<&String> = todo.iter().map(|(at, _)| *at).collect();
    let placed: BTreeMap<String, String> =
        placed.iter().filter(|(_, id)| !dropped.contains(id)).map(|(a, i)| (a.clone(), i.clone())).collect();
    state::write(
        opts.dir,
        &State {
            version: 1,
            hash: opts.hash.clone(),
            complete,
            store: opts.store.dir.display().to_string(),
            production: opts.production,
            tarballs: opts.tarballs.clone(),
            inputs: inputs.map(|i| i.hash.clone()),
            summary: inputs.map(|i| i.summary.clone()),
            root: inputs.map(|_| RootLinks::default()),
            stamps: inputs.and_then(|i| i.stamps.clone()),
            hoisted: true,
            // Built before and placed as they were; this run's are added once their scripts ran.
            built: was_built.iter().filter(|at| !todo_at.contains(*at) && placed.contains_key(*at)).cloned().collect(),
            placed,
            ..State::default()
        },
    )?;
    Ok(Outcome { stats: counts.stats(), dropped, up_to_date: false, turn, built })
}

/// `node_modules/@s/x` as (`node_modules`, `@s/x`).
fn split_place(at: &str) -> Option<(&str, &str)> {
    let i = at.rfind("node_modules/")? + "node_modules".len();
    Some((&at[..i], &at[i + 1..]))
}

/// The package in the store, waiting for its download where one is under way.
fn ready(opts: &Options, p: &Package) -> bool {
    match opts.fetch {
        Some(fetch) => fetch(p).is_ok(),
        None => opts.store.has(&p.integrity),
    }
}

/// One package at `at`: a link to a workspace or a linked directory, else its files.
fn place(
    opts: &Options,
    real_root: &Path,
    counts: &Counts,
    copy_only: &AtomicBool,
    at: &str,
    pkg: &Package,
) -> Result<()> {
    let path = opts.dir.join(at);
    within(&path, opts.dir)?;
    let parent = path.parent().unwrap_or(opts.dir);
    // Never through a link out of the project, which a checkout can leave where a package was:
    // what of the parent is there already leads inside it.
    let there = parent.ancestors().find(|a| fs::symlink_metadata(a).is_ok()).unwrap_or(opts.dir);
    inside(there, real_root)?;
    fs::create_dir_all(parent)
        .map_err(|e| Error::io(&e, format!("cannot create {}", parent.display())).with_code("ELINK"))?;
    // Whatever is there goes first, a link as a link: never filled through.
    if fs::symlink_metadata(&path).is_ok() {
        remove_link(&path)
            .map_err(|e| Error::io(&e, format!("cannot replace {}", path.display())).with_code("ELINK"))?;
    }
    if let Some(local) = &pkg.local {
        let target = relative(parent, &opts.dir.join(local));
        return sys::symlink_dir(&target.to_string_lossy(), &path)
            .map_err(|e| Error::io(&e, format!("cannot link {}", path.display())).with_code("ELINK"));
    }
    if let Some(fetch) = opts.fetch {
        fetch(pkg)?;
    }
    let index = opts
        .store
        .index(&pkg.integrity)
        .ok_or_else(|| fail(format!("{} is not in the store at {}", pkg.key(), opts.store.dir.display())))?;
    let src = opts.store.pkg_dir(&pkg.integrity)?;
    let (index, src) = match (pkg.runtime.is_some(), pkg.within()) {
        // A runtime is its binary alone (see `Linker::index`).
        (true, _) => {
            let files: Vec<FileEntry> =
                index.files.iter().filter(|f| pkg.bin.values().any(|b| *b == f.path)).cloned().collect();
            let unpacked_size = files.iter().map(|f| f.size).sum();
            (std::sync::Arc::new(Index { files, unpacked_size, suffixed: index.suffixed, stamp: index.stamp }), src)
        }
        (false, Some((_, under))) => (std::sync::Arc::new(index.under(under)), src.join(under)),
        (false, None) => (index, src),
    };
    let copy = opts.built.contains(&pkg.key()) || pkg.patch.is_some();
    place_files(counts, copy_only, &index, &src, &path, copy)?;
    if let Some(hash) = &pkg.patch {
        let patch = opts.patches.iter().find(|p| p.hash == *hash).ok_or_else(|| {
            Error::new(
                "EPATCH",
                format!("{}@{} is patched, and no patch of the project has its hash", pkg.name, pkg.version),
            )
        })?;
        crate::patch::apply(&path, &patch.text).map_err(|why| {
            Error::new("EPATCH", format!("{} does not apply to {}@{}: {why}", patch.path, pkg.name, pkg.version))
        })?;
    }
    Ok(())
}

/// The `.bin` of `nm_rel`, from the packages placed in it (`here`); a top's own dependencies'
/// bins first, where two packages there have one of the same name.
fn bins(
    res: &Resolution,
    opts: &Options,
    counts: &Counts,
    nm_rel: &str,
    here: &[(&str, &String)],
    own: Option<&BTreeMap<String, String>>,
) -> Result<()> {
    let nm = opts.dir.join(nm_rel);
    let bin_dir = nm.join(".bin");
    let _ = remove_link(&bin_dir);
    let mut chosen: BTreeMap<&String, (&str, &String, &Package)> = BTreeMap::new();
    let first = |name: &str| own.is_some_and(|d| d.contains_key(name));
    let mut ordered: Vec<&(&str, &String)> = here.iter().collect();
    ordered.sort_by_key(|(name, _)| !first(name));
    for (name, id) in ordered {
        let pkg = &res.packages[*id];
        for (bin, target) in &pkg.bin {
            chosen.entry(bin).or_insert((name, target, pkg));
        }
    }
    if chosen.is_empty() || !nm.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(&bin_dir).map_err(|e| Error::io(&e, "cannot create .bin").with_code("ELINK"))?;
    for (bin, (name, target, pkg)) in chosen {
        let file = nm.join(name).join(target);
        // A workspace's bin is the project's own file: made runnable, as npm and pnpm do.
        if pkg.local.as_deref().is_some_and(|p| !p.starts_with("..")) {
            if !file.exists() {
                continue; // not built yet (see `link_top`)
            }
            executable(&file);
        }
        if WIN {
            let head = crate::shim::read_head(&file);
            for (sfx, text) in crate::shim::shims_of(&relative(&bin_dir, &file).to_string_lossy(), head.as_deref())? {
                let at = bin_dir.join(format!("{bin}{sfx}"));
                fs::write(&at, text)
                    .map_err(|e| Error::io(&e, format!("cannot write {}", at.display())).with_code("ELINK"))?;
            }
        } else {
            let at = bin_dir.join(bin);
            symlink_file(&bin_link(name, target), &at)
                .map_err(|e| Error::io(&e, format!("cannot link {}", at.display())).with_code("ELINK"))?;
        }
        Counts::add(&counts.bins, 1);
    }
    Ok(())
}

/// Every recorded place still there.
pub(super) fn placed_standing(dir: &Path, placed: &BTreeMap<String, String>) -> bool {
    placed.keys().all(|at| fs::symlink_metadata(dir.join(at)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str, deps: &[(&str, &str)]) -> (String, Package) {
        let dependencies = deps.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        let p = Package { name: name.into(), version: version.into(), dependencies, ..Package::default() };
        (format!("{name}@{version}"), p)
    }

    fn graph(pkgs: Vec<(String, Package)>, root: &[(&str, &str)]) -> Resolution {
        let mut res = Resolution::default();
        res.packages.extend(pkgs);
        res.root.dependencies = root.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        res
    }

    /// Every edge, from where its package was placed, finds what the graph says on Node's walk
    /// up: the root's from `node_modules`, a package's from its own `node_modules` up.
    fn resolves_as_the_graph_says(res: &Resolution, placed: &BTreeMap<String, String>) {
        // `node_modules/a/node_modules/b/node_modules`, then `node_modules/a/node_modules`, ...
        let find = |from: &str, name: &str| -> Option<&String> {
            let mut dir = from.to_string();
            loop {
                if let Some(id) = placed.get(&format!("{dir}/{name}")) {
                    return Some(id);
                }
                let up = dir.strip_suffix("/node_modules")?;
                dir = up[..up.rfind("node_modules/")? + "node_modules".len()].to_string();
            }
        };
        for (n, v) in &res.root.dependencies {
            assert_eq!(placed.get(&format!("node_modules/{n}")), Some(&format!("{n}@{v}")), "root's {n}");
        }
        for (at, id) in placed {
            for (n, v) in res.packages[id].all_deps() {
                assert_eq!(find(&format!("{at}/node_modules"), &n), Some(&format!("{n}@{v}")), "{id} at {at}: {n}");
            }
        }
    }

    #[test]
    fn nests_only_where_versions_meet() {
        // root -> a@1 -> c@1; root -> b@1 -> c@2, d@1; c@2 -> d@2; root -> c@3.
        let res = graph(
            vec![
                pkg("a", "1.0.0", &[("c", "1.0.0")]),
                pkg("b", "1.0.0", &[("c", "2.0.0"), ("d", "1.0.0")]),
                pkg("c", "1.0.0", &[]),
                pkg("c", "2.0.0", &[("d", "2.0.0")]),
                pkg("c", "3.0.0", &[]),
                pkg("d", "1.0.0", &[]),
                pkg("d", "2.0.0", &[]),
            ],
            &[("a", "1.0.0"), ("b", "1.0.0"), ("c", "3.0.0")],
        );
        let placed = plan(&res, &tops_of(Path::new("/p"), &res), &HashSet::new(), &HashMap::new());
        resolves_as_the_graph_says(&res, &placed);
        assert_eq!(placed.get("node_modules/c").map(String::as_str), Some("c@3.0.0"), "the root's own");
        assert_eq!(placed.get("node_modules/a/node_modules/c").map(String::as_str), Some("c@1.0.0"));
        assert_eq!(placed.len(), 7);
    }

    #[test]
    fn gives_the_root_the_copy_most_packages_use() {
        // x@1 is met first, but three packages use x@2: x@2 at the root, x@1 under its one user
        // (cal.com's googleapis-common, 5.1.0 for googleapis against 7.0.1 for three others).
        let res = graph(
            vec![
                pkg("first", "1.0.0", &[("x", "1.0.0")]),
                pkg("p", "1.0.0", &[("x", "2.0.0")]),
                pkg("q", "1.0.0", &[("x", "2.0.0")]),
                pkg("r", "1.0.0", &[("x", "2.0.0")]),
                pkg("x", "1.0.0", &[]),
                pkg("x", "2.0.0", &[]),
            ],
            &[("first", "1.0.0"), ("p", "1.0.0"), ("q", "1.0.0"), ("r", "1.0.0")],
        );
        let placed = plan(&res, &tops_of(Path::new("/p"), &res), &HashSet::new(), &HashMap::new());
        resolves_as_the_graph_says(&res, &placed);
        assert_eq!(placed.get("node_modules/x").map(String::as_str), Some("x@2.0.0"));
        assert_eq!(placed.get("node_modules/first/node_modules/x").map(String::as_str), Some("x@1.0.0"));
        // The project's lockfile has the last word on the root's copy.
        let lock: HashMap<String, String> = [("x".to_string(), "1.0.0".to_string())].into();
        let placed = plan(&res, &tops_of(Path::new("/p"), &res), &HashSet::new(), &lock);
        resolves_as_the_graph_says(&res, &placed);
        assert_eq!(placed.get("node_modules/x").map(String::as_str), Some("x@1.0.0"));
    }

    #[test]
    fn never_hides_what_something_below_found_higher_up() {
        // root -> a@1, b@2, c@2, z@1; a -> b@1, c@1 (both nested under a); b@1 -> z@1, found at
        // the root past a's node_modules; c@1 -> z@2, which must not go into a's node_modules,
        // where it would hide z@1 from b@1.
        let res = graph(
            vec![
                pkg("a", "1.0.0", &[("b", "1.0.0"), ("c", "1.0.0")]),
                pkg("b", "1.0.0", &[("z", "1.0.0")]),
                pkg("b", "2.0.0", &[]),
                pkg("c", "1.0.0", &[("z", "2.0.0")]),
                pkg("c", "2.0.0", &[]),
                pkg("z", "1.0.0", &[]),
                pkg("z", "2.0.0", &[]),
            ],
            &[("a", "1.0.0"), ("b", "2.0.0"), ("c", "2.0.0"), ("z", "1.0.0")],
        );
        let placed = plan(&res, &tops_of(Path::new("/p"), &res), &HashSet::new(), &HashMap::new());
        resolves_as_the_graph_says(&res, &placed);
        assert_eq!(placed.get("node_modules/a/node_modules/z"), None);
    }
}
