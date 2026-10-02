//! Peer-dependent copies. A package sees its peers where it is installed, so one reached along
//! two paths whose scopes hold different peers is two packages, as under pnpm and yarn: a `ui-lib`
//! that workspace A reaches with React 17 and workspace B with React 18 is one copy for each.
//!
//! The walk goes down from each top (the root, then each workspace under it), a level per
//! package: its dependencies by name, and itself. A peer takes the nearest level that has its
//! name; with none, the edge the resolver settled, which becomes the package's own. A copy is its
//! key and the peers it took from above, its dependencies' ones too, keyed as pnpm keys them:
//! `ui-lib@1.0.0(react@18.2.0)`. Copies whose peers are the same are one, so a package is
//! walked again only where what it would take from above differs, and a package with one copy
//! keeps its plain key.

use std::collections::{HashMap, HashSet};

use crate::graph::{Deps, Package, PeerKind, Resolution};

const NONE: usize = usize::MAX;
/// How many copies of one package may be open along one path: a cycle through peers ends
/// on the nearest of them after that.
const OPEN: usize = 4;

/// One package of the input.
struct Pkg<'a> {
    key: &'a str,
    p: &'a Package,
    /// The peers it takes from its scope.
    peers: Vec<&'a str>,
    /// Every edge, by name, to its package.
    edges: Vec<(&'a str, usize)>,
    /// Neither it nor anything it reaches has peers: one copy, as it is.
    plain: bool,
}

#[derive(Default)]
struct Node<'a> {
    pkg: usize,
    /// Another node it turned out to be.
    forward: Option<usize>,
    /// Its edges, by name, to nodes; empty for a plain package or a top.
    edges: Vec<(&'a str, usize)>,
    /// The peers it takes from above its own level, its dependencies' included.
    above: Vec<(&'a str, usize)>,
    /// The peers it looked for above its level and found nowhere, each with the level where it
    /// took the edge the resolver gave it instead.
    missing: Vec<(&'a str, usize)>,
}

#[derive(Clone, Copy)]
enum Slot {
    Pending(usize),
    Open(usize),
    Done(usize),
}

/// A package's dependencies, as a scope its own dependencies look in.
struct Level<'a> {
    parent: usize,
    owner: Option<usize>,
    owner_name: &'a str,
    slots: Vec<(&'a str, Slot)>,
    /// The packages aliases here install: a peer by that name stops at this level, and keeps the
    /// edge the resolver gave it (which settles on the alias's package).
    aliased: Vec<&'a str>,
}

struct Split<'a> {
    pkgs: Vec<Pkg<'a>>,
    nodes: Vec<Node<'a>>,
    levels: Vec<Level<'a>>,
    /// The one node of a plain package or a top.
    fixed: Vec<usize>,
    /// Each package's finished copies, and the ones open on the path being walked.
    done: Vec<Vec<usize>>,
    open: Vec<Vec<usize>>,
}

/// Split each package the resolver settled into a copy per set of peers. `res` has no peer
/// suffixes yet; one without a package that has peers comes back as it is.
pub fn split(res: Resolution) -> Resolution {
    if res.packages.values().all(|p| p.peers.as_ref().is_none_or(|p| p.is_empty())) {
        return res;
    }
    // Deep trees recurse deep: a thread of its own with room for it.
    let plan = std::thread::scope(|s| {
        let walk = std::thread::Builder::new().stack_size(64 << 20).spawn_scoped(s, || plan(&res)).ok()?;
        walk.join().ok()
    });
    let Some(Some(plan)) = plan else { return res };
    let mut res = res;
    res.root.dependencies = plan.root;
    for key in plan.gone {
        res.packages.remove(&key);
    }
    // A package moves to its last copy; only the others are clones.
    for (key, mut copies) in plan.copies {
        let Some(p) = res.packages.remove(&key) else { continue };
        let mut place = |c: Copy, mut p: Package| {
            p.peer_suffix = c.suffix;
            if let Some((deps, optional)) = c.edges {
                p.dependencies = deps;
                p.optional_dependencies = optional;
            }
            res.packages.insert(c.key, p);
        };
        let last = copies.pop();
        for c in copies {
            place(c, p.clone());
        }
        if let Some(c) = last {
            place(c, p);
        }
    }
    // `optional` and `dev` stay the package's: what a copy is, the lockfile says when read.
    res
}

/// One copy of a package in place of another whose peers it has and more, as pnpm's
/// `dedupePeerDependents`: sveltejs/kit's vitest with `@types/node` alone and the one with jsdom
/// and the rest too were two vitests, and a `declare module 'vitest'` reached only one. A copy
/// goes into the one copy of its package that has every peer it has, and more peers than any
/// other such copy, when each edge it has the other has too, to the same package once the
/// merges are made. Merges are proposed all at once and dropped until every one holds, so two
/// copies that reach each other (vitest and `@vitest/ui`) merge together.
pub fn dedupe(mut res: Resolution) -> Resolution {
    let peer_edges = |p: &Package| -> Vec<String> {
        let peers = p.peers.as_ref();
        let mut names: Vec<String> = p
            .dependencies
            .keys()
            .chain(p.optional_dependencies.keys())
            .filter(|n| peers.is_some_and(|ps| ps.contains_key(*n)))
            .cloned()
            .collect();
        names.sort();
        names
    };
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for (key, p) in &res.packages {
        if !p.peer_suffix.is_empty() && p.local.is_none() {
            groups.entry(crate::graph::split_peers(key).0).or_default().push(key);
        }
    }
    let mut into: HashMap<String, String> = HashMap::new();
    for keys in groups.values().filter(|k| k.len() > 1) {
        let names: Vec<Vec<String>> = keys.iter().map(|k| peer_edges(&res.packages[*k])).collect();
        let covers = |a: usize, b: usize| names[b].iter().all(|n| names[a].contains(n));
        // The copy with the most peers that has all of this one's; of two with the same, the
        // longer key, whose suffix names the bigger copies below it.
        // ponytail: key length stands in for "its peers' copies are the bigger ones".
        for b in 0..keys.len() {
            let best = (0..keys.len())
                .filter(|&a| covers(a, b))
                .max_by_key(|&a| (names[a].len(), keys[a].len(), std::cmp::Reverse(keys[a])));
            if let Some(a) = best.filter(|&a| a != b) {
                into.insert(keys[b].to_string(), keys[a].to_string());
            }
        }
    }
    // A target is never merged itself: follow to the end, a cycle cut.
    let end = |into: &HashMap<String, String>, key: &str| -> String {
        let mut at = key.to_string();
        for _ in 0..into.len() + 1 {
            match into.get(&at) {
                Some(next) => at = next.clone(),
                None => break,
            }
        }
        at
    };
    let target = |into: &HashMap<String, String>, name: &str, version: &str| end(into, &format!("{name}@{version}"));
    loop {
        let wrong: Vec<String> = into
            .iter()
            .filter(|(b, a)| {
                let (b, a) = (&res.packages[*b], &res.packages[*a]);
                let (from, to) = (all_edges(b), all_edges(a));
                let peers = a.peers.as_ref();
                let own = |n: &str| peers.is_none_or(|ps| !ps.contains_key(n));
                let same = from.iter().all(|(n, v)| {
                    to.iter().find(|(m, _)| m == n).is_some_and(|(_, w)| target(&into, n, v) == target(&into, n, w))
                });
                let extra = to.iter().any(|(n, _)| own(n) && !from.iter().any(|(m, _)| m == n));
                !same || extra
            })
            .map(|(b, _)| b.clone())
            .collect();
        if wrong.is_empty() {
            break;
        }
        for b in wrong {
            into.remove(&b);
        }
    }
    if into.is_empty() {
        return res;
    }
    let moved = |into: &HashMap<String, String>, deps: &mut Deps| {
        for (n, v) in deps.iter_mut() {
            let to = target(into, n, v);
            if let Some(version) = to.strip_prefix(n.as_str()).and_then(|t| t.strip_prefix('@')) {
                *v = version.to_string();
            }
        }
    };
    moved(&into, &mut res.root.dependencies);
    for key in into.keys() {
        res.packages.remove(key);
    }
    for p in res.packages.values_mut() {
        moved(&into, &mut p.dependencies);
        moved(&into, &mut p.optional_dependencies);
    }
    res
}

fn all_edges(p: &Package) -> Vec<(&String, &String)> {
    p.dependencies.iter().chain(&p.optional_dependencies).collect()
}

/// A copy of a package: its key, its suffix, and its edges when they change.
struct Copy {
    key: String,
    suffix: String,
    edges: Option<(Deps, Deps)>,
}

/// What the split changes: the copies of each package that has other keys or edges now, by its
/// key; the packages no copy reaches; the root's edges.
struct Plan {
    copies: Vec<(String, Vec<Copy>)>,
    gone: Vec<String>,
    root: Deps,
}

/// `None` when nothing changes.
fn plan(res: &Resolution) -> Option<Plan> {
    let index: HashMap<&str, usize> = res.packages.keys().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
    let mut key = String::new();
    let mut find = |n: &String, v: &String| {
        key.clear();
        key.push_str(n);
        key.push('@');
        key.push_str(v);
        index.get(key.as_str()).copied()
    };
    let mut pkgs: Vec<Pkg> = res
        .packages
        .iter()
        .map(|(key, p)| {
            let mut edges: Vec<(&str, usize)> = p
                .dependencies
                .iter()
                .chain(&p.optional_dependencies)
                .filter_map(|(n, v)| Some((n.as_str(), find(n, v)?)))
                .collect();
            edges.sort_unstable();
            edges.dedup_by(|a, b| a.0 == b.0);
            // The peers the resolver settled: one it left unmet (a range it cannot read, an
            // override that drops it) stays so. A package never takes itself as its peer, as
            // pnpm leaves such a peer out.
            let settled = |n: &&str| *n != p.name && edges.iter().any(|e| e.0 == *n);
            let peers = match &p.local {
                Some(_) => Vec::new(),
                None => p.peers.iter().flatten().map(|(n, _)| n.as_str()).filter(settled).collect(),
            };
            Pkg { key, p, peers, edges, plain: false }
        })
        .collect();
    // Plain: nothing it reaches has peers, found from the ones that do up their parents.
    let mut up: Vec<Vec<usize>> = vec![Vec::new(); pkgs.len()];
    for (i, pkg) in pkgs.iter().enumerate() {
        for &(_, t) in &pkg.edges {
            up[t].push(i);
        }
    }
    let mut peery: Vec<bool> = pkgs.iter().map(|p| !p.peers.is_empty()).collect();
    let mut queue: Vec<usize> = (0..pkgs.len()).filter(|&i| peery[i]).collect();
    while let Some(i) = queue.pop() {
        for &parent in &up[i] {
            if !peery[parent] {
                peery[parent] = true;
                queue.push(parent);
            }
        }
    }
    for (pkg, peery) in pkgs.iter_mut().zip(peery) {
        pkg.plain = !peery || pkg.p.local.is_some();
    }
    let n = pkgs.len();
    let mut split = Split {
        pkgs,
        nodes: Vec::new(),
        levels: Vec::new(),
        fixed: vec![NONE; n],
        done: vec![Vec::new(); n],
        open: vec![Vec::new(); n],
    };

    // The root, then each workspace under it (a peer of a workspace's package may be the
    // root's, as pnpm resolves peers from the workspace root).
    let root_edges: Vec<(&str, usize)> =
        res.root.dependencies.iter().filter_map(|(n, v)| Some((n.as_str(), find(n, v)?))).collect();
    let root = split.level(NONE, None, "", &root_edges);
    let mut top_edges: Vec<(usize, Vec<(&str, usize)>)> = vec![(NONE, split.fill(root))];
    for i in 0..split.pkgs.len() {
        let p = split.pkgs[i].p;
        let top = p.local.as_deref().is_some_and(|path| path != crate::project::ROOT_PATH) && !p.linked;
        if !top {
            continue;
        }
        let owner = split.fixed_node(i);
        let edges = split.pkgs[i].edges.clone();
        let level = split.level(root, Some(owner), p.name.as_str(), &edges);
        top_edges.push((i, split.fill(level)));
    }
    split.finish(res, top_edges)
}

impl<'a> Split<'a> {
    fn find(&self, mut n: usize) -> usize {
        while let Some(f) = self.nodes[n].forward {
            n = f;
        }
        n
    }

    fn node(&mut self, pkg: usize) -> usize {
        self.nodes.push(Node { pkg, ..Node::default() });
        self.nodes.len() - 1
    }

    fn fixed_node(&mut self, pkg: usize) -> usize {
        if self.fixed[pkg] == NONE {
            self.fixed[pkg] = self.node(pkg);
        }
        self.fixed[pkg]
    }

    fn level(&mut self, parent: usize, owner: Option<usize>, owner_name: &'a str, edges: &[(&'a str, usize)]) -> usize {
        // Edges come sorted by name, so the slots are.
        let slots: Vec<(&str, Slot)> = edges.iter().map(|&(n, p)| (n, Slot::Pending(p))).collect();
        let aliased = edges.iter().filter_map(|&(_, p)| self.pkgs[p].p.alias.as_deref()).collect();
        self.levels.push(Level { parent, owner, owner_name, slots, aliased });
        self.levels.len() - 1
    }

    /// Every slot of a level, in name order.
    fn fill(&mut self, level: usize) -> Vec<(&'a str, usize)> {
        (0..self.levels[level].slots.len()).map(|i| (self.levels[level].slots[i].0, self.slot(level, i))).collect()
    }

    /// The node a slot is, walked the first time it is asked for: a sibling a peer needs is
    /// walked before the package that needs it is done.
    fn slot(&mut self, level: usize, i: usize) -> usize {
        let pkg = match self.levels[level].slots[i].1 {
            Slot::Open(n) | Slot::Done(n) => return self.find(n),
            Slot::Pending(pkg) => pkg,
        };
        let n = if self.pkgs[pkg].plain {
            self.fixed_node(pkg)
        } else {
            let n = self.node(pkg);
            self.levels[level].slots[i].1 = Slot::Open(n);
            self.place(n, pkg, level)
        };
        self.levels[level].slots[i].1 = Slot::Done(n);
        n
    }

    /// What `name` is from `level` up: the nearest level's dependency by that name, else that
    /// level's package if it is so named.
    fn lookup(&mut self, mut level: usize, name: &str) -> Option<usize> {
        while level != NONE {
            let l = &self.levels[level];
            if let Ok(i) = l.slots.binary_search_by(|s| s.0.cmp(name)) {
                return Some(self.slot(level, i));
            }
            if let Some(owner) = l.owner.filter(|_| l.owner_name == name) {
                return Some(self.find(owner));
            }
            if l.aliased.contains(&name) {
                return None;
            }
            level = l.parent;
        }
        None
    }

    /// Whether `node` is what `pkg` would be at `level`: every peer it took from above is what
    /// the scope has there, and every one it missed is still missing, or is there as the very
    /// copy it took instead (a cycle back to it).
    fn fits(&mut self, node: usize, level: usize) -> bool {
        let above = self.nodes[node].above.clone();
        for (name, t) in above {
            let found = self.lookup(level, name);
            if found != Some(self.find(t)) {
                return false;
            }
        }
        let missing = self.nodes[node].missing.clone();
        missing.into_iter().all(|(name, at)| match self.lookup(level, name) {
            None => true,
            found => found == self.taken(at, name),
        })
    }

    /// The node a level's slot is, if it has been walked.
    fn taken(&self, level: usize, name: &str) -> Option<usize> {
        let l = &self.levels[level];
        match l.slots.binary_search_by(|s| s.0.cmp(name)).map(|i| l.slots[i].1) {
            Ok(Slot::Open(n) | Slot::Done(n)) => Some(self.find(n)),
            _ => None,
        }
    }

    /// Walk `pkg` as node `n` below `level`, or find a copy it is already.
    fn place(&mut self, n: usize, pkg: usize, level: usize) -> usize {
        let mut above = Vec::new();
        let mut missing = Vec::new();
        for i in 0..self.pkgs[pkg].peers.len() {
            let name = self.pkgs[pkg].peers[i];
            match self.lookup(level, name) {
                Some(t) => above.push((name, t)),
                None => missing.push(name),
            }
        }
        let candidates: Vec<usize> = self.done[pkg].iter().chain(self.open[pkg].iter().rev()).copied().collect();
        for c in candidates {
            let c = self.find(c);
            if self.fits(c, level) {
                self.nodes[n].forward = Some(c);
                return c;
            }
        }
        if self.open[pkg].len() >= OPEN
            && let Some(&c) = self.open[pkg].last()
        {
            self.nodes[n].forward = Some(c);
            return c;
        }
        // Its own level: its dependencies, and the peers it found nowhere, on the edges the
        // resolver gave them.
        let own_peers = above.len();
        let taken = |name: &str| above.iter().any(|a| a.0 == name);
        let own: Vec<(&str, usize)> = self.pkgs[pkg].edges.iter().filter(|e| !taken(e.0)).copied().collect();
        let name = self.pkgs[pkg].p.name.as_str();
        let here = self.level(level, Some(n), name, &own);
        let mut missing: Vec<(&str, usize)> = missing.into_iter().map(|name| (name, here)).collect();
        self.nodes[n].above = above.clone();
        self.nodes[n].missing = missing.clone();
        self.open[pkg].push(n);
        let mut edges = self.fill(here);
        // What its dependencies took from above its level, it takes too.
        let at_here =
            |l: &Level, name: &str| l.owner_name == name || l.slots.binary_search_by(|s| s.0.cmp(name)).is_ok();
        let level = &self.levels[here];
        for edge in &mut edges {
            edge.1 = self.find(edge.1);
            let c = &self.nodes[edge.1];
            for &(name, t) in &c.above {
                if !at_here(level, name) && !above.iter().any(|a| a.0 == name) {
                    above.push((name, t));
                }
            }
            for &(name, at) in &c.missing {
                if !at_here(level, name) && !missing.iter().any(|m| m.0 == name) {
                    missing.push((name, at));
                }
            }
        }
        edges.extend_from_slice(&above[..own_peers]);
        above.sort_unstable();
        missing.sort_unstable();
        let node = &mut self.nodes[n];
        node.edges = edges;
        node.above = above;
        node.missing = missing;
        self.open[pkg].pop();
        self.done[pkg].push(n);
        n
    }

    /// Each node's key: its package's, and pnpm's suffix of what it takes from above, each
    /// peer's own key nested, sorted as text. A peer whose key is still being made (a cycle) is
    /// written without its suffix. With `copies`, a package that has one copy keeps its key bare.
    fn keys(&self, copies: Option<&[usize]>) -> Vec<Option<String>> {
        let mut out: Vec<Option<String>> = vec![None; self.nodes.len()];
        let mut making = vec![false; self.nodes.len()];
        // A plain package's key is its own: made only where another's names it.
        for n in 0..self.nodes.len() {
            if self.nodes[n].forward.is_none() && !self.pkgs[self.nodes[n].pkg].plain {
                self.key_of(n, copies, &mut out, &mut making);
            }
        }
        out
    }

    fn key_of(
        &self,
        n: usize,
        copies: Option<&[usize]>,
        out: &mut Vec<Option<String>>,
        making: &mut Vec<bool>,
    ) -> String {
        let n = self.find(n);
        if let Some(k) = &out[n] {
            return k.clone();
        }
        let pkg = self.nodes[n].pkg;
        let base = self.pkgs[pkg].key;
        if making[n] {
            return base.to_string();
        }
        if copies.is_some_and(|c| c[pkg] < 2) {
            out[n] = Some(base.to_string());
            return base.to_string();
        }
        making[n] = true;
        let mut groups: Vec<String> =
            self.nodes[n].above.iter().map(|&(_, t)| format!("({})", self.key_of(t, copies, out, making))).collect();
        making[n] = false;
        groups.sort_unstable();
        let key = format!("{base}{}", groups.concat());
        out[n] = Some(key.clone());
        key
    }

    fn finish(&mut self, res: &Resolution, top_edges: Vec<(usize, Vec<(&str, usize)>)>) -> Option<Plan> {
        // What a plain package reaches is plain, and was not walked: it is there as it is.
        let mut queue: Vec<usize> = (0..self.pkgs.len()).filter(|&p| self.fixed[p] != NONE).collect();
        while let Some(p) = queue.pop() {
            if self.pkgs[p].p.local.is_some() {
                continue;
            }
            for i in 0..self.pkgs[p].edges.len() {
                let t = self.pkgs[p].edges[i].1;
                if self.fixed[t] == NONE && self.pkgs[t].plain {
                    self.fixed_node(t);
                    queue.push(t);
                }
            }
        }
        // Copies are told apart by their whole peer sets; only a package with more than one
        // is written with its suffix, so a tree whose peers are one set per package keeps its keys.
        let whole = self.keys(None);
        let mut seen: HashSet<&str> = HashSet::new();
        let mut copies = vec![0usize; self.pkgs.len()];
        for (n, node) in self.nodes.iter().enumerate() {
            if let Some(k) = whole[n].as_deref().filter(|_| node.forward.is_none())
                && seen.insert(k)
            {
                copies[node.pkg] += 1;
            }
        }
        let keys = self.keys(Some(&copies));
        let key = |n: usize| {
            let n = self.find(n);
            keys[n].as_deref().unwrap_or(self.pkgs[self.nodes[n].pkg].key)
        };
        let edge = |name: &str, n: usize| key(n)[name.len() + 1..].to_string();
        let rewrite = |deps: &Deps, edges: &[(&str, usize)]| -> Deps {
            let to =
                |name: &str, v: &String| edges.iter().find(|e| e.0 == name).map_or(v.clone(), |&(_, t)| edge(name, t));
            deps.iter().map(|(name, v)| (name.clone(), to(name, v))).collect()
        };
        let top = |pkg: usize| top_edges.iter().find(|t| t.0 == pkg).map(|t| t.1.as_slice());
        let mut by_pkg: Vec<Vec<Copy>> = (0..self.pkgs.len()).map(|_| Vec::new()).collect();
        let mut made: HashSet<&str> = HashSet::new();
        for (n, node) in self.nodes.iter().enumerate() {
            let pkg = &self.pkgs[node.pkg];
            let k = key(n);
            if node.forward.is_some() || (pkg.plain && top(node.pkg).is_none()) || !made.insert(k) {
                continue;
            }
            let edges = if let Some(edges) = top(node.pkg) {
                (rewrite(&pkg.p.dependencies, edges), rewrite(&pkg.p.optional_dependencies, edges))
            } else {
                let (mut deps, mut optional) = (Deps::new(), Deps::new());
                for &(name, t) in &node.edges {
                    // A peer the resolver left unwired is optional where it is optional.
                    let soft = pkg.p.optional_dependencies.contains_key(name)
                        || (!pkg.p.dependencies.contains_key(name)
                            && pkg.p.peers.as_ref().and_then(|ps| ps.get(name)) == Some(&PeerKind::Optional));
                    let map = if soft { &mut optional } else { &mut deps };
                    map.insert(name.to_string(), edge(name, t));
                }
                (deps, optional)
            };
            let same = edges.0 == pkg.p.dependencies && edges.1 == pkg.p.optional_dependencies;
            let suffix = k[pkg.key.len()..].to_string();
            by_pkg[node.pkg].push(Copy { key: k.to_string(), suffix, edges: (!same).then_some(edges) });
        }
        let copies: Vec<(String, Vec<Copy>)> = by_pkg
            .into_iter()
            .enumerate()
            .filter(|(_, c)| c.len() > 1 || c.first().is_some_and(|c| c.edges.is_some() || !c.suffix.is_empty()))
            .map(|(i, c)| (self.pkgs[i].key.to_string(), c))
            .collect();
        // A package only a peer edge the scope now meets reached is no more.
        let mut reached = vec![false; self.pkgs.len()];
        for n in &self.nodes {
            reached[n.pkg] = true;
        }
        let gone: Vec<String> =
            (0..self.pkgs.len()).filter(|&i| !reached[i]).map(|i| self.pkgs[i].key.to_string()).collect();
        let root = rewrite(&res.root.dependencies, top(NONE).unwrap_or_default());
        if copies.is_empty() && gone.is_empty() && root == res.root.dependencies {
            return None;
        }
        Some(Plan { copies, gone, root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(key: &str, deps: &[(&str, &str)], peers: &[(&str, PeerKind)]) -> (String, Package) {
        let (name, version) = crate::graph::split_key(key).unwrap();
        let edges = |optional: bool| -> Deps {
            deps.iter()
                .filter(|(n, _)| peers.iter().any(|p| p.0 == *n && p.1 == PeerKind::Optional) == optional)
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect()
        };
        let peers = (!peers.is_empty()).then(|| peers.iter().map(|(n, k)| (n.to_string(), *k)).collect());
        let p = Package {
            name: name.into(),
            version: version.into(),
            dependencies: edges(false),
            optional_dependencies: edges(true),
            peers,
            ..Package::default()
        };
        (key.to_string(), p)
    }

    fn resolution(root: &[(&str, &str)], packages: Vec<(String, Package)>) -> Resolution {
        let mut res = Resolution { packages: packages.into_iter().collect(), ..Resolution::default() };
        res.root.dependencies = root.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        res
    }

    #[test]
    fn a_cycle_back_through_a_peer_ends() {
        // pnpm's recursive-with-optional-peer: r's peer is the root's a 1.0.1, and d, below r,
        // brings a 1.0.0 and r again: that r is another copy, and its d is the first one.
        let res = resolution(
            &[("r", "1.0.0"), ("a", "1.0.1")],
            vec![
                pkg("a@1.0.0", &[], &[]),
                pkg("a@1.0.1", &[], &[]),
                pkg("r@1.0.0", &[("a", "1.0.1"), ("d", "1.0.0")], &[("a", PeerKind::Optional)]),
                pkg("d@1.0.0", &[("a", "1.0.0"), ("r", "1.0.0")], &[]),
            ],
        );
        let out = split(res.clone());
        let keys: Vec<&str> = out.packages.keys().map(String::as_str).collect();
        assert_eq!(keys, ["a@1.0.0", "a@1.0.1", "d@1.0.0", "r@1.0.0(a@1.0.0)", "r@1.0.0(a@1.0.1)"]);
        assert_eq!(out.root.dependencies["r"], "1.0.0(a@1.0.1)");
        assert_eq!(out.packages["d@1.0.0"].dependencies["r"], "1.0.0(a@1.0.0)");
        assert_eq!(out.packages["r@1.0.0(a@1.0.0)"].dependencies["d"], "1.0.0");
        assert_eq!(out.packages["r@1.0.0(a@1.0.0)"].optional_dependencies["a"], "1.0.0");
        // The same input, the same copies.
        assert_eq!(split(res).packages, out.packages);
    }

    #[test]
    fn a_tree_without_peers_is_left_as_it_is() {
        let res = resolution(&[("x", "1.0.0")], vec![pkg("x@1.0.0", &[("y", "1.0.0")], &[]), pkg("y@1.0.0", &[], &[])]);
        assert_eq!(split(res.clone()).packages, res.packages);
        // Peers met the same way everywhere: the keys stay plain.
        let res = resolution(
            &[("host", "1.0.0"), ("p", "1.0.0"), ("q", "1.0.0")],
            vec![
                pkg("host@1.0.0", &[], &[]),
                pkg("p@1.0.0", &[("plugin", "1.0.0")], &[]),
                pkg("q@1.0.0", &[("plugin", "1.0.0")], &[]),
                pkg("plugin@1.0.0", &[("host", "1.0.0")], &[("host", PeerKind::Required)]),
            ],
        );
        assert_eq!(split(res.clone()).packages, res.packages);
    }
}
