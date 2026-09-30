//! Store entry keys. An entry is keyed by its whole subgraph, so two packages sharing a name
//! and version but differing below never share a directory. The graph has cycles and heavy
//! sharing, so the hash runs bottom-up over its strongly connected components: linear.

use std::collections::{BTreeMap, HashMap};

use crate::graph::{Deps, Package};
use crate::util::{full_hash, short_hash};

/// Every registry or tarball package's entry directory name, `<name>@<version>-<hash>`, one path
/// segment: a scope's `/` becomes `+`, which no package name can hold. A workspace has none.
pub fn store_keys(packages: &BTreeMap<String, Package>) -> HashMap<String, String> {
    let digests = digests(packages, false);
    packages
        .iter()
        .filter(|(_, p)| p.local.is_none())
        .map(|(k, p)| (k.clone(), format!("{}@{}-{}", p.dir_name().replace('/', "+"), p.version, digests[k])))
        .collect()
}

/// Every registry or tarball package's subgraph digest in full, 43 characters of SHA-256 where
/// `store_keys` keeps 22: a global entry's name shows the start of it, and the entry holds it
/// whole (see `link`), so no two subgraphs ever pass for one.
pub fn full_digests(packages: &BTreeMap<String, Package>) -> HashMap<String, String> {
    let mut digests = digests(packages, true);
    digests.retain(|k, _| packages[k].local.is_none());
    digests
}

/// An entry directory's package name and version, as `store_keys` wrote them.
pub fn name_version(key: &str) -> Option<(String, &str)> {
    // The hash is 22 characters of base64url, which may hold a `-`.
    let id = key.get(..key.len().checked_sub(23)?).filter(|_| key.as_bytes()[key.len() - 23] == b'-')?;
    let at = crate::graph::name_end(id)?;
    Some((id[..at].replace('+', "/"), &id[at + 1..]))
}

/// Identity, content and what it resolves its deps to. Integrity, not the url: a republished
/// tarball is new content, and a mirror serving the same bytes is not. An alias is its real
/// package: two names for one package with the same deps are one entry, as under pnpm.
fn line_of(p: &Package) -> String {
    match &p.local {
        Some(path) => format!("{}@link:{path}::local", p.name),
        // A built or patched package is its own entry: its files are not the store's. A directory
        // inside a package is the part of its tarball there.
        None => format!(
            "{}@{}::{}::{}{}{}{}",
            p.dir_name(),
            p.version,
            p.integrity,
            edges(&p.all_deps()),
            if p.build { "::build" } else { "" },
            p.patch.as_ref().map_or(String::new(), |h| format!("::patch:{h}")),
            p.within().map_or(String::new(), |(_, at)| format!("::in:{at}"))
        ),
    }
}

fn edges(deps: &Deps) -> String {
    let mut list: Vec<String> = deps.iter().map(|(n, v)| format!("{n}@{v}")).collect();
    list.sort();
    list.join(",")
}

fn hash(mut lines: Vec<String>, full: bool) -> String {
    lines.sort();
    if full { full_hash(&lines.join("\n")) } else { short_hash(&lines.join("\n")) }
}

/// A digest per package, Merkle-style over the components. Tarjan yields sinks first, so every
/// component below is hashed before the one above it; a cycle's members share one digest.
fn digests(packages: &BTreeMap<String, Package>, full: bool) -> HashMap<String, String> {
    let ids: Vec<&String> = packages.keys().collect();
    let index: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
    // An alias with the content and edges of the real package at its version is that package:
    // a peer on the real name, met below the alias (it depends on something that peers on it),
    // is then the same copy, not a twin in a cycle of its own.
    let twin: HashMap<usize, usize> = ids
        .iter()
        .enumerate()
        .filter_map(|(i, k)| {
            let p = &packages[*k];
            let real = format!("{}@{}", p.alias.as_deref()?, p.version);
            let &j = index.get(real.as_str())?;
            (packages[ids[j]].local.is_none() && line_of(&packages[ids[j]]) == line_of(p)).then_some((i, j))
        })
        .collect();
    let graph: Vec<Vec<usize>> = ids
        .iter()
        .map(|k| {
            let p = &packages[*k];
            if p.local.is_some() {
                return Vec::new();
            }
            let child =
                |n: &String, v: &String| index.get(format!("{n}@{v}").as_str()).map(|i| *twin.get(i).unwrap_or(i));
            p.all_deps().iter().filter_map(|(n, v)| child(n, v)).collect()
        })
        .collect();
    let mut digest: Vec<Option<String>> = vec![None; ids.len()];
    for group in components(&graph) {
        let mut lines: Vec<String> = group.iter().map(|&n| line_of(&packages[ids[n]])).collect();
        for &n in &group {
            for &child in &graph[n] {
                if let Some(d) = &digest[child] {
                    lines.push(format!(">{d}"));
                }
            }
        }
        let h = hash(lines, full);
        for &n in &group {
            digest[n] = Some(h.clone());
        }
    }
    for (&i, &j) in &twin {
        digest[i] = digest[j].clone();
    }
    ids.into_iter().zip(digest).map(|(k, d)| (k.clone(), d.unwrap_or_default())).collect()
}

/// Tarjan, iterative: strongly connected components, sinks first.
fn components(graph: &[Vec<usize>]) -> Vec<Vec<usize>> {
    const NONE: usize = usize::MAX;
    let n = graph.len();
    let (mut index, mut low, mut open) = (vec![NONE; n], vec![0; n], vec![false; n]);
    let (mut path, mut out, mut counter) = (Vec::new(), Vec::new(), 0);
    for start in 0..n {
        if index[start] != NONE {
            continue;
        }
        let mut work = vec![(start, 0usize)];
        while let Some(&(node, next)) = work.last() {
            if next == 0 && index[node] == NONE {
                index[node] = counter;
                low[node] = counter;
                counter += 1;
                path.push(node);
                open[node] = true;
            }
            if let Some(&kid) = graph[node].get(next) {
                let top = work.len() - 1;
                work[top].1 += 1;
                if index[kid] == NONE {
                    work.push((kid, 0));
                } else if open[kid] {
                    low[node] = low[node].min(index[kid]);
                }
                continue;
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                low[parent] = low[parent].min(low[node]);
            }
            if low[node] != index[node] {
                continue;
            }
            let mut group = Vec::new();
            loop {
                let member = path.pop().unwrap_or(node);
                open[member] = false;
                group.push(member);
                if member == node {
                    break;
                }
            }
            out.push(group);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, deps: &[&str]) -> Package {
        Package {
            name: name.into(),
            version: "1.0.0".into(),
            integrity: format!("sha512-{name}"),
            dependencies: deps.iter().map(|d| (d.to_string(), "1.0.0".to_string())).collect(),
            ..Package::default()
        }
    }

    fn graph(list: &[(&str, &[&str])]) -> BTreeMap<String, Package> {
        list.iter().map(|(n, d)| (format!("{n}@1.0.0"), pkg(n, d))).collect()
    }

    #[test]
    fn keys_follow_the_subgraph() {
        let a = store_keys(&graph(&[("a", &["b"]), ("b", &[])]));
        let mut changed = graph(&[("a", &["b"]), ("b", &[])]);
        changed.get_mut("b@1.0.0").unwrap().integrity = "sha512-other".into();
        let b = store_keys(&changed);
        assert_ne!(a["a@1.0.0"], b["a@1.0.0"], "a change below moves the parent");
        let c = store_keys(&graph(&[("a", &["b"]), ("b", &[]), ("x", &[])]));
        assert_eq!(a["a@1.0.0"], c["a@1.0.0"], "an unrelated package moves nothing");
        assert!(a["a@1.0.0"].starts_with("a@1.0.0-"));
    }

    #[test]
    fn cycles_share_a_digest() {
        let keys = store_keys(&graph(&[("a", &["b"]), ("b", &["a"]), ("c", &["a"])]));
        let tail = |k: &str| keys[k].rsplit('-').next().unwrap().to_string();
        assert_eq!(tail("a@1.0.0"), tail("b@1.0.0"));
        assert_ne!(tail("a@1.0.0"), tail("c@1.0.0"));
    }

    #[test]
    fn an_alias_is_its_real_package() {
        // `a` is an alias of `r`, whose `b` peers on `r`: alias and real are one entry, named `r`.
        let mut g = graph(&[("r", &["b"]), ("b", &["r"])]);
        let mut alias = pkg("r", &["b"]);
        alias.name = "a".into();
        alias.alias = Some("r".into());
        g.insert("a@npm:r@1.0.0".into(), alias);
        let keys = store_keys(&g);
        assert_eq!(keys["a@npm:r@1.0.0"], keys["r@1.0.0"]);
        assert!(keys["r@1.0.0"].starts_with("r@1.0.0-"));
        // With other edges it is an entry of its own, still under the real name.
        g.get_mut("a@npm:r@1.0.0").unwrap().dependencies.clear();
        let keys = store_keys(&g);
        assert_ne!(keys["a@npm:r@1.0.0"], keys["r@1.0.0"]);
        assert!(keys["a@npm:r@1.0.0"].starts_with("r@1.0.0-"));
    }

    #[test]
    fn escapes_scopes() {
        let mut g = BTreeMap::new();
        g.insert("@s/a@1.0.0".to_string(), pkg("@s/a", &[]));
        assert!(store_keys(&g)["@s/a@1.0.0"].starts_with("@s+a@1.0.0-"));
    }

    #[test]
    fn reads_name_and_version_back() {
        let mut g = graph(&[("a", &[])]);
        let mut scoped = pkg("@s/b", &[]);
        scoped.version = "2.0.0-beta.1".into();
        g.insert("@s/b@2.0.0-beta.1".into(), scoped);
        for (id, key) in store_keys(&g) {
            let (name, version) = name_version(&key).unwrap();
            assert_eq!(format!("{name}@{version}"), id);
        }
        assert_eq!(name_version("@babel+core@7.29.7-PEUj-xSY3KB71f6RKBUtQw"), Some(("@babel/core".into(), "7.29.7")));
        assert_eq!(name_version("a@1.0.0-short"), None);
        assert_eq!(name_version(".hoist"), None);
    }
}
