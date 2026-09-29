//! Store entry keys. An entry is keyed by its whole subgraph, so two packages sharing a name
//! and version but differing below never share a directory. The graph has cycles and heavy
//! sharing, so the hash runs bottom-up over its strongly connected components: linear.

use std::collections::{BTreeMap, HashMap};

use crate::graph::{Deps, Package};
use crate::util::short_hash;

/// Every registry or tarball package's entry directory name, `<name>@<version>-<hash>`, one path
/// segment: a scope's `/` becomes `+`, which no package name can hold. A workspace has none.
pub fn store_keys(packages: &BTreeMap<String, Package>) -> HashMap<String, String> {
    let digests = digests(packages);
    packages
        .iter()
        .filter(|(_, p)| p.local.is_none())
        .map(|(k, p)| (k.clone(), format!("{}@{}-{}", p.name.replace('/', "+"), p.version, digests[k])))
        .collect()
}

/// Identity, content and what it resolves its deps to. Integrity, not the url: a republished
/// tarball is new content, and a mirror serving the same bytes is not.
fn line_of(p: &Package) -> String {
    match &p.local {
        Some(path) => format!("{}@link:{path}::local", p.name),
        // A built or patched package is its own entry: its files are not the store's.
        None => format!(
            "{}@{}::{}::{}{}{}",
            p.name,
            p.version,
            p.integrity,
            edges(&p.all_deps()),
            if p.build { "::build" } else { "" },
            p.patch.as_ref().map_or(String::new(), |h| format!("::patch:{h}"))
        ),
    }
}

fn edges(deps: &Deps) -> String {
    let mut list: Vec<String> = deps.iter().map(|(n, v)| format!("{n}@{v}")).collect();
    list.sort();
    list.join(",")
}

fn hash(mut lines: Vec<String>) -> String {
    lines.sort();
    short_hash(&lines.join("\n"))
}

/// A digest per package, Merkle-style over the components. Tarjan yields sinks first, so every
/// component below is hashed before the one above it; a cycle's members share one digest.
fn digests(packages: &BTreeMap<String, Package>) -> HashMap<String, String> {
    let ids: Vec<&String> = packages.keys().collect();
    let index: HashMap<&str, usize> = ids.iter().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
    let graph: Vec<Vec<usize>> = ids
        .iter()
        .map(|k| {
            let p = &packages[*k];
            if p.local.is_some() {
                return Vec::new();
            }
            p.all_deps().iter().filter_map(|(n, v)| index.get(format!("{n}@{v}").as_str()).copied()).collect()
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
        let h = hash(lines);
        for &n in &group {
            digest[n] = Some(h.clone());
        }
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
    fn escapes_scopes() {
        let mut g = BTreeMap::new();
        g.insert("@s/a@1.0.0".to_string(), pkg("@s/a", &[]));
        assert!(store_keys(&g)["@s/a@1.0.0"].starts_with("@s+a@1.0.0-"));
    }
}
