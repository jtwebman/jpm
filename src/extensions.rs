//! `packageExtensions`: the project's fixes to the manifests of the packages it installs, a
//! dependency or a peer a package forgot to declare, or a peer to make optional. Read from
//! pnpm-workspace.yaml, package.json's `pnpm.packageExtensions` and `.yarnrc.yml`, and applied
//! to a package's manifest as the walk reads it, before its edges and peers are walked.
//!
//! As pnpm's read-package hook has it (`createPackageExtender`, hooks/read-package-hook): a key is
//! `name` or `name@range`, a range matching the version as `semver.satisfies` does (no
//! prereleases unless the range names one); for each of `dependencies`, `optionalDependencies`,
//! `peerDependencies` and `peerDependenciesMeta`, what the package declares itself wins over the
//! extension (`{ ...extension, ...manifest }`); extensions are applied in the order they are
//! written, each onto what the ones before it made, so the first to name a dependency gives its
//! range. The root and the workspaces are extended too, as pnpm extends its projects.

use crate::graph::Deps;
use crate::json::Value;
use crate::manifest::Manifest;
use crate::project::RootManifest;
use crate::{semver, spec, ui};

/// The four fields an extension may set.
pub const FIELDS: [&str; 4] = ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"];

/// Where an extension was written: which decides how its values are read (berry writes
/// `npm:^1.2.3` for a registry range), and the order they apply in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Pnpm,
    Yarn,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extension {
    /// The package it extends.
    pub name: String,
    /// Only the versions this range allows; `None` for every version.
    pub range: Option<String>,
    pub dependencies: Deps,
    pub optional_dependencies: Deps,
    pub peer_dependencies: Deps,
    /// `peerDependenciesMeta`: each name, and its `optional` as jpm.lock writes it: `true`,
    /// `false`, or `-` for an entry that does not say.
    pub peer_meta: Deps,
}

impl Extension {
    /// `name`, or `name@range`.
    pub fn selector(&self) -> String {
        self.range.as_ref().map_or_else(|| self.name.clone(), |r| format!("{}@{r}", self.name))
    }

    /// Whether it extends `name` at `version`. A package with no version is matched only by a
    /// key with no range, as pnpm matches one.
    pub fn matches(&self, name: &str, version: Option<&str>) -> bool {
        self.name == name
            && match (&self.range, version) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(r), Some(v)) => semver::satisfies(v, if r.is_empty() { "*" } else { r }),
            }
    }

    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
            && self.optional_dependencies.is_empty()
            && self.peer_dependencies.is_empty()
            && self.peer_meta.is_empty()
    }

    /// As package.json writes it, which `jpm lock --json` prints.
    pub fn to_value(&self) -> Value {
        let mut o = crate::json::Object::new();
        for (field, map) in [
            (FIELDS[0], &self.dependencies),
            (FIELDS[1], &self.optional_dependencies),
            (FIELDS[2], &self.peer_dependencies),
        ] {
            if !map.is_empty() {
                o.insert(field, crate::json::str_map(map));
            }
        }
        if !self.peer_meta.is_empty() {
            let meta = self.peer_meta.iter().map(|(n, optional)| {
                let mut entry = crate::json::Object::new();
                if optional != "-" {
                    entry.insert("optional", (optional == "true").into());
                }
                (n.clone(), Value::Object(entry))
            });
            o.insert(FIELDS[3], Value::Object(meta.collect()));
        }
        Value::Object(o)
    }

    /// Each entry as jpm.lock writes it: field, name, value.
    pub fn entries(&self) -> Vec<(&'static str, &str, &str)> {
        let mut out = Vec::new();
        for (field, map) in [
            (FIELDS[0], &self.dependencies),
            (FIELDS[1], &self.optional_dependencies),
            (FIELDS[2], &self.peer_dependencies),
            (FIELDS[3], &self.peer_meta),
        ] {
            out.extend(map.iter().map(|(n, r)| (field, n.as_str(), r.as_str())));
        }
        out
    }

    /// One entry as jpm.lock writes it, added to this extension; `None` when it is not one.
    pub fn add_entry(&mut self, field: &str, name: &str, value: &str) -> Option<()> {
        let map = match field {
            "dependencies" => &mut self.dependencies,
            "optionalDependencies" => &mut self.optional_dependencies,
            "peerDependencies" => &mut self.peer_dependencies,
            "peerDependenciesMeta" if matches!(value, "true" | "false" | "-") => &mut self.peer_meta,
            _ => return None,
        };
        map.insert(name.into(), value.into());
        Some(())
    }

    /// The extension of a selector as jpm.lock writes it, no entries yet.
    pub fn parse_selector(selector: &str) -> Option<Self> {
        let (name, range) = name_range(selector);
        spec::check_name(&name, selector).ok()?;
        Some(Self { name, range, ..Self::default() })
    }
}

/// `name` or `name@range`, as pnpm's `parseWantedDependency` splits a key.
fn name_range(s: &str) -> (String, Option<String>) {
    match crate::graph::name_end(s) {
        Some(at) => (s[..at].trim().to_string(), Some(s[at + 1..].trim().to_string())),
        None => (s.trim().to_string(), None),
    }
}

/// The extensions one file gives, in the order written. `file` names it in a warning; what jpm
/// cannot read is left out with one.
pub fn read(v: Option<&Value>, source: Source, file: &str) -> Vec<Extension> {
    let mut out = Vec::new();
    let Some(map) = v.and_then(Value::as_object) else {
        if v.is_some_and(|v| !v.is_null()) {
            ui::warn(&format!("{file}: packageExtensions is not a map of package selectors; it is ignored"));
        }
        return out;
    };
    for (key, value) in map.iter().filter(|(k, _)| !k.starts_with("//")) {
        let skip = |why: &str| ui::warn(&format!("{file}: packageExtensions {key} {why}; it is ignored"));
        let Some(mut ext) = Extension::parse_selector(key) else {
            skip("is not a package name or name@range");
            continue;
        };
        if source == Source::Yarn {
            // berry's descriptor: `name@npm:^1` is the range `^1`.
            ext.range = ext.range.map(|r| npm_range(&r));
        }
        if ext.range.as_deref().is_some_and(|r| !r.is_empty() && !semver::valid_range(r)) {
            skip("has a range jpm cannot read");
            continue;
        }
        let Some(fields) = value.as_object() else {
            skip("is not a map of fields");
            continue;
        };
        let mut ok = true;
        // A field set to null is not set, as pnpm reads one.
        for (field, v) in fields.iter().filter(|(_, v)| !v.is_null()) {
            let ranges = |map: &mut Deps| -> bool {
                let Some(o) = v.as_object() else { return false };
                for (name, range) in o.iter() {
                    let Some(range) = range.as_str() else { return false };
                    let range = if source == Source::Yarn { npm_range(range) } else { range.trim().to_string() };
                    map.insert(name.clone(), range);
                }
                true
            };
            let read = match field.as_str() {
                "dependencies" => ranges(&mut ext.dependencies),
                "optionalDependencies" => ranges(&mut ext.optional_dependencies),
                "peerDependencies" => ranges(&mut ext.peer_dependencies),
                "peerDependenciesMeta" => match v.as_object() {
                    Some(o) => {
                        for (name, meta) in o.iter() {
                            let optional = meta.get("optional").and_then(Value::as_bool);
                            let optional = optional.map_or("-", |o| if o { "true" } else { "false" });
                            ext.peer_meta.insert(name.clone(), optional.into());
                        }
                        true
                    }
                    None => false,
                },
                // A field pnpm does not read from an extension changes nothing.
                _ => {
                    let what = format!("{file}: packageExtensions {key} sets {field}, which an extension cannot");
                    ui::warn(&format!("{what}; that field is ignored"));
                    continue;
                }
            };
            if !read {
                skip(&format!("has a {field} that is not a map of ranges"));
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        if let Some(why) = refused(&ext) {
            skip(&why);
            continue;
        }
        out.push(ext);
    }
    out
}

/// One list of extensions from several files, in order: one that sets nothing left out (it
/// changes nothing), and one whose selector came before folded into that one, the earlier's
/// entries winning, as pnpm merges two extensions of one selector (`mergePackageExtension`).
pub fn merged(list: Vec<Extension>) -> Vec<Extension> {
    let mut out: Vec<Extension> = Vec::with_capacity(list.len());
    for ext in list.into_iter().filter(|e| !e.is_empty()) {
        let Some(first) = out.iter_mut().find(|e| e.name == ext.name && e.range == ext.range) else {
            out.push(ext);
            continue;
        };
        for (n, r) in ext.dependencies {
            first.dependencies.entry(n).or_insert(r);
        }
        for (n, r) in ext.optional_dependencies {
            first.optional_dependencies.entry(n).or_insert(r);
        }
        for (n, r) in ext.peer_dependencies {
            first.peer_dependencies.entry(n).or_insert(r);
        }
        for (n, o) in ext.peer_meta {
            first.peer_meta.entry(n).or_insert(o);
        }
    }
    out
}

/// berry writes `npm:^1.2.3` for a registry range of the package itself.
fn npm_range(r: &str) -> String {
    let r = r.trim();
    r.strip_prefix("npm:").filter(|x| semver::valid_range(x)).unwrap_or(r).to_string()
}

/// Why jpm will not take an extension's values: a name that is not a package's, or a value an
/// extension may not give. A registry range, tag or `npm:` alias is fine, and so is a git or
/// tarball url, as an override's is: the project chose it. A path (`file:`, `link:`) would be
/// read from inside the package it extends, and `workspace:` only the project's own packages may
/// use, so both are refused.
fn refused(ext: &Extension) -> Option<String> {
    let maps = [&ext.dependencies, &ext.optional_dependencies, &ext.peer_dependencies];
    for (name, range) in maps.iter().flat_map(|m| m.iter()) {
        let Ok(s) = spec::parse_dep(name, range) else {
            return Some(format!("gives {name} the range {range}, which jpm cannot read"));
        };
        if matches!(s.kind, spec::Kind::Directory | spec::Kind::Workspace)
            || s.fetch_spec.starts_with("file:")
            || s.fetch_spec.starts_with("link:")
        {
            return Some(format!("gives {name} {range}: an extension cannot name a path or a workspace"));
        }
        if s.kind == spec::Kind::Runtime {
            return Some(format!("gives {name} {range}: an extension cannot name a runtime"));
        }
    }
    for name in ext.peer_meta.keys().chain(maps.iter().flat_map(|m| m.keys())) {
        if spec::check_name(name, name).is_err() {
            return Some(format!("names {name}, which is not a package name"));
        }
    }
    None
}

/// pnpm's merge of one field, `{ ...extension, ...manifest }`: the entries of `ext` the package
/// does not declare (`has`), or `None` when it declares them all.
fn missing(ext: &Deps, has: &dyn Fn(&str) -> bool) -> Option<Deps> {
    let added: Deps = ext.iter().filter(|(n, _)| !has(n)).map(|(n, r)| (n.clone(), r.clone())).collect();
    (!added.is_empty()).then_some(added)
}

/// `m` as the extensions make it, or `None` when none changes it. `name` is the package it was
/// fetched as: the registry's name for a registry package, its own for another source.
pub fn extend(exts: &[Extension], name: &str, m: &Manifest) -> Option<Manifest> {
    extend_with(exts, name, m, &|_, _| {})
}

/// `extend`, telling `seen` each extension that matches, by its index, and whether it changed
/// the manifest.
pub fn extend_with(exts: &[Extension], name: &str, m: &Manifest, seen: &dyn Fn(usize, bool)) -> Option<Manifest> {
    let mut out: Option<Manifest> = None;
    let version = Some(m.version.as_str()).filter(|v| !v.is_empty());
    for (i, ext) in exts.iter().enumerate().filter(|(_, e)| e.matches(name, version)) {
        let cur = out.as_ref().unwrap_or(m);
        // A bundled dependency is declared, though jpm takes it out of `dependencies`.
        let deps = missing(&ext.dependencies, &|n| cur.dependencies.contains_key(n) || cur.bundled.contains_key(n));
        let optional = missing(&ext.optional_dependencies, &|n| cur.optional_dependencies.contains_key(n));
        let peers = missing(&ext.peer_dependencies, &|n| cur.peer_dependencies.contains_key(n));
        // An entry of `peerDependenciesMeta` is the package's whole when it has one.
        let meta: Vec<(String, bool)> = ext
            .peer_meta
            .iter()
            .filter(|(n, _)| !cur.peer_meta.contains(n))
            .map(|(n, o)| (n.clone(), o == "true"))
            .collect();
        let changes = deps.is_some() || optional.is_some() || peers.is_some() || !meta.is_empty();
        seen(i, changes);
        if !changes {
            continue;
        }
        let next = out.get_or_insert_with(|| m.clone());
        next.dependencies.extend(deps.into_iter().flatten());
        next.optional_dependencies.extend(optional.into_iter().flatten());
        next.peer_dependencies.extend(peers.into_iter().flatten());
        for (n, optional) in meta {
            if optional {
                next.peer_optional.push(n.clone());
            }
            next.peer_meta.push(n);
        }
    }
    // An optional peer named in peerDependenciesMeta alone takes any version, as the manifest's
    // own does (`Manifest::read`).
    if let Some(m) = &mut out {
        for n in &m.peer_optional {
            m.peer_dependencies.entry(n.clone()).or_insert_with(|| "*".into());
        }
    }
    out
}

/// A top (the root, or a workspace) as the extensions make it, as pnpm extends its projects.
pub fn extend_top(exts: &[Extension], m: &mut RootManifest) {
    let Some(name) = m.name.clone().filter(|n| !n.is_empty()) else { return };
    let version = m.version.clone().filter(|v| !v.is_empty());
    let mut meta: Vec<String> = m
        .doc
        .get("peerDependenciesMeta")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();
    for ext in exts.iter().filter(|e| e.matches(&name, version.as_deref())) {
        let deps = missing(&ext.dependencies, &|n| m.dependencies.contains_key(n));
        m.dependencies.extend(deps.into_iter().flatten());
        let optional = missing(&ext.optional_dependencies, &|n| m.optional_dependencies.contains_key(n));
        m.optional_dependencies.extend(optional.into_iter().flatten());
        let own = m.peer_dependencies.clone().unwrap_or_default();
        if let Some(peers) = missing(&ext.peer_dependencies, &|n| own.contains_key(n)) {
            m.peer_dependencies.get_or_insert_with(Deps::new).extend(peers);
        }
        for (n, optional) in &ext.peer_meta {
            if !meta.contains(n) {
                meta.push(n.clone());
                if optional == "true" {
                    m.peer_optional.push(n.clone());
                }
            }
        }
    }
}

/// Whether an extension of `name` at `version` gives the dependency `dep` the range `range`:
/// an edge the project chose, as an override's is.
pub fn gives(exts: &[Extension], name: &str, version: &str, dep: &str, range: &str) -> bool {
    exts.iter().filter(|e| e.matches(name, Some(version).filter(|v| !v.is_empty()))).any(|e| {
        [&e.dependencies, &e.optional_dependencies, &e.peer_dependencies]
            .iter()
            .any(|m| m.get(dep).is_some_and(|r| r == range))
    })
}

/// pnpm's `packageExtensionsChecksum` of its `packageExtensions` as written: `sha256-` and the
/// base64 SHA-256 of object-hash's stream with sorted keys (`hashObjectNullableWithPrefix`,
/// crypto/object-hasher; the stream as pnpm's Rust port spells it out in graph-hasher's
/// object_hasher.rs). `None` for none, or an empty map, which pnpm records as no checksum.
pub fn pnpm_checksum(v: &Value) -> Option<String> {
    match v {
        Value::Null => return None,
        Value::Object(o) if o.is_empty() => return None,
        _ => {}
    }
    let mut out = Vec::new();
    object_hash(&mut out, v);
    let digest = jpm_crypto::hash::digest(jpm_crypto::hash::Alg::Sha256, &out);
    Some(format!("sha256-{}", crate::util::to_base64(&digest)))
}

/// object-hash 3's stream with `respectType: false` and unordered objects and arrays.
fn object_hash(out: &mut Vec<u8>, v: &Value) {
    let string = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(format!("string:{}:", s.encode_utf16().count()).as_bytes());
        out.extend_from_slice(s.as_bytes());
    };
    match v {
        Value::Null => out.extend_from_slice(b"Null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"bool:true" } else { b"bool:false" }),
        Value::Number(n) => out.extend_from_slice(format!("number:{n}").as_bytes()),
        Value::String(s) => string(out, s),
        // Unordered: two or more entries are each streamed, sorted, and written as strings.
        Value::Array(items) if items.len() > 1 => {
            let mut each: Vec<String> = items
                .iter()
                .map(|item| {
                    let mut one = Vec::new();
                    object_hash(&mut one, item);
                    String::from_utf8_lossy(&one).into_owned()
                })
                .collect();
            each.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            // Its header, then the sorted entries' own array, header and all (`_array`).
            let header = format!("array:{}:", items.len());
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(header.as_bytes());
            for one in each {
                string(out, &one);
            }
        }
        Value::Array(items) => {
            out.extend_from_slice(format!("array:{}:", items.len()).as_bytes());
            for item in items {
                object_hash(out, item);
            }
        }
        Value::Object(o) => {
            let mut keys: Vec<(&String, &Value)> = o.iter().collect();
            // JavaScript's sort, by UTF-16 code units.
            keys.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.extend_from_slice(format!("object:{}:", keys.len()).as_bytes());
            for (k, v) in keys {
                string(out, k);
                out.push(b':');
                object_hash(out, v);
                out.push(b',');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exts(text: &str) -> Vec<Extension> {
        merged(read(Some(&crate::json::parse(text).unwrap()), Source::Pnpm, "test"))
    }

    fn manifest(text: &str) -> Manifest {
        Manifest::from_json(text).unwrap()
    }

    #[test]
    fn matches_selectors_as_pnpm_does() {
        let e = exts(
            r#"{ "a": { "dependencies": { "x": "1" } }, "@s/b@^1.2.0": { "dependencies": { "x": "1" } },
                 "c@>=2 <3": { "dependencies": { "x": "1" } }, "d@": { "dependencies": { "x": "1" } } }"#,
        );
        let sel: Vec<String> = e.iter().map(Extension::selector).collect();
        assert_eq!(sel, ["a", "@s/b@^1.2.0", "c@>=2 <3", "d@"]);
        // A bare name: every version, and a package with none.
        assert!(e[0].matches("a", Some("0.0.1")) && e[0].matches("a", Some("9.0.0-rc.1")) && e[0].matches("a", None));
        assert!(!e[0].matches("ab", Some("1.0.0")));
        // A range: semver.satisfies, so no prerelease unless the range names one; never no version.
        assert!(e[1].matches("@s/b", Some("1.3.0")) && !e[1].matches("@s/b", Some("2.0.0")));
        assert!(!e[1].matches("@s/b", Some("1.3.0-beta.1")) && !e[1].matches("@s/b", None));
        assert!(e[2].matches("c", Some("2.5.0")) && !e[2].matches("c", Some("3.0.0")));
        // `name@` is `*`.
        assert!(e[3].matches("d", Some("4.0.0")));
    }

    #[test]
    fn leaves_out_what_it_cannot_take() {
        let e = exts(
            r#"{ "ok": { "dependencies": { "git": "github:a/b", "url": "https://x.test/a.tgz", "alias": "npm:other@^1", "tag": "latest" } },
                 "../x": { "dependencies": { "a": "1" } },
                 "bad-range@not a range!": { "dependencies": { "a": "1" } },
                 "path": { "dependencies": { "a": "file:../a" } },
                 "link": { "dependencies": { "a": "link:../a" } },
                 "ws": { "dependencies": { "a": "workspace:*" } },
                 "dev": { "devDependencies": { "a": "1" }, "dependencies": { "a": "1" }, "peerDependencies": null },
                 "shape": { "dependencies": ["a"] },
                 "empty": {},
                 "//": "a comment" }"#,
        );
        // A field pnpm does not read is left out, the rest kept; a null one is no field.
        assert_eq!(e.iter().map(Extension::selector).collect::<Vec<_>>(), ["ok", "dev"]);
        assert_eq!(e[0].dependencies.len(), 4);
        assert_eq!(e[1].dependencies.len(), 1);
    }

    #[test]
    fn what_the_package_declares_wins() {
        let e = exts(
            r#"{ "p": { "dependencies": { "a": "^2", "b": "^1" }, "peerDependencies": { "r": "*" },
                        "peerDependenciesMeta": { "r": { "optional": true }, "q": { "optional": true } },
                        "optionalDependencies": { "o": "1" } } }"#,
        );
        let m = manifest(
            r#"{ "name": "p", "version": "1.0.0", "dependencies": { "a": "^1" },
                 "peerDependencies": { "q": "^3" }, "peerDependenciesMeta": { "q": { "optional": false } } }"#,
        );
        let x = extend(&e, "p", &m).unwrap();
        assert_eq!(x.dependencies.get("a").unwrap(), "^1", "the package's own range");
        assert_eq!(x.dependencies.get("b").unwrap(), "^1");
        assert_eq!(x.optional_dependencies.get("o").unwrap(), "1");
        assert_eq!(x.peer_dependencies.get("r").unwrap(), "*");
        // Its own peerDependenciesMeta entry is whole: q stays required.
        assert!(x.is_optional_peer("r") && !x.is_optional_peer("q"));
        // Nothing to add, or no match: the manifest as it is.
        let full = manifest(
            r#"{ "name": "p", "version": "1.0.0", "dependencies": { "a": "1", "b": "1" }, "optionalDependencies": { "o": "1" },
                 "peerDependencies": { "r": "1" }, "peerDependenciesMeta": { "r": {}, "q": {} } }"#,
        );
        assert!(extend(&e, "p", &full).is_none());
        assert!(extend(&e, "other", &m).is_none());
    }

    #[test]
    fn several_extensions_apply_in_order_the_first_winning() {
        let e = exts(
            r#"{ "p": { "dependencies": { "a": "1" } }, "p@^1": { "dependencies": { "a": "2", "b": "2" } },
                 "p@^2": { "dependencies": { "c": "3" } }, "q": { "peerDependenciesMeta": { "x": { "optional": true } } } }"#,
        );
        let x = extend(&e, "p", &manifest(r#"{ "name": "p", "version": "1.5.0" }"#)).unwrap();
        assert_eq!(x.dependencies, Deps::from([("a".into(), "1".into()), ("b".into(), "2".into())]));
        // An optional peer named in peerDependenciesMeta alone takes any version.
        let x = extend(&e, "q", &manifest(r#"{ "name": "q", "version": "1.0.0" }"#)).unwrap();
        assert_eq!(x.peer_dependencies.get("x").unwrap(), "*");
        assert!(x.is_optional_peer("x"));
        // A bundled dependency is declared.
        let b = manifest(
            r#"{ "name": "p", "version": "1.0.0", "dependencies": { "a": "9" }, "bundleDependencies": ["a"] }"#,
        );
        let x = extend(&e, "p", &b).unwrap();
        assert!(!x.dependencies.contains_key("a"));
    }

    #[test]
    fn merges_one_selector_from_several_files_the_first_winning() {
        let text = |t: &str| crate::json::parse(t).unwrap();
        let pnpm = read(Some(&text(r#"{ "p@^1": { "dependencies": { "a": "1" } } }"#)), Source::Pnpm, "x");
        let yarn = read(
            Some(&text(r#"{ "p@npm:^1": { "dependencies": { "a": "npm:2", "b": "npm:^2.0.0" } } }"#)),
            Source::Yarn,
            "y",
        );
        let all = merged(pnpm.into_iter().chain(yarn).collect());
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].selector(), "p@^1");
        // berry's `npm:<range>` is the range.
        assert_eq!(all[0].dependencies, Deps::from([("a".into(), "1".into()), ("b".into(), "^2.0.0".into())]));
    }

    #[test]
    fn writes_entries_as_the_lockfile_reads_them() {
        let e = exts(
            r#"{ "p@^1": { "peerDependenciesMeta": { "x": { "optional": true }, "y": {} }, "dependencies": { "a": ">=1 <2" } } }"#,
        );
        let mut back = Extension::parse_selector(&e[0].selector()).unwrap();
        for (field, name, value) in e[0].entries() {
            back.add_entry(field, name, value).unwrap();
        }
        assert_eq!(back, e[0]);
        assert!(back.add_entry("devDependencies", "a", "1").is_none());
        assert!(back.add_entry("peerDependenciesMeta", "a", "yes").is_none());
    }

    #[test]
    fn computes_pnpms_checksum() {
        // Vectors from object-hash 3.0.0 with pnpm's options: crypto/object-hasher's own test,
        // and node runs of it.
        let sum = |text: &str| pnpm_checksum(&crate::json::parse(text).unwrap());
        assert_eq!(sum(r#"{ "b": 1, "a": 2 }"#).unwrap(), "sha256-48AVoXIXcTKcnHt8qVKp5vNw4gyOB5VfztHwtYBRcAQ=");
        assert_eq!(
            sum(r#"{ "is-positive": { "dependencies": { "@pnpm.e2e/bar": "100.1.0" } } }"#).unwrap(),
            "sha256-HZEpjtRdr7gJfO0V6YoFDfxWmaw3anoE1/tQQbzas+E="
        );
        assert_eq!(
            sum(r#"{ "b@^1": { "peerDependencies": { "x": "*" }, "peerDependenciesMeta": { "x": { "optional": true } } },
                     "a": { "dependencies": { "é": "1", "z": "2" } } }"#)
            .unwrap(),
            "sha256-cRAHtuhkw7sfx7TX2CUR3mpmYKaOgbzjncpMZWHW5xI="
        );
        assert_eq!(
            sum(r#"{ "a": ["x", "b", { "c": true }] }"#).unwrap(),
            "sha256-/z1z5JnVtBeXCz8ujb6Zknd26+4ndN4Osq0XHcIvQJw="
        );
        assert_eq!(sum("{}"), None);
        assert_eq!(sum("null"), None);
    }

    #[test]
    fn extends_a_top() {
        let e = exts(
            r#"{ "app@*": { "dependencies": { "a": "1" }, "peerDependencies": { "r": "*" }, "peerDependenciesMeta": { "r": { "optional": true } } } }"#,
        );
        let parse = |t: &str| RootManifest::parse(t, std::path::Path::new("package.json")).unwrap();
        let mut m = parse(r#"{ "name": "app", "version": "1.0.0", "dependencies": { "a": "2" } }"#);
        extend_top(&e, &mut m);
        assert_eq!(m.dependencies.get("a").unwrap(), "2");
        assert_eq!(m.peer_dependencies.as_ref().unwrap().get("r").unwrap(), "*");
        assert_eq!(m.peer_optional, ["r"]);
        // No version: a range never matches.
        let mut m = parse(r#"{ "name": "app" }"#);
        extend_top(&e, &mut m);
        assert!(m.dependencies.is_empty());
    }
}
