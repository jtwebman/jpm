//! A package's `bin` field as a clean `{ name: relative target }` map, as
//! `npm-normalize-package-bin` has it. Security critical: a bin name or target that escapes the
//! package would let an install write outside `node_modules/.bin`.

use std::collections::BTreeMap;

use serde_json::Value;

pub type Bins = BTreeMap<String, String>;

/// `directories.bin` is not read: that needs a directory listing, and packages using it get none.
pub fn normalize(name: Option<&str>, bin: Option<&Value>) -> Bins {
    let mut out = Bins::new();
    match bin {
        Some(Value::String(target)) => {
            if let Some(name) = name.filter(|n| !n.is_empty()) {
                put(&mut out, name, target);
            }
        }
        Some(Value::Array(list)) => {
            for target in list.iter().filter_map(Value::as_str) {
                put(&mut out, basename(target), target);
            }
        }
        Some(Value::Object(map)) => {
            for (key, target) in map {
                if let Some(target) = target.as_str() {
                    put(&mut out, key, target);
                }
            }
        }
        _ => {}
    }
    out
}

/// A map already normalized once (a lockfile's), cleaned again: a hand edit is untrusted.
pub fn clean_map(map: &BTreeMap<String, String>) -> Bins {
    let mut out = Bins::new();
    for (key, target) in map {
        put(&mut out, key, target);
    }
    out
}

fn put(out: &mut Bins, key: &str, target: &str) {
    let key = basename(&key.replace(['\\', ':'], "/")).to_string();
    if matches!(key.as_str(), "" | "." | "..") {
        return;
    }
    let target = rooted(&target.replace('\\', "/"));
    if matches!(target.as_str(), "" | "." | "..") {
        return;
    }
    out.insert(key, target);
}

fn basename(p: &str) -> &str {
    let trimmed = p.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// `path.posix.join("/", p).slice(1)`: `.` and `..` collapsed, never above the root.
fn rooted(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if !joined.is_empty() && p.ends_with('/') { format!("{joined}/") } else { joined }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bins(name: &str, bin: Value) -> Vec<(String, String)> {
        normalize(Some(name), Some(&bin)).into_iter().collect()
    }

    #[test]
    fn normalizes_shapes() {
        assert_eq!(bins("foo", json!("./cli.js")), [("foo".into(), "cli.js".into())]);
        assert_eq!(bins("@s/foo", json!("cli.js")), [("foo".into(), "cli.js".into())]);
        assert_eq!(bins("x", json!(["bin/a.js"])), [("a.js".into(), "bin/a.js".into())]);
        assert_eq!(bins("x", json!({"a": "b", "c": 1})), [("a".into(), "b".into())]);
    }

    #[test]
    fn keeps_bins_inside() {
        assert_eq!(bins("x", json!({"../../evil": "../../../etc/passwd"})), [("evil".into(), "etc/passwd".into())]);
        assert!(bins("x", json!({"..": "a", "b": ".."})).is_empty());
        assert_eq!(bins("x", json!({"c:\\x": "a\\b"})), [("x".into(), "a/b".into())]);
    }
}
