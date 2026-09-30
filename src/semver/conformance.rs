//! node-semver's own test tables, from tests/conformance/semver, run against this module. Each
//! row's answer is node-semver's as npm asks it (`loose: true`); see that directory's README.
//!
//! Not run: increments.js and truncations.js (jpm never bumps or truncates a version) and the
//! version-{gt,lt,not-gt,not-lt}-range.js tables and test/ranges/subset.js (jpm has no gtr, ltr,
//! outside or subset: overrides match with intersects, as pnpm's do). Rows with
//! `includePrerelease` run where jpm takes that flag (parsing and satisfies) and are skipped in
//! comparator-intersection, whose jpm function has no such mode.

use super::*;
use serde_json::Value;

const TABLES: &[(&str, &str)] = &[
    ("comparisons", include_str!("../../tests/conformance/semver/comparisons.json")),
    ("equality", include_str!("../../tests/conformance/semver/equality.json")),
    ("valid-versions", include_str!("../../tests/conformance/semver/valid-versions.json")),
    ("invalid-versions", include_str!("../../tests/conformance/semver/invalid-versions.json")),
    ("range-parse", include_str!("../../tests/conformance/semver/range-parse.json")),
    ("range-include", include_str!("../../tests/conformance/semver/range-include.json")),
    ("range-exclude", include_str!("../../tests/conformance/semver/range-exclude.json")),
    ("range-intersection", include_str!("../../tests/conformance/semver/range-intersection.json")),
    ("comparator-intersection", include_str!("../../tests/conformance/semver/comparator-intersection.json")),
];

/// Rows where jpm answers otherwise on purpose: (table, first column, why).
const KNOWN: &[(&str, &str, &str)] = &[];

/// A range as node-semver's `validRange` prints it.
fn canonical(sets: &[Vec<Comparator>]) -> String {
    let text = sets.iter().map(|s| s.iter().map(Comparator::value).collect::<Vec<_>>().join(" "));
    let text = text.collect::<Vec<_>>().join("||");
    if text.is_empty() { "*".into() } else { text }
}

fn ids(v: &Version) -> Value {
    v.pre
        .iter()
        .map(|id| match id {
            Id::Num(n) => Value::from(*n),
            Id::Str(s) => Value::from(s.as_str()),
        })
        .collect()
}

fn ord(a: &Version, b: &Version) -> i64 {
    match a.cmp(b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// jpm's answer to one row, as the table's last column would put it; `None` skips the row.
fn answer(table: &str, row: &[Value]) -> Option<Value> {
    let s = |i: usize| row[i].as_str().unwrap();
    let flag = |i: usize| row[i].as_bool().unwrap();
    Some(match table {
        "comparisons" | "equality" => {
            let (Some(a), Some(b)) = (parse(s(0)), parse(s(1))) else { return Some(Value::Null) };
            // Both directions, so an asymmetric comparison shows up as a wrong answer.
            let (x, y) = (ord(&a, &b), ord(&b, &a));
            if x != -y { Value::from("asymmetric") } else { Value::from(x) }
        }
        "valid-versions" => {
            parse(s(0)).map_or(Value::Null, |v| Value::from(vec![Value::from(v.text.as_str()), ids(&v)]))
        }
        "invalid-versions" => parse(s(0)).map_or(Value::Null, |v| Value::from(v.text)),
        "range-parse" => {
            let parsed = parse_range(s(0), flag(1)).map(|sets| canonical(&sets));
            // validRange itself has no includePrerelease in jpm; it must agree where it applies.
            if !flag(1) && valid_range(s(0)) != parsed.is_some() {
                return Some(Value::from("valid_range disagrees"));
            }
            parsed.map_or(Value::Null, Value::from)
        }
        "range-include" | "range-exclude" => {
            Value::from(parse(s(1)).is_some_and(|v| satisfies_version(&v, s(0), flag(2))))
        }
        "range-intersection" => {
            let (x, y) = (intersects(s(0), s(1)), intersects(s(1), s(0)));
            if x != y { Value::from("asymmetric") } else { Value::from(x) }
        }
        "comparator-intersection" if flag(2) => return None,
        "comparator-intersection" => {
            let (x, y) = (intersects(s(0), s(1)), intersects(s(1), s(0)));
            if x != y { Value::from("asymmetric") } else { Value::from(x) }
        }
        _ => panic!("no runner for {table}"),
    })
}

#[test]
fn matches_node_semver() {
    let mut wrong = Vec::new();
    let mut known_hit = vec![false; KNOWN.len()];
    let mut counts = Vec::new();
    for (name, text) in TABLES {
        let doc: Value = serde_json::from_str(text).unwrap();
        let want_at = doc["columns"].as_array().unwrap().len() - 1;
        let (mut ran, mut skipped) = (0, 0);
        for row in doc["rows"].as_array().unwrap() {
            let row = row.as_array().unwrap();
            let Some(got) = answer(name, row) else {
                skipped += 1;
                continue;
            };
            ran += 1;
            if got == row[want_at] {
                continue;
            }
            let key = row[0].as_str().unwrap();
            match KNOWN.iter().position(|(t, k, _)| t == name && *k == key) {
                Some(i) => known_hit[i] = true,
                None => wrong.push(format!("{name}: {} => jpm {got}", Value::from(row.clone()))),
            }
        }
        counts.push(format!("{name} {ran} run, {skipped} skipped"));
    }
    let stale: Vec<_> = KNOWN.iter().zip(&known_hit).filter(|(_, hit)| !**hit).map(|(k, _)| k).collect();
    assert!(stale.is_empty(), "allowlisted rows that now match node-semver: {stale:?}");
    assert!(
        wrong.is_empty(),
        "{} rows differ from node-semver ({}):\n{}",
        wrong.len(),
        counts.join("; "),
        wrong.join("\n")
    );
}
