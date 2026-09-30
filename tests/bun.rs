//! End to end: install outcomes from bun's own tests (github.com/oven-sh/bun, test/cli/install,
//! MIT), on bun's registry fixtures (test/cli/install/registry/packages). Each test names the
//! bun test it follows; where jpm decides otherwise on purpose, the test says so and why.

mod common;

use common::{Env, Registry, pkg};
use serde_json::{Value, json};

/// The packages of bun's mock registry these tests use, as bun's fixtures publish them.
fn registry() -> Registry {
    Registry::start(vec![
        pkg("no-deps", "1.0.0", json!({})),
        pkg("no-deps", "1.0.1", json!({})),
        pkg("no-deps", "1.1.0", json!({})),
        pkg("no-deps", "2.0.0", json!({})),
        pkg("one-dep", "1.0.0", json!({ "dependencies": { "no-deps": "1.0.1" } })),
        pkg("one-range-dep", "1.0.0", json!({ "dependencies": { "no-deps": "^1.0.0" } })),
        pkg("one-fixed-dep", "1.0.0", json!({ "dependencies": { "no-deps": "1.0.0" } })),
        pkg("one-fixed-dep", "2.0.0", json!({ "dependencies": { "no-deps": "2.0.0" } })),
        pkg("peer-deps", "1.0.0", json!({ "peerDependencies": { "no-deps": "*" } })),
        pkg(
            "one-optional-peer-dep",
            "1.0.2",
            json!({ "peerDependencies": { "no-deps": "^1.0.0" }, "peerDependenciesMeta": { "no-deps": { "optional": true } } }),
        ),
        pkg("a-dep", "1.0.1", json!({})),
    ])
}

/// bun's `twoParents`: one-fixed-dep at both its versions, under two aliases.
fn two_parents() -> Value {
    json!({ "ofd1": "npm:one-fixed-dep@1.0.0", "ofd2": "npm:one-fixed-dep@2.0.0" })
}

fn install(r: &Registry, manifest: Value) -> (Env, String) {
    let env = Env::new(r);
    env.manifest(manifest);
    let out = env.ok(&["install"]);
    (env, out)
}

/// What `require(dep)` finds from the package installed as `from` (the root for ""): its
/// `name@version`.
fn sees(env: &Env, from: &str, dep: &str) -> String {
    // A scoped package sits a folder deeper.
    let up = if from.starts_with('@') { "../.." } else { ".." };
    let at = if from.is_empty() { format!("node_modules/{dep}") } else { format!("node_modules/{from}/{up}/{dep}") };
    let text = env.read(&format!("{at}/index.js"));
    text.split('\'').nth(1).unwrap_or_default().to_string()
}

#[test]
fn a_nested_override_applies_to_its_parent_only() {
    // nested-overrides.test.ts "npm object scopes the rule to the parent's edge", and the same
    // rule as yarn's paths and pnpm's selector ("yarn resolutions path", "pnpm parent>child").
    let r = registry();
    let deps = json!({ "one-dep": "1.0.0", "one-range-dep": "1.0.0" });
    let forms = [
        json!({ "overrides": { "one-dep": { "no-deps": "2.0.0" } } }),
        json!({ "resolutions": { "one-dep/no-deps": "2.0.0" } }),
        json!({ "resolutions": { "**/one-dep/no-deps": "2.0.0" } }),
        json!({ "resolutions": { "one-dep@npm:1.0.0/no-deps": "2.0.0" } }),
        json!({ "pnpm": { "overrides": { "one-dep>no-deps": "2.0.0" } } }),
        json!({ "pnpm": { "overrides": { "one-dep@<2 >=1>no-deps": "2.0.0" } } }),
        json!({ "pnpm": { "overrides": { "one-dep@>=1 <2>no-deps": "2.0.0" } } }),
        json!({ "pnpm": { "overrides": { "one-dep>no-deps@>=1": "2.0.0" } } }),
    ];
    for form in forms {
        let mut manifest = json!({ "dependencies": deps });
        manifest.as_object_mut().unwrap().extend(form.as_object().unwrap().clone());
        let (env, out) = install(&r, manifest);
        assert_eq!(sees(&env, "one-dep", "no-deps"), "no-deps@2.0.0", "{form}\n{out}");
        assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.1.0", "{form}");
        assert!(!out.contains("warn"), "{form}\n{out}");
    }
}

#[test]
fn a_nested_override_can_move_its_parent_too() {
    // "\".\" overrides the parent itself next to its children".
    let r = registry();
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "one-fixed-dep": "^2.0.0" },
            "overrides": { "one-fixed-dep": { ".": "1.0.0", "no-deps": "1.1.0" } },
        }),
    );
    assert_eq!(sees(&env, "", "one-fixed-dep"), "one-fixed-dep@1.0.0");
    assert_eq!(sees(&env, "one-fixed-dep", "no-deps"), "no-deps@1.1.0");
}

#[test]
fn a_parent_range_matches_the_version_the_parent_resolved_to() {
    // "parent range is matched against the parent's resolved version, through an alias", and
    // pnpm's form of it ("pnpm parent@range>child selectors, including a range containing >").
    let r = registry();
    let (env, _) = install(
        &r,
        json!({ "dependencies": two_parents(), "overrides": { "one-fixed-dep@1": { "no-deps": "1.1.0" } } }),
    );
    assert_eq!(sees(&env, "ofd1", "no-deps"), "no-deps@1.1.0");
    assert_eq!(sees(&env, "ofd2", "no-deps"), "no-deps@2.0.0");
    let pnpm = json!({ "one-fixed-dep@1>no-deps": "1.1.0", "one-fixed-dep@>=2 <3>no-deps": "1.0.1" });
    let (env, _) = install(&r, json!({ "dependencies": two_parents(), "pnpm": { "overrides": pnpm } }));
    assert_eq!(sees(&env, "ofd1", "no-deps"), "no-deps@1.1.0");
    assert_eq!(sees(&env, "ofd2", "no-deps"), "no-deps@1.0.1");
}

#[test]
fn a_reference_borrows_the_roots_range() {
    // "$ref inside a nested value resolves against the root's dependencies", and the flat
    // `$one-fixed-dep` that borrows another package's range, not its package.
    let r = registry();
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "no-deps": "1.1.0", "one-dep": "1.0.0" },
            "overrides": { "one-dep": { "no-deps": "$no-deps" } },
        }),
    );
    assert_eq!(sees(&env, "one-dep", "no-deps"), "no-deps@1.1.0");
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "one-range-dep": "1.0.0", "one-fixed-dep": "1.0.0" },
            "overrides": { "no-deps": "$one-fixed-dep" },
        }),
    );
    assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.0.0");
    // A range the root declares only as a dev dependency or a peer counts too.
    for group in ["devDependencies", "peerDependencies"] {
        let (env, _) = install(
            &r,
            json!({
                "dependencies": { "one-range-dep": "1.0.0" },
                group: { "no-deps": "1.0.0" },
                "overrides": { "no-deps": "$no-deps" },
            }),
        );
        assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.0.0", "{group}");
    }
}

#[test]
fn a_version_scoped_override_matches_ranges_it_meets() {
    // "Version-scoped targets": a key's range is matched against the range an edge declares,
    // where the two meet; a dist-tag meets none.
    let r = registry();
    let mut deps = two_parents();
    deps["one-range-dep"] = json!("1.0.0");
    let (env, _) = install(&r, json!({ "dependencies": deps, "overrides": { "no-deps@1": "1.0.0" } }));
    assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.0.0");
    assert_eq!(sees(&env, "ofd1", "no-deps"), "no-deps@1.0.0");
    assert_eq!(sees(&env, "ofd2", "no-deps"), "no-deps@2.0.0");
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "one-dep": "1.0.0", "ofd1": "npm:one-fixed-dep@1.0.0", "ofd2": "npm:one-fixed-dep@2.0.0" },
            "overrides": { "no-deps@1.0.0 || 2.0.0": "1.1.0" },
        }),
    );
    assert_eq!(sees(&env, "ofd1", "no-deps"), "no-deps@1.1.0");
    assert_eq!(sees(&env, "ofd2", "no-deps"), "no-deps@1.1.0");
    assert_eq!(sees(&env, "one-dep", "no-deps"), "no-deps@1.0.1");
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "no-deps": "latest", "one-range-dep": "1.0.0" },
            "overrides": { "no-deps@>=1": "1.0.0" },
        }),
    );
    assert_eq!(sees(&env, "", "no-deps"), "no-deps@2.0.0");
    assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.0.0");
}

#[test]
fn an_override_reaches_an_auto_installed_peer_and_an_alias() {
    // "run under both linkers": a parent's override settles the peer it installs, and a rule
    // may name another package.
    let r = registry();
    let (env, out) = install(
        &r,
        json!({ "dependencies": { "peer-deps": "1.0.0" }, "overrides": { "peer-deps": { "no-deps": "1.0.0" } } }),
    );
    assert_eq!(sees(&env, "peer-deps", "no-deps"), "no-deps@1.0.0", "{out}");
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "one-dep": "1.0.0", "one-range-dep": "1.0.0" },
            "overrides": { "one-dep": { "no-deps": "npm:a-dep@1.0.1" } },
        }),
    );
    assert_eq!(sees(&env, "one-dep", "no-deps"), "a-dep@1.0.1");
    assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.1.0");
}

#[test]
fn two_aliases_of_one_package_share_its_optional_peer() {
    // hoist.test.ts: two aliases of a package whose optional peer another dependency brings in.
    let r = registry();
    let (env, _) = install(
        &r,
        json!({
            "dependencies": {
                "dep-1": "npm:one-optional-peer-dep@1.0.2",
                "dep-2": "npm:one-optional-peer-dep@1.0.2",
                "one-dep": "1.0.0",
            }
        }),
    );
    assert_eq!(sees(&env, "", "dep-1"), "one-optional-peer-dep@1.0.2");
    assert_eq!(sees(&env, "", "dep-2"), "one-optional-peer-dep@1.0.2");
    assert_eq!(sees(&env, "one-dep", "no-deps"), "no-deps@1.0.1");
}

/// Where `.bin/<name>` leads: the file a link resolves to, or what a Windows shim runs.
fn bin(env: &Env, name: &str) -> String {
    let at = env.path(&format!("node_modules/.bin/{name}"));
    if cfg!(windows) {
        std::fs::read_to_string(&at).unwrap_or_default().replace('\\', "/")
    } else {
        std::fs::canonicalize(&at).map(|p| p.display().to_string()).unwrap_or_default()
    }
}

fn fails(env: &Env, args: &[&str]) -> String {
    let out = env.jpm(args);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "jpm {args:?} succeeded:\n{text}");
    text
}

#[test]
fn comment_keys_in_overrides_are_comments() {
    // nested-overrides.test.ts 'a "//" comment key in overrides/resolutions': ignored, silently.
    let r = registry();
    for field in ["overrides", "resolutions"] {
        let rules = json!({ "//": "pins no-deps until upstream updates", "no-deps": "1.0.0" });
        let (env, out) = install(&r, json!({ "dependencies": { "one-dep": "1.0.0" }, field: rules }));
        assert_eq!(sees(&env, "one-dep", "no-deps"), "no-deps@1.0.0", "{field}");
        assert!(!out.contains("warn"), "{field}: {out}");
    }
}

#[test]
fn an_override_of_a_name_leaves_an_alias_to_that_package() {
    // bun-install.test.ts "should not apply overrides to package name of aliased package", as
    // pnpm matches an override to the dependency's own name.
    let r = registry();
    let (env, _) =
        install(&r, json!({ "dependencies": { "nd": "npm:no-deps@1.0.1" }, "overrides": { "no-deps": "2.0.0" } }));
    assert_eq!(sees(&env, "", "nd"), "no-deps@1.0.1");
}

#[test]
fn picks_versions_by_tag_and_range() {
    // bun-install-registry.test.ts "semver" and "prereleases", bun-install.test.ts "chooses".
    let tags = json!({ "latest": "3.0.0", "pre-1": "1.0.1", "pre-2": "2.0.1", "pre-3": "3.0.1" });
    let future = json!({ "latest": "1.0.0-future.4" });
    let mut pkgs = Vec::new();
    for v in ["1.0.0", "1.0.1", "2.0.0", "2.0.1", "3.0.0", "3.0.1"] {
        pkgs.push(pkg("dep-with-tags", v, json!({ "dist-tags": tags })));
    }
    for v in ["1.0.0-future.0", "1.0.0-future.1", "1.0.0-future.4", "1.0.0-future.5", "1.0.0-future.7"] {
        pkgs.push(pkg("prereleases-1", v, json!({ "dist-tags": future })));
    }
    pkgs.push(pkg("prereleases-4", "2.0.0-pre.0", json!({})));
    let r = Registry::start(pkgs);
    let picks = [
        ("dep-with-tags", "", "3.0.0"),
        ("dep-with-tags", "pre-2", "2.0.1"),
        ("dep-with-tags", "pre-3", "3.0.1"),
        ("dep-with-tags", "1||2", "2.0.1"),
        ("dep-with-tags", "||", "3.0.0"),
        // node-semver reads an empty side of `||` as any version: latest, where bun takes 1.0.1.
        ("dep-with-tags", "|| 1", "3.0.0"),
        ("prereleases-1", "1.0.0-future.1", "1.0.0-future.1"),
        ("prereleases-1", "latest", "1.0.0-future.4"),
        ("prereleases-1", "^1.0.0-future.4", "1.0.0-future.4"),
        ("prereleases-1", "^1.0.0-future.5", "1.0.0-future.7"),
    ];
    for (name, range, want) in picks {
        let (env, _) = install(&r, json!({ "dependencies": { name: range } }));
        assert_eq!(sees(&env, "", name), format!("{name}@{want}"), "{name}@{range:?}");
    }
    // A wildcard matches no prerelease, even the one `latest` names.
    for range in ["x", "2.x", "2.0.x"] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "prereleases-4": range } }));
        fails(&env, &["install"]);
    }
}

#[test]
fn aliases_install_under_their_own_names() {
    // bun-install-registry.test.ts "packages dependening on each other with aliases does not
    // infinitely loop"; bun-install.test.ts "should handle unscoped alias on scoped dependency",
    // "should handle scoped alias on unscoped dependency" and "should handle aliased dependency
    // referenced in a nested dependency" (an alias in a package reaches the registry's package,
    // not the root's alias of that name).
    let r = Registry::start(vec![
        pkg("alias-loop-1", "1.0.0", json!({ "dependencies": { "alias1": "npm:alias-loop-2@*" } })),
        pkg("alias-loop-2", "1.0.0", json!({ "dependencies": { "alias2": "npm:alias-loop-1@*" } })),
        pkg("bar", "0.0.2", json!({ "dependencies": { "baz-old": "npm:baz@>=0.0.1" } })),
        pkg("baz", "0.0.3", json!({ "bin": { "baz-run": "index.js" } })),
        pkg("@barn/moo", "0.1.0", json!({})),
    ]);
    let (env, _) = install(&r, json!({ "dependencies": { "alias-loop-1": "1.0.0", "alias-loop-2": "1.0.0" } }));
    assert_eq!(sees(&env, "alias-loop-1", "alias1"), "alias-loop-2@1.0.0");
    assert_eq!(sees(&env, "alias-loop-2", "alias2"), "alias-loop-1@1.0.0");
    let (env, _) = install(&r, json!({ "dependencies": { "@barn/moo": "latest", "moo": "npm:@barn/moo" } }));
    assert_eq!(sees(&env, "", "moo"), "@barn/moo@0.1.0");
    assert_eq!(sees(&env, "", "@barn/moo"), "@barn/moo@0.1.0");
    let (env, _) = install(&r, json!({ "dependencies": { "@baz/bar": "npm:baz", "baz": "latest" } }));
    assert_eq!(sees(&env, "", "@baz/bar"), "baz@0.0.3");
    let (env, _) = install(&r, json!({ "dependencies": { "baz": "npm:bar@0.0.2" } }));
    assert_eq!(sees(&env, "", "baz"), "bar@0.0.2");
    assert_eq!(sees(&env, "baz", "baz-old"), "baz@0.0.3");
    // An alias's bin is reached through the alias's folder.
    let (env, _) = install(&r, json!({ "dependencies": { "Bar": "npm:baz@0.0.3" } }));
    assert!(bin(&env, "baz-run").contains("index.js"), "{}", bin(&env, "baz-run"));
}

#[test]
fn refuses_an_alias_name_that_climbs_out_of_node_modules() {
    // bun-install-registry.test.ts "rejects dependency aliases containing relative path
    // segments", bun-install.test.ts "should reject npm alias names with path traversal".
    let r = registry();
    for name in ["../escaped-target", "../../escaped-target"] {
        let env = Env::new(&r);
        env.manifest(json!({ "dependencies": { "no-deps": "1.0.0", name: "npm:one-fixed-dep@2.0.0" } }));
        fails(&env, &["install"]);
        assert!(!env.root.join("escaped-target").exists() && !env.exists("escaped-target"), "{name}");
    }
}

#[test]
fn one_name_in_two_groups_takes_the_stronger_group() {
    // bun-install.test.ts "should prefer optional over prod", "should prefer prod over peer",
    // and duplicate-optional's own optionalDependencies over its dependencies.
    let r = registry();
    let (env, _) =
        install(&r, json!({ "dependencies": { "no-deps": "2.0.0" }, "optionalDependencies": { "no-deps": "1.0.0" } }));
    assert_eq!(sees(&env, "", "no-deps"), "no-deps@1.0.0");
    let (env, _) =
        install(&r, json!({ "dependencies": { "no-deps": "2.0.0" }, "peerDependencies": { "no-deps": "1.0.0" } }));
    assert_eq!(sees(&env, "", "no-deps"), "no-deps@2.0.0");
    let r = Registry::start(vec![
        pkg("no-deps", "1.0.0", json!({})),
        pkg("no-deps", "1.0.1", json!({})),
        pkg(
            "duplicate-optional",
            "1.0.1",
            json!({ "dependencies": { "no-deps": "1.0.0" }, "optionalDependencies": { "no-deps": "1.0.1" } }),
        ),
    ]);
    let (env, _) = install(&r, json!({ "dependencies": { "duplicate-optional": "1.0.1" } }));
    assert_eq!(sees(&env, "duplicate-optional", "no-deps"), "no-deps@1.0.1");
}

#[test]
fn a_bundled_dependency_comes_from_its_parent() {
    // bun-install-registry.test.ts "bundledDependencies": a bundled copy is what the parent
    // ships, not installed beside it; `true` bundles every dependency. One the registry does
    // not have (bundled-private) is no reason to fail.
    let shipped = |p: common::Pkg| {
        p.file("node_modules/no-deps/package.json", 0o644, r#"{"name":"no-deps","version":"1.0.0"}"#).file(
            "node_modules/no-deps/index.js",
            0o644,
            "module.exports = 'no-deps@1.0.0'",
        )
    };
    let bundles = |b: Value| json!({ "dependencies": { "no-deps": "1.0.0" }, "bundleDependencies": b });
    let r = Registry::start(vec![
        pkg("no-deps", "1.0.0", json!({})),
        pkg("no-deps", "2.0.0", json!({})),
        shipped(pkg("bundled-1", "1.0.0", bundles(json!(["no-deps"])))),
        shipped(pkg("bundled-true", "1.0.0", bundles(json!(true)))),
        shipped(pkg(
            "bundled-private",
            "1.0.0",
            json!({ "dependencies": { "no-deps": "9.9.9" }, "bundledDependencies": ["no-deps"] }),
        )),
    ]);
    for parent in ["bundled-1", "bundled-true", "bundled-private"] {
        let (env, _) = install(&r, json!({ "dependencies": { parent: "1.0.0", "no-deps": "2.0.0" } }));
        assert_eq!(sees(&env, "", "no-deps"), "no-deps@2.0.0", "{parent}");
        let inside = env.read(&format!("node_modules/{parent}/node_modules/no-deps/index.js"));
        assert_eq!(inside, "module.exports = 'no-deps@1.0.0'", "{parent}");
        assert!(env.lock()["packages"].get("no-deps@1.0.0").is_none(), "{parent}");
    }
}

#[test]
fn an_optional_dependency_that_cannot_be_fetched_is_left_out() {
    // bun-install-registry.test.ts "exit code is 0 when optional dependency tarball is missing"
    // and "exit code is 0 when (root) optional dependency does not exist in registry"; the same
    // as a dependency fails.
    let r = registry();
    r.publish(pkg("missing-tarball", "1.0.0", json!({ "dist": { "tarball": format!("{}/gone.tgz", r.url) } })));
    let missing = json!({ "optionalDependencies": { "not-in-the-registry": "1.0.0" } });
    r.publish(pkg("has-missing-optional-dep", "1.0.0", missing));
    let (env, _) = install(
        &r,
        json!({
            "dependencies": { "no-deps": "1.0.0", "has-missing-optional-dep": "1.0.0" },
            "optionalDependencies": { "missing-tarball": "1.0.0", "not-in-the-registry": "||" },
        }),
    );
    assert_eq!(sees(&env, "", "no-deps"), "no-deps@1.0.0");
    assert!(!env.exists("node_modules/missing-tarball") && !env.exists("node_modules/not-in-the-registry"));
    let env = Env::new(&r);
    env.manifest(json!({ "dependencies": { "missing-tarball": "1.0.0" } }));
    fails(&env, &["install"]);
}

#[test]
fn peers_settle_on_what_the_tree_has() {
    // bun-install-registry.test.ts "peerDependency in child npm dependency should not maintain
    // old version when package is upgraded", "update › duplicate peer dependency", and yarn's
    // dragon test 3 (a package and its dependency peer on each other).
    let r = registry();
    r.publish(pkg("peer-deps-fixed", "1.0.0", json!({ "peerDependencies": { "no-deps": "^1.0.0" } })));
    let (env, _) = install(&r, json!({ "dependencies": { "peer-deps-fixed": "1.0.0", "no-deps": "1.0.0" } }));
    assert_eq!(sees(&env, "peer-deps-fixed", "no-deps"), "no-deps@1.0.0");
    env.manifest(json!({ "dependencies": { "peer-deps-fixed": "1.0.0", "no-deps": "1.0.1" } }));
    env.ok(&["install"]);
    assert_eq!(sees(&env, "peer-deps-fixed", "no-deps"), "no-deps@1.0.1");
    let (env, _) =
        install(&r, json!({ "dependencies": { "no-deps": "^1.0.0" }, "peerDependencies": { "no-deps": "^1.0.0" } }));
    assert_eq!(sees(&env, "", "no-deps"), "no-deps@1.1.0");
    r.publish(pkg(
        "dragon-test-3-a",
        "1.0.0",
        json!({ "dependencies": { "dragon-test-3-b": "1.0.0" }, "peerDependencies": { "no-deps": "*" } }),
    ));
    r.publish(pkg("dragon-test-3-b", "1.0.0", json!({ "peerDependencies": { "dragon-test-3-a": "*" } })));
    let (env, _) = install(&r, json!({ "dependencies": { "dragon-test-3-a": "1.0.0" } }));
    assert_eq!(sees(&env, "dragon-test-3-a", "dragon-test-3-b"), "dragon-test-3-b@1.0.0");
    assert_eq!(sees(&env, "dragon-test-3-a", "no-deps"), "no-deps@2.0.0");
    assert_eq!(sees(&env, "dragon-test-3-a/../dragon-test-3-b", "dragon-test-3-a"), "dragon-test-3-a@1.0.0");
}

#[test]
fn a_peer_out_of_its_range_takes_the_roots_copy() {
    // bun-install-registry.test.ts "hoisting/using incorrect peer dep on initial install" and
    // "after install", and "it should warn when the peer dependency resolution is incompatible":
    // peer-deps-fixed (^1.0.0) under a root with no-deps 2.0.0 gets that copy, with a warning,
    // and none of its own; either way round, the next install follows the root.
    let r = registry();
    r.publish(pkg("peer-deps-fixed", "1.0.0", json!({ "peerDependencies": { "no-deps": "^1.0.0" } })));
    let manifest = |no_deps: &str| json!({ "dependencies": { "peer-deps-fixed": "1.0.0", "no-deps": no_deps } });
    for (first, then) in [("1.0.0", "2.0.0"), ("2.0.0", "1.0.0")] {
        let (env, mut out) = install(&r, manifest(first));
        for version in [first, then] {
            if version == then {
                env.manifest(manifest(then));
                out = env.ok(&["install"]);
            }
            assert_eq!(sees(&env, "peer-deps-fixed", "no-deps"), format!("no-deps@{version}"));
            assert_eq!(out.contains("unmet peer no-deps@^1.0.0 of peer-deps-fixed@1.0.0"), version == "2.0.0", "{out}");
            let lock = env.lock();
            let copies = lock["packages"].as_object().unwrap().keys().filter(|k| k.starts_with("no-deps@")).count();
            assert_eq!(copies, 1, "{lock}");
        }
    }
}

#[test]
fn a_workspace_settles_its_peers_as_the_root_does() {
    // bun-install-registry.test.ts "it should ignore peerDependencies within workspaces" (peers
    // enabled), "optionalPeers" (an optional peer of a workspace is not installed), and yarn's
    // dragon test 4 (a workspace's dev dependency is the version its peer takes).
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"], "dependencies": { "a-dep": "1.0.1" } }));
    env.write("packages/baz/package.json", r#"{ "name": "baz", "peerDependencies": { "one-dep": ">=1.0.0" } }"#);
    env.write(
        "packages/pkg1/package.json",
        r#"{ "name": "pkg1", "peerDependencies": { "no-deps": "1.0.0" }, "peerDependenciesMeta": { "no-deps": { "optional": true } } }"#,
    );
    env.write(
        "packages/my-workspace/package.json",
        r#"{ "name": "my-workspace", "peerDependencies": { "one-range-dep": "*", "peer-deps": "*" },
             "devDependencies": { "one-range-dep": "1.0.0", "peer-deps": "1.0.0" } }"#,
    );
    env.ok(&["install"]);
    let lock = env.lock();
    assert_eq!(lock["workspaces"]["packages/baz"]["dependencies"]["one-dep"], "1.0.0", "{lock}");
    assert!(lock["workspaces"]["packages/pkg1"]["dependencies"].get("no-deps").is_none(), "{lock}");
    assert_eq!(lock["workspaces"]["packages/my-workspace"]["dependencies"]["peer-deps"], "1.0.0");
    // peer-deps' own peer takes what its parent has: one-range-dep's no-deps, none of its own.
    assert!(lock["packages"]["peer-deps@1.0.0"]["dependencies"]["no-deps"].is_string(), "{lock}");
}

#[test]
fn a_workspace_dev_dependency_wins_over_its_peer() {
    // bun-workspaces.test.ts "matching workspace devDependency and npm peerDependency" and
    // test-dev-peer-dependency-priority.test.ts: the dev spec picks, the peer range only warns.
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"] }));
    env.write(
        "packages/pkg1/package.json",
        r#"{ "name": "pkg1", "devDependencies": { "no-deps": "workspace:*" }, "peerDependencies": { "no-deps": "2.0.0" } }"#,
    );
    env.write("packages/pkg2/package.json", r#"{ "name": "no-deps", "version": "1.0.0" }"#);
    env.ok(&["install"]);
    assert!(env.read("packages/pkg1/node_modules/no-deps/package.json").contains("1.0.0"));
    assert!(env.lock()["packages"].get("no-deps@2.0.0").is_none());
}

#[test]
fn workspaces_are_the_ones_the_root_lists() {
    // bun-workspaces.test.ts "should ignore negative workspace patterns"; bun-install.test.ts
    // "should ignore workspaces within workspaces" and "should handle duplicate workspace names";
    // bun-workspaces.test.ts "only root package.json overrides and resolutions are honored".
    let r = registry();
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*", "!packages/pkg2"] }));
    env.write("packages/pkg1/package.json", r#"{ "name": "pkg1", "dependencies": { "no-deps": "1.0.0" } }"#);
    env.write("packages/pkg2/package.json", r#"{ "name": "pkg2", "dependencies": { "doesnt-exist-oops": "1.2.3" } }"#);
    env.ok(&["install"]);
    assert!(env.read("packages/pkg1/node_modules/no-deps/index.js").contains("no-deps@1.0.0"));

    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["bar"] }));
    env.write("bar/package.json", r#"{ "name": "bar", "workspaces": ["baz"] }"#);
    env.write("bar/baz/package.json", r#"{ "name": "baz", "dependencies": { "doesnt-exist-oops": "1.2.3" } }"#);
    env.ok(&["install"]);
    assert!(!env.exists("node_modules/baz"));

    // Two of one name are refused once something depends on the name, which could mean either;
    // bun refuses them outright.
    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["bar", "baz"], "dependencies": { "moo": "workspace:*" } }));
    env.write("bar/package.json", r#"{ "name": "moo" }"#);
    env.write("baz/package.json", r#"{ "name": "moo" }"#);
    let err = fails(&env, &["install"]);
    assert!(err.contains("both named moo"), "{err}");

    let env = Env::new(&r);
    env.manifest(json!({ "name": "root", "workspaces": ["packages/*"], "dependencies": { "one-range-dep": "1.0.0" } }));
    env.write(
        "packages/pkg1/package.json",
        r#"{ "name": "pkg1", "dependencies": { "one-range-dep": "1.0.0" },
             "overrides": { "no-deps": "1.0.0" }, "resolutions": { "no-deps": "1.0.0" } }"#,
    );
    env.ok(&["install"]);
    assert_eq!(sees(&env, "one-range-dep", "no-deps"), "no-deps@1.1.0");
}

#[test]
fn links_every_kind_of_bin() {
    // bun-install-registry.test.ts "bin types", "one version with binary map", "it will skip
    // (without errors) if a folder from directories.bin does not exist" and "bin targets with a
    // trailing slash are linked". `directories.bin` alone links nothing (src/bin.rs): npm
    // publish writes those files into `bin`, and jpm does not list a tarball as it resolves.
    let exe = |p: common::Pkg, file: &str| p.file(file, 0o755, "#!/usr/bin/env node\n");
    let r = Registry::start(vec![
        exe(pkg("dep-with-file-bin", "1.0.0", json!({ "bin": "file-bin" })), "file-bin"),
        exe(
            exe(
                pkg(
                    "dep-with-map-bins",
                    "1.0.0",
                    json!({ "bin": { "map-bin-1": "map-bin-1", "map-bin-2": "map-bin-2" } }),
                ),
                "map-bin-1",
            ),
            "map-bin-2",
        ),
        exe(
            pkg("map-bin", "1.0.2", json!({ "bin": { "map-bin": "bin/map-bin", "map_bin": "bin/map-bin" } })),
            "bin/map-bin",
        ),
        pkg("missing-directory-bin", "1.1.1", json!({ "directories": { "bin": "./missing" } })),
        exe(
            exe(
                pkg(
                    "trailing-slash",
                    "1.0.0",
                    json!({ "bin": { "slash-1": "slash-1.js/", "slash-2": "./bin/slash-2.js/" } }),
                ),
                "slash-1.js",
            ),
            "bin/slash-2.js",
        ),
    ]);
    let (env, _) = install(
        &r,
        json!({ "dependencies": {
            "dep-with-file-bin": "1.0.0", "dep-with-map-bins": "1.0.0",
            "map-bin": "1.0.2", "missing-directory-bin": "1.1.1", "trailing-slash": "1.0.0",
        } }),
    );
    let bins = [
        ("dep-with-file-bin", "file-bin"),
        ("map-bin-1", "map-bin-1"),
        ("map-bin-2", "map-bin-2"),
        ("map-bin", "bin/map-bin"),
        ("map_bin", "bin/map-bin"),
        ("slash-1", "slash-1.js"),
        ("slash-2", "bin/slash-2.js"),
    ];
    for (name, target) in bins {
        assert!(bin(&env, name).contains(target), "{name}: {:?}", bin(&env, name));
    }
}

#[test]
fn installs_tarball_urls_and_archives() {
    // bun-install.test.ts "should handle tarball URL with aliasing", "should handle tarball URL
    // with existing lockfile" (a tarball's dependencies come from the registry, shared with the
    // root's), and "should handle tarball path with aliasing" / "... .tar and uppercase .TGZ".
    let baz = pkg("baz", "0.0.3", json!({ "bin": { "baz-run": "index.js" } }));
    let moo = pkg("@barn/moo", "0.1.0", json!({ "dependencies": { "bar": "0.0.2", "baz": "latest" } }));
    let r = Registry::start(vec![pkg("bar", "0.0.2", json!({})), baz.clone()]);
    r.serve("/baz-0.0.3.tgz", baz.tarball());
    r.serve("/moo-0.1.0.tgz", moo.tarball());
    let (env, _) = install(&r, json!({ "dependencies": { "bar": format!("{}/baz-0.0.3.tgz", r.url) } }));
    assert_eq!(sees(&env, "", "bar"), "baz@0.0.3");
    assert!(bin(&env, "baz-run").contains("index.js"));
    let (env, _) =
        install(&r, json!({ "dependencies": { "@barn/moo": format!("{}/moo-0.1.0.tgz", r.url), "bar": "<=0.0.2" } }));
    assert_eq!(sees(&env, "@barn/moo", "baz"), "baz@0.0.3");
    assert_eq!(sees(&env, "", "bar"), "bar@0.0.2");
    assert_eq!(env.lock()["packages"].as_object().unwrap().keys().filter(|k| k.starts_with("bar@")).count(), 1);
    // A plain tar, and a name in capitals.
    let env = Env::new(&r);
    let raw = common::tar(&[
        ("package/package.json".into(), 0o644, br#"{"name":"baz","version":"0.0.3"}"#.to_vec()),
        ("package/index.js".into(), 0o644, b"module.exports = 'baz@0.0.3'".to_vec()),
    ]);
    std::fs::write(env.project().join("baz.tar"), &raw).unwrap();
    std::fs::write(env.project().join("BAZ.TGZ"), baz.tarball()).unwrap();
    env.manifest(json!({ "dependencies": { "a": "./baz.tar", "b": "./BAZ.TGZ" } }));
    env.ok(&["install"]);
    assert_eq!(sees(&env, "", "a"), "baz@0.0.3");
    assert_eq!(sees(&env, "", "b"), "baz@0.0.3");
}

#[test]
fn a_package_cannot_name_a_workspace() {
    // bun-workspaces.test.ts "workspace: protocol inside a tarball dependency does not create a
    // workspace": an optional `workspace:` dependency of a tarball is left out, nothing linked.
    let r = registry();
    let env = Env::new(&r);
    let lib = pkg("lib", "1.0.0", json!({ "optionalDependencies": { "extra": "workspace:extra" } })).file(
        "extra/package.json",
        0o644,
        r#"{"name":"extra","version":"1.0.0"}"#,
    );
    std::fs::write(env.project().join("lib.tgz"), lib.tarball()).unwrap();
    env.manifest(json!({ "dependencies": { "lib": "file:./lib.tgz" } }));
    env.ok(&["install"]);
    assert!(env.exists("node_modules/lib") && !env.exists("node_modules/extra"));
    assert!(!env.exists("node_modules/lib/../extra"));
}

#[test]
fn reads_what_it_can_of_a_packument() {
    // bun-install.test.ts "should skip non-string dependency values in npm manifests" and
    // "should skip versions that are not valid semver in npm manifests".
    let tags = json!({ "dist-tags": { "latest": "0.0.2" } });
    let r = Registry::start(vec![
        pkg("bar", "0.0.2", json!({ "dependencies": { "baz": null, "qux": 1, "no-deps": "1.0.0" } })),
        pkg("bar", "not-a-version", tags.clone()),
        pkg("bar", "1.0.0.1", tags),
        pkg("no-deps", "1.0.0", json!({})),
    ]);
    for range in ["*", ">=0.0.1", ""] {
        let (env, _) = install(&r, json!({ "dependencies": { "bar": range } }));
        assert_eq!(sees(&env, "", "bar"), "bar@0.0.2", "{range:?}");
        assert_eq!(sees(&env, "bar", "no-deps"), "no-deps@1.0.0");
    }
}
