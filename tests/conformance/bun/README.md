# bun.lock conformance cases

`lockfiles.json` holds every bun.lock found in the install tests of
[bun](https://github.com/oven-sh/bun) (`test/cli/install/`) at commit
`2722608f474a2d9468e9d1ac3a1eb2fe6e630901` (bun 1.4.3). bun's LICENSE.md says "Bun itself is
MIT-licensed." and names no copyright holder; [LICENSE](LICENSE) has the MIT text, attributed to
Oven and Bun contributors.

It is generated, not written by hand:

    git clone --filter=blob:none --no-checkout https://github.com/oven-sh/bun
    git -C bun sparse-checkout set --no-cone test/cli/install/
    git -C bun checkout 2722608f474a2d9468e9d1ac3a1eb2fe6e630901
    node tests/conformance/gen/bun.mjs bun

A lockfile is taken from three places: the `bun.lock` fixtures (`registry/fixtures/audit`),
the snapshots of lockfiles bun wrote (`__snapshots__/*.snap`, inline snapshots, and the
lockfiles bun migrated from npm's arborist fixtures, pnpm and yarn), and the ones tests write
out as template or object literals. The TypeScript is not run: each literal around a
`lockfileVersion` is evaluated alone, a name from the test's scope standing in as
`PLACEHOLDER` (in a url, a path or an integrity). A literal whose maps came from the test's
scope is left out, and one lockfile text is kept once, with the other places it appears in
`also`.

Each case has `name` (its test's title, numbered when a test has several), `from` (file and
line), `package.json` and `bun.lock` (the text, trailing commas and all). The package.json is
the fixture's own where there is one; otherwise it is the one bun wrote the lockfile from, as
bun records it in `workspaces[""]` (groups, peers, optional peers), with the `overrides`,
`patchedDependencies`, `catalog` and `catalogs` recorded beside it.

`tests/conformance/bun_lock.rs` imports each as `jpm install` does and checks the result
against the file: what it refuses, and why, is listed there.
