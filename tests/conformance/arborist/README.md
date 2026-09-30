# @npmcli/arborist fixture lockfiles

The files under `fixtures/` are copied from the test fixtures of
[@npmcli/arborist](https://github.com/npm/cli/tree/latest/workspaces/arborist), npm's tree
builder, in the [npm/cli](https://github.com/npm/cli) repository at commit
`0c3b82a9a612c3f9399d35c28c86708b1f8ea7d4` (arborist 10.0.3), from
`workspaces/arborist/test/fixtures`. @npmcli/arborist is licensed under the ISC License,
`Copyright npm, Inc.`; its license text (`workspaces/arborist/LICENSE.md`) is in
[LICENSE](LICENSE). The npm/cli repository as a whole is under the Artistic License 2.0; these
files come from the arborist workspace alone.

Each is every `package-lock.json` and `npm-shrinkwrap.json` in that folder that is not inside a
`node_modules` folder, with the `package.json` beside it, byte for byte. A file over 32 KiB is
stored gzipped as `<name>.gz` to keep the copy small (twelve lockfiles). The `node_modules` trees,
the mock registry and the other test files are not copied.

They are copied, not written by hand:

    git clone -c core.autocrlf=false --filter=blob:none --sparse https://github.com/npm/cli npm-cli
    git -C npm-cli sparse-checkout set workspaces/arborist
    git -C npm-cli checkout 0c3b82a9a612c3f9399d35c28c86708b1f8ea7d4
    node tests/conformance/gen/arborist.mjs npm-cli

`tests/conformance/arborist.rs`, built into jpm's unit tests from `src/foreign.rs`, reads every
lockfile as jpm reads one it finds in a project, and `expected.json` holds what jpm does with
each: `imported` (with the package count, any warnings, and any way the import differs from the
tree the file describes), `refused` (with jpm's message and why), or `skipped` for a fixture
folder with no npm lockfile (with why). `pins` is what jpm's fallback, a resolve preferring the
file's versions, reads from it: the number of versions, or its error.
`JPM_BLESS=1 cargo test arborist` rewrites the outcomes and keeps each `why`.
