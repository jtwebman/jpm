# node-semver conformance tables

These JSON files are derived from node-semver's test tables and are generated, not written by
hand. `src/semver/conformance.rs` runs every row against jpm's semver.

- Source: https://github.com/npm/node-semver
- Commit: `6e05b7637396ac66522cff8731f07cfe0ef49a29` (v7.8.5)
- License: ISC, Copyright (c) Isaac Z. Schlueter and Contributors; the full text is in
  [LICENSE](LICENSE).
- Generator: `tests/conformance/gen/semver.mjs`

The tables come from `test/fixtures/*.js` at that commit, and `subset.json` from the table in
`test/ranges/subset.js`. Each row keeps the fixture's inputs; its answer, the last column, is
node-semver's own at that commit, called the way npm calls it (`loose: true`, which
npm-package-arg and npm-pick-manifest pass). Where a fixture tests strict mode and the loose
answer differs, the fixture's strict answer follows as an extra column, for the record. The
generator stops if any fixture disagrees with the code at its own commit. Rows whose input is
not a string (they test JavaScript types) are left out.

To regenerate, from the repository root:

```sh
git clone https://github.com/npm/node-semver /tmp/node-semver
git -C /tmp/node-semver checkout 6e05b7637396ac66522cff8731f07cfe0ef49a29
node tests/conformance/gen/semver.mjs /tmp/node-semver
```
