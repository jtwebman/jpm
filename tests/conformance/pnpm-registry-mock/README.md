# pnpm registry-mock differential tests

[pnpm/registry-mock](https://github.com/pnpm/registry-mock) is a Verdaccio registry of ~200
synthetic packages (`@pnpm.e2e/*` and a few other scopes) that pnpm's own tests install to
exercise package-manager edge cases: peers (circular, optional, named only in
`peerDependenciesMeta`, missing), aliases, optional and platform-specific dependencies, bins,
prereleases, dependency loops. This directory installs scenarios built from those packages with
jpm and compares the result with what pnpm installs.

- Source: https://github.com/pnpm/registry-mock, version 6.0.0 (tag `v6.0.0`, commit
  `c33fd83c7d51e9da90733ecf609c2dc200325ef0`), run from npm as `@pnpm/registry-mock@6.0.0` with
  verdaccio 6.8.0.
- License: MIT, Copyright (c) 2017-2026 pnpm; the full text is in [LICENSE](LICENSE). The package
  names in `scenarios.json` and the trees in `expected.json` are derived from it.

## Files

- `scenarios.json`: `single` lists every package the registry serves without auth (all but
  `@pnpm.e2e/needs-auth` and `@private/foo`, and `@pnpm.e2e/cli-with-node-engine`, which would
  download Node), each installed alone at `latest`; `scenarios` are projects modelled on pnpm's
  install tests (`pnpm11/installing/deps-installer/test/install/*.ts` and
  `pnpm/crates/cli/tests/suite`) with the registry's own dist-tags. A scenario's
  `packageExtensions` is written to `pnpm-workspace.yaml` (from
  `installing/deps-installer/test/install/packageExtensions.ts`), and what it adds is read as
  the extended package's own.
- `expected.json`: what pnpm 12.8.1 installed for each scenario on linux-x64-glibc, written by
  `diff.mjs --record`.
- `allowlist.json`: the differences jpm makes on purpose, each scenario's exact lines under a
  reason. A difference not listed fails the run, and so does a listed one that no longer shows.
- `diff.mjs`: the harness. `registry.sh`: starts the registry at the pinned versions.

Each scenario is a fresh project installed with `--ignore-scripts` and a store, cache and config
of its own per manager. The result is read from `node_modules`, not a lockfile, so both layouts
come out in one shape: every installed package as `name@version` with what each name in its
`dependencies`, `optionalDependencies` and `peerDependencies` (and `peerDependenciesMeta`)
resolves to from its own directory (`-` for nothing), the root's dependencies, and the root's
bins. Copies of a package that differ only in their peers' peers read as one, since a line shows
only what its own names resolve to. A line is `-` when only pnpm has it and `+` when only jpm has it.

## Running

```sh
bash tests/conformance/pnpm-registry-mock/registry.sh /tmp/regmock          # port 4873
cargo build --release
node tests/conformance/pnpm-registry-mock/diff.mjs                          # jpm vs expected.json
node tests/conformance/pnpm-registry-mock/diff.mjs --pnpm "$(which pnpm)"   # jpm vs pnpm, live
kill "$(cat /tmp/regmock/registry.pid)"
```

`--only <regex>` picks scenarios, `--jobs <n>` installs at once (4), `--keep` keeps the scratch
projects, `--registry <url>` and `--jpm <bin>` point elsewhere. Comparing against
`expected.json` needs the platform it was recorded on (linux-x64-glibc), since packages with `os`
or `cpu` fields install or not; elsewhere compare live with `--pnpm`.

To record `expected.json` again (a new registry-mock or pnpm version, or new scenarios), on
linux-x64-glibc:

```sh
npm install --prefix /tmp/pnpm pnpm@12.8.1
node tests/conformance/pnpm-registry-mock/diff.mjs --record --pnpm /tmp/pnpm/node_modules/.bin/pnpm
```

CI runs the comparison against `expected.json` on Linux (the `registry-mock` job in
`.github/workflows/ci.yml`).
