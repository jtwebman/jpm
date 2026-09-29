# jpm

A fast, small package manager for the npm registry, written in Rust.

jpm is a port of [upm](https://github.com/unjs/upm) to Rust. It installs the same
isolated `node_modules` layout and takes the same commands and flags. It needs no Node.js
to install packages; Node is only needed to run them.

## Install

```sh
curl -fsSL https://getjpm.sh | sh                  # macOS and Linux
```

```powershell
irm https://getjpm.sh/install.ps1 | iex              # Windows
```

The script downloads the binary for your platform from the
[latest release](https://github.com/jtwebman/jpm/releases/latest), checks its SHA-256, and
puts `jpm` and `jpx` in `~/.jpm/bin`. `JPM_VERSION=v0.1.0` picks a release and `JPM_INSTALL`
another directory. Each platform has its own build:

| Platform      | Release asset           | Target                       |
| ------------- | ----------------------- | ---------------------------- |
| Linux x64     | `jpm-linux-x64`         | `x86_64-unknown-linux-musl`  |
| Linux arm64   | `jpm-linux-arm64`       | `aarch64-unknown-linux-musl` |
| macOS x64     | `jpm-darwin-x64`        | `x86_64-apple-darwin`        |
| macOS arm64   | `jpm-darwin-arm64`      | `aarch64-apple-darwin`       |
| Windows x64   | `jpm-windows-x64.exe`   | `x86_64-pc-windows-msvc`     |
| Windows arm64 | `jpm-windows-arm64.exe` | `aarch64-pc-windows-msvc`    |

The Linux builds are static, so they run on glibc and musl (Alpine) alike. Tests run on Linux
for now; macOS and Windows builds are not yet tested in CI.

Or build it:

```sh
cargo build --release    # target/release/jpm
```

## Use

```sh
jpm install                          # install the project's dependencies
jpm add vue@^3 nanoid                # save to package.json, then install
jpm add --dev vitest                 # save as a dev dependency
jpm remove nanoid                    # remove from package.json, then install
jpm run build                        # run a package.json script
jpm build                            # the same, when build is not a jpm command
jpm run --workspaces build           # build every workspace, dependencies first
jpm exec cowsay hello                # run a package's bin, installing it if needed
jpm dedupe                           # reduce duplicate versions already locked
jpm install --production             # skip packages only dev dependencies use
jpm ci                               # fail if the lockfile is missing or stale
jpm install --offline                # no network: install from jpm.lock and the store
jpm lock                             # write jpm.lock without installing
jpm resolve vue@^3                   # show which version a spec picks
jpm fetch --lock                     # fill the store from jpm.lock, no linking
jpm prune                            # remove entries and store content no project uses
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every option.

## Coming from another package manager

Run `jpm install`. With no `jpm.lock`, jpm reads the lockfile that is there and writes
`jpm.lock` from it:

- `package-lock.json` and `npm-shrinkwrap.json` (npm 7 and later), `pnpm-lock.yaml`
  (pnpm 9 and later) and `bun.lock` are carried over as they are: the same versions and the
  same tree, with no registry lookups.
- `yarn.lock` (yarn 1, and yarn 2 and later) records no peers, platforms or bins, so jpm
  reads those from the registry and gives every range the version yarn gave it.
- When that is not possible (the file is out of date with `package.json`, has workspaces, or
  is an older format such as npm 6's or pnpm 8's), jpm resolves the tree with the file's
  versions preferred wherever the ranges in `package.json` allow them.
- `upm.lock` is read the same way.

The old lockfile is left in place and no longer read; delete it when you are ready.
`jpm install --frozen-lockfile` (and `jpm ci`) write nothing: in CI they install from the
old lockfile as it is, so a pipeline keeps working before `jpm.lock` is committed.

## The lockfile

`jpm.lock` is a text file: one fact per line, sorted, so a change is a small diff.

```
jpm-lock 2
hash 0c1f…
root
  spec dependencies nuxt ^4.5.2
  dep nuxt 4.5.2
package @babel/core@7.29.7
  integrity sha512-…
  subgraph Kc9…
  dep @babel/generator 7.29.8
  bin babel bin/babel.js
```

Each package records the hash of everything it depends on (`subgraph`), which names its
directory under `node_modules/.jpm`. The `hash` line covers the rest of the file: while it
matches, jpm uses the recorded subgraphs instead of hashing the graph again. A hand edit or a
merge is fine; the hash no longer matches, so jpm checks everything and writes the file again.
`jpm lock --json` prints the lockfile as JSON, in upm's format.

## How it works

- **Resolve.** The dependency graph is walked on a pool of threads. Each package is picked
  from the registry's abbreviated document, fetched once per run and kept on disk between
  runs (revalidated by ETag). Peer dependencies are settled against the tree after the walk,
  so a plugin uses the host version the tree already has.
- **Store.** Each tarball is checked against its integrity and unpacked once into a shared
  store (`~/.jpm/store`, or `JPM_STORE`). Files there are read-only.
- **Link.** Each package gets an entry, `<name>@<version>-<hash>/`, named by a hash of the
  package and everything below it. The entry holds the package's files, hardlinked from the
  store (a single `clonefile` per package on macOS), and a symlink (a junction on Windows) to
  each of its dependencies, so a package can import only what it declared.
- **Global virtual store.** Entries are built once, in the store (`v1/links`), and shared by
  every project on the machine: `node_modules/<dep>` links straight to one. A warm install
  makes only those links. An entry missing an optional package, or depending on one that is,
  is built in the project's `node_modules/.jpm` instead, as every entry is when the global
  store is off.
- **Repeat installs.** `node_modules/.jpm.json` records what was installed. When the
  lockfile, `package.json` and settings are unchanged, a repeat install checks a few links and
  exits.

Dependency lifecycle scripts (`postinstall` and the like) are not run.

## Configuration

`.npmrc` is read from the project, the user's home and npm's global location, plus
`npm_config_*` variables. jpm reads `registry`, `@scope:registry`, credentials
(`//host/:_authToken`, `_auth`, `username` and `_password`), `save-exact`, `offline`,
`prefer-offline`, `min-release-age`, `before` and `min-release-age-exclude`.

New versions are held back for one day by default (`min-release-age`). Set it to `0` to
turn this off.

The global virtual store is on by default. Turn it off with `global-store=false` in `.npmrc`,
`JPM_GLOBAL_STORE=0` or `--no-global-store`. It is off inside containers (`/.dockerenv` or
`/run/.containerenv`), where a mounted project would not see the store, and when the store
cannot be written. Tools that expect a package's real path to sit inside the project may need
it off.

`jpm prune` removes what no project uses. Every install registers its project with the store
(`v1/projects`), and a prune keeps the global entries and packages that registered projects
still use. A project that is gone, or on a drive that is not mounted, is dropped from the
register; its next install rebuilds what it needs. Installs and prunes take a lock on the store
(`v1/lock`), so a prune waits for installs to finish and removes what is unused at once. On a
filesystem without working file locks, such as some network mounts, an install running
alongside a prune can lose entries; installing again repairs it.

## Development

```sh
cargo test                       # unit tests and end-to-end tests against a local registry
cargo build --release            # built for size, the CPU-heavy crates for speed
cargo build --profile fast       # every crate at full speed, for comparing
```

Platform-specific code lives in `src/sys/`, one file per OS; only the target's file is
compiled.

## Benchmarks

Medians of 3 runs per phase on Linux (WSL2, 4 cores), 2026-09-28, against the live npm
registry. Every manager has private caches and lifecycle scripts off; all 297 runs succeeded.
Fixtures: `nitro` (62 packages), `nuxt` (591), `next` (275).

**Cold** (no cache, no lockfile):

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | **766 ms** | 3.60 s | 4.51 s |
| upm 1.2 | 850 ms | 3.51 s | **4.50 s** |
| aube 2.6 | 859 ms | **3.29 s** | 4.67 s |
| pnpm 12.8 | **766 ms** | 4.04 s | 5.97 s |
| bun 1.4 | 1.19 s | 5.11 s | 7.01 s |
| npm 12.1 | 1.36 s | 13.7 s | 7.90 s |

Cold installs are bound by the registry, and vary from run to run by more than the gaps
here.

**Warm** (cache and lockfile kept, `node_modules` deleted):

| manager | nitro | nuxt | next |
| --- | ---: | ---: | ---: |
| **jpm** | **4 ms** | **11 ms** | **6 ms** |
| aube 2.6 | 16 ms | 104 ms | 97 ms |
| deno 2.9 | 31 ms | 188 ms | 135 ms |
| bun 1.4 | 31 ms | 221 ms | 112 ms |
| pnpm 12.8 | 42 ms | 222 ms | 131 ms |
| upm 1.2 | 64 ms | 261 ms | 122 ms |
| npm 12.1 | 552 ms | 3.02 s | 4.14 s |

With the global virtual store, a warm install only links a project's direct dependencies to
entries already built in the store. Before the global store, jpm took 21, 146 and 114 ms.

**Repeat** (nothing changed): jpm 0 ms, bun 2–9 ms, aube 3–24 ms, pnpm 12 6–7 ms,
deno 6–16 ms, upm 22–23 ms, npm 166–391 ms.

jpm uses the least memory in all but one phase (bun's cold `next`): 7.5 MB for a warm `nuxt` against 58 MB for pnpm 12,
80 MB for aube and 120 MB for upm, and 151 MB for a cold `nuxt` against 421 MB for aube and
557 MB for upm. Its binary is 2.4 MB; bun's is 80 MB, pnpm 12's 60 MB and aube's 152 MB.

Charts: [cold](bench/charts/cold.svg), [warm](bench/charts/warm.svg),
[repeat](bench/charts/repeat.svg), [memory](bench/charts/cold.memory.svg),
[size](bench/charts/size.svg).

`bench/` holds the harness from upm with a `jpm` runner added. To run it:

```sh
jpm install --dir bench          # the harness's own tools
bench/bench.sh -r jpm,upm,npm,pnpm12,bun -f nuxt
```

## License

MIT. jpm is a port of upm, Copyright (c) Pooya Parsa.
