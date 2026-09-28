# jpm

A fast, small package manager for the npm registry, written in Rust.

jpm is a port of [upm](https://github.com/unjs/upm) to Rust. It installs the same
isolated `node_modules` layout, reads and writes the same lockfile format (`jpm.lock`,
and it reads `upm.lock`), and takes the same commands and flags. It needs no Node.js to
install packages; Node is only needed to run them.

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
jpm prune                            # remove unused entries
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every option.

With no `jpm.lock`, jpm installs from `upm.lock` if there is one, since the format is the
same. Otherwise it reads `package-lock.json`, `pnpm-lock.yaml` or `bun.lock` and writes
nothing beside it; commands that would change the tree are refused there. Delete the other
lockfile to switch to jpm.

## How it works

- **Resolve.** The dependency graph is walked on a pool of threads. Each package is picked
  from the registry's abbreviated document, fetched once per run and kept on disk between
  runs (revalidated by ETag). Peer dependencies are settled against the tree after the walk,
  so a plugin uses the host version the tree already has.
- **Store.** Each tarball is checked against its integrity and unpacked once into a shared
  store (`~/.jpm/store`, or `JPM_STORE`). Files there are read-only.
- **Link.** `node_modules/.jpm/<name>@<version>-<hash>/` holds each package, hardlinked from
  the store (a single `clonefile` per package on macOS). Everything else is a symlink (a
  junction on Windows), so a package can import only what it declared.
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

## Development

```sh
cargo test                       # unit tests and end-to-end tests against a local registry
cargo build --release            # optimized, stripped binary
cargo build --profile small      # optimized for size instead of speed
```

Platform-specific code lives in `src/sys/`, one file per OS; only the target's file is
compiled.

## Benchmarks

`bench/` holds the benchmark harness from upm, with a `jpm` runner added. It compares cold,
warm and repeat installs across jpm, upm, npm, pnpm, yarn, bun, deno and others, with
private caches for each and lifecycle scripts off everywhere.

```sh
jpm install --dir bench          # the harness's own tools
bench/bench.sh -r jpm,upm,npm,pnpm12,bun -f nuxt
```

## License

MIT. jpm is a port of upm, Copyright (c) Pooya Parsa.
