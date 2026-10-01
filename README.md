# jpm

A fast, small package manager for the npm registry, secure by default, written in Rust. It
installs the same projects as npm, pnpm, yarn and bun, from their lockfiles, and saves CI time
and money: less wall time, less CPU, less memory and less disk than the others in most of our
benchmarks.

jpm started as a Rust port of [upm](https://github.com/unjs/upm).

## How jpm is different

- **One small binary.** About 2 MB, with its own TLS and no Node.js needed to install
  packages (Node is only needed to run them). bun is about 80 MB, pnpm 60 MB, aube 150 MB.
- **Fast where CI spends its time.** On GitHub's runners jpm is the fastest of eight package
  managers in 9 of 12 benchmark cells, and repeat installs take 1-2 ms
  ([Benchmarks](#benchmarks)).
- **Lean.** The least memory in 11 of 12 cells (34 MB to install nuxt from a lockfile, where
  bun takes 89 MB, pnpm 184 MB and npm 387 MB) and the least disk for `node_modules` and its
  store together.
- **Secure by default.**
  - A dependency's install scripts, the way most npm malware runs, don't run until you approve
    that package and version ([Install scripts](docs/install-scripts.md)).
  - New versions are held back for a day (`min-release-age`), exact pins deep in the tree
    included, so a hijacked release has time to be caught.
  - A published package can't pull in git or tarball dependencies, or paths outside itself.
  - Every package is checked against its lockfile integrity before it is visible.
  - Credentials never go into `jpm.lock`, and a cloned repository's `.npmrc` can't weaken
    TLS, proxy or release-age settings.
- **Drop-in.** It reads `package-lock.json`, `pnpm-lock.yaml`, `bun.lock` and `yarn.lock`,
  workspaces, catalogs, overrides, patches and `pnpm-workspace.yaml` settings, and installs
  pnpm's isolated `node_modules` layout, with packages shared across projects through a global
  store.
- **Checked against the others.** Its tests run npm's (node-semver, npm-package-arg,
  hosted-git-info, arborist), pnpm's (registry-mock), yarn's (berry acceptance) and bun's own
  test cases, and it installs 92 of 98 large real projects on Windows. The other six fail on
  purpose (git and tarball dependencies of published packages) or would fail with any package
  manager.

## Install

```sh
curl -fsSL https://getjpm.sh | sh                  # macOS and Linux
```

```powershell
irm https://getjpm.sh/install.ps1 | iex              # Windows
```

The script checks the binary's SHA-256 and puts `jpm` and `jpx` in `~/.jpm/bin`. Platforms,
glibc and musl builds, and building from source: [docs/install.md](docs/install.md).

## Use

```sh
jpm install                          # install the project's dependencies
jpm add vue@^3 nanoid                # save to package.json, then install
jpm add --dev vitest                 # save as a dev dependency
jpm remove nanoid                    # remove from package.json, then install
jpm run build                        # run a package.json script
jpm exec cowsay hello                # run a package's bin, installing it if needed
jpm ci                               # fail if the lockfile is missing or stale
jpm approve esbuild                  # let a package's install scripts run
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every command and option; more in
[docs/usage.md](docs/usage.md).

**Coming from another package manager:** run `jpm install`. jpm reads the lockfile that is
there and writes `jpm.lock` with the same versions, and leaves the old file alone. See
[docs/migrating.md](docs/migrating.md).

## Benchmarks

Medians of 5 runs on GitHub's `ubuntu-latest` (4 cores), 2026-09-30, against the live npm
registry; 480 runs, all succeeded. **ci** installs from a lockfile with no cache (CI without a
cache), **warm** with the cache restored, **cold** with neither. Wall time, `nuxt` (591
packages):

| manager | cold | warm | ci | repeat |
| --- | ---: | ---: | ---: | ---: |
| **jpm** | **1.22 s** | 206 ms | 734 ms | **2 ms** |
| bun 1.4 | 1.28 s | 234 ms | **676 ms** | 18 ms |
| aube 2.6 | 3.00 s | **186 ms** | 896 ms | 7 ms |
| pnpm 12.8 | 1.72 s | 435 ms | 1.53 s | 11 ms |
| deno 2.9 | 7.64 s | 338 ms | 1.20 s | 28 ms |
| upm 1.3 | 3.52 s | 447 ms | 2.06 s | 44 ms |
| yarn 4.18 | 9.63 s | 3.13 s | 5.58 s | 1.02 s |
| npm 12.1 | 18.5 s | 4.69 s | 6.62 s | 794 ms |

Across `nitro`, `nuxt` and `next`, jpm is fastest in 9 of 12 cells. bun wins cold `nitro` and
`nuxt` ci, and aube `nuxt` warm. On Windows, where Defender scans every file an install writes,
jpm is fastest on `next`, and upm, aube and npm each beat it in one phase of `nuxt`. Every
table, with CPU, memory, disk and cache, and how to run them:
[docs/benchmarks.md](docs/benchmarks.md).

## Documentation

- [Install](docs/install.md) and [usage](docs/usage.md)
- [Coming from another package manager](docs/migrating.md)
- [Configuration](docs/configuration.md): `.npmrc`, registries, credentials, TLS, proxies,
  release age
- [Install scripts](docs/install-scripts.md)
- [The lockfile](docs/lockfile.md)
- [Overrides](docs/overrides.md) and [patches](docs/patches.md)
- [Directory dependencies](docs/directory-dependencies.md) and
  [git dependencies](docs/git-dependencies.md)
- [Runtimes](docs/runtimes.md): Node.js, Bun and Deno from `package.json`
- [How it works](docs/how-it-works.md)
- [Development](docs/development.md)

## License

MIT, Copyright (c) 2026 JT Turner. jpm started as a port of upm, Copyright (c) Pooya Parsa,
also MIT. See [LICENSE](LICENSE). [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) credits the
code, crates and test data jpm builds on, and ships with every release.
