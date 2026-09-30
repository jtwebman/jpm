# jpm

A fast, small package manager for the npm registry, written in Rust.

jpm started as a Rust port of [upm](https://github.com/unjs/upm). It installs the same
isolated `node_modules` layout and takes the same commands and flags. It needs no Node.js
to install packages; Node is only needed to run them.

## Install

```sh
curl -fsSL https://getjpm.sh | sh                  # macOS and Linux
```

```powershell
irm https://getjpm.sh/install.ps1 | iex              # Windows
```

Where security software stops a script piped into `iex`, download it and run it as a file:
`irm https://getjpm.sh/install.ps1 -OutFile install.ps1; powershell -ExecutionPolicy Bypass -File install.ps1`.

The script downloads the binary for your platform from the
[latest release](https://github.com/jtwebman/jpm/releases/latest), checks its SHA-256, and
puts `jpm` and `jpx` in `~/.jpm/bin`. `JPM_VERSION=v0.1.0` picks a release and `JPM_INSTALL`
another directory. Each platform has its own build:

| Platform      | Release asset           | Target                           |
| ------------- | ----------------------- | -------------------------------- |
| Linux x64     | `jpm-linux-x64`         | `x86_64-unknown-linux-musl`      |
| Linux arm64   | `jpm-linux-arm64`       | `aarch64-unknown-linux-musl`     |
| Linux armv7   | `jpm-linux-armv7`       | `armv7-unknown-linux-musleabihf` |
| macOS x64     | `jpm-darwin-x64`        | `x86_64-apple-darwin`            |
| macOS arm64   | `jpm-darwin-arm64`      | `aarch64-apple-darwin`           |
| Windows x64   | `jpm-windows-x64.exe`   | `x86_64-pc-windows-msvc`         |
| Windows arm64 | `jpm-windows-arm64.exe` | `aarch64-pc-windows-msvc`        |

The Linux builds are static, so they run on glibc and musl (Alpine) alike. Tests run on
Linux x64, Windows x64 and macOS arm64.

Or build it:

```sh
cargo build --release    # target/release/jpm
```

## Use

```sh
jpm install                          # install the project's dependencies
jpm                                  # the same: no command is install
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
jpm patch lodash                     # copy a package to edit; patch-commit saves the patch
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every option.

An install that takes longer than a tenth of a second shows one line of progress on stderr
(packages resolved, fetched and linked), and takes it off before the summary. Windows
Terminal, iTerm2 3.6 and later, Ghostty, WezTerm, ConEmu and VS Code also show it on their tab
or taskbar (OSC 9;4). There is no progress when stderr is not a terminal, when `CI` is set,
or with `--silent`, `--json` or `--no-progress`.

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

Workspaces are read from package.json, or from `pnpm-workspace.yaml` when package.json lists
none. `catalog:` and `catalog:<name>` ranges are read from the root's `pnpm-workspace.yaml`,
`.yarnrc.yml` or package.json (`catalog` and `catalogs`, at the top or under `workspaces`).

`pnpm-workspace.yaml` settings that change what pnpm installs and jpm does not read, such as
`packageExtensions` or `minimumReleaseAge`, are named in a warning; the rest are left alone.

The old lockfile is left in place and no longer read; delete it when you are ready.
`jpm install --frozen-lockfile` (and `jpm ci`) write nothing: in CI they install from the
old lockfile as it is, so a pipeline keeps working before `jpm.lock` is committed.

## Overrides

An override replaces the range an edge asks for, before it is resolved, in every package and
for peers too. jpm reads each manager's field:

| Field | Keys |
| --- | --- |
| npm's `overrides` (bun's too) | `name`, `name@range`, `{ "parent": { "name": … } }`, `.` for the parent itself |
| yarn's `resolutions` (bun's too) | `name`, `**/name`, `parent/name` |
| `pnpm.overrides`, `pnpm-workspace.yaml` `overrides` | `name`, `name@range`, `parent@range>name`, `name@` |

A value is a range, an `npm:` alias, `$name` for the root's own range of `name`, `catalog:`, or
for pnpm `-`, which takes the edge out. A `name@range` key matches as its manager does: npm's
where the two ranges meet, pnpm's where the edge's range is inside it, yarn's where they are
the same. jpm keeps one copy of each version of a package, so a nested rule applies to the
parent's own dependencies wherever the parent is; a rule nested deeper applies to its nearest
parent's, with a warning. When two rules match, the one with a parent wins, then one with a
range, then a name alone; pnpm's rules go before npm's, and npm's before yarn's.

## Patches

A patch changes a package's files as it is installed. jpm reads `patchedDependencies` from
`pnpm-workspace.yaml`, package.json `pnpm.patchedDependencies` and package.json
`patchedDependencies` (bun's):

```yaml
patchedDependencies:
  lodash@4.17.21: patches/lodash@4.17.21.patch
```

A key is `name@version`, `name@range`, or `name` for every version. A version's own patch goes
before a range's, and a range's before the name's. The value is a path, from the project root,
to a diff as `git diff` writes it, with paths relative to the package. The path stays in the
project: no `..`, no absolute path, no symlink on the way, and a file of at most 16 MiB. A hunk
whose lines do not match, a path that leaves the package, or a patch that no package in the
tree takes stops the install, as in pnpm.

yarn's `patch:` protocol is read too, in the root package.json's `resolutions` and dependencies:

```json
"resolutions": { "lodash@npm:4.17.21": "patch:lodash@npm%3A4.17.21#./.yarn/patches/lodash-npm-4.17.21-6382451519.patch" }
```

The package is the source before the `#` and the patch the path after it (`~/` is the project
root). yarn's builtin patches (`optional!builtin<compat/typescript>`) are for Plug'n'Play and
are skipped; the package is installed as published. A `patch:` range in a workspace's
package.json is refused unless it is a builtin one.

A patched package is a copy of its own, built under a key that includes the patch's hash; so is
every package that depends on it. The clean package in the store is not changed. jpm.lock
records the patch's sha256 on the package (`patch <hash>`): editing, adding or removing a patch
makes the file out of date, so `jpm install` writes it again and `--frozen-lockfile` fails. A
package that is also approved for install scripts is patched before they run.
`pnpm-lock.yaml` and `bun.lock` are carried over when they name the same patches.

To make a patch:

```sh
jpm patch lodash                     # copies lodash to node_modules/.jpm_patches/lodash@4.17.21
                                     # edit the files there, then:
jpm patch-commit node_modules/.jpm_patches/lodash@4.17.21
```

`jpm patch <name>[@version]` copies the version jpm.lock has into a directory to edit
(`--edit-dir` picks another), with the project's patch for it already applied. `jpm
patch-commit <dir>` writes the difference from the published package with `git diff` to
`patches/<name>@<version>.patch` (a scope's `/` as `__`), or to the file that already patches
it, names it in `patchedDependencies` (in `pnpm-workspace.yaml` when that file lists patches,
else in package.json), and installs. git must be installed.

A script that edits `node_modules/<name>` in place, as patch-package does, fails: those files
are read-only links into the store.

## The lockfile

`jpm.lock` is a text file: one fact per line, sorted, so a change is a small diff.

```
jpm-lock 2
hash 0c1f…
root
  override pnpm vite@^7>esbuild 0.25.9
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
`jpm lock --json` prints the lockfile as JSON, in upm's format, with `root.overrides` added.

An `npm:` alias is keyed by the package it installs as well as the name it takes:
`"typescript": "npm:@typescript/typescript6@^6"` is `package typescript@npm:@typescript/typescript6@6.0.2`,
and an edge to it reads `dep typescript npm:@typescript/typescript6@6.0.2`. The real typescript
at the same version stays a package of its own. A lockfile written before this keys an alias
by its name and version, which it could only do where nothing else had that name at that
version; it installs as it is.

The root records the ranges package.json declares (`spec`, a `catalog:` range as the range it
stands for) and each override the tree was resolved under (`override`: manager, pnpm-style
selector, value with `$name` and `catalog:` resolved, in the order they apply). Another range,
catalog entry or override makes the file out of date: `jpm install` resolves again, and
`--frozen-lockfile` fails.

With no `jpm.lock` (and no other manager's lockfile to bring over), `jpm install` keeps the
versions a `node_modules` jpm installed already has, wherever the ranges in package.json allow
them, and resolves the rest; then it writes `jpm.lock`. For a fresh resolve, delete `jpm.lock`
and run `jpm lock`, which does not read `node_modules`, or delete `node_modules` too.

## Directory dependencies

A dependency can be a directory, given relative to the package.json that names it:

```json
"dependencies": {
  "ui": "file:packages/ui",
  "tool": "link:../tool"
}
```

- `link:<dir>` is a symlink (a junction on Windows) to the directory, as pnpm makes one. Its
  dependencies are its own business: jpm installs nothing for it, and the directory need not
  exist yet. Its bins are linked, read from its package.json when the lockfile is written.
- `file:<dir>` (or a bare `./<dir>`) inside the project is linked the same way, and installed
  as a workspace is: its dependencies go in its own `node_modules`, and a `file:` directory it
  names in turn is installed too. This is npm's default (`install-links=false`). Its
  package.json is read on every install, so an edit there makes the lockfile stale, as an edit
  to a workspace's does. Its own lifecycle scripts do not run.
- yarn's `portal:<dir>` is read as `file:<dir>`: the directory linked, its dependencies installed.
- `file:<dir>` outside the project (`file:../sibling`) is linked as `link:` is, with a warning:
  installing its dependencies would mean writing its `node_modules`, and jpm writes nothing
  outside the project. Run `jpm install` in that directory for them.
- A `file:` path ending in `.tgz`, `.tar.gz` or `.tar` is a tarball, copied into the store.
- Only the root and workspaces (and `file:` directories) may depend on a path; a registry
  package that does is an error.

In `jpm.lock`, a `file:` directory inside the project is a `workspace` section under the name
it is installed as, and an edge to either kind is `link:<path>`, the path from the project root.
A linked directory is a `package <name>@link:<path>` entry holding only its version and bins.
A lockfile edge to a directory must match the spec package.json gives it, and an edge by name
alone must reach a workspace, not a `file:` directory that shares its name, so an edit to the
lockfile alone cannot point a name at another directory.

A checkout can ship `node_modules`, or a directory in it (`.bin`, `.jpm`, the hidden hoist, a
scope in it, an entry's own `node_modules`), as a symlink out of the project. jpm refuses to
link, write or sweep through one.

## Git dependencies

```json
"dependencies": {
  "a": "github:user/repo#v1.2.0",
  "b": "user/repo#semver:^2",
  "c": "git+ssh://git@example.com/team/c.git#main",
  "d": "gitlab:group/d#9f2c4e1b7a0d3c5e8f6a2b4c1d3e5f7a9b0c2d4e"
}
```

`github:`, `gitlab:`, `bitbucket:` and `user/repo` shorthands are read, and `git+https://`,
`git+ssh://` (and scp-like `git@host:path`) and `git://` urls, each with `#<commit>`,
`#<branch or tag>` or `#semver:<range>` (the highest tag in the range; none means the default
branch). `git+http://` is refused, as are credentials in a url: they would be written to
jpm.lock, and belong in git's credential helper or ssh. `gist:` is not read yet.

- **Resolving.** A ref becomes a commit through `git ls-remote`, so git must be installed. A
  commit is given as its full id; a short one is refused. jpm.lock keys the package by its
  commit (`a@git+https://github.com/user/repo.git#<commit>`), and keeps that commit until
  package.json names another ref: a branch is not followed by a later install.
- **Fetching.** A GitHub, GitLab or Bitbucket repository over https is downloaded as the host's
  archive of the commit, through jpm's own client; if there is none (a private repository), and
  for every other url, jpm fetches the one commit into a temporary repository
  (`git fetch --depth 1`) and reads it with `git archive`. Only the files `npm pack` would keep
  under package.json's `files` are stored, with package.json, the readme, the licence, `main`
  and the bins always kept and `node_modules` never; `.npmignore` and `.gitignore` are not read.
- **Integrity.** A host's archive is not the same bytes from one year to the next (GitHub's
  compression changed in 2023), so the integrity jpm locks is not of the archive: it is the
  sha512 of the stored tree, each file's path, mode, size and bytes in path order. A download
  that unpacks to other files under the locked commit fails, however it was compressed.
- **Scripts.** A git package's `prepare`, which npm runs to build it, counts as an install
  script: it runs only once approved (`jpm approve <name>`), before its other install scripts,
  in the package's copy. Its devDependencies are not installed for it.
- **Lockfile.** A git or tarball edge of the root or a workspace in jpm.lock must be what
  package.json names: the same url, or the same repository at the commit package.json pins, if
  it pins one. A package's own git or tarball edge must be what its package.json (or the
  registry's copy of it) names. An edit to jpm.lock alone cannot put another repository, commit
  or url in its place: `--frozen-lockfile` fails, and `jpm install` resolves package.json again.
- **Dependencies' repositories.** Only the root and workspaces may take a package from a git
  repository or a tarball url: a registry package that depends on one is refused, as pnpm 10.26
  and later refuse it (`block-exotic-subdeps`, on by default). `block-exotic-subdeps=false` in
  `~/.npmrc`, `npm_config_block_exotic_subdeps=false` or `--no-block-exotic-subdeps` allows it,
  as npm does; a project's own .npmrc cannot. Either way, for a repository no package.json of
  the project names, git asks nothing: no credential prompt, askpass program or
  Git Credential Manager window, and ssh runs in batch mode (no passphrase or host-key question)
  unless `GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand` runs it another way. For the
  project's own repositories, git asks on a terminal as it always does.
- **Security.** git runs with only https, ssh and git:// allowed (`GIT_ALLOW_PROTOCOL`: never a
  transport helper such as `ext::`, nor `file://`), with every url after `--`, and without the
  repository variables (`GIT_DIR` and the like) of a git that ran jpm. It runs in an empty
  directory of jpm's own with `GIT_CEILING_DIRECTORIES` set, so it reads no repository's config:
  not the project's, and not one a checkout carries as plain files. A url, host or user starting
  with `-`, a host other than letters, digits, `.` and `-` (or an IPv6 address in brackets), a
  one-letter scp host (a drive to git on Windows), a `::` (git's transport-helper syntax), a ref
  starting with `-`, or a url with a space or a control character in it is refused when
  package.json or jpm.lock is read. Registry tokens are never sent to a git host.

Another manager's lockfile with a git dependency is brought over by resolving package.json
with its versions preferred.

## Runtimes

A package can depend on the runtime its scripts run on, as in pnpm: jpm downloads Node.js, Bun
or Deno, locks the version, keeps it in the store and links its binary into that package's
`node_modules/.bin`.

```sh
jpm add --dev node@runtime:22        # saved to devEngines.runtime, as pnpm saves it
jpm add bun@runtime:^1.2             # saved to engines.runtime
```

package.json can say it either way pnpm reads:

```json
"devEngines": { "runtime": { "name": "node", "version": "22", "onFail": "download" } },
"devDependencies": { "deno": "runtime:^2.4" }
```

- **Versions.** The range is resolved once, to the newest release it allows, and `jpm.lock`
  keeps that version: everyone installs the same one until package.json names a range it does
  not meet. For Node the range can also be `lts`, an LTS codename (`jod`) or `latest`; only
  releases are installed, never prereleases or nightlies. `add` saves the range as typed (pnpm
  saves the exact version), no range as `^<newest>`, and `--exact` the version itself.
- **Checks only.** A `devEngines.runtime` or `engines.runtime` entry whose `onFail` is `warn`,
  `error` or missing is checked against the runtime on PATH: jpm warns when it is missing or
  outside the range, and installs anyway. `ignore` turns the check off.
- **Bins.** The runtime installs as the package `node` (`bun`, `deno`), with one bin of the same
  name, as in pnpm: Node's `npm`, `npx` and `corepack` are not linked.
- **Workspaces.** Each workspace can declare its own. `jpm run` puts `node_modules/.bin` of the
  package's directory and of each directory above it first on PATH, so a script, and a bin whose
  `#!` line runs `node`, gets the runtime its package declares, else the root's, else the
  system's.

Node comes from `https://nodejs.org/download/release`, or the mirror `node-mirror:release=<url>`
(in `.npmrc`, as pnpm 10 reads it) or `NODEJS_ORG_MIRROR` names. The version is picked from its
`index.json`, and each build is checked against the release's `SHASUMS256.txt`: the `.tar.gz` on
Linux and macOS, and on Windows the bare `node.exe`. A musl build is the release's own (Node 26
and later) or, from nodejs.org only, unofficial-builds.nodejs.org's. Bun and Deno come from npm:
the package `bun` (`deno`) gives the version, and the platform packages it lists as optional
dependencies (`@oven/bun-linux-x64`, `@deno/linux-x64-glibc`, …) are the builds, fetched through
the registry like any package. pnpm takes Bun and Deno from their GitHub release zips instead.
On arm64 macOS and Windows, a version with no arm64 build installs the x64 one.

As in pnpm, the `SHASUMS256.txt` is trusted only once its signature, `SHASUMS256.txt.sig`, checks
out against Node's release keys. jpm carries only the keys' fingerprints (every current and past
releaser's, from nodejs/release-keys): it fetches the signer's key from that repository once,
keeps it under the store's `metadata/`, and uses it only when it has the fingerprint jpm expects.
This happens when a version is resolved; installs from `jpm.lock` check downloads against the
lock alone. A mirror that publishes no signatures needs `verify-node-signature=false` in
`~/.npmrc` (not the project's) or `--no-verify-node-signature`. unofficial-builds.nodejs.org's musl list is not
signed; it is trusted as far as its TLS download, as pnpm trusts it.

In `jpm.lock` the runtime is a package holding every platform's build:

```
root
  spec devDependencies node runtime:22
  dep node runtime:22.12.0
package node@runtime:22.12.0
  version 22.12.0
  variant darwin-arm64 sha256-… node-v22.12.0-darwin-arm64.tar.gz
  variant linux-x64 sha256-… node-v22.12.0-linux-x64.tar.gz
  variant win32-x64 sha256-… win-x64/node.exe
```

A `variant` is a platform (`<os>-<cpu>`, `-musl` for a musl build), its integrity, and where the
build is: a file of the release (or a url), or for Bun and Deno the platform package. An install
takes this machine's and checks the download against it, so a lockfile made on Linux installs on
macOS or Windows without asking the network what to trust. A new range makes the file out of
date, as any other does. The build is unpacked into the store like a package; its entry links
the binary alone (not Node's npm and headers, 4,000 files), and `jpm prune` removes the build
once no registered project's lockfile names it.

A `pnpm-lock.yaml` brought over keeps the version pnpm locked for each runtime (`runtime:` in
its importers). jpm reads the builds from the release as for its own lockfile; each one pnpm
recorded that jpm uses too (Node's `.tar.gz` builds, matched by file name) must have the same
integrity, or the install stops. pnpm's Windows Node, and its Bun and Deno, are zip files jpm
does not use, so they are not compared.

## How it works

- **Resolve.** The dependency graph is walked on a pool of threads. Each package is picked
  from the registry's abbreviated document, fetched once per run and kept on disk between
  runs (revalidated by ETag). Peer dependencies are settled against the tree after the walk,
  so a plugin uses the host version the tree already has. Consumers that miss the same peer
  share one version when one fits them all.
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

## Install scripts

A dependency's install scripts (`preinstall`, `install`, `postinstall`, or `node-gyp rebuild`
for a `binding.gyp`) are how most npm malware runs, so jpm runs them only when you ask:

```sh
jpm install                 # "install scripts not run for esbuild@0.21.5: `jpm approve <name>` runs them"
jpm approve                 # list what waits
jpm approve esbuild         # trust it, approve this version, install
```

`jpm approve` adds the name to `trustedDependencies` in package.json (bun's field; pnpm's
`onlyBuiltDependencies`, and `pnpm-workspace.yaml`'s `onlyBuiltDependencies` and `allowBuilds`,
are read too, where `name: false` takes a name out and silences it) and marks the locked version `build` in jpm.lock. Both
must agree: a new version of a trusted package does not run its scripts until it is approved
again. Approved packages are copies, not links into the store, kept in the project; their
scripts run once, dependencies first, with output in `.build.log` beside the package and
shown when a script fails. npm, yarn and bun tokens are taken out of their environment, but
that is hygiene, not a sandbox: an approved script runs as you and can read your files. Only
the package the registry serves under the approved name and version runs its scripts, so an
alias or a lockfile edit pointing elsewhere does not.

The project's own lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare` and
their pre/post) run on installs that change the tree, after it is linked. `--ignore-scripts`
or `ignore-scripts=true` in .npmrc turns every script off.

## Configuration

`.npmrc` is read from the project, the user's home and npm's global location, plus
`npm_config_*` variables. jpm reads `registry`, `@scope:registry`, credentials
(`//host/:_authToken`, `_auth`, `username` and `_password`), `save-exact`, `offline`,
`prefer-offline`, `min-release-age`, `before`, `min-release-age-exclude`,
`block-exotic-subdeps` (see Git dependencies) and the network settings below.

The project's `.npmrc` comes with the repository, so it cannot weaken what the others check:
`ca`, `cafile`, `proxy`, `https-proxy`, `http-proxy`, `strict-ssl=false`,
`block-exotic-subdeps=false`, `verify-node-signature=false`, and a `min-release-age` or `before` that lets in newer versions
than the user's setting (or the default) does, are ignored there with a warning naming them.
Set them in `~/.npmrc`, the global npmrc, `npm_config_*` or a flag. A cloned repository could
otherwise send the user's registry token through a proxy of its choosing. `registry`, scoped
registries, `noproxy` and `node-mirror:release` still work from the project.

jpm has its own TLS and trusts Mozilla's root certificates and the operating system's: the
Windows certificate store (the current user's `ROOT`, which includes the machine's and group
policy's), or on Linux the distribution's CA bundle (`SSL_CERT_FILE` names another). A company
proxy that inspects TLS usually installs its root there, so it works without settings. For a
registry with a private CA, or a root only in a file, tell jpm which certificates to trust, as
with npm:

- `NODE_EXTRA_CA_CERTS=/path/ca.pem` adds the certificates in a PEM file to Mozilla's roots, as
  Node does.
- `cafile=/path/ca.pem` in `.npmrc` trusts the certificates in the file *instead of* Mozilla's
  and the system's roots (and of `NODE_EXTRA_CA_CERTS`), as it does in npm. `ca="-----BEGIN CERTIFICATE-----\n…"`
  does the same with the PEM text on one line, `\n` for its line breaks; `ca[]=` once per
  certificate lists several. `cafile` wins when both are set.
- `strict-ssl=false` turns the certificate checks off, and jpm warns on every run that it is
  off. The connection is still encrypted, but anyone on the network can pose as the registry.

A file that cannot be read, or holds no certificate, is an error that names it.

`https-proxy` (else `proxy`) in `.npmrc` sends requests through a proxy, `http://user:pass@host:port`
for one that wants credentials (jpm reaches a proxy over plain http, so an `https://` proxy is
refused rather than sent credentials in the clear), and `noproxy` lists the hosts (and domains under them) that go
direct. They take the place of `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, which jpm reads when
`.npmrc` names none. https goes through the proxy by CONNECT, so TLS runs end to end.

New versions are held back for one day by default (`min-release-age`). Set it to `0` to
turn this off.

The global virtual store is on by default. Turn it off with `global-store=false` in `.npmrc`,
`JPM_GLOBAL_STORE=0` or `--no-global-store`. It is off inside containers (`/.dockerenv` or
`/run/.containerenv`), where a mounted project would not see the store, and when the store
cannot be written. It is also off, with a note, for a project that depends on `next` or `nuxt`:
Next's Turbopack compiles nothing outside the project, and Nuxt imports packages it does not
declare. `global-store=true` overrides that.

Every project also gets a hidden hoist, `node_modules/.jpm/node_modules`: the highest version
of every package the root does not link itself, which Node reaches when a package imports
something it did not declare, as pnpm does with `.pnpm/node_modules`. Packages in the global
store resolve from the store and cannot reach it on their own, so under the global store
`jpm run`, `jpm exec` and install scripts point Node at it: `NODE_PATH` gets the hoist and the
project's `node_modules` (for `require`), and `NODE_OPTIONS` gets
`--require node_modules/.jpm/hoist.cjs`, a resolve hook that retries a missing `import` from
the project. The hook needs Node 22.15 or later; older Node gets only `NODE_PATH`, so an
undeclared `require` works there and an undeclared `import` does not. Both add to what is
already set. Plain
`node app.js`, outside jpm, gets neither: an undeclared import fails there unless the project
is installed with `--no-global-store`.

`jpm prune` removes what no project uses. Every install registers its project with the store
(`v1/projects`), and a prune keeps the global entries and packages that registered projects
still use. A project that is gone, or on a drive that is not mounted, is dropped from the
register; its next install rebuilds what it needs. Installs and prunes take a lock on the store
(`v1/lock`), so a prune waits for installs to finish and removes what is unused at once. On a
filesystem without working file locks, such as some network mounts, an install running
alongside a prune can lose entries; installing again repairs it.

## Development

```sh
cargo test --workspace           # unit tests and end-to-end tests against a local registry
cargo build --release            # built for size, the CPU-heavy crates for speed
cargo build --profile fast       # every crate at full speed, for comparing
```

Platform-specific code lives in `src/sys/`, one file per OS; only the target's file is
compiled.

The git tests use bare repositories on disk and a local server for GitHub's archives, through
two switches meant for tests only: `JPM_GIT_ALLOW_FILE=1` lets git fetch `file://` urls, and
`JPM_CODELOAD_URL` replaces `https://codeload.github.com`. The runtime tests serve real Node
release signatures and keys (`tests/fixtures/node`) from a local server, which
`JPM_NODE_KEYS_URL` points jpm at in place of nodejs/release-keys; a key is still used only when
its fingerprint is one jpm carries.

jpm has its own TLS and cryptography, in three crates:

- `crates/crypto` (`jpm-crypto`): SHA-1/2, HMAC, HKDF, AES-GCM and ChaCha20-Poly1305, built for
  speed. It uses the CPU's AES, carry-less multiply and SHA instructions where it has them and
  constant-time portable code where it does not.
- `crates/pk` (`jpm-pk`): X25519, P-256, P-384 and RSA signature checks, built for size: they
  run a few times per connection, not per byte. Ed25519 checks too, for Node's release keys.
- Both are tested against RFC and NIST vectors, the Wycheproof suites, and ring on random
  inputs.
- `crates/tls` (`jpm-tls`): a TLS 1.3 and 1.2 client (ECDHE and AEAD suites only) and Web PKI
  certificate checks, with Mozilla's roots from `webpki-roots`. Tested against rustls-webpki
  and the x509-limbo suite, against rustls and OpenSSL servers, and with a scripted server
  that sends every kind of bad message.

The tests that need the network are ignored by default:
`cargo test -p jpm-tls --release --test live -- --ignored` (registries and badssl.com), and
`--test openssl` for OpenSSL interop, which needs the `openssl` command.

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
557 MB for upm. Its binary is 1.6 MB; bun's is 80 MB, pnpm 12's 60 MB and aube's 152 MB.

These were measured with the earlier harness, taken from upm, on 2026-09-28. To run the
benchmarks (see [bench/README.md](bench/README.md)):

```sh
bench/bench.sh -r jpm,npm,pnpm,bun -f nuxt
```

## License

MIT, Copyright (c) 2026 JT Turner. jpm started as a port of upm, Copyright (c) Pooya Parsa,
also MIT. See [LICENSE](LICENSE).
