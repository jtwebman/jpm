# Runtimes

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
