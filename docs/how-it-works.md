# How it works

- **Resolve.** The dependency graph is walked on a pool of threads. Each package is picked
  from the registry's abbreviated document, fetched once per run and kept on disk between
  runs (revalidated by ETag). Peer dependencies are settled against the tree after the walk,
  so a plugin uses the host version the tree already has. Consumers that miss the same peer
  share one version when one fits them all. A package takes its peers from where it is
  installed, so one reached with two sets of peers is two copies, as under pnpm: a library
  that workspaces on two Reacts share is `ui-lib@1.0.0(react@17.0.2)` and
  `ui-lib@1.0.0(react@18.2.0)` in `jpm.lock`, each linked to its React. A package with one set
  keeps its plain key. A peer that nothing in its consumer's scope has, when a workspace (or the
  root) goes by its name, is linked to that workspace before anything is fetched, out of the
  peer's range too with a warning: yarn 1 and npm link every workspace at the root, where any
  package finds it, as facebook/react's `react-dom@17` finds packages/react.
- **Store.** Each tarball is checked against its integrity and unpacked once into a shared
  store (`~/.jpm/store`, or `JPM_STORE`). Files there are read-only.
- **Link.** Each package gets an entry, `<name>@<version>-<hash>/`, named by a hash of the
  package and everything below it. The entry holds the package's files, hardlinked from the
  store (a single `clonefile` per package on macOS), and a symlink (a junction on Windows) to
  each of its dependencies, so a package can import only what it declared.
- **Global virtual store.** Entries are built once, in the store (`v1/links`), and shared by
  every project on the machine: `node_modules/<dep>` links straight to one. A warm install
  makes only those links. An entry missing an optional package, or whose peer is a workspace,
  or depending on one that is, is built in the project's `node_modules/.jpm` instead, as every
  entry is when the global store is off.
- **Repeat installs.** `node_modules/.jpm.json` records what was installed. When the
  lockfile, `package.json` and settings are unchanged, a repeat install checks a few links and
  exits.
