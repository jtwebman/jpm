# Coming from another package manager

Run `jpm install`. With no `jpm.lock`, jpm reads the lockfile that is there and writes
`jpm.lock` from it. A project with more than one reads the one package.json's `packageManager`
names, else the first of `bun.lock`, `pnpm-lock.yaml`, `yarn.lock`, `npm-shrinkwrap.json` and
`package-lock.json`, and says which:

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

A root or workspace range lands on a workspace of its name, as npm, yarn and bun link one (in an
npm project a dependency's range does too, as npm's root holds every workspace; in pnpm, with
`linkWorkspacePackages: deep`), but
in a pnpm 9 or later project (a `pnpm-workspace.yaml`) only a `workspace:` range does, unless
`linkWorkspacePackages` (or `.npmrc`'s `link-workspace-packages`) is on. `.yarnrc.yml`'s
`enableTransparentWorkspaces: false` does the same for yarn.

Of copies of one package that differ in peers, a copy whose peers another copy has too, and
more, is that copy, as pnpm's `dedupePeerDependents` makes it; `dedupePeerDependents: false` in
`pnpm-workspace.yaml` keeps them apart.

`pnpm-workspace.yaml` settings that change what pnpm installs and jpm does not read, such as
`hoistPattern` or `injectWorkspacePackages`, are named in a warning; the rest are left alone. Its
`overrides`, `patchedDependencies`, `onlyBuiltDependencies`, `allowBuilds` and
`packageExtensions` are read, and so is `.yarnrc.yml`'s `packageExtensions`
([package extensions](overrides.md#package-extensions)).
Its `minimumReleaseAge` (in minutes) and `minimumReleaseAgeExclude` are read as the project's
`min-release-age` and `min-release-age-exclude`, under its `.npmrc` and held to the same rule.

Tools that read the other manager's state find what they need: beside `pnpm-lock.yaml`, jpm
writes the `node_modules/.modules.yaml` nx looks for; beside a yarn 2 or later `yarn.lock` with
`nodeLinker: node-modules`, it writes yarn's `node_modules/.yarn-state.yml`, so `yarn run` and
`yarn <bin>` (turbo's, or a build script's) find each package where jpm put it. yarn names a
package with peer dependencies by a hash of its own resolution, which jpm cannot know, so yarn
does not find those packages' bins (grafana's `yarn nx`): `jpm run` and `jpx` do.

The old lockfile is left in place and no longer read; delete it when you are ready.
`jpm install --frozen-lockfile` (and `jpm ci`) write nothing: in CI they install from the
old lockfile as it is, so a pipeline keeps working before `jpm.lock` is committed.

## Known differences

jpm lays out `node_modules` as pnpm does: each package is a link to its own entry, holding
links to what it declares. npm, yarn's node-modules linker and pnpm's `node-linker=hoisted`
make real directories instead, nested where versions differ. Node finds packages the same way
in both, but a tool that reads file paths can see the difference. Each case below has a change
in the project that works under jpm and under pnpm alike.

- **TypeScript declarations** (`TS2742` or `TS2883`: "The inferred type of 'x' cannot be named
  without a reference to '.jpm/…'. This is likely not portable."): a declaration needs a type
  from a package the workspace does not depend on itself. Add that package to the workspace's
  dependencies, or give the export an explicit type. Seen in strapi (`logform`), cal.com
  (`@prisma/client`), medusa (`@eslint/core`) and Trilium (`@ai-sdk/provider`).
- **Paths written for npm's layout**: a script or config that names `node_modules/<pkg>/…` or
  takes a package name out of a real path breaks when that path is `node_modules/.jpm/…`. Read
  the name after the last `node_modules/` instead (webpack's `tooling/generate-types.js`), and
  give generated code a path of its own: Prisma's generator `output`, rather than
  `node_modules/.prisma/client` (documenso's vite config).
- **Electron apps** pack `node_modules` into the app and rebuild native modules for Electron in
  place, so jpm keeps every package inside the project for a project that depends on
  `electron`, as `global-store=false` does. A tool that follows `require` itself from a link's
  path rather than its target, as hyper's V8 snapshot builder (electron-link) does, can still
  pick the wrong copy of a package that has two: that needs real directories, which jpm does
  not make.
