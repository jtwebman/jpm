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

A root or workspace range lands on a workspace of its name, as npm, yarn and bun link one, but
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

The old lockfile is left in place and no longer read; delete it when you are ready.
`jpm install --frozen-lockfile` (and `jpm ci`) write nothing: in CI they install from the
old lockfile as it is, so a pipeline keeps working before `jpm.lock` is committed.
