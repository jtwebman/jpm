# Coming from another package manager

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
`packageExtensions` or `publicHoistPattern`, are named in a warning; the rest are left alone.
Its `minimumReleaseAge` (in minutes) and `minimumReleaseAgeExclude` are read as the project's
`min-release-age` and `min-release-age-exclude`, under its `.npmrc` and held to the same rule.

The old lockfile is left in place and no longer read; delete it when you are ready.
`jpm install --frozen-lockfile` (and `jpm ci`) write nothing: in CI they install from the
old lockfile as it is, so a pipeline keeps working before `jpm.lock` is committed.
