# Overrides

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
the same. jpm resolves each version of a package once, so a nested rule applies to the
parent's own dependencies wherever the parent is; a rule nested deeper applies to its nearest
parent's, with a warning. When two rules match, the one with a parent wins, then one with a
range, then a name alone; pnpm's rules go before npm's, and npm's before yarn's.

## Package extensions

`packageExtensions` fixes a published package's manifest without forking it: a dependency it
forgot to declare, a peer it uses without saying so, or a peer to make optional. jpm reads them
from `pnpm-workspace.yaml`, from package.json's `pnpm.packageExtensions`, and from `.yarnrc.yml`:

```yaml
# pnpm-workspace.yaml
packageExtensions:
  forgetful@1:
    dependencies:
      helper: ^1.0.0
  plugin:
    peerDependencies:
      host: '*'
    peerDependenciesMeta:
      host:
        optional: true
```

A key is `name` or `name@range`; a value sets any of `dependencies`, `optionalDependencies`,
`peerDependencies` and `peerDependenciesMeta`. jpm applies them as pnpm's read-package hook
does (`createPackageExtender`):

- A range matches the package's version as `semver.satisfies` does: a prerelease only where the
  range names one. A key with no range matches every version.
- What the package declares itself wins: an extension adds only the names it lacks, field by
  field. A `peerDependenciesMeta` entry the package has is kept whole.
- Several keys can match one version (`foo` and `foo@1`). They apply in the order they are
  written, each onto what the ones before made, so the first to name a dependency gives its
  range.
- Every package is extended as the walk reads its manifest, before its dependencies and peers
  are walked: from the registry, a tarball or a git repository. The root and the workspaces are
  too, as pnpm extends its projects: a workspace `app` at 1.0.0 matches `app@1`.
- What an extension adds is a dependency like any other: overrides apply to it, it waits out
  `min-release-age`, its integrity is checked, and its install scripts wait for approval.

Where they come from, in the order they apply: `pnpm-workspace.yaml`'s, else package.json's
`pnpm.packageExtensions`, then `.yarnrc.yml`'s. pnpm 10 takes pnpm-workspace.yaml's in place of
package.json's, and jpm warns when both set them; pnpm 11 reads only pnpm-workspace.yaml's. A
key written in two places is one extension, the first place's entries winning.

A value is a registry range, a tag, an `npm:` alias, or a git or tarball url: the project chose
it, as it chooses an override's, so `block-exotic-subdeps` lets it through. A path (`file:`,
`link:`), `workspace:` and `runtime:` are not: a path in a package's manifest is read from inside
that package, and only the project's own packages may link a workspace. An extension jpm cannot
read is named in a warning and left out; a field pnpm does not read from one, such as
`devDependencies`, is named and ignored.

`jpm.lock` records each extension the tree was resolved under (`extension` lines, see
[the lockfile](lockfile.md)), so changing one makes it out of date: `jpm install` resolves
again, walking every package afresh with the locked versions preferred, and `--frozen-lockfile`
fails. A project with no extensions writes no such line. A resolve that read every manifest names
an extension that matched no package, or only packages that declare what it adds, as yarn does.

A `pnpm-lock.yaml` already holds what its extensions added. jpm brings it over as it is when its
`packageExtensionsChecksum` is pnpm's checksum of the project's extensions, and resolves again
when it is not. `package-lock.json` and `bun.lock` record none, so a project with extensions
resolves again from them, as it does from `yarn.lock`, keeping their versions where it can.

Where yarn differs, jpm does what pnpm does:

- yarn matches a prerelease against any range (`satisfiesWithPrereleases`); pnpm does not.
- yarn lets an extension's `peerDependenciesMeta` replace the package's own value; pnpm keeps the
  package's.
- yarn requires a range in the key and reads no `optionalDependencies`; jpm takes both.
- yarn records the packages as published in yarn.lock and applies the extensions on every
  install; jpm.lock records the extended packages and the extensions they were resolved under.
- Both managers also apply a built-in list of fixes for well-known packages (`@yarnpkg/extensions`,
  pnpm's unless `ignoreCompatibilityDb`). jpm applies only the project's own, so a project
  without extensions resolves as before.
