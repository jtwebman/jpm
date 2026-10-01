# Patches

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
