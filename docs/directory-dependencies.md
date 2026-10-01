# Directory dependencies

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
- A registry package may depend on a path only inside itself, where the files come from its
  own tarball, checked against the same integrity:
  - itself (`"its-name": "link:."`) is no dependency: it requires itself anyway, as under pnpm;
  - a directory its tarball ships (`"local-dep": "file:./local-dep"`) is a package of its own,
    linked beside it: its files are that directory's, and the dependencies in its package.json
    are installed as any package's;
  - a directory its tarball lacks (a monorepo published without it) is left out, with a warning.

  A path out of the package (`..` past its root, an absolute path, `~`, a drive or a UNC path),
  or one with a `%` in it, is an error: it could reach anything on the machine installing it.
  So is a path dependency of a git or tarball package. Anything else may depend on a path only
  from the root, a workspace or a `file:` directory.

In `jpm.lock`, a `file:` directory inside the project is a `workspace` section under the name
it is installed as, and an edge to either kind is `link:<path>`, the path from the project root.
A linked directory is a `package <name>@link:<path>` entry holding only its version and bins.
A directory inside a registry package is `package <name>@path:<package key>/<path>`, with that
package's integrity; only the package itself, or another directory inside it, may link it.
A lockfile edge to a directory must match the spec package.json gives it, and an edge by name
alone must reach a workspace, not a `file:` directory that shares its name, so an edit to the
lockfile alone cannot point a name at another directory.

A checkout can ship `node_modules`, or a directory in it (`.bin`, `.jpm`, the hidden hoist, a
scope in it, an entry's own `node_modules`), as a symlink out of the project. jpm refuses to
link, write or sweep through one.
