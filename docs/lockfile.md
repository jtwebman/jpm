# The lockfile

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

A `jsr:` range is jsr's package from its npm registry, as pnpm reads it: `"fs": "jsr:@std/fs@^1"`
(or `"@std/fs": "jsr:^1"`) is `npm:@jsr/std__fs@^1`, from `https://npm.jsr.io` unless
`@jsr:registry` names another.

The root records the ranges package.json declares (`spec`, a `catalog:` range as the range it
stands for) and each override the tree was resolved under (`override`: manager, pnpm-style
selector, value with `$name` and `catalog:` resolved, in the order they apply). Another range,
catalog entry or override makes the file out of date: `jpm install` resolves again, and
`--frozen-lockfile` fails.

With no `jpm.lock` (and no other manager's lockfile to bring over), `jpm install` keeps the
versions a `node_modules` jpm installed already has, wherever the ranges in package.json allow
them, and resolves the rest; then it writes `jpm.lock`. For a fresh resolve, delete `jpm.lock`
and run `jpm lock`, which does not read `node_modules`, or delete `node_modules` too.
