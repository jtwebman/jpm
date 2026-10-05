# The global store

jpm builds each package's entry once, in the store (`~/.jpm/store/v1/links`), and every project
on the machine links to it. A project's `node_modules/<name>` is a link straight into the store.

## Why

- **One copy.** Ten projects on the same `react@19.2.0` share one entry, its files and its links
  to its own dependencies. Nothing is copied or linked again per project.
- **Fast installs.** A warm install (the store has the packages, `node_modules` is gone) only
  makes the project's top-level links: 206 ms for `nuxt` (591 packages) on a CI runner, and a
  repeat install takes 2 ms. See [benchmarks](benchmarks.md).
- **Less disk.** The store holds each file once, however many projects use it.

## What it cannot do

A package imports what it declares. Some packages import something they do not declare, and
work under npm and yarn only because their flat `node_modules` happens to put it within reach.
jpm keeps every such package in a hidden hoist, `node_modules/.jpm/node_modules`, which Node
reaches from the project: under the global store, `jpm run`, `jpm exec` and install scripts point
Node at it (`NODE_PATH` for `require`, a resolve hook for `import`).

A tool that resolves imports itself, from a package's real path, does not get that help. A
package in the global store really lives in the store, so walking up from it never reaches the
project, and an import the package never declared finds nothing. Bundlers do this (vite, webpack,
rollup, rolldown, esbuild, parcel, rspack, tsup, tsdown), and so does `tsc` when a package's
types import another package's types they do not declare. The error is a missing package that
is plainly installed:

```
Could not resolve "load-tsconfig" from ".../store/v1/links/esbuild-fix-imports-plugin@1.0.22-…/…"
```

One such case jpm handles itself: a package's types importing its peer's types. tsc resolves
react-router's `import 'react'` from react-router's folder, where `react` is linked but the
project's `@types/react` is not, so the import loses its types (`NavLink` had no props). Under
the global store, a package that takes a peer gets the project's `@types/<peer>` linked beside
it, and an entry with one version of the types is never shared with one with another.

That is why `jpm install` warns when a project declares a bundler and the global store is on.
The package at fault is the one importing what it does not declare; the fix that always works
is to build entries in the project instead.

## Turning it off

Any one of:

```sh
echo "global-store=false" >> .npmrc      # this project, committed
JPM_GLOBAL_STORE=0 jpm install           # one shell
jpm install --no-global-store            # one install
```

Entries are then built in the project's own `node_modules/.jpm`, where everything walks up to
the project. It is already off for projects that depend on `next` or `nuxt`, inside
containers, and when the store cannot be written. `global-store=true` turns it back on. It is
always off with `node-linker=hoisted`, npm's layout, which a project that depends on `electron`
gets by default, unless pnpm made it ([configuration](configuration.md)).

## Do you still need a bundler?

Often not, for code that runs on a server or a command line. What a bundler was once needed for,
the runtimes now do themselves:

- **TypeScript.** Node 22.18 and 23.6 and later run `.ts` files directly, stripping the types
  (`node app.ts`; `--experimental-transform-types` for enums and namespaces). Bun and Deno have
  always run TypeScript. Type-check with `tsc --noEmit` and run the sources as they are.
- **Modules.** ES modules, `import.meta.dirname`, top-level `await` and JSON imports work in
  Node without a build step.
- **The rest.** `node --watch` reloads, `node --test` runs tests, `node --env-file=.env` reads
  an env file.

A browser app still wants a bundler for now. For a library, publishing what `tsc` emits, or the
sources themselves for runtimes that read TypeScript, is often enough. Without a bundler there
is nothing that resolves from the store, and the global store has nothing to warn about.
