# Install scripts

A dependency's install scripts (`preinstall`, `install`, `postinstall`, or `node-gyp rebuild`
for a `binding.gyp`) are how most npm malware runs, so jpm runs them only when you ask:

```sh
jpm install                 # "install scripts not run for esbuild@0.21.5: `jpm approve <name>` runs them"
jpm approve                 # list what waits
jpm approve esbuild         # trust it, approve this version, install
```

`jpm approve` adds the name to `trustedDependencies` in package.json (bun's field; pnpm's
`onlyBuiltDependencies`, and `pnpm-workspace.yaml`'s `onlyBuiltDependencies` and `allowBuilds`,
are read too, where `name: false` takes a name out and silences it) and marks the locked version `build` in jpm.lock. Both
must agree: a new version of a trusted package does not run its scripts until it is approved
again. Approved packages are copies, not links into the store, kept in the project; their
scripts run once, dependencies first, with output in `.build.log` beside the package and
shown when a script fails. npm, yarn and bun tokens are taken out of their environment, but
that is hygiene, not a sandbox: an approved script runs as you and can read your files. Only
the package the registry serves under the approved name and version runs its scripts, so an
alias or a lockfile edit pointing elsewhere does not.

The project's own lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare` and
their pre/post) run on installs that change the tree, after it is linked. `--ignore-scripts`
or `ignore-scripts=true` in .npmrc turns every script off.
