# Use

```sh
jpm install                          # install the project's dependencies
jpm                                  # the same: no command is install
jpm add vue@^3 nanoid                # save to package.json, then install
jpm add --dev vitest                 # save as a dev dependency
jpm remove nanoid                    # remove from package.json, then install
jpm run build                        # run a package.json script
jpm build                            # the same, when build is not a jpm command
jpm run --workspaces build           # build every workspace, dependencies first
jpm exec cowsay hello                # run a package's bin, installing it if needed
jpm dedupe                           # reduce duplicate versions already locked
jpm install --production             # skip packages only dev dependencies use
jpm ci                               # remove node_modules, then install the lockfile as it is
jpm install --frozen-lockfile        # fail if the lockfile is missing or stale, keep node_modules
jpm install --offline                # no network: install from jpm.lock and the store
jpm lock                             # write jpm.lock without installing
jpm resolve vue@^3                   # show which version a spec picks
jpm fetch --lock                     # fill the store from jpm.lock, no linking
jpm prune                            # remove entries and store content no project uses
jpm patch lodash                     # copy a package to edit; patch-commit saves the patch
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every option.

`jpm ci` (or `jpm clean-install`) is `jpm install --frozen-lockfile` after removing the
project's `node_modules`, and each workspace's, as `npm ci` does. Nothing in a `node_modules`
it finds is trusted, even one jpm made: a checkout that commits `node_modules` can change a
package's files there, which an install reusing the tree would keep. The old `node_modules` is
renamed to `node_modules.jpm-old-<id>` and deleted before linking starts; if jpm is stopped
before that finishes, the next install deletes what is left. Links in it, to the store or out
of the project, are removed as links, never followed, and the store's files are not changed.
Anything else under `node_modules` goes too, such as an unfinished `jpm patch` copy in
`node_modules/.jpm_patches`. `--frozen-lockfile` keeps the tree, as it does in pnpm and yarn.

An install that takes longer than a tenth of a second shows one line of progress on stderr
(packages resolved, fetched and linked), and takes it off before the summary. Windows
Terminal, iTerm2 3.6 and later, Ghostty, WezTerm, ConEmu and VS Code also show it on their tab
or taskbar (OSC 9;4). There is no progress when stderr is not a terminal, when `CI` is set,
or with `--silent`, `--json` or `--no-progress`.
