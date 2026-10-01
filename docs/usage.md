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
jpm ci                               # fail if the lockfile is missing or stale
jpm install --offline                # no network: install from jpm.lock and the store
jpm lock                             # write jpm.lock without installing
jpm resolve vue@^3                   # show which version a spec picks
jpm fetch --lock                     # fill the store from jpm.lock, no linking
jpm prune                            # remove entries and store content no project uses
jpm patch lodash                     # copy a package to edit; patch-commit saves the patch
```

Commit `jpm.lock` with `package.json`. `jpm --help` lists every option.

An install that takes longer than a tenth of a second shows one line of progress on stderr
(packages resolved, fetched and linked), and takes it off before the summary. Windows
Terminal, iTerm2 3.6 and later, Ghostty, WezTerm, ConEmu and VS Code also show it on their tab
or taskbar (OSC 9;4). There is no progress when stderr is not a terminal, when `CI` is set,
or with `--silent`, `--json` or `--no-progress`.
