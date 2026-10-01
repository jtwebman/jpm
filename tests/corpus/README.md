# Real projects

`repos.txt` lists large public projects across every lockfile jpm reads (npm, pnpm, yarn 1 and
berry, bun) and some with none, gathered from the Windows and macOS hardening runs. `run.py`
installs each with jpm and reports what failed:

```sh
cargo build --release
python3 tests/corpus/run.py                # every project, 4 at a time
python3 tests/corpus/run.py vitejs/vite    # just these
python3 tests/corpus/run.py --run          # also run a build, typecheck, check or lint script
```

For each project it clones the repository (depth 1) into the work dir, `~/.cache/jpm-corpus` by
default (`--work`), or resets the clone already there, then runs:

1. `jpm install --ignore-scripts` (`--scripts` runs them)
2. the same again, which must say "up to date"
3. `--frozen-lockfile`
4. the install again after the ignored files (`node_modules`) are deleted
5. `--verify`

A line's `# with: <flags>` names the flags its installs need (`--no-block-exotic-subdeps` where a
published package takes a git or tarball dependency); the install is run with them.

Each run writes this platform's result for every project it ran to `results/<platform>.tsv`, and
`run.py --report` prints them all as one table (`docs/compatibility.md`): a project's lockfile,
whether it installs on each platform, the settings it needs, and what its scripts would need
changed for jpm, found by reading them: a script that starts pnpm, yarn or bun, and a preinstall
that lets only one manager in.

`--fixup` tests those changes: it makes them in each project's `package.json` files (a script's
pnpm, yarn or bun becomes jpm, `dlx` and `bunx` become jpx, a one-manager preinstall goes), then
installs with scripts and runs the build script. Its results go to `results/<platform>.fixup.tsv`,
the table's *after changes* column. jpm and jpx are on `PATH` for every script.

All projects share one store under the work dir. Logs of every step are kept in its `logs/`,
and the results in `results-<stamp>.json`. A line's `# expect: <reason>` marks a failure by
design (a published package taking a git or tarball dependency, which `block-exotic-subdeps`
refuses) or one any manager would have; the run reports those apart, and exits 1 only for the
others. It needs the network, git and Python 3.9 or later, and takes about an hour: it is not
part of `cargo test`.
