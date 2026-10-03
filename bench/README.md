# Benchmarks

`bench.sh` times installs of the projects in `fixtures/` with jpm and other package
managers, and prints the medians as Markdown tables.

Each fixture is installed in four phases:

- **cold**: no cache, no lockfile, no `node_modules`
- **warm**: cache and lockfile kept, `node_modules` deleted: CI with its cache restored
- **ci**: lockfile kept, no cache, no `node_modules`: CI with no cache
- **repeat**: nothing changed

Besides wall time, each install records the CPU time of every process it starts and its peak
memory: a CI runner has two to four cores, so CPU time is what an install costs there. After a
cold install, the bench also records the disk it took: `node_modules` and the manager's cache
or store together, a hardlinked file counted once, and the cache alone, which is what CI saves
and restores between runs.

Every phase runs `-n` times. Each round runs every manager once before the next round
starts, so a slow minute on the network is spread over all of them.

Each manager gets its own home, caches and store under the work dir, a fresh copy of the
fixture, lifecycle scripts off, and no telemetry or update checks. jpm is built with
`cargo build --release` first, so the working tree is what is measured.

## Managers

Every run measures the latest release of each manager. Before timing, the jpm just built
installs the newest npm, pnpm, yarn (berry), upm, bun and deno from the npm registry into
the work dir's `tools/`. jpm's minimum release age applies, so a version published less
than a day ago is not used yet. aube comes from its newest GitHub release that is at least a day old. pnpm, bun and deno run as their native
binaries, not through the packages' Node launchers.

`--installed` measures the managers on `PATH` instead, and `--bin name=path` names one
binary.

## Requirements

Linux, a POSIX shell, coreutils, curl and tar (for aube), GNU time at `/usr/bin/time`
(`apt install time` on Debian and Ubuntu), cargo, and Node.js on `PATH` for npm, yarn and
upm.

On macOS run `bench/bench-mac.sh`, which takes the same options. It needs nothing beyond the
system's own tools: BSD `/usr/bin/time -l` for CPU time and peak RSS, and Perl's clock for wall
time. `du` counts an APFS clone (jpm, pnpm and bun copy files that way on a Mac) at its full size,
so the disk column there overstates what cloned files take. Spotlight and any antivirus scan the
files an install writes; say whether real-time protection was on when quoting results.

On Windows it runs under Git Bash, which brings the shell, coreutils, curl and unzip.
GNU time has no Windows build, so the script compiles `measure.cs` with the C# compiler
that ships with Windows (.NET Framework 4) and times with that. It runs each install in a
job object, so every process the manager starts is counted. Windows keeps no peak RSS for
a tree of processes, so the memory column there is the tree's peak committed memory. That
is a different measure from RSS, so compare it only with other Windows runs. Keep
`BENCH_WORK` on a short path such as `C:\bench`, because npm's nested trees can exceed
the 260-character path limit. Windows Defender scans every file an install writes, and
this is most of a cold install's cost. Say whether real-time protection was on when
quoting results.

## Options

```
-r, --runners a,b     package managers (default: all)
-f, --fixtures a,b    fixtures (default: nitro,nuxt,next; tiny and cline also exist)
-n, --samples N       runs per phase (default: 3)
    --phases a,b      cold, warm, repeat (default: all three)
    --bin name=path   use this binary for a runner (repeatable)
    --installed       use the managers on PATH instead of fetching the latest
    --hoisted         npm's layout for all: node-linker=hoisted for jpm and pnpm,
                      --linker hoisted for bun (runners: jpm,npm,pnpm,bun,yarn)
    --min-free GB     stop when the work dir has less free space (default: 3)
    --keep            keep the projects and caches afterwards
    --dry-run         print what would run
    --report FILE     print the tables for a results file
```

The work dir is `$BENCH_WORK`, by default `~/.cache/jpm-bench`. Logs of every run are kept
in its `logs/`.

`cline` is cline's monorepo, its 25 package.json files alone (2,400 packages, about 250,000
files): what a big workspace costs to lay out. Its `workspace:` specs are `*`, so npm, yarn and
bun link the workspaces too, and its overrides are given to pnpm and yarn as well. npm cannot
install it: its peers conflict, as they do in the project, which bun installs.

## Results

Every run is one line in `results/<date>-<time>.tsv`: runner, version, fixture, phase,
sample, exit status, wall time (ms), user+system CPU time (ms), peak RSS (KB), and after a
cold install the disk used and the cache's size (KB). A failed
run is recorded and counted, and left out of the medians. The time taken by the timing
wrapper itself is measured at the start and taken off every wall time.

## On GitHub's runners

The `bench` workflow runs this on `ubuntu-latest`, the runner most CI pays for: start it from
the Actions tab (or `gh workflow run bench.yml`), optionally naming runners, fixtures and
samples. The tables go to the run's summary, and the results file is kept as an artifact.

## Example

```sh
bench/bench.sh -r jpm,npm,pnpm,bun -f nuxt -n 5
bench/bench.sh --report bench/results/20260929-120000.tsv
```
