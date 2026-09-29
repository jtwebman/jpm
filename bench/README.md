# Benchmarks

`bench.sh` times installs of the projects in `fixtures/` with jpm and other package
managers, and prints the medians as Markdown tables.

Each fixture is installed in three phases:

- **cold**: no cache, no lockfile, no `node_modules`
- **warm**: cache and lockfile kept, `node_modules` deleted
- **repeat**: nothing changed

Every phase runs `-n` times. Each round runs every manager once before the next round
starts, so a slow minute on the network is spread over all of them.

Each manager gets its own home, caches and store under the work dir, a fresh copy of the
fixture, lifecycle scripts off, and no telemetry or update checks. jpm is built with
`cargo build --release` first, so the working tree is what is measured.

## Requirements

A POSIX shell, coreutils, GNU time at `/usr/bin/time` (`apt install time` on Debian and
Ubuntu), and the package managers. Known runners: jpm, npm, pnpm, bun, yarn (berry), deno,
aube and upm. Those not on `PATH` are skipped.

## Options

```
-r, --runners a,b     package managers (default: all that are found)
-f, --fixtures a,b    fixtures (default: nitro,nuxt,next; tiny also exists)
-n, --samples N       runs per phase (default: 3)
    --phases a,b      cold, warm, repeat (default: all three)
    --bin name=path   use this binary for a runner (repeatable)
    --min-free GB     stop when the work dir has less free space (default: 3)
    --keep            keep the projects and caches afterwards
    --dry-run         print what would run
    --report FILE     print the tables for a results file
```

The work dir is `$BENCH_WORK`, by default `~/.cache/jpm-bench`. Logs of every run are kept
in its `logs/`.

## Results

Every run is one line in `results/<date>-<time>.tsv`: runner, version, fixture, phase,
sample, exit status, wall time (ms), user+system CPU time (ms) and peak RSS (KB). A failed
run is recorded and counted, and left out of the medians. The time taken by the timing
wrapper itself is measured at the start and taken off every wall time.

## Example

```sh
bench/bench.sh -r jpm,npm,pnpm,bun -f nuxt -n 5
bench/bench.sh --report bench/results/20260929-120000.tsv
```
