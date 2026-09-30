#!/bin/bash
# Throwaway: traces of the resolver walk (JPM_TRACE: requests and jobs with times) on cold
# installs and locks, FIFO and LIFO job order, and CPU profiles of a nuxt cold install and lock.
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe; mkdir -p "$W"
(CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release 2>&1 | tail -1)
JPM=$PWD/target/release/jpm; FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
run() { # run <fixture> <cmd> <tag> [VAR=value...]
  local f=$1 cmd=$2 tag=$3; shift 3
  local d=$W/$f; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  (cd $d/proj && env HOME=$d/home JPM_STORE=$d/home/store JPM_TRACE=1 JPM_PHASES=1 "$@" /usr/bin/time -f "time %e %U %S %M" $JPM $cmd --ignore-scripts >/dev/null 2>$OUT/tr-$f-$cmd-$tag.txt)
  echo "$(grep -E '^time|^phase' $OUT/tr-$f-$cmd-$tag.txt | tr '\n' ' ') $f $cmd $tag"
}
for f in nuxt next nitro; do run $f lock warmup >/dev/null; done
for c in 32 64 32 64; do
  d=$W/nuxt; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/nuxt/package.json $d/proj/
  (cd $d/proj && env HOME=$d/home JPM_STORE=$d/home/store JPM_CONCURRENCY=$c perf stat -e task-clock,context-switches,cpu-migrations,page-faults,instructions,cycles -o $OUT/stat-$c.txt -a --append $JPM lock >/dev/null 2>&1)
done
cat $OUT/stat-*.txt
prof() { # prof <fixture> <cmd> <tag> [VAR=value]
  local f=$1 cmd=$2 tag=$3 d=$W/$1; shift 3; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  (cd $d/proj && sudo -E env HOME=$d/home JPM_STORE=$d/home/store "$@" perf record -F 4999 -g -o $W/p.data $JPM $cmd --ignore-scripts >/dev/null 2>&1)
  sudo chmod a+r $W/p.data; sudo chown -R $(id -u):$(id -g) $W
  perf report -i $W/p.data --no-children --sort dso,symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -150 > $OUT/self-$f-$cmd-$tag.txt
  perf report -i $W/p.data --no-children --sort comm --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -20 > $OUT/comm-$f-$cmd-$tag.txt
  rm -f $W/p.data
}
prof nuxt lock c32 JPM_CONCURRENCY=32
prof nuxt lock c64 JPM_CONCURRENCY=64
prof nuxt lock c32b JPM_CONCURRENCY=32
prof nuxt lock c64b JPM_CONCURRENCY=64
