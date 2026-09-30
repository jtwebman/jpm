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
for i in 1 2 3 4 5 6 7 8; do
  run nuxt install h0-$i
  run nuxt install h100-$i JPM_HEDGE_MS=100
  run next install h0-$i
  run next install h100-$i JPM_HEDGE_MS=100
done
prof() { # prof <fixture> <cmd>
  local f=$1 cmd=$2 d=$W/$1; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  (cd $d/proj && sudo -E env HOME=$d/home JPM_STORE=$d/home/store perf record -F 2999 --call-graph dwarf,16384 -o $W/p.data $JPM $cmd --ignore-scripts >/dev/null 2>&1)
  sudo chmod a+r $W/p.data; sudo chown -R $(id -u):$(id -g) $W
  perf report -i $W/p.data --children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -250 > $OUT/incl-$f-$cmd.txt
  perf report -i $W/p.data --no-children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -150 > $OUT/self-$f-$cmd.txt
  perf report -i $W/p.data --no-children --sort comm --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -20 > $OUT/comm-$f-$cmd.txt
  rm -f $W/p.data
}
