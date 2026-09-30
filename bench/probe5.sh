#!/bin/bash
# Throwaway: 30 nuxt ci installs with JPM_TRACE, to catch the multi-second outliers.
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/p5; mkdir -p "$W"
cargo build --release 2>&1 | tail -1
JPM=$PWD/target/release/jpm; FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
mkdir -p $W/proj $W/home; cp $FIX/nuxt/package.json $W/proj/
(cd $W/proj && HOME=$W/home JPM_STORE=$W/home/store $JPM install --ignore-scripts >/dev/null 2>&1)
for i in $(seq 1 30); do
  wipe $W/proj/node_modules; wipe $W/home; mkdir -p $W/home
  (cd $W/proj && env HOME=$W/home JPM_STORE=$W/home/store JPM_TRACE=1 /usr/bin/time -f "run $i wall %e cpu-user %U sys %S" -o $W/time $JPM install --ignore-scripts >$W/log 2>&1)
  cat $W/time
  cp $W/log $OUT/trace-$i.txt
  grep -E " (gap|conn) " $W/log | awk '$4=="gap"{print "   gap", ($6-$5)/1000, "ms", $7, $8, $9} $4=="conn"{c=($6-$5)/1000; h=($7-$6)/1000; if (c>100||h>100) print "   conn tcp+tls", c, "head", h, $8}'
  grep " dl " $W/log | awk '{h=($6-$5)/1000; if (h>300) print "   slow head", h, "ms", $8}'
done
