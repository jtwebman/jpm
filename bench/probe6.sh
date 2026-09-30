#!/bin/bash
# Throwaway: where a warm install (lockfile and store kept, node_modules gone) waits, for nuxt
# and next: time's voluntary switches, strace's wall per syscall, perf sched's off-CPU time, and
# the same after a big dirty write, as the bench's other managers leave behind.
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/p6; mkdir -p "$W"
git worktree add --detach ../main origin/main >/dev/null 2>&1
(cd ../main && cargo build --release 2>&1 | tail -1)
JPM=$PWD/../main/target/release/jpm; FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
for f in nuxt next; do
  d=$W/$f; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  cd $d/proj
  e="env HOME=$d/home JPM_STORE=$d/home/store"
  $e $JPM install --ignore-scripts >/dev/null 2>&1
  echo "== $f warm, 7 runs: wall user sys voluntary involuntary"
  for i in $(seq 1 7); do wipe node_modules; $e /usr/bin/time -f "%e %U %S %w %c" $JPM install --ignore-scripts 2>&1 >/dev/null | tail -1; done
  echo "== $f warm after writing 2 GB not yet flushed"
  for i in 1 2 3; do wipe node_modules; dd if=/dev/zero of=$W/dirty bs=1M count=2048 2>/dev/null; $e /usr/bin/time -f "%e %U %S %w %c" $JPM install --ignore-scripts 2>&1 >/dev/null | tail -1; rm -f $W/dirty; sync; done
  echo "== $f warm after sync and dropping caches"
  for i in 1 2 3; do wipe node_modules; sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null; $e /usr/bin/time -f "%e %U %S %w %c" $JPM install --ignore-scripts 2>&1 >/dev/null | tail -1; done
  echo "== $f strace -f -c -w (wall per syscall)"
  wipe node_modules; $e strace -f -c -w -o $OUT/strace-$f.txt $JPM install --ignore-scripts >/dev/null 2>&1; head -25 $OUT/strace-$f.txt
  echo "== $f strace -f -c (CPU per syscall)"
  wipe node_modules; $e strace -f -c -o $OUT/strace-cpu-$f.txt $JPM install --ignore-scripts >/dev/null 2>&1; head -25 $OUT/strace-cpu-$f.txt
  echo "== $f threads and syscall counts"
  wipe node_modules; $e strace -f -e trace=clone,clone3 -o $OUT/clone-$f.txt $JPM install --ignore-scripts >/dev/null 2>&1; grep -c clone $OUT/clone-$f.txt
  echo "== $f perf sched timehist summary"
  wipe node_modules; $e perf sched record -o $W/sched.data -- $JPM install --ignore-scripts >/dev/null 2>&1
  perf sched timehist -i $W/sched.data -s 2>/dev/null | grep -A40 'Runtime summary' | head -60 > $OUT/sched-$f.txt; head -60 $OUT/sched-$f.txt
  perf sched timehist -i $W/sched.data 2>/dev/null | awk 'NR>3 && $2 ~ /jpm/ {w+=$4; s+=$5; r+=$6} END {print "sum wait", w, "sch delay", s, "run", r, "ms"}'
  echo "== $f off-CPU by wakeup reason (perf sched timehist -w top)"
  cd - >/dev/null
done
