#!/bin/bash
# Throwaway: timelines (JPM_TRACE), sched stats and syscall wall times of jpm installs from a
# lockfile on ubuntu-latest, warm (store kept, node_modules wiped just before) and ci.
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe; mkdir -p "$W"
source bench/probe.env
(CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_TARGET_DIR=$PWD/../target-sym cargo build --release 2>&1 | tail -1)
JPM=$(cd ..; pwd)/target-sym/release/jpm; FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
setup() { # setup <fixture> <phase>
  wipe $W/$1/proj/node_modules
  if [ $2 = ci ]; then wipe $W/$1/home; mkdir -p $W/$1/home; fi
}
runj() { # runj <fixture> <wrapper...>
  local f=$1; shift
  (cd $W/$f/proj && env HOME=$W/$f/home JPM_STORE=$W/$f/home/store "$@" $JPM install --ignore-scripts >$W/log 2>&1) || tail -3 $W/log
}
for f in ${FIXTURES//,/ }; do
  d=$W/$f; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  runj $f
  for p in ${PHASES//,/ }; do
    k=$f-$p
    for i in $(seq 1 $N); do
      setup $f $p; runj $f env JPM_TRACE=1 $EXTRA /usr/bin/time -f "$k-$i wall %e user %U sys %S rss %M" -a -o $OUT/times.txt
      cp $W/log $OUT/trace-$k-$i.txt
      { echo "== $k-$i"; tail -1 $OUT/times.txt; python3 bench/p5-ana.py $W/log 20000; } >> $OUT/ana-$k.txt
    done
    setup $f $p; runj $f strace -f -w -c -o $OUT/strace-wall-$k.txt
    setup $f $p; runj $f strace -f -c -o $OUT/strace-c-$k.txt
    setup $f $p
    (cd $W/$f/proj && sudo -E env HOME=$W/$f/home JPM_STORE=$W/$f/home/store perf sched record -g -o $W/s.data $JPM install --ignore-scripts >/dev/null 2>&1)
    sudo chmod a+r $W/s.data; sudo chown -R $(id -u):$(id -g) $W
    perf sched timehist -i $W/s.data -s 2>/dev/null | tail -80 > $OUT/sched-sum-$k.txt
    perf sched timehist -i $W/s.data -g --state 2>/dev/null | awk '$0 ~ /jpm/' | head -3000 > $OUT/sched-hist-$k.txt
    rm -f $W/s.data
    setup $f $p
    (cd $W/$f/proj && sudo -E env HOME=$W/$f/home JPM_STORE=$W/$f/home/store perf record -F 2999 -g -o $W/p.data $JPM install --ignore-scripts >/dev/null 2>&1)
    sudo chmod a+r $W/p.data; sudo chown -R $(id -u):$(id -g) $W
    perf report -i $W/p.data --no-children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -120 > $OUT/self-$k.txt
    perf report -i $W/p.data --children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -150 > $OUT/incl-$k.txt
    rm -f $W/p.data
  done
done
cat $OUT/times.txt
for f in $OUT/ana-*.txt; do echo "#### $f"; grep -E "^==|wall|l-entries|l-hoisted|phase (start|planned|filled|linked)|entries|entry time|exit|downloads" $f; done
