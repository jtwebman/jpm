#!/bin/bash
# Throwaway: who calls malloc on nuxt and next from a lockfile (uprobe on glibc's malloc).
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe; mkdir -p "$W"
(CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_TARGET_DIR=$PWD/target-sym cargo build --release 2>&1 | tail -1)
JPM=$PWD/target-sym/release/jpm; FIX=$PWD/bench/fixtures
LIBC=$(ldd $JPM | awk '/libc.so.6/{print $3}')
sudo perf probe -x $LIBC malloc 2>&1 | tail -2
sudo perf probe -x $LIBC realloc 2>&1 | tail -2
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
for f in nuxt; do
  d=$W/$f; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
  (cd $d/proj && HOME=$d/home JPM_STORE=$d/home/store $JPM install --ignore-scripts >/dev/null 2>&1)
  wipe $d/proj/node_modules; wipe $d/home; mkdir -p $d/home
  (cd $d/proj && sudo -E env HOME=$d/home JPM_STORE=$d/home/store perf record -e probe_libc:malloc -e probe_libc:realloc -c 50 --call-graph dwarf,8192 -o $OUT/m-$f.data $JPM install --ignore-scripts >/dev/null 2>&1)
  sudo chmod a+r $OUT/m-$f.data
  perf report -i $OUT/m-$f.data --children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | grep -v "\[k\]" | head -150 > $OUT/malloc-incl-$f.txt
  perf report -i $OUT/m-$f.data --no-children --sort symbol --stdio -g caller,0.5,callee,function,percent --percent-limit 2 2>/dev/null | head -600 > $OUT/malloc-callers-$f.txt
  perf report -i $OUT/m-$f.data --stdio --sort comm 2>/dev/null | grep -E '^ +[0-9]' | head > $OUT/malloc-comm-$f.txt
  perf script -i $OUT/m-$f.data 2>/dev/null | awk '/probe_libc:(malloc|realloc)/{getline a; getline b; getline c; getline d; print b" <- "c" <- "d}' | sed 's/^[ \t]*[0-9a-f]* //; s/<- *[0-9a-f]* /<- /g' | sort | uniq -c | sort -rn | head -80 > $OUT/malloc-stacks-$f.txt
  rm -f $OUT/m-$f.data
done
