#!/bin/bash
# Throwaway: syscalls (counts, failures) and a CPU profile of jpm installs from a lockfile:
# nuxt (project layout) and nitro (global store), warm (store kept) and ci (empty store).
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe; mkdir -p "$W"
source bench/probe.env
git worktree add --detach ../src "$REF" >/dev/null 2>&1
(cd ../src && CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_TARGET_DIR=$PWD/../target-sym cargo build --release 2>&1 | tail -1)
JPM=$(cd ..; pwd)/target-sym/release/jpm; FIX=$PWD/bench/fixtures
echo "probing $REF $(git rev-parse --short $REF)"
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
    setup $f $p; runj $f /usr/bin/time -f "$k wall %e user %U sys %S rss %M" -a -o $OUT/times.txt
    setup $f $p; runj $f strace -f -c -o $OUT/strace-c-$k.txt
    setup $f $p; runj $f strace -f -qq -e trace=mkdir,mkdirat,link,linkat,symlink,symlinkat,rename,renameat2,openat,unlinkat,chmod,fchmodat,statx,newfstatat,readlinkat -o $W/tr.txt
    # Calls by name and result.
    sed -nE 's/^[0-9]+ +([a-z0-9_]+)\(.*\) += (-1 [A-Z]+|[0-9x]+).*/\1 \2/p' $W/tr.txt | sed -E 's/ [0-9x]+$/ ok/' | sort | uniq -c | sort -rn > $OUT/calls-$k.txt
    # Failed mkdirs and links: the paths, with the temp names and hashes blurred.
    grep -E '^[0-9]+ +(mkdir|mkdirat|linkat|symlink|symlinkat)\(.*= -1' $W/tr.txt | sed -E 's/^[0-9]+ +//; s/\.tmp-[0-9a-zA-Z_-]+/.tmp-X/g; s/@[0-9][^/]*-[A-Za-z0-9_-]{22}/@V-H/g' | head -300 > $OUT/failed-$k.txt
    grep -E '^[0-9]+ +(mkdir|mkdirat)\(.*= -1' $W/tr.txt | sed -E 's/^[0-9]+ +//; s/"[^"]*\/([^/"]+)"/"...\/\1"/' | sed -E 's/\(.*\) += -1 ([A-Z]+).*/ \1/' | sort | uniq -c | sort -rn | head -40 > $OUT/failed-mkdir-kinds-$k.txt
    setup $f $p
    (cd $W/$f/proj && sudo -E env HOME=$W/$f/home JPM_STORE=$W/$f/home/store perf record -F 2999 --call-graph dwarf,16384 -o $W/p.data $JPM install --ignore-scripts >/dev/null 2>&1)
    sudo chmod a+r $W/p.data
    perf report -i $W/p.data --children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -200 > $OUT/incl-$k.txt
    perf report -i $W/p.data --no-children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -120 > $OUT/self-$k.txt
    perf report -i $W/p.data --no-children --sort dso --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -20 > $OUT/dso-$k.txt
    perf report -i $W/p.data --children --sort symbol --stdio -g caller,0.5,callee,function,percent --percent-limit 3 --symbol-filter=jpm:: 2>/dev/null | head -1500 > $OUT/callers-$k.txt
    rm -f $W/p.data
  done
done
cat $OUT/times.txt
