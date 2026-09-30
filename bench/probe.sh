#!/bin/bash
# Throwaway: who calls malloc on nuxt from a lockfile (uprobe on glibc's malloc, dwarf stacks).
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe; mkdir -p "$W"
(CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=2 CARGO_TARGET_DIR=$PWD/target-sym cargo build --release 2>&1 | tail -1)
JPM=$PWD/target-sym/release/jpm; FIX=$PWD/bench/fixtures
LIBC=$(ldd $JPM | awk '/libc.so.6/{print $3}')
sudo perf probe -x $LIBC malloc 2>&1 | tail -2
sudo perf probe -x $LIBC realloc 2>&1 | tail -2
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
f=nuxt
d=$W/$f; wipe $d; mkdir -p $d/proj $d/home; cp $FIX/$f/package.json $d/proj/
(cd $d/proj && HOME=$d/home JPM_STORE=$d/home/store $JPM install --ignore-scripts >/dev/null 2>&1)
wipe $d/proj/node_modules; wipe $d/home; mkdir -p $d/home
(cd $d/proj && sudo -E env HOME=$d/home JPM_STORE=$d/home/store perf record -e probe_libc:malloc -e probe_libc:realloc -c 50 --call-graph dwarf,8192 -o $OUT/m.data $JPM install --ignore-scripts >/dev/null 2>&1)
sudo chmod a+r $OUT/m.data
perf script -i $OUT/m.data -F ip,sym > $OUT/script.txt 2>/dev/null
cat > $OUT/stacks.awk <<'AWK'
BEGIN { RS = ""; FS = "\n" }
{
  k = ""; c = 0
  for (i = 1; i <= NF && c < 7; i++) {
    s = $i; sub(/^[ \t]*[0-9a-f]+ /, "", s)
    if (s ~ /^(malloc|realloc|__rdl|__rust_|alloc::|<alloc::|core::fmt|<core::fmt|<&str as core::fmt|<alloc::string::String as core::fmt|<std::path::Path>::_join|<std::path::PathBuf>::_push|<std::path::Path>::join|<std::path::Path>::_with)/) continue
    k = k " <- " s; c++
  }
  print k
}
AWK
awk -f $OUT/stacks.awk $OUT/script.txt | sort | uniq -c | sort -rn | head -150 > $OUT/malloc-stacks.txt
awk -f $OUT/stacks.awk $OUT/script.txt | awk -F' <- ' '{print $2}' | sort | uniq -c | sort -rn | head -60 > $OUT/malloc-first.txt
wc -l $OUT/script.txt
rm -f $OUT/m.data $OUT/script.txt
