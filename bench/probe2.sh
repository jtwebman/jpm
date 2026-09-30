#!/bin/bash
# Throwaway: nuxt warm installs of jpm, aube and bun, alone and right after another process
# wrote 300 MB (as the bench's previous runner does), and what aube and bun do on disk.
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe2; mkdir -p "$W"
cargo build --release 2>&1 | tail -1
JPM=$PWD/target/release/jpm; FIX=$PWD/bench/fixtures
tag=v2.6.0; mkdir -p $W/aube; curl -fsSL "https://github.com/aubepkg/aube/releases/download/$tag/aube-$tag-x86_64-unknown-linux-gnu.tar.gz" | tar -xz -C $W/aube
AUBE=$(find $W/aube -type f -name aube | head -1); BUN=$(command -v bun)
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
declare -A BIN=([jpm]=$JPM [aube]=$AUBE [bun]=$BUN)
envs() { echo "HOME=$W/$1/home XDG_CACHE_HOME=$W/$1/home/.cache XDG_DATA_HOME=$W/$1/home/.local/share XDG_STATE_HOME=$W/$1/home/.local/state JPM_STORE=$W/$1/home/store BUN_INSTALL_CACHE_DIR=$W/$1/home/bun-cache DO_NOT_TRACK=1"; }
for r in jpm aube bun; do
  mkdir -p $W/$r/proj $W/$r/home; cp $FIX/nuxt/package.json $W/$r/proj/
  (cd $W/$r/proj && env $(envs $r) ${BIN[$r]} install --ignore-scripts >$OUT/setup-$r.txt 2>&1)
  echo "$r: files $(find $W/$r/proj/node_modules -type f | wc -l) links $(find $W/$r/proj/node_modules -type l | wc -l) dirs $(find $W/$r/proj/node_modules -type d | wc -l); nuxt -> $(readlink $W/$r/proj/node_modules/nuxt)" | tee -a $OUT/layout.txt
  ls -la $W/$r/proj/node_modules | head -8 >> $OUT/layout.txt
  wipe $W/$r/proj/node_modules
  (cd $W/$r/proj && env $(envs $r) strace -f -c -o $OUT/strace-c-$r.txt ${BIN[$r]} install --ignore-scripts >/dev/null 2>&1)
done
run() { # run <runner> <label>
  local r=$1 l=$2
  wipe $W/$r/proj/node_modules
  cd $W/$r/proj
  t0=$(date +%s%N)
  env $(envs $r) /usr/bin/time -f '%U %S %M' -o $W/time ${BIN[$r]} install --ignore-scripts >$W/log 2>&1 || { echo "FAILED $r"; tail -3 $W/log; }
  t1=$(date +%s%N); cd - >/dev/null
  read u s m < <(tail -1 $W/time)
  awk -v w=$(( (t1-t0)/1000000 )) -v u=$u -v s=$s -v m=$m -v k="$r $l" 'BEGIN{printf "%s wall %d cpu %d\n", k, w, (u+s)*1000}'
}
for i in 1 2 3 4 5 6 7; do
  for r in jpm aube bun; do
    run $r alone
    dd if=/dev/urandom of=$W/junk bs=1M count=300 status=none; rm -f $W/junk
    run $r after-300MB
    dd if=/dev/urandom of=$W/junk bs=1M count=300 status=none; rm -f $W/junk; sync
    run $r after-300MB-sync
  done
done | tee $OUT/warm.txt
awk '{k=$1" "$2; w[k]=w[k]" "$4; c[k]=c[k]" "$6} END{for(k in w) print k, "wall" w[k], "| cpu" c[k]}' $OUT/warm.txt | sort
