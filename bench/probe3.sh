#!/bin/bash
# Throwaway: jpm nuxt warm installs with 1, 2, 4, 8 and 16 link threads, and where the kernel
# spins (call graphs of the lock spinning).
set -u
OUT=${OUT:-$PWD/probe-out}; mkdir -p "$OUT"
W=$RUNNER_TEMP/probe3; mkdir -p "$W"
CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release 2>&1 | tail -1
JPM=$PWD/target/release/jpm; FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
E="HOME=$W/home XDG_CACHE_HOME=$W/home/.cache JPM_STORE=$W/home/store"
mkdir -p $W/proj $W/home; cp $FIX/nuxt/package.json $W/proj/
(cd $W/proj && env $E $JPM install --ignore-scripts >/dev/null 2>&1)
run() { # run <threads> [wrapper]
  local t=$1; shift
  wipe $W/proj/node_modules; sync
  cd $W/proj
  t0=$(date +%s%N)
  env $E JPM_LINK_THREADS=$t "$@" /usr/bin/time -f '%U %S %M' -o $W/time $JPM install --ignore-scripts >$W/log 2>&1 || tail -3 $W/log
  t1=$(date +%s%N); cd - >/dev/null
  read u s m < <(tail -1 $W/time)
  awk -v w=$(( (t1-t0)/1000000 )) -v u=$u -v s=$s -v k="threads $t" 'BEGIN{printf "%s wall %d cpu %d user %d sys %d\n", k, w, (u+s)*1000, u*1000, s*1000}'
}
for i in 1 2 3 4 5 6 7; do for t in 1 2 4 8 16; do run $t; done; done | tee $OUT/threads.txt
awk '{k=$1" "$2; w[k]=w[k]" "$4; c[k]=c[k]" "$6; s[k]=s[k]" "$10} END{for(k in w) print k, "wall" w[k], "| cpu" c[k], "| sys" s[k]}' $OUT/threads.txt | sort -k2 -n
for t in 1 8; do
  wipe $W/proj/node_modules; sync
  (cd $W/proj && sudo -E env $E JPM_LINK_THREADS=$t perf record -F 4999 -g -o $W/p.data $JPM install --ignore-scripts >/dev/null 2>&1)
  sudo chmod a+r $W/p.data
  perf report -i $W/p.data --no-children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -60 > $OUT/self-t$t.txt
  perf report -i $W/p.data --no-children --sort symbol --stdio -G -S rwsem_spin_on_owner,osq_lock,rwsem_down_write_slowpath,native_queued_spin_lock_slowpath,__pv_queued_spin_lock_slowpath,_raw_spin_unlock_irqrestore,ext4_match 2>/dev/null | head -400 > $OUT/spin-t$t.txt
  perf report -i $W/p.data --children --sort symbol --stdio -g none 2>/dev/null | grep -E '^ +[0-9]' | head -120 > $OUT/incl-t$t.txt
  sudo rm -f $W/p.data
done
