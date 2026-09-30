#!/bin/bash
# Throwaway (never merged): interleaved A/B installs of two jpm builds on one runner.
# ab.sh <binA> <binB> <n> <phases> <fixtures>
set -u
A=$1 B=$2 N=$3 PH=$4 FX=$5
W=$RUNNER_TEMP/ab; mkdir -p $W
FIX=$PWD/bench/fixtures
wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }
run() { # run <bin> <fixture> <phase> <tag>
  bin=$1 f=$2 p=$3 tag=$4
  d=$W/$f; wipe $d/proj/node_modules; wipe $d/home; mkdir -p $d/home $d/proj
  cp $FIX/$f/package.json $d/proj/
  if [ $p = cold ]; then rm -f $d/proj/jpm.lock; else cp $W/$f.lock $d/proj/jpm.lock; fi
  cd $d/proj
  t0=$(date +%s%N)
  env HOME=$d/home XDG_CACHE_HOME=$d/home/.cache JPM_STORE=$d/home/store /usr/bin/time -f '%U %S %M' -o $W/time $bin install --ignore-scripts >$W/log 2>&1
  st=$?; t1=$(date +%s%N); cd - >/dev/null
  read u s m < <(tail -1 $W/time)
  [ $st = 0 ] || { echo "FAILED $tag $f $p"; tail -3 $W/log; }
  awk -v w=$(( (t1-t0)/1000000 )) -v u=$u -v s=$s -v m=$m -v k="$f $p $tag" 'BEGIN{printf "%s %d %d %d %d %d\n", k, w, (u+s)*1000, u*1000, s*1000, m}'
}
for f in ${FX//,/ }; do
  # One lockfile for both, made by A.
  wipe $W/$f; mkdir -p $W/$f/proj $W/$f/home; cp $FIX/$f/package.json $W/$f/proj/
  (cd $W/$f/proj && HOME=$W/$f/home JPM_STORE=$W/$f/home/store $A install --ignore-scripts >/dev/null 2>&1); cp $W/$f/proj/jpm.lock $W/$f.lock
  for p in ${PH//,/ }; do
    for i in $(seq 1 $N); do
      if [ $((i % 2)) = 0 ]; then run $A $f $p A; run $B $f $p B; else run $B $f $p B; run $A $f $p A; fi
    done
  done
done > $W/rows
cat $W/rows
echo
echo "| fixture | phase | build | wall ms (median, range) | CPU ms | user ms | sys ms | peak RSS KB |"
echo "|---|---|---|---|---|---|---|---|"
awk '
function med(s,   a,n,i,j,t){ n=split(s,a," "); for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(a[j]+0<a[i]+0){t=a[i];a[i]=a[j];a[j]=t}; return (n%2)?a[(n+1)/2]:int((a[n/2]+a[n/2+1])/2) }
function rng(s,   a,n,i,lo,hi){ n=split(s,a," "); lo=a[1];hi=a[1]; for(i=1;i<=n;i++){if(a[i]+0<lo+0)lo=a[i]; if(a[i]+0>hi+0)hi=a[i]}; return lo "-" hi }
$1=="FAILED" {next}
NF==8 { k=$1" | "$2" | "$3; if(!(k in W)) order[++n]=k; W[k]=W[k]" "$4; C[k]=C[k]" "$5; U[k]=U[k]" "$6; S[k]=S[k]" "$7; R[k]=R[k]" "$8 }
END { for(i=1;i<=n;i++){k=order[i]; printf "| %s | %d (%s) | %d (%s) | %d (%s) | %d (%s) | %d |\n", k, med(W[k]), rng(W[k]), med(C[k]), rng(C[k]), med(U[k]), rng(U[k]), med(S[k]), rng(S[k]), med(R[k]) } }' $W/rows | sort
