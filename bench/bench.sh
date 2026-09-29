#!/bin/sh
# Benchmark jpm against other package managers. See bench/README.md.
set -u

BENCH=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$BENCH")
ALL="jpm npm pnpm bun yarn deno aube upm"
RUNNERS=$ALL
FIXTURES="nitro nuxt next"
PHASES="cold warm repeat"
SAMPLES=3
MIN_FREE=3
KEEP=0
DRY=0
BINS=""
W=${BENCH_WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/jpm-bench}

usage() {
	cat <<EOF
usage: bench/bench.sh [options]
       bench/bench.sh --report results/<stamp>.tsv

  -r, --runners a,b     package managers (default: those found of $ALL)
  -f, --fixtures a,b    fixtures from bench/fixtures (default: nitro,nuxt,next)
  -n, --samples N       runs per phase (default: 3)
      --phases a,b      cold, warm, repeat (default: all three)
      --bin name=path   use this binary for a runner (repeatable)
      --min-free GB     stop when the work dir has less free space (default: 3)
      --keep            keep the projects and caches afterwards
      --dry-run         print what would run
      --report FILE     print the tables for a results file
  -h, --help            this text

Work dir: \$BENCH_WORK (now $W).
EOF
}

die() { echo "bench: $*" >&2; exit 1; }
list() { echo "$1" | tr ',' ' '; }

# Markdown tables of medians from a results file.
report() {
	awk -F '\t' '
	function ftime(ms) {
		if (ms < 1000) return sprintf("%d ms", ms)
		if (ms < 10000) return sprintf("%.2f s", ms / 1000)
		if (ms < 100000) return sprintf("%.1f s", ms / 1000)
		return sprintf("%.0f s", ms / 1000)
	}
	function fmem(kb) { return kb < 10240 ? sprintf("%.1f MB", kb / 1024) : sprintf("%.0f MB", kb / 1024) }
	function median(k, col,   n, i, j, a, t) {
		n = cnt[k]
		for (i = 1; i <= n; i++) a[i] = v[k, i, col] + 0
		for (i = 2; i <= n; i++) for (j = i; j > 1 && a[j - 1] > a[j]; j--) { t = a[j]; a[j] = a[j - 1]; a[j - 1] = t }
		return n % 2 ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
	}
	function row(r) { return "| " r (ver[r] == "" ? "" : " " ver[r]) " |" }
	# One table: runners down, the given columns across, lowest median in bold.
	function table(nc, col,   i, r, k, best, m, line) {
		line = "| manager |"; for (i = 1; i <= nc; i++) line = line " " C[i] " |"; print line
		line = "| --- |"; for (i = 1; i <= nc; i++) line = line " ---: |"; print line
		for (i = 1; i <= nc; i++) {
			best[i] = -1
			for (r = 1; r <= nr; r++) if (cnt[k = R[r] SUBSEP K[i]]) {
				med[k] = median(k, col)
				if (best[i] < 0 || med[k] < best[i]) best[i] = med[k]
			}
		}
		for (r = 1; r <= nr; r++) {
			line = row(R[r])
			for (i = 1; i <= nc; i++) {
				k = R[r] SUBSEP K[i]
				if (!cnt[k]) m = fail[k] ? "failed" : "-"
				else m = col == 1 ? ftime(med[k]) : fmem(med[k])
				if (cnt[k] && med[k] == best[i]) m = "**" m "**"
				line = line " " m " |"
			}
			print line
		}
		print ""
	}
	NR == 1 { next }
	{
		if (!($1 in sr)) { sr[$1]; R[++nr] = $1; ver[$1] = $2 }
		if (!($3 in sf)) { sf[$3]; F[++nf] = $3 }
		if (!($4 in sp)) { sp[$4]; P[++np] = $4 }
		runs++
		k = $1 SUBSEP $3 SUBSEP $4
		if ($6 != 0) { fail[k]++; nfail++; next }
		n = ++cnt[k]; v[k, n, 1] = $7; v[k, n, 2] = $9
	}
	END {
		d["cold"] = "no cache, no lockfile"
		d["warm"] = "cache and lockfile kept, `node_modules` deleted"
		d["repeat"] = "nothing changed"
		for (p = 1; p <= np; p++) {
			print "**" toupper(substr(P[p], 1, 1)) substr(P[p], 2) "** (" d[P[p]] "):\n"
			for (f = 1; f <= nf; f++) { C[f] = F[f]; K[f] = F[f] SUBSEP P[p] }
			table(nf, 1)
		}
		print "**Peak memory** (max RSS):\n"
		nc = 0
		for (f = 1; f <= nf; f++) for (p = 1; p <= np; p++) { C[++nc] = F[f] " " P[p]; K[nc] = F[f] SUBSEP P[p] }
		table(nc, 2)
		printf "%d runs, %d failed.\n", runs, nfail
		for (k in fail) { split(k, a, SUBSEP); printf "  failed: %s %s %s (%d)\n", a[1], a[2], a[3], fail[k] }
	}' "$1"
}

while [ $# -gt 0 ]; do
	case $1 in
	-r | --runners) RUNNERS=$(list "${2:?}"); shift ;;
	-f | --fixtures) FIXTURES=$(list "${2:?}"); shift ;;
	-n | --samples) SAMPLES=${2:?}; shift ;;
	--phases) PHASES=$(list "${2:?}"); shift ;;
	--bin) BINS="$BINS ${2:?}"; shift ;;
	--min-free) MIN_FREE=${2:?}; shift ;;
	--keep) KEEP=1 ;;
	--dry-run) DRY=1 ;;
	--report) report "${2:?}"; exit ;;
	-h | --help) usage; exit ;;
	*) usage >&2; exit 2 ;;
	esac
	shift
done

case $SAMPLES$MIN_FREE in *[!0-9]*) die "-n and --min-free take whole numbers" ;; esac
case $W in /*[!/]*) ;; *) die "BENCH_WORK must be an absolute path below /: $W" ;; esac
case $W in *[[:space:]]*) die "BENCH_WORK must not contain spaces: $W" ;; esac
for p in $PHASES; do case $p in cold | warm | repeat) ;; *) die "unknown phase: $p" ;; esac; done
for f in $FIXTURES; do case $f in */* | .*) die "bad fixture name: $f" ;; esac; [ -f "$BENCH/fixtures/$f/package.json" ] || die "no fixture: $f"; done
/usr/bin/time -f %M true >/dev/null 2>&1 ||
	die "needs GNU time at /usr/bin/time (Debian/Ubuntu: apt install time)"
case $(date +%N) in *N*) die "needs GNU date (date +%N)" ;; esac

# The explicit --bin for a runner, if any.
given() { for b in $BINS; do case $b in "$1"=*) echo "${b#*=}"; return ;; esac; done; }

# Arguments for an install.
args() {
	case $1 in
	jpm | aube | upm | bun) echo "install --ignore-scripts" ;;
	npm) echo "install --ignore-scripts --no-audit --no-fund" ;;
	pnpm) echo "install --ignore-scripts --no-frozen-lockfile" ;;
	yarn) echo "install" ;;
	deno) echo "install" ;;
	esac
}

# Environment for runner $1 with home $2: HOME and the XDG dirs point into the
# runner's own dir, so every cache and store lands there; the rest names each
# cache explicitly and turns scripts, telemetry and update checks off.
envs() {
	h=$2
	echo "HOME=$h XDG_CACHE_HOME=$h/.cache XDG_CONFIG_HOME=$h/.config XDG_DATA_HOME=$h/.local/share"
	echo "XDG_STATE_HOME=$h/.local/state COREPACK_HOME=$W/corepack DO_NOT_TRACK=1"
	echo "npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false"
	case $1 in
	jpm) echo "JPM_STORE=$h/store" ;;
	npm) echo "npm_config_cache=$h/npm-cache" ;;
	pnpm) echo "npm_config_store_dir=$h/pnpm-store npm_config_cache_dir=$h/pnpm-cache" \
		"pnpm_config_store_dir=$h/pnpm-store pnpm_config_cache_dir=$h/pnpm-cache" ;;
	bun) echo "BUN_INSTALL_CACHE_DIR=$h/bun-cache" ;;
	yarn) echo "YARN_GLOBAL_FOLDER=$h/yarn YARN_ENABLE_SCRIPTS=false YARN_ENABLE_TELEMETRY=0" \
		"YARN_NODE_LINKER=node-modules YARN_ENABLE_IMMUTABLE_INSTALLS=false" ;;
	deno) echo "DENO_DIR=$h/deno DENO_NO_UPDATE_CHECK=1" ;;
	esac
}

# Runs a command under GNU time; sets ST, WALL (ms), CPU (ms) and RSS (KB).
# OVER, the cost of the wrapper itself in µs, is taken off the wall time.
OVER=0
timed() {
	log=$1; shift
	t0=$(date +%s%N)
	/usr/bin/time -f '%U %S %M' -o "$W/time" "$@" >"$log" 2>&1
	ST=$?
	t1=$(date +%s%N)
	us=$(( (t1 - t0) / 1000 - OVER ))
	[ "$us" -gt 0 ] || us=0
	WALL=$(( (us + 500) / 1000 ))
	# shellcheck disable=SC2046
	set -- $(tail -n 1 "$W/time" 2>/dev/null) 0 0 0
	CPU=$(awk -v u="$1" -v s="$2" 'BEGIN { printf "%d", (u + s) * 1000 + 0.5 }')
	RSS=$3
}

[ $DRY = 1 ] || mkdir -p "$W/logs" "$BENCH/results" || exit 1

# Find each runner, print its version once (a first-run download is not timed).
FOUND=""
for r in $RUNNERS; do
	case " $ALL " in *" $r "*) ;; *) die "unknown runner: $r (known: $ALL)" ;; esac
	bin=$(given "$r")
	if [ -z "$bin" ] && [ "$r" = jpm ]; then
		bin=${CARGO_TARGET_DIR:-$ROOT/target}/release/jpm
		[ $DRY = 1 ] || cargo build --release --manifest-path "$ROOT/Cargo.toml" || die "cargo build failed"
	fi
	case $bin in /*) ;; */*) bin=$PWD/$bin ;; *) bin=$(command -v "${bin:-$r}") || { echo "skip $r: not found"; continue; } ;; esac
	[ $DRY = 1 ] || [ -x "$bin" ] || { echo "skip $r: $bin is not executable"; continue; }
	eval "BIN_$r=\$bin"
	ver="?"
	if [ $DRY = 0 ]; then
		mkdir -p "$W/r/$r/vhome"
		# shellcheck disable=SC2046
		ver=$(env $(envs "$r" "$W/r/$r/vhome") "$bin" --version 2>&1 | head -n 1 |
			sed -n 's/^[^0-9]*\([0-9][0-9.]*[0-9]\).*/\1/p')
		[ -n "$ver" ] || { echo "skip $r: $bin --version failed"; continue; }
		case $r$ver in yarn1.*) echo "skip yarn: $ver is yarn classic, not berry"; continue ;; esac
	fi
	eval "VER_$r=\$ver"
	echo "$r $ver: $bin"
	FOUND="$FOUND $r"
done
[ -n "$FOUND" ] || die "no runners"

# Stops cleanly when the work dir's disk runs low.
check_disk() {
	free=$(df -Pk "$W" | awk 'NR == 2 { print $4 }')
	[ "$free" -ge $((MIN_FREE * 1024 * 1024)) ] && return
	echo "bench: stopping, less than $MIN_FREE GB free under $W" >&2
	STOP=1
}

# Deletes a dir under the work dir; stores keep their files read-only.
wipe() {
	case $1 in "$W"/?*) ;; *) die "refusing to delete $1" ;; esac
	[ -e "$1" ] || return 0
	chmod -R u+w "${1:?}"
	rm -rf "${1:?}"
	[ ! -e "$1" ] || die "could not delete $1"
}

# A fresh project: no cache, no lockfile, no node_modules.
fresh() {
	wipe "$1"
	mkdir -p "$1/home" "$1/proj" && cp -R "$BENCH/fixtures/$2/." "$1/proj/"
}

# One install for runner $1 in dir $2; log name $3.
pm_install() {
	eval "bin=\$BIN_$1"
	ST=125 WALL=0 CPU=0 RSS=0
	cd "$2/proj" || return
	# shellcheck disable=SC2046,SC2086
	timed "$W/logs/$3.log" env $(envs "$1" "$2/home") "$bin" $(args "$1")
	cd "$ROOT" || exit 1
	if [ "$ST" = 0 ]; then : >"$2/ok"; else rm -f "$2/ok"; fi
}

if [ $DRY = 0 ]; then
	best=999999999
	for _ in 1 2 3 4 5; do timed /dev/null env A=1 true; [ "$us" -lt "$best" ] && best=$us; done
	OVER=$best
fi

STAMP=$(date +%Y%m%d-%H%M%S)
RES=$BENCH/results/$STAMP.tsv
[ $DRY = 1 ] || printf 'runner\tversion\tfixture\tphase\tsample\tstatus\twall_ms\tcpu_ms\trss_kb\n' >"$RES"
STOP=0
for f in $FIXTURES; do
	for p in $PHASES; do
		s=0
		while [ "$s" -lt "$SAMPLES" ]; do
			s=$((s + 1))
			for r in $FOUND; do
				d=$W/r/$r/$f
				if [ $DRY = 1 ]; then
					eval "bin=\$BIN_$r"
					echo "$p $f $s: cd $d/proj && $bin $(args "$r")"
					continue
				fi
				check_disk
				[ $STOP = 0 ] || break 4
				# Prepare: cold starts empty; warm and repeat start from a good install.
				if [ "$p" = cold ]; then
					fresh "$d" "$f"
				elif [ ! -f "$d/ok" ]; then
					fresh "$d" "$f" && pm_install "$r" "$d" "$r-$f-$p-$s-setup"
				fi
				[ "$p" = warm ] && wipe "$d/proj/node_modules"
				pm_install "$r" "$d" "$r-$f-$p-$s"
				eval "ver=\$VER_$r"
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
					"$r" "$ver" "$f" "$p" "$s" "$ST" "$WALL" "$CPU" "$RSS" >>"$RES"
				printf '%-6s %-6s %-6s %s  %6s ms  %s\n' "$r" "$f" "$p" "$s" "$WALL" \
					"$([ "$ST" = 0 ] || echo "FAILED ($ST), see $W/logs/$r-$f-$p-$s.log")"
			done
		done
	done
done
[ $DRY = 1 ] && exit
[ $KEEP = 1 ] || wipe "$W/r"
echo
report "$RES"
echo
echo "results: $RES"
