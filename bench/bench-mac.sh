#!/bin/sh
# bench.sh for macOS: BSD time and Perl's clock for GNU time and date, the darwin builds of
# each manager. The tables come from bench.sh --report. See bench/README.md.
set -u

BENCH=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$BENCH")
ALL="jpm npm pnpm bun yarn deno aube upm"
RUNNERS=$ALL
FIXTURES="nitro nuxt next"
PHASES="cold warm ci repeat"
SAMPLES=3
MIN_FREE=3
KEEP=0
DRY=0
INSTALLED=0
HOISTED=0
BINS=""
W=${BENCH_WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/jpm-bench}
# An idle Mac sleeps, and a wall time would count the sleep (an install timed at 33 minutes that
# took 88 s): the whole run is kept awake. -i alone still lets a closed Mac take its maintenance
# sleeps; -s holds the system awake on AC power.
if [ -z "${BENCH_AWAKE:-}" ] && command -v caffeinate >/dev/null; then
	export BENCH_AWAKE=1
	exec caffeinate -i -s "$0" "$@"
fi

usage() {
	cat <<EOF
usage: bench/bench-mac.sh [options]
       bench/bench.sh --report results/<stamp>.tsv

  -r, --runners a,b     package managers (default: $ALL)
  -f, --fixtures a,b    fixtures from bench/fixtures (default: nitro,nuxt,next)
  -n, --samples N       runs per phase (default: 3)
      --phases a,b      cold, warm, ci, repeat (default: all four)
      --bin name=path   use this binary for a runner (repeatable)
      --installed       use the managers on PATH instead of fetching the latest
      --hoisted         npm's layout for all: node-linker=hoisted for jpm and pnpm,
                        --linker hoisted for bun (runners: jpm,npm,pnpm,bun,yarn)
      --min-free GB     stop when the work dir has less free space (default: 3)
      --keep            keep the projects and caches afterwards
      --dry-run         print what would run
      --report FILE     print the tables for a results file
  -h, --help            this text

Every run fetches the latest release of each manager into the work dir,
unless --installed or --bin says otherwise. jpm is built from this tree.

Work dir: \$BENCH_WORK (now $W).
EOF
}

die() { echo "bench: $*" >&2; exit 1; }
list() { echo "$1" | tr ',' ' '; }

while [ $# -gt 0 ]; do
	case $1 in
	-r | --runners) RUNNERS=$(list "${2:?}"); shift ;;
	-f | --fixtures) FIXTURES=$(list "${2:?}"); shift ;;
	-n | --samples) SAMPLES=${2:?}; shift ;;
	--phases) PHASES=$(list "${2:?}"); shift ;;
	--bin) BINS="$BINS ${2:?}"; shift ;;
	--min-free) MIN_FREE=${2:?}; shift ;;
	--keep) KEEP=1 ;;
	--installed) INSTALLED=1 ;;
	--hoisted) HOISTED=1 ;;
	--dry-run) DRY=1 ;;
	--report) exec "$BENCH/bench.sh" --report "${2:?}" ;;
	-h | --help) usage; exit ;;
	*) usage >&2; exit 2 ;;
	esac
	shift
done
# deno, aube and upm keep layouts of their own.
[ $HOISTED = 0 ] || [ "$RUNNERS" != "$ALL" ] || RUNNERS="jpm npm pnpm bun yarn"

case $SAMPLES$MIN_FREE in *[!0-9]*) die "-n and --min-free take whole numbers" ;; esac
case $W in /*[!/]*) ;; *) die "BENCH_WORK must be an absolute path below /: $W" ;; esac
case $W in *[[:space:]]*) die "BENCH_WORK must not contain spaces: $W" ;; esac
for p in $PHASES; do case $p in cold | warm | ci | repeat) ;; *) die "unknown phase: $p" ;; esac; done
for f in $FIXTURES; do case $f in */* | .*) die "bad fixture name: $f" ;; esac; [ -f "$BENCH/fixtures/$f/package.json" ] || die "no fixture: $f"; done
[ "$(uname -s)" = Darwin ] || die "this is the macOS bench; elsewhere run bench/bench.sh"

# The explicit --bin for a runner, if any.
given() { for b in $BINS; do case $b in "$1"=*) echo "${b#*=}"; return ;; esac; done; }

# Arguments for an install.
args() {
	case $1 in
	jpm | aube | upm) echo "install --ignore-scripts" ;;
	bun) echo "install --ignore-scripts$([ $HOISTED = 0 ] || echo " --linker hoisted")" ;;
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
	case $1 in jpm | pnpm) [ $HOISTED = 0 ] || echo "npm_config_node_linker=hoisted pnpm_config_node_linker=hoisted" ;; esac
}

# Microseconds since the epoch: macOS's date has no %N.
now() { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1e6'; }

# Runs a command under BSD time; sets ST, WALL (ms), CPU (ms) and RSS (KB). `-l` reports the
# max RSS (bytes) of the process and every child it waited for, as GNU time's %M does.
# OVER, the cost of the wrapper itself in µs, is taken off the wall time.
OVER=0
timed() {
	log=$1; shift
	t0=$(now)
	/usr/bin/time -l -p -o "$W/time" "$@" >"$log" 2>&1
	ST=$?
	t1=$(now)
	us=$((t1 - t0 - OVER))
	[ "$us" -gt 0 ] || us=0
	WALL=$(( (us + 500) / 1000 ))
	CPU=$(awk '$1 == "user" { u = $2 } $1 == "sys" { s = $2 } END { printf "%d", (u + s) * 1000 + 0.5 }' "$W/time" 2>/dev/null)
	RSS=$(awk '/maximum resident set size/ { printf "%d", $1 / 1024 }' "$W/time" 2>/dev/null)
	CPU=${CPU:-0} RSS=${RSS:-0}
}

[ $DRY = 1 ] || mkdir -p "$W/logs" "$BENCH/results" || exit 1

JPM=${CARGO_TARGET_DIR:-$ROOT/target}/release/jpm
[ $DRY = 1 ] || cargo build --release --manifest-path "$ROOT/Cargo.toml" || die "cargo build failed"
# Deletes a dir under the work dir; stores keep their files read-only. Deleting needs only the
# directories writable: a file under node_modules is often a hardlink to a store's, and making it
# writable would change the store's copy too, before the next timed run. Files are made writable
# only if the delete still fails.
wipe() {
	case $1 in "$W"/?*) ;; *) die "refusing to delete $1" ;; esac
	[ -e "$1" ] || return 0
	find "${1:?}" -type d ! -perm -u+w -exec chmod u+w {} + 2>/dev/null
	rm -rf "${1:?}" 2>/dev/null || { chmod -R u+w "${1:?}" && rm -rf "${1:?}"; }
	[ ! -e "$1" ] || die "could not delete $1"
}

# The npm package each manager is published as.
package() {
	case $1 in
	npm | pnpm | upm | bun | deno) echo "$1" ;;
	yarn) echo "@yarnpkg/cli-dist" ;;
	esac
}

# The latest release of each manager asked for, into $W/tools: the npm packages
# installed by the jpm just built (a fresh project, so "latest" is resolved
# again; the store is kept, so an unchanged version is not downloaded twice),
# and aube from its GitHub releases. Sets TOOL_<runner>.
# shellcheck disable=SC2034 # the TOOL_ variables are read through eval
fetch_tools() {
	t=$W/tools
	m=$t/proj/node_modules
	case $(uname -m) in
	x86_64 | amd64) a=x64 b=x64 ;;
	aarch64 | arm64) a=arm64 b=aarch64 ;;
	*) a=none b=none ;;
	esac
	TOOL_npm=$m/.bin/npm TOOL_yarn=$m/.bin/yarn TOOL_upm=$m/.bin/upm
	# The native binaries, not the node launchers their packages put in .bin:
	# each is a dependency of its package, so a sibling of it.
	TOOL_pnpm=$m/pnpm/../@pnpm/exe.darwin-$a/pnpm
	TOOL_bun=$m/bun/../@oven/bun-darwin-$b/bin/bun
	TOOL_deno=$m/deno/../@deno/darwin-$a/deno
	deps=""
	for r in $RUNNERS; do
		pkg=$(package "$r")
		[ -n "$pkg" ] && [ -z "$(given "$r")" ] && deps="$deps${deps:+, }\"$pkg\": \"latest\""
	done
	if [ -n "$deps" ]; then
		echo "fetching the latest: $deps"
		if [ $DRY = 0 ]; then
			wipe "$t/proj"
			mkdir -p "$t/proj" && printf '{ "private": true, "dependencies": { %s } }\n' "$deps" >"$t/proj/package.json"
			# jpm's default minimum release age applies: nothing under a day old.
			(cd "$t/proj" && JPM_STORE=$t/store "$JPM" install --ignore-scripts >"$W/logs/tools.log" 2>&1) ||
				die "could not fetch the managers; see $W/logs/tools.log"
		fi
	fi
	case " $RUNNERS " in *" aube "*) [ -n "$(given aube)" ] || fetch_aube ;; esac
}

# shellcheck disable=SC2034
fetch_aube() {
	echo "fetching the latest aube"
	[ $DRY = 0 ] || return
	url=https://github.com/aubepkg/aube/releases
	# The newest release at least a day old, as jpm's minimum release age would pick.
	# awk reads to the end: exiting early fails curl's write.
	cut=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)
	tag=$(curl -fsS "https://api.github.com/repos/aubepkg/aube/releases?per_page=20" | awk -F '"' -v cut="$cut" '
		/"tag_name":/ { tag = $4; skip = 0 }
		/"(draft|prerelease)": true/ { skip = 1 }
		/"published_at":/ && !skip && !found && $4 <= cut { print tag; found = 1 }')
	case $tag in v[0-9]*) ;; *) echo "skip fetching aube: no release a day old found"; return ;; esac
	d=$W/tools/aube/$tag
	if [ ! -d "$d" ]; then
		wipe "$d.part"
		mkdir -p "$d.part" || exit 1
		cpu=$(uname -m); [ "$cpu" = arm64 ] && cpu=aarch64
		curl -fsSL "$url/download/$tag/aube-$tag-$cpu-apple-darwin.tar.gz" | tar -xz -C "$d.part"
		# shellcheck disable=SC2181
		if [ $? != 0 ]; then
			wipe "$d.part"
			echo "skip fetching aube: download failed"
			return
		fi
		mv "$d.part" "$d" || exit 1
	fi
	TOOL_aube=$(find "$d" -type f \( -name aube -o -name aube.exe \) | head -n 1)
}

[ $INSTALLED = 1 ] || fetch_tools

# Find each runner, print its version once (a first-run download is not timed).
FOUND=""
for r in $RUNNERS; do
	case " $ALL " in *" $r "*) ;; *) die "unknown runner: $r (known: $ALL)" ;; esac
	bin=$(given "$r")
	if [ -z "$bin" ] && [ "$r" = jpm ]; then
		bin=$JPM
	elif [ -z "$bin" ] && [ $INSTALLED = 0 ]; then
		eval "bin=\${TOOL_$r:-}"
		[ -n "$bin" ] || { echo "skip $r: no latest release fetched"; continue; }
		case $r in npm | yarn | upm) command -v node >/dev/null || { echo "skip $r: needs node on PATH"; continue; } ;; esac
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
		# upm has no --version: its package.json says.
		[ -n "$ver" ] || ver=$(sed -n 's/^ *"version": *"\([0-9][^"]*\)".*/\1/p' \
			"$(dirname "$(readlink -f "$bin")")/../package.json" "$W/tools/proj/node_modules/$r/package.json" \
			2>/dev/null | head -n 1)
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

# Sets DISK, in KB: the project's node_modules and the runner's home, where every cache and store
# is (see envs), counted together so a file hardlinked into both counts once; and CACHE: the home
# alone, what CI would save and restore.
sizes() {
	DISK=$(du -sk "$1/proj/node_modules" "$1/home" 2>/dev/null | awk '{ n += $1 } END { print n + 0 }')
	CACHE=$(du -sk "$1/home" 2>/dev/null | awk '{ print $1 + 0 }')
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
[ $DRY = 1 ] || printf 'runner\tversion\tfixture\tphase\tsample\tstatus\twall_ms\tcpu_ms\trss_kb\tdisk_kb\tcache_kb\n' >"$RES"
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
				# CI with no cache: the lockfile alone, every cache and store gone.
				if [ "$p" = ci ]; then
					wipe "$d/proj/node_modules"
					wipe "$d/home" && mkdir -p "$d/home"
				fi
				pm_install "$r" "$d" "$r-$f-$p-$s"
				eval "ver=\$VER_$r"
				DISK="" CACHE=""
				if [ "$p" = cold ] && [ "$ST" = 0 ]; then sizes "$d"; fi
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
					"$r" "$ver" "$f" "$p" "$s" "$ST" "$WALL" "$CPU" "$RSS" "$DISK" "$CACHE" >>"$RES"
				printf '%-6s %-6s %-6s %s  %6s ms  %s\n' "$r" "$f" "$p" "$s" "$WALL" \
					"$([ "$ST" = 0 ] || echo "FAILED ($ST), see $W/logs/$r-$f-$p-$s.log")"
			done
		done
	done
done
[ $DRY = 1 ] && exit
[ $KEEP = 1 ] || wipe "$W/r"
echo
"$BENCH/bench.sh" --report "$RES"
echo
echo "results: $RES"
