#!/usr/bin/env python3
"""Install every project in repos.txt with jpm and report what failed. See README.md.

Each repository is cloned (depth 1) into the work dir, or reset to its commit when it is there,
then: install, a second install (which must be a no-op), --frozen-lockfile, an install after the
ignored files (node_modules) are gone, and --verify. --run adds the first of its build,
typecheck, check or lint scripts. Python 3.9 and git; nothing else.
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LOCKS = [("bun.lock", "bun"), ("pnpm-lock.yaml", "pnpm"), ("package-lock.json", "npm"),
         ("npm-shrinkwrap.json", "npm"), ("yarn.lock", "yarn")]


def repos(path, only):
    """(name, expect, with): a line's `# with: <flags>; expect: <reason>`, either part optional."""
    out = []
    for line in open(path, encoding="utf-8"):
        name, _, note = line.partition("#")
        name = name.strip()
        if name and (not only or name.lower() in only):
            parts = dict(p.strip().split(":", 1) for p in note.split(";") if ":" in p)
            out.append((name, parts.get("expect", "").strip(), parts.get("with", "").split()))
    return out


# A manager in command position: a line's start, or after ; && || | or (.
OTHER_PM = re.compile(r"(?:^|[;&|(])\s*(pnpm|yarn|bunx?)(?=\s|$)")


def calls(work):
    """What a project's scripts need changed for jpm: scripts that start another manager (npm and
    npx work on jpm's tree), and a preinstall that lets only one manager in."""
    files = subprocess.run(["git", "ls-files", "package.json", "*/package.json"], cwd=work,
                           capture_output=True, text=True).stdout.split()
    used, guard = {}, ""
    for f in files:
        try:
            scripts = json.load(open(os.path.join(work, f), encoding="utf-8")).get("scripts") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for key, line in scripts.items() if isinstance(scripts, dict) else []:
            if not isinstance(line, str):
                continue
            for pm in set(OTHER_PM.findall(line)):
                pm = "bun" if pm == "bunx" else pm
                used[pm] = used.get(pm, 0) + 1
            if key == "preinstall" and ("only-allow" in line or "npm_config_user_agent" in line or "block-npm" in line):
                guard = "preinstall allows only " + (line.split("only-allow", 1)[1].split()[0] if "only-allow" in line else "its own manager")
    notes = [f"scripts call {pm} ({n}): use jpm" for pm, n in sorted(used.items())]
    return "; ".join(([guard] if guard else []) + notes)


def run(cmd, cwd, env, log, timeout):
    t = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out = "timeout", str(e.stdout or "") + str(e.stderr or "")
    with open(log, "w", encoding="utf-8") as f:
        f.write(out)
    tail = [l for l in out.strip().splitlines() if l.strip()]
    return {"rc": rc, "secs": round(time.time() - t, 1), "last": tail[-1][:300] if tail else "", "out": out}


def one(name, expect, extra, a, env):
    work = os.path.join(a.work, "repos", name.replace("/", "__"))
    logs = os.path.join(a.work, "logs", name.replace("/", "__"))
    os.makedirs(logs, exist_ok=True)
    r = {"repo": name, "expect": expect, "with": extra, "steps": {}}

    def step(key, cmd, cwd=work, timeout=900):
        s = run(cmd, cwd, env, os.path.join(logs, key + ".log"), timeout)
        r["steps"][key] = {k: v for k, v in s.items() if k != "out"}
        return s

    if os.path.isdir(os.path.join(work, ".git")):
        subprocess.run(["git", "checkout", "-q", "."], cwd=work)
        subprocess.run(["git", "clean", "-fdxq"], cwd=work)
    elif step("clone", ["git", "clone", "-q", "--depth", "1", f"https://github.com/{name}.git", work],
              cwd=a.work, timeout=900)["rc"] != 0:
        return r
    r["lock"] = next((k for f, k in LOCKS if os.path.exists(os.path.join(work, f))), "none")
    r["calls"] = calls(work)
    flags = ([] if a.scripts else ["--ignore-scripts"]) + extra
    jpm = [a.jpm, "install", *flags]
    if step("install", jpm)["rc"] != 0:
        return r
    again = step("again", jpm)
    if again["rc"] == 0 and "up to date" not in again["out"]:
        r["steps"]["again"]["rc"] = "not a no-op"
    step("frozen", [*jpm, "--frozen-lockfile"])
    subprocess.run(["git", "clean", "-fdXq"], cwd=work)  # ignored files only: tracked node_modules stay
    step("reinstall", jpm)
    step("verify", [*jpm, "--verify"])
    if a.run:
        try:
            scripts = json.load(open(os.path.join(work, "package.json"), encoding="utf-8")).get("scripts", {})
        except (OSError, ValueError):
            scripts = {}
        script = next((s for s in ["build", "typecheck", "check", "lint"] if s in scripts), None)
        if script:
            step("run", [a.jpm, "run", script])
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    exe = "jpm.exe" if os.name == "nt" else "jpm"
    p.add_argument("--jpm", default=os.path.join(ROOT, "target", "release", exe), help="the jpm to test")
    p.add_argument("--work", default=os.path.join(os.path.expanduser("~"), ".cache", "jpm-corpus"),
                   help="clones, store and logs (default ~/.cache/jpm-corpus)")
    p.add_argument("--list", default=os.path.join(HERE, "repos.txt"))
    p.add_argument("-j", "--jobs", type=int, default=4, help="repositories at a time (default 4)")
    p.add_argument("--scripts", action="store_true", help="run install scripts (default --ignore-scripts)")
    p.add_argument("--run", action="store_true", help="also run a build, typecheck, check or lint script")
    p.add_argument("--report", action="store_true", help="print the table of every platform's results")
    p.add_argument("only", nargs="*", help="just these owner/repo names")
    a = p.parse_args()
    if a.report:
        return report(a.list)
    a.jpm = os.path.abspath(a.jpm)
    os.makedirs(a.work, exist_ok=True)
    env = dict(os.environ, CI="1", JPM_STORE=os.path.join(a.work, "store"))
    todo = repos(a.list, {o.lower() for o in a.only})
    results = []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        for r in ex.map(lambda t: one(*t, a, env), todo):
            results.append(r)
            bad = [k for k, s in r["steps"].items() if s["rc"] != 0]
            print(f"{r['repo']:<45} {r.get('lock', '-'):<5} {'ok' if not bad else 'FAILED ' + ','.join(bad)}", flush=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = os.path.join(a.work, f"results-{stamp}.json")
    json.dump(results, open(out, "w", encoding="utf-8"), indent=1)
    fails = [r for r in results if any(s["rc"] != 0 for s in r["steps"].values())]
    print(f"\n{len(results) - len(fails)} of {len(results)} passed every step; "
          f"{sum(1 for r in fails if r['expect'])} expected failures, {sum(1 for r in fails if not r['expect'])} others")
    for r in fails:
        key, s = next((k, s) for k, s in r["steps"].items() if s["rc"] != 0)
        print(f"  {r['repo']}: {key} {'(expected: ' + r['expect'] + ')' if r['expect'] else ''}\n    {s['last']}")
    print(f"results: {out}")
    summary(results, todo)
    sys.exit(1 if any(not r["expect"] for r in fails) else 0)


PLATFORMS = [("linux", "Linux"), ("darwin", "macOS"), ("win32", "Windows")]
RESULTS = os.path.join(HERE, "results")


def summary(results, todo):
    """results/<platform>.tsv: this platform's line for each project run, the others kept."""
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, f"{sys.platform}.tsv")
    rows = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8").read().splitlines()[1:]:
            rows[line.split("\t")[0].lower()] = line
    for r in results:
        bad = next((k for k, s in r["steps"].items() if s["rc"] != 0), "")
        status = "expected" if bad and r["expect"] else "fail" if bad else "with" if r["with"] else "pass"
        rows[r["repo"].lower()] = "\t".join([r["repo"], r.get("lock", "-"), status, bad, r.get("calls", ""),
                                             time.strftime("%Y-%m-%d")])
    with open(path, "w", encoding="utf-8") as f:
        f.write("repo\tlock\tstatus\tstep\tcalls\tdate\n")
        f.writelines(rows[k] + "\n" for k in sorted(rows))


def report(listing):
    """A Markdown table: each project's lockfile, result on each platform, and the settings it needs."""
    marks = {"pass": "✅", "with": "⚙️", "fail": "❌", "expected": "➖"}
    seen = {}
    for plat, _ in PLATFORMS:
        path = os.path.join(RESULTS, f"{plat}.tsv")
        if os.path.exists(path):
            for line in open(path, encoding="utf-8").read().splitlines()[1:]:
                repo, lock, status, step, needs, _ = line.split("\t")
                seen.setdefault(repo.lower(), {})[plat] = (lock, status, step, needs)
    cols = [(p, n) for p, n in PLATFORMS if any(p in v for v in seen.values())]
    print("| project | lockfile | " + " | ".join(n for _, n in cols) + " | settings | note |")
    print("| --- | --- | " + " | ".join(":---:" for _ in cols) + " | --- | --- |")
    for name, expect, extra in repos(listing, set()):
        got = seen.get(name.lower(), {})
        lock = next((v[0] for v in got.values()), "")
        needs = next((v[3] for v in got.values() if v[3]), "")
        cells = []
        for p, _ in cols:
            _, status, step, _ = got.get(p, ("", "", "", ""))
            cells.append(marks.get(status, "") + (f" {step}" if status in ("fail", "expected") else ""))
        print(f"| [{name}](https://github.com/{name}) | {lock} | " + " | ".join(cells)
              + f" | {' '.join(f'`{w}`' for w in extra)} | {'; '.join(n for n in [expect, needs] if n)} |")
    print("\n✅ installs · ⚙️ installs with the settings named · ❌ fails (at the step named) · "
          "➖ fails by design or outside jpm, as noted")


if __name__ == "__main__":
    main()
