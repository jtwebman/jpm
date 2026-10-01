#!/usr/bin/env python3
"""Seed corpora for the fuzz targets, from the repository's own test data.

    python3 fuzz/seed.py [--extra DIR ...] [--npm-cache DIR]

writes fuzz/corpus/<target>/. `--extra` adds every lockfile, package.json, .npmrc and
pnpm-workspace.yaml found under DIR (a checkout of real projects, read only); `--npm-cache` adds
small tarballs and registry documents from an npm cache (~/.npm/_cacache).
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "fuzz" / "corpus"
CONF = ROOT / "tests" / "conformance"
LOCKS = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]
MAX = 256 * 1024


def put(target, data):
    if isinstance(data, str):
        data = data.encode()
    if len(data) > MAX:
        return
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha1(data).hexdigest()).write_bytes(data)


def foreign(file, manifest, lock):
    put("foreign", bytes([LOCKS.index(file)]) + manifest + b"\0" + lock)


def tarball(entries, fmt):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if name.endswith(".sh") else 0o644
            if kind == "file":
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            else:
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = data
                t.addfile(info)
    return buf.getvalue()


def tars():
    pkg = b'{"name":"a","version":"1.0.0","bin":{"a":"bin/a.js"}}'
    sets = [
        [("package/package.json", "file", pkg), ("package/bin/a.js", "file", b"#!/usr/bin/env node\n")],
        [("package/" + "d" * 120 + "/x.js", "file", b"x"), ("package/index.js", "file", b"1")],
        [("package/lib", "dir", None), ("package/lib/a.js", "file", b"a"), ("package/l", "sym", "../../etc")],
        [("package/a.js", "file", b"a"), ("package/A.js", "file", b"b"), ("package/a.js", "file", b"c")],
        [("package/h", "hard", "package/a.js"), ("package/run.sh", "file", b"echo")],
        [("package/../evil", "file", b"e"), ("/abs", "file", b"e"), ("package/c:x", "file", b"e")],
        [("package/ü/ñ.js", "file", b"u"), ("package/sp ace.js", "file", b"s")],
    ]
    for entries in sets:
        for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            try:
                raw = tarball(entries, fmt)
            except ValueError:
                continue
            put("tar", raw)
            put("extract", b"\0" + raw)
            put("extract", b"\0" + gzip.compress(raw))
            put("extract", b"\3" + raw)


def conformance():
    def rows(doc):
        return doc if isinstance(doc, list) else doc.get("rows") or doc.get("cases") or []

    for f in (CONF / "semver").glob("*.json"):
        for row in rows(json.loads(f.read_text())):
            items = row if isinstance(row, list) else [row]
            put("semver", "\n".join(x for x in items if isinstance(x, str)))
    for d in ("npm-package-arg", "hosted-git-info"):
        for f in (CONF / d).glob("*.json"):
            for row in rows(json.loads(f.read_text())):
                if not isinstance(row, dict):
                    continue
                for k in ("arg", "input", "raw", "spec"):
                    if isinstance(row.get(k), str):
                        put("spec", row[k])
                        put("spec", "a\n" + row[k])
                expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}
                if isinstance(expect.get("name"), str) and isinstance(expect.get("rawSpec"), str):
                    put("spec", expect["name"] + "\n" + expect["rawSpec"])
    for f in (CONF / "arborist" / "fixtures").rglob("*"):
        if f.name in ("package-lock.json", "npm-shrinkwrap.json") or f.name == "package-lock.json.gz":
            lock = gzip.decompress(f.read_bytes()) if f.suffix == ".gz" else f.read_bytes()
            pj = f.parent / "package.json"
            manifest = pj.read_bytes() if pj.exists() else b"{}"
            foreign("package-lock.json", manifest, lock)
            put("json", lock)
        if f.name == "package.json":
            put("json", f.read_bytes())
            put("manifest", f.read_bytes())
    for row in json.loads((CONF / "bun" / "lockfiles.json").read_text()):
        if "bun.lock" in row:
            foreign("bun.lock", json.dumps(row.get("package.json", {})).encode(), row["bun.lock"].encode())
    mock = CONF / "pnpm-registry-mock"
    for f in mock.glob("*.json"):
        put("json", f.read_bytes())


def extra(base):
    for d in pathlib.Path(base).iterdir():
        if not d.is_dir():
            continue
        pj = d / "package.json"
        manifest = pj.read_bytes() if pj.exists() else b"{}"
        if pj.exists():
            put("json", manifest)
            put("manifest", manifest)
        for name in LOCKS:
            f = d / name
            if f.exists():
                data = f.read_bytes()
                if name in ("pnpm-lock.yaml", "yarn.lock") and len(data) > MAX:
                    data = data[: data.rfind(b"\n", 0, 32 * 1024) + 1]
                foreign(name, manifest, data)
                if name.endswith(".yaml"):
                    put("yaml", data)
        for name in ("pnpm-workspace.yaml", ".yarnrc.yml"):
            if (d / name).exists():
                put("yaml", (d / name).read_bytes())
        if (d / ".npmrc").exists():
            put("npmrc", (d / ".npmrc").read_bytes())
        if (d / "jpm.lock").exists():
            lock = (d / "jpm.lock").read_bytes()
            put("lockfile", lock)
            # The big ones cut at a line: their sections still read, if not their edges.
            put("lockfile", lock[: lock.rfind(b"\n", 0, 32 * 1024) + 1])


def npm_cache(base, limit=300):
    tgz = docs = 0
    for f in (pathlib.Path(base) / "content-v2").rglob("*"):
        if not f.is_file() or f.stat().st_size > 64 * 1024:
            continue
        head = f.read_bytes()[:2]
        if head == b"\x1f\x8b" and tgz < limit:
            tgz += 1
            data = f.read_bytes()
            put("extract", b"\0" + data)
            try:
                put("tar", gzip.decompress(data))
            except Exception:
                pass
        elif head[:1] == b"{" and docs < limit:
            data = f.read_bytes()
            if b'"versions"' in data:
                docs += 1
                put("packument", b"^1.0.0\n" + data)
                put("json", data)


def by_hand():
    put("lockfile", "jpm-lock 1\nhash 0\nroot\n  dep a 1.0.0\npackage a@1.0.0\n  version 1.0.0\n  integrity sha512-AAAA\n")
    put("lockfile", "jpm-lock 2\nhash 0\nroot\n  spec dependencies a ^1\n  spec dependencies p ^1\n  dep a 1.0.0(p@1.0.0)\n"
                    "  dep p 1.0.0\npackage a@1.0.0(p@1.0.0)\n  integrity sha512-AAAA\n  dep p 1.0.0\n  peer p ^1\n"
                    "  settled p required\npackage p@1.0.0\n  integrity sha512-BBBB\n  os linux\n  bin p p.js\n")
    put("npmrc", "registry=https://r.example/\n@s:registry=https://s.example/\n//r.example/:_authToken=${TOKEN}\n"
                 "a[]=1\na[]=2\nstrict-ssl=false\nmin-release-age=3\n; c\n# c\n[section]\nk='v'\n")
    put("yaml", "packages:\n  - 'a/*'\ncatalog:\n  react: ^18\noverrides:\n  a@1>b: 2\nonlyBuiltDependencies:\n  - esbuild\n")
    put("json", '{"a":[1,-2.5e3,true,false,null,"\\u00e9\\ud83d\\ude00"],"b":{}}')
    put("packument", '^1\n{"name":"a","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"a","version":"1.0.0",'
                     '"dist":{"integrity":"sha512-AAAA","tarball":"https://r/a.tgz"},"dependencies":{"b":"^2"}}},'
                     '"time":{"1.0.0":"2020-01-01T00:00:00.000Z"}}')
    put("manifest", '{"name":"a","version":"1.0.0","bin":"x.js","dist":{"shasum":"0000000000000000000000000000000000000000"}}')


def patches():
    put("patch", "diff --git a/index.js b/index.js\n--- a/index.js\n+++ b/index.js\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
    put("patch", "diff --git a/lib/x.js b/lib/y.js\nsimilarity index 50%\nrename from lib/x.js\nrename to lib/y.js\n"
                 "--- a/lib/x.js\n+++ b/lib/y.js\n@@ -1,2 +1,2 @@\n x\r\n-y\r\n+z\r\n")
    put("patch", "diff --git a/new.js b/new.js\nnew file mode 100755\n--- /dev/null\n+++ b/new.js\n@@ -0,0 +1 @@\n+n\n"
                 "\\ No newline at end of file\n")
    put("patch", "diff --git a/index.js b/index.js\ndeleted file mode 100644\nindex 1234567..0000000\n--- a/index.js\n"
                 "+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n-b\n-c\n")
    put("patch", 'diff --git "a/sp ace.js" "b/\\303\\274.js"\n--- "a/sp ace.js"\n+++ "b/\\303\\274.js"\n@@ -1 +1 @@\n-a\n+b\n')
    node = ROOT / "tests" / "fixtures" / "node"
    keys = sorted(node.glob("*.asc"))
    for sig in node.glob("*.sig"):
        s, doc = sig.read_bytes(), (node / sig.name[:-4]).read_bytes()
        for key in keys:
            k = key.read_bytes()
            put("pgp", len(s).to_bytes(2, "big") + s + len(k).to_bytes(2, "big") + k + doc)


def certs():
    for f in pathlib.Path("/etc/ssl/certs").glob("*.pem"):
        text = f.read_text(errors="ignore")
        if "BEGIN CERTIFICATE" not in text:
            continue
        import base64
        body = text.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
        der = base64.b64decode("".join(body.split()))
        put("x509", der)
        put("x509", len(der).to_bytes(2, "big") + der + len(der).to_bytes(2, "big") + der)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--extra", action="append", default=[])
    p.add_argument("--npm-cache")
    a = p.parse_args()
    tars()
    conformance()
    by_hand()
    patches()
    certs()
    for e in a.extra:
        extra(e)
    if a.npm_cache:
        npm_cache(a.npm_cache)
    for d in sorted(OUT.iterdir()):
        print(f"{d.name}: {len(list(d.iterdir()))}")


if __name__ == "__main__":
    os.umask(0o022)
    main()
