// Copies @npmcli/arborist's fixture lockfiles into tests/conformance/arborist/fixtures.
//
//   git clone -c core.autocrlf=false --filter=blob:none --sparse https://github.com/npm/cli npm-cli
//   git -C npm-cli sparse-checkout set workspaces/arborist && git -C npm-cli checkout <COMMIT>
//   node tests/conformance/gen/arborist.mjs path/to/npm-cli
//
// Every package-lock.json and npm-shrinkwrap.json under workspaces/arborist/test/fixtures that
// is not inside a node_modules folder is copied as it is, with the package.json beside it. A
// file over 32 KiB is gzipped (`<name>.gz`) to keep the copy small. The fixture folders with no
// such file are printed: they get a `skipped` row in expected.json by hand.

import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'

const COMMIT = '0c3b82a9a612c3f9399d35c28c86708b1f8ea7d4'
const LOCKS = ['package-lock.json', 'npm-shrinkwrap.json']
const BIG = 32 * 1024

const src = process.argv[2]
if (!src) {
  console.error('usage: node arborist.mjs <npm/cli checkout>')
  process.exit(1)
}
const head = execFileSync('git', ['-C', src, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
if (head !== COMMIT) {
  console.error(`${src} is at ${head}, not the pinned ${COMMIT}`)
  process.exit(1)
}

const arborist = join(src, 'workspaces', 'arborist')
const fixtures = join(arborist, 'test', 'fixtures')
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'arborist')
rmSync(join(out, 'fixtures'), { recursive: true, force: true })
copyFileSync(join(arborist, 'LICENSE.md'), join(out, 'LICENSE'))

const found = []
const walk = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules') continue
    const p = join(dir, e.name)
    if (e.isDirectory()) walk(p)
    else if (LOCKS.includes(e.name)) found.push(p)
  }
}
walk(fixtures)

const copy = (from, to) => {
  mkdirSync(dirname(to), { recursive: true })
  if (statSync(from).size > BIG) writeFileSync(to + '.gz', gzipSync(readFileSync(from), { level: 9 }))
  else copyFileSync(from, to)
}
const withLock = new Set()
for (const lock of found.sort()) {
  const rel = relative(fixtures, lock)
  withLock.add(rel.split(sep)[0])
  copy(lock, join(out, 'fixtures', rel))
  const pj = join(dirname(lock), 'package.json')
  if (existsSync(pj)) copy(pj, join(out, 'fixtures', dirname(rel), 'package.json'))
}
console.log(`${found.length} lockfiles copied`)
for (const e of readdirSync(fixtures, { withFileTypes: true })) {
  if (e.isDirectory() && !withLock.has(e.name)) console.log(`no lockfile: ${e.name}`)
}
