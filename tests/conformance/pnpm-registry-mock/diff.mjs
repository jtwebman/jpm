// Installs each scenario in scenarios.json from pnpm's registry-mock with jpm, and compares what
// it installed with what pnpm installs from the same registry.
//
//   node tests/conformance/pnpm-registry-mock/diff.mjs [options]
//
//   --jpm <bin>        jpm to test (default target/release/jpm)
//   --pnpm <bin>       run pnpm too and compare against it live, not expected.json
//   --record           with --pnpm: write pnpm's results to expected.json, run no jpm
//   --registry <url>   the running registry-mock (default http://localhost:4873/)
//   --only <regex>     scenarios whose id matches
//   --jobs <n>         installs at once (default 4)
//   --keep             keep the scratch projects, and print where they are
//
// Both managers install into a fresh project per scenario, with their own store, cache and
// config, and without scripts. The result is read from node_modules on disk, not from a
// lockfile, so the two layouts come out in one shape: each package instance as name@version and
// what each name in its dependencies, optionalDependencies and peerDependencies resolves to from
// its own directory, the root's dependencies the same way, and the root's bins. An instance is
// kept once per distinct set of resolutions, so pnpm's copies of a package that differ only in
// their peers' peers read as one, as jpm keeps them. A difference fails the run unless
// allowlist.json names it, with a reason.

import { spawn } from 'node:child_process'
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..', '..')

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf(name)
  return i < 0 ? fallback : args[i + 1]
}
const flag = (name) => args.includes(name)
const exe = process.platform === 'win32' ? '.exe' : ''
const JPM = resolve(opt('--jpm', join(process.env.CARGO_TARGET_DIR ?? join(REPO, 'target'), 'release', `jpm${exe}`)))
const PNPM = opt('--pnpm')
const RECORD = flag('--record')
const REGISTRY = opt('--registry', 'http://localhost:4873/')
const ONLY = new RegExp(opt('--only', ''))
const JOBS = Number(opt('--jobs', '4'))
const KEEP = flag('--keep')
if (RECORD && !PNPM) {
  console.error('--record needs --pnpm <bin>')
  process.exit(2)
}

// This machine as the results depend on it: packages with os, cpu or libc fields install or not.
const libc = () => {
  if (process.platform !== 'linux') {
    return ''
  }
  const report = process.report?.getReport()
  return report?.header?.glibcVersionRuntime ? '-glibc' : '-musl'
}
const PLATFORM = `${process.platform}-${process.arch}${libc()}`

const spec = JSON.parse(readFileSync(join(HERE, 'scenarios.json'), 'utf8'))
const scenarios = [
  ...spec.single.map((name) => ({ id: `single ${name}`, dependencies: { [name]: 'latest' } })),
  ...spec.scenarios,
].filter((s) => ONLY.test(s.id))

const expectedFile = join(HERE, 'expected.json')
const expected = !PNPM && JSON.parse(readFileSync(expectedFile, 'utf8'))
if (expected && expected.platform !== PLATFORM) {
  console.error(`expected.json was recorded on ${expected.platform}, this is ${PLATFORM}; ` +
    'pass --pnpm <bin> to compare against pnpm live')
  process.exit(2)
}
// Each allowed difference names why jpm differs on purpose, as a key of `reasons`.
const { reasons, allowed: allowlist } = JSON.parse(readFileSync(join(HERE, 'allowlist.json'), 'utf8'))
const unexplained = allowlist.filter((a) => !reasons[a.reason])
if (unexplained.length) {
  console.error(`allowlist.json: no reason for ${unexplained.map((a) => a.scenario).join(', ')}`)
  process.exit(2)
}

const scratch = mkdtempSync(join(tmpdir(), 'jpm-regmock-'))
const run = (cmd, argv, cwd, env) => new Promise((done) => {
  const child = spawn(cmd, argv, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { out += d })
  child.on('error', (e) => done({ code: -1, out: String(e) }))
  child.on('close', (code) => done({ code, out }))
})

const managers = {
  pnpm: (dir, home) => run(PNPM, [
    'install', '--registry', REGISTRY, '--store-dir', join(home, 'store'), `--config.cache-dir=${join(home, 'cache')}`,
    '--ignore-scripts', '--config.minimum-release-age=0', '--config.update-notifier=false',
  ], dir, { npm_config_userconfig: join(home, 'npmrc'), XDG_CONFIG_HOME: join(home, 'config'), CI: '1' }),
  jpm: (dir, home) => run(JPM, [
    'install', '--registry', REGISTRY, '--store', join(home, 'store'), '--min-release-age', '0',
    '--ignore-scripts', '--silent',
  ], dir, { npm_config_userconfig: join(home, 'npmrc'), JPM_STORE: join(home, 'store'), CI: '1' }),
}

const readJson = (file) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

// The node_modules a package's directory sits in: its dependencies are linked there, beside it.
const enclosing = (dir) => {
  let d = dirname(dir)
  while (basename(d) !== 'node_modules' && dirname(d) !== d) {
    d = dirname(d)
  }
  return d
}

// Every name a manifest asks for, as the kinds pnpm and jpm install or link it.
const asked = (manifest, root) => {
  const kinds = root
    ? ['dependencies', 'devDependencies', 'optionalDependencies']
    : ['dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta']
  return [...new Set(kinds.flatMap((k) => Object.keys(manifest[k] ?? {})))].sort()
}

const bundled = (manifest) => {
  const b = manifest.bundleDependencies ?? manifest.bundledDependencies
  return b === true ? Object.keys(manifest.dependencies ?? {}) : Array.isArray(b) ? b : []
}

const idOf = (dir) => {
  const m = readJson(join(dir, 'package.json'))
  return m ? `${m.name}@${m.version}` : `(no package.json in ${basename(dir)})`
}

// Reads what was installed under project `dir` into sorted lines.
const snapshot = (dir) => {
  const rootManifest = readJson(join(dir, 'package.json'))
  const seen = new Map()
  const queue = []
  // A name's target, as its version alone when it is the package of that name.
  const short = (name, id) => id?.startsWith(`${name}@`) ? id.slice(name.length + 1) : id
  const locate = (from, name) => {
    const at = join(from, name)
    if (!existsSync(at)) {
      return null
    }
    const real = realpathSync(at)
    if (!seen.has(real)) {
      seen.set(real, null)
      queue.push(real)
    }
    return idOf(real)
  }
  const root = asked(rootManifest, true).map((name) =>
    `${name} -> ${short(name, locate(join(dir, 'node_modules'), name)) ?? '(missing)'}`)
  while (queue.length) {
    const real = queue.shift()
    const manifest = readJson(join(real, 'package.json')) ?? {}
    const own = new Set(bundled(manifest))
    const links = asked(manifest, false).map((name) => {
      const from = own.has(name) ? join(real, 'node_modules') : enclosing(real)
      return `${name}=${short(name, locate(from, name)) ?? '-'}`
    })
    seen.set(real, `${idOf(real)}${links.length ? ' ' + links.join(' ') : ''}`)
  }
  const binDir = join(dir, 'node_modules', '.bin')
  const bins = existsSync(binDir)
    ? [...new Set(readdirSync(binDir).map((f) => f.replace(/\.(cmd|ps1|exe)$/i, '')))].sort()
    : []
  return { root, packages: [...new Set(seen.values())].sort(), bins }
}

const install = async (manager, s) => {
  const dir = join(scratch, manager, s.id.replace(/[^\w.@-]+/g, '_'))
  const home = join(scratch, `${manager}-home`)
  mkdirSync(dir, { recursive: true })
  mkdirSync(join(home, 'config'), { recursive: true })
  writeFileSync(join(home, 'npmrc'), '')
  const manifest = { name: 'scenario', version: '1.0.0', private: true }
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    if (s[k]) {
      manifest[k] = s[k]
    }
  }
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2))
  const { code, out } = await managers[manager](dir, home)
  if (code !== 0) {
    const line = out.split(/\r?\n/).find((l) => /ERR|error/i.test(l)) ?? out.trim().split(/\r?\n/).pop()
    return { failed: (line ?? `exit ${code}`).trim().slice(0, 200) }
  }
  return snapshot(dir)
}

// The lines one result has and the other lacks: `-` pnpm only, `+` jpm only.
const compare = (want, got) => {
  if (want.failed || got.failed) {
    return want.failed && got.failed
      ? []
      : [`failed: pnpm ${want.failed ? 'failed' : 'succeeded'}, jpm ${got.failed ? 'failed' : 'succeeded'}`]
  }
  const lines = []
  for (const part of ['root', 'packages', 'bins']) {
    const a = new Set(want[part])
    const b = new Set(got[part])
    lines.push(...[...a].filter((x) => !b.has(x)).map((x) => `${part}: - ${x}`))
    lines.push(...[...b].filter((x) => !a.has(x)).map((x) => `${part}: + ${x}`))
  }
  return lines
}

const pool = async (items, fn) => {
  const results = new Array(items.length)
  let next = 0
  await Promise.all(Array.from({ length: Math.min(JOBS, items.length) }, async () => {
    while (next < items.length) {
      const i = next++
      results[i] = await fn(items[i])
    }
  }))
  return results
}

if (RECORD) {
  const results = await pool(scenarios, (s) => install('pnpm', s))
  const old = existsSync(expectedFile) ? JSON.parse(readFileSync(expectedFile, 'utf8')) : { results: {} }
  const merged = { ...old.results }
  scenarios.forEach((s, i) => { merged[s.id] = results[i] })
  const version = (await run(PNPM, ['--version'], scratch, {})).out.trim()
  const sorted = Object.fromEntries(Object.keys(merged).sort().map((k) => [k, merged[k]]))
  const doc = { registryMock: spec.registryMock, pnpm: version, platform: PLATFORM, results: sorted }
  writeFileSync(expectedFile, JSON.stringify(doc, null, 1) + '\n')
  console.log(`recorded ${scenarios.length} scenarios with pnpm ${version} on ${PLATFORM}`)
} else {
  const allowed = new Map(allowlist.map((a) => [a.scenario, new Set(a.diff)]))
  const why = new Map(allowlist.map((a) => [a.scenario, a.reason]))
  const reports = await pool(scenarios, async (s) => {
    const [want, got] = await Promise.all([
      PNPM ? install('pnpm', s) : expected.results[s.id],
      install('jpm', s),
    ])
    if (!want) {
      return { fail: true, text: `? ${s.id}: not in expected.json; record it with --record --pnpm <bin>` }
    }
    const diff = compare(want, got)
    const ok = allowed.get(s.id) ?? new Set()
    const stale = [...ok].filter((d) => !diff.includes(d))
    if (!diff.length && !stale.length) {
      return null
    }
    const fail = diff.some((d) => !ok.has(d)) || stale.length > 0
    const lines = [fail ? `FAIL ${s.id}` : `allowed ${s.id} (${why.get(s.id)})`]
    if (got.failed) {
      lines.push(`  jpm: ${got.failed}`)
    }
    if (want.failed) {
      lines.push(`  pnpm: ${want.failed}`)
    }
    lines.push(...diff.map((d) => `  ${ok.has(d) ? ' ' : '!'} ${d}`))
    lines.push(...stale.map((d) => `  ? allowed but not seen: ${d}`))
    return { fail, differs: diff.length > 0, text: lines.join('\n') }
  })
  // An allowlist entry for a scenario that no longer exists is stale too.
  const ids = new Set(scenarios.map((s) => s.id))
  const orphans = ONLY.source === '(?:)' ? allowlist.filter((a) => !ids.has(a.scenario)) : []
  for (const r of reports.filter(Boolean)) {
    console.log(r.text)
  }
  for (const a of orphans) {
    console.log(`FAIL allowlist.json names ${a.scenario}, which scenarios.json does not have`)
  }
  const failures = reports.filter((r) => r?.fail).length + orphans.length
  const differing = reports.filter((r) => r?.differs).length
  console.log(`${scenarios.length} scenarios, ${differing} differ, ${failures} not allowed`)
  process.exitCode = failures ? 1 : 0
}

if (KEEP) {
  console.log(`scratch projects kept in ${scratch}`)
} else {
  // jpm's store is read-only by design: lift that so the scratch directory can go.
  const writable = (dir) => {
    chmodSync(dir, 0o755)
    for (const e of readdirSync(dir)) {
      const at = join(dir, e)
      if (lstatSync(at).isDirectory()) {
        writable(at)
      }
    }
  }
  writable(scratch)
  rmSync(scratch, { recursive: true, force: true })
}
