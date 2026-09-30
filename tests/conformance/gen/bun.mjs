// Extracts the bun.lock files in bun's install tests into tests/conformance/bun/lockfiles.json.
//
//   git clone --filter=blob:none --no-checkout https://github.com/oven-sh/bun
//   git -C bun sparse-checkout set --no-cone test/cli/install/
//   git -C bun checkout <COMMIT>
//   node tests/conformance/gen/bun.mjs bun
//
// A bun.lock is found three ways: a `bun.lock` file among the fixtures, a snapshot of one bun
// wrote (`__snapshots__/*.snap`, and inline snapshots), or one a test writes out, as a template
// literal or an object literal. The sources are TypeScript, which is not run: each literal
// around a `lockfileVersion` is cut out and evaluated alone, any name it reads from the test's
// scope standing in as `PLACEHOLDER`. The innermost that comes out as a lockfile (an object with
// a numeric `lockfileVersion` and `workspaces` or `packages`) is kept, once per distinct text.
//
// Each case gets a package.json: the fixture's own where there is one, else the one bun wrote
// the lockfile from, as bun records it in `workspaces[""]` (its groups, peers and optional
// peers) with the overrides, patches and catalogs recorded beside it.

import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const COMMIT = '2722608f474a2d9468e9d1ac3a1eb2fe6e630901'
const ROOT = 'test/cli/install'

const src = process.argv[2]
if (!src) {
  console.error('usage: node bun.mjs <bun checkout>')
  process.exit(1)
}
const head = execFileSync('git', ['-C', src, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
if (head !== COMMIT) {
  console.error(`${src} is at ${head}, not the pinned ${COMMIT}`)
  process.exit(1)
}

function walk (dir, out = []) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      if (name !== 'node_modules') walk(path, out)
    } else {
      out.push(path)
    }
  }
  return out
}

// --- literals in TypeScript -------------------------------------------------------------

// Spans of string, template and brace literals, found by a scan that knows comments, regexes
// and `${}` inside templates: enough for bun's tests, not a parser.
function literals (text) {
  const spans = []
  const stack = [] // { kind: 'brace' | 'interp', at }
  let i = 0
  let last = '' // the last significant character in code, to tell a regex from a division
  const code = () => {
    while (i < text.length) {
      const c = text[i]
      const n = text[i + 1]
      if (c === '/' && n === '/') {
        i = text.indexOf('\n', i)
        if (i < 0) i = text.length
      } else if (c === '/' && n === '*') {
        i = text.indexOf('*/', i + 2) + 2
        if (i < 2) i = text.length
      } else if (c === '"' || c === "'") {
        const at = i++
        while (i < text.length && text[i] !== c && text[i] !== '\n') i += text[i] === '\\' ? 2 : 1
        i++
        spans.push({ start: at, end: i })
        last = c
      } else if (c === '`') {
        template()
        last = '`'
      } else if (c === '/' && (last === '' || '(,=:[!&|?{};+-*%<>~^'.includes(last) || /\breturn\s*$/.test(text.slice(Math.max(0, i - 8), i)))) {
        i++
        let cls = false
        while (i < text.length && text[i] !== '\n' && (cls || text[i] !== '/')) {
          if (text[i] === '\\') i++
          else if (text[i] === '[') cls = true
          else if (text[i] === ']') cls = false
          i++
        }
        i++
        while (/[a-z]/.test(text[i] ?? '')) i++
        last = '/'
      } else if (c === '{') {
        stack.push({ kind: 'brace', at: i })
        i++
        last = c
      } else if (c === '}') {
        const top = stack.pop()
        i++
        if (top?.kind === 'interp') return
        if (top) spans.push({ start: top.at, end: i })
        last = c
      } else {
        if (!/\s/.test(c)) last = c
        i++
      }
    }
  }
  const template = () => {
    const at = i++
    while (i < text.length) {
      const c = text[i]
      if (c === '\\') {
        i += 2
      } else if (c === '`') {
        i++
        spans.push({ start: at, end: i })
        return
      } else if (c === '$' && text[i + 1] === '{') {
        i += 2
        stack.push({ kind: 'interp', at: i })
        last = '{'
        code()
      } else {
        i++
      }
    }
  }
  code()
  return spans
}

// Any name the literal reads that is not a global: callable, and `PLACEHOLDER` as text.
const placeholder = new Proxy(function () {}, {
  get (_, key) {
    if (key === Symbol.toPrimitive || key === 'toString') return () => 'PLACEHOLDER'
    if (key === 'toJSON') return () => 'PLACEHOLDER'
    return placeholder
  },
  apply () {
    return placeholder
  },
})
const scope = new Proxy({}, {
  has (_, key) {
    return typeof key === 'string' && !(key in globalThis)
  },
  get (_, key) {
    // A lockfile built by a function of its version: bun reads 1 and 2 alike.
    if (key === 'lockfileVersion') return 1
    return key === Symbol.unscopables ? undefined : placeholder
  },
})

function evaluate (source) {
  try {
    // eslint-disable-next-line no-new-func
    return new Function('scope', `with (scope) { return (${source}\n) }`)(scope)
  } catch {
    return undefined
  }
}

// A lockfile's text as bun writes it: JSON, with trailing commas.
function parseLock (text) {
  try {
    return JSON.parse(stripTrailingCommas(text))
  } catch {
    return undefined
  }
}

function stripTrailingCommas (text) {
  let out = ''
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (inString) {
      if (c === '\\') {
        out += c + text[++i]
        continue
      }
      if (c === '"') inString = false
    } else if (c === '"') {
      inString = true
    } else if (c === ',' && /^\s*[}\]]/.test(text.slice(i + 1))) {
      continue
    }
    out += c
  }
  return out
}

// package-lock.json has a numeric lockfileVersion and packages too, each an object.
// One whose map a name from the test's scope stood in for is left out: its shape is not bun's.
const isMap = (v) => v === undefined || (v !== null && typeof v === 'object' && !Array.isArray(v))
const GROUPS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
const isLock = (v) =>
  isMap(v) && typeof v?.lockfileVersion === 'number' &&
  (typeof v.workspaces === 'object' || typeof v.packages === 'object') &&
  [v.packages, v.overrides, v.workspaces].every(isMap) &&
  Object.values(v.packages ?? {}).every(Array.isArray) &&
  Object.values(v.workspaces ?? {}).every((w) => isMap(w) && GROUPS.every((g) => isMap(w[g])))

// The lockfile a literal's value is, as its text: a string as written (a snapshot's is quoted
// once more), an object as `JSON.stringify` writes it.
function lockText (value) {
  if (typeof value === 'string') {
    let text = value.trim()
    if (text.startsWith('"') && text.endsWith('"')) text = text.slice(1, -1).trim()
    // A migration snapshot has bun's output above the lockfile.
    const at = text.indexOf('\n{\n')
    if (!text.startsWith('{') && at >= 0) text = text.slice(at + 1, text.lastIndexOf('}') + 1)
    return isLock(parseLock(text)) ? text + '\n' : undefined
  }
  return isLock(value) ? JSON.stringify(value, null, 2) + '\n' : undefined
}

// The test around `at`: the title of the nearest `it(`, `test(` or snapshot export before it.
function titleAt (text, at) {
  const before = text.slice(0, at)
  const re = /(?:\b(?:it|test|describe)(?:\.\w+)*\s*\(\s*|exports\[)(["'`])((?:\\.|(?!\1).)*)\1/g
  let title = ''
  for (const m of before.matchAll(re)) title = m[2]
  return title.replace(/\\`/g, '`')
}

// --- the cases --------------------------------------------------------------------------

const cases = []
const seen = new Map()

function add (name, from, text, manifest) {
  if (seen.has(text)) {
    seen.get(text).also.push(from)
    return
  }
  const lock = parseLock(text)
  // Names are what the Rust test's tables key on: one test writing two lockfiles numbers them.
  const taken = new Set(cases.map((c) => c.name))
  let unique = name
  for (let n = 2; taken.has(unique); n++) unique = `${name} #${n}`
  const c = { name: unique, from, also: [], 'package.json': manifest ?? manifestOf(lock), 'bun.lock': text }
  seen.set(text, c)
  cases.push(c)
}

// The package.json bun wrote a lockfile from, as it records it.
function manifestOf (lock) {
  const root = lock.workspaces?.[''] ?? {}
  const out = {}
  for (const key of ['name', 'version', 'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    if (root[key] !== undefined) out[key] = root[key]
  }
  if (Array.isArray(root.optionalPeers) && root.optionalPeers.length) {
    out.peerDependenciesMeta = Object.fromEntries(root.optionalPeers.map((p) => [p, { optional: true }]))
  }
  const others = Object.keys(lock.workspaces ?? {}).filter((w) => w !== '')
  if (others.length) out.workspaces = others
  if (lock.overrides !== undefined) out.overrides = lock.overrides
  if (lock.patchedDependencies !== undefined) out.patchedDependencies = lock.patchedDependencies
  if (lock.catalog !== undefined) out.catalog = lock.catalog
  if (lock.catalogs !== undefined) out.catalogs = lock.catalogs
  return out
}

const base = join(src, ROOT)
const files = walk(base)
const rel = (p) => relative(src, p).split('\\').join('/')

// Fixture files, beside their package.json.
for (const file of files.filter((f) => f.endsWith('/bun.lock') || f.endsWith('\\bun.lock'))) {
  const text = readFileSync(file, 'utf8')
  const pkg = join(dirname(file), 'package.json')
  const manifest = existsSync(pkg) ? JSON.parse(readFileSync(pkg, 'utf8')) : undefined
  add(rel(dirname(file)).slice(ROOT.length + 1), rel(file), text, manifest)
}

// Literals in the tests and snapshots.
let skipped = 0
for (const file of files.filter((f) => /\.(ts|snap)$/.test(f))) {
  const text = readFileSync(file, 'utf8')
  if (!text.includes('lockfileVersion')) continue
  const spans = literals(text).sort((a, b) => a.end - a.start - (b.end - b.start))
  const hits = [...text.matchAll(/lockfileVersion/g)].map((m) => m.index)
  const taken = new Set()
  for (const at of hits) {
    let found
    for (const s of spans) {
      if (s.start > at || s.end <= at) continue
      if (taken.has(s.start)) {
        found = 'taken'
        break
      }
      const t = lockText(evaluate(text.slice(s.start, s.end)))
      if (t !== undefined) {
        taken.add(s.start)
        found = t
        const line = text.slice(0, s.start).split('\n').length
        add(titleAt(text, s.start), `${rel(file)}:${line}`, t)
        break
      }
    }
    if (found === undefined) {
      skipped++
      if (process.env.DEBUG) {
        const line = text.slice(0, at).split('\n').length
        console.log(`${rel(file)}:${line}: ${text.slice(at - 40, at + 40).replace(/\s+/g, ' ')}`)
      }
    }
  }
}

const out = dirname(fileURLToPath(import.meta.url)) + '/../bun/lockfiles.json'
writeFileSync(out, JSON.stringify(cases, null, 1) + '\n')
console.log(`${cases.length} lockfiles written to ${out}; ${skipped} mentions of lockfileVersion were no lockfile`)
