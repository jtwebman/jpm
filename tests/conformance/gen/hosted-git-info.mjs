// Extracts hosted-git-info's test cases into tests/conformance/hosted-git-info/*.json.
//
//   git clone https://github.com/npm/hosted-git-info && git -C hosted-git-info checkout <COMMIT>
//   node tests/conformance/gen/hosted-git-info.mjs path/to/hosted-git-info
//
// Each test file runs with node:test stubbed: its `valid` and `invalid` tables (and
// invalid.js's `urls`) are read from its own scope, and every string the tests hand to
// `fromUrl` is recorded. What the library at the pinned commit returns for each input is the
// expectation, and the tests are run too, so a table that no longer holds fails here.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import Module, { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert'

const REPO = 'https://github.com/npm/hosted-git-info'
const COMMIT = '8c3bebb5e42142b7bce06b085b4c1bd1adba7371'
// The files read: the rest test fromManifest, parseUrl's internals or hosts added at run time.
const FILES = ['github', 'gitlab', 'bitbucket', 'sourcehut', 'gist', 'invalid']

const src = process.argv[2]
if (!src) {
  console.error('usage: node hosted-git-info.mjs <hosted-git-info checkout>')
  process.exit(1)
}
const head = execFileSync('git', ['-C', src, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
if (head !== COMMIT) {
  console.error(`${src} is at ${head}, not the pinned ${COMMIT}`)
  process.exit(1)
}

// lru-cache is its one dependency, and only a cache: a Map does.
const load = Module._load
Module._load = function (request, ...rest) {
  if (request === 'lru-cache') {
    return { LRUCache: class extends Map { constructor () { super() } } }
  }
  return load.call(this, request, ...rest)
}
const req = createRequire(join(src, 'package.json'))
const HostedGit = req('./lib/index.js')

const describe = (input) => {
  const h = HostedGit.fromUrl(input)
  if (!h) {
    return null
  }
  return {
    type: h.type,
    user: h.user,
    project: h.project,
    committish: h.committish,
    auth: h.auth,
    default: h.default,
    https: h.https(),
    sshurl: h.sshurl(),
    tarball: h.tarball(),
  }
}

const out = dirname(fileURLToPath(import.meta.url)) + '/../hosted-git-info'
let total = 0
for (const name of FILES) {
  const file = join(src, 'test', `${name}.js`)
  const tests = []
  const calls = []
  const recording = new Proxy(HostedGit, {
    get (target, prop) {
      if (prop === 'fromUrl') {
        return (u, opts) => {
          if (typeof u === 'string') {
            calls.push(u)
          }
          return target.fromUrl(u, opts)
        }
      }
      return Reflect.get(target, prop)
    },
  })
  const stubs = {
    'node:test': { test: (title, fn) => tests.push([title, fn]) },
    'node:assert': assert,
    '..': recording,
  }
  const body = readFileSync(file, 'utf8') + `
;return {
  valid: typeof valid === 'undefined' ? undefined : valid,
  invalid: typeof invalid === 'undefined' ? undefined : invalid,
  urls: typeof urls === 'undefined' ? undefined : urls,
}`
  // eslint-disable-next-line no-new-func
  const tables = new Function('require', 'module', 'exports', body)(
    (m) => stubs[m] ?? req(m), { exports: {} }, {})
  for (const [title, fn] of tests) {
    try {
      await fn()
    } catch (e) {
      throw new Error(`${name}.js: "${title}" fails at ${COMMIT}: ${e.message}`)
    }
  }

  const cases = []
  const seen = new Set()
  const add = (input, from) => {
    if (typeof input !== 'string' || seen.has(input)) {
      return
    }
    seen.add(input)
    cases.push({ input, from, expect: describe(input) })
  }
  for (const input of Object.keys(tables.valid ?? {})) {
    add(input, 'valid')
  }
  for (const input of [...(tables.invalid ?? []), ...(tables.urls ?? [])]) {
    add(input, 'invalid')
  }
  for (const input of calls) {
    add(input, 'call')
  }
  for (const c of cases) {
    assert.equal(c.expect === null, c.from === 'invalid', `${name}.js: ${c.input}`)
  }
  total += cases.length
  const doc = {
    source: `${REPO}/blob/${COMMIT}/test/${name}.js`,
    commit: COMMIT,
    license: 'ISC',
    cases,
  }
  writeFileSync(join(out, `${name}.json`), JSON.stringify(doc, null, 2) + '\n')
  console.log(`${name}.json: ${cases.length} cases`)
}
console.log(`${total} cases`)
