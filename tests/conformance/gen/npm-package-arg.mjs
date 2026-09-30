// Writes tests/conformance/npm-package-arg/*.json from npm-package-arg's own tests.
//
//   git clone https://github.com/npm/npm-package-arg <dir>
//   git -C <dir> checkout <COMMIT>
//   node tests/conformance/gen/npm-package-arg.mjs <dir>
//
// Each test file runs against a stub of tap and of npa itself: the stub records every spec a
// test hands npa and every expectation the test asserts on the result (`t.has`, `t.match`,
// `t.equal` on a field, `t.throws` around the call). Nothing of npm-package-arg's own code runs,
// so its dependencies need not be installed and the output is the same on every platform.

import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const COMMIT = '31dc824945365794c9569037805a0727026647d4'
const REPO = 'https://github.com/npm/npm-package-arg'
// Which platform's reading each file pins; the rest hold everywhere.
const FILES = {
  'basic.js': 'any',
  'github.js': 'any',
  'gitlab.js': 'any',
  'bitbucket.js': 'any',
  'invalid-url.js': 'any',
  'realize-package-specifier.js': 'any',
  'posix.js': 'posix',
  'windows.js': 'win32',
}

const src = process.argv[2]
if (!src) {
  console.error('usage: node npm-package-arg.mjs <npm-package-arg checkout>')
  process.exit(2)
}
const head = execFileSync('git', ['-C', src, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
if (head !== COMMIT) {
  console.error(`${src} is at ${head}, not ${COMMIT}`)
  process.exit(1)
}
const out = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'npm-package-arg')
mkdirSync(out, { recursive: true })

const CASE = Symbol('case')
const TOKEN = 'npa-case:'

function harness (file, platform) {
  const cases = []
  let names = []
  let throwing = null
  let teardowns = []

  // A value read off a recorded result: remembers which case and which field.
  const field = (c, path) => new Proxy(function () {}, {
    get (_, key) {
      if (key === CASE) {
        return { c, path }
      }
      if (key === 'replace') {
        return () => field(c, path)
      }
      if (typeof key === 'symbol') {
        return undefined
      }
      return field(c, [...path, key])
    },
    apply () {
      return field(c, path)
    },
  })

  const record = (input) => {
    const c = { test: names.join(' > '), input, platform }
    if (throwing) {
      c.throws = throwing
    }
    cases.push(c)
    return new Proxy({}, {
      get (_, key) {
        if (key === CASE) {
          return { c, path: [] }
        }
        if (typeof key === 'symbol') {
          return undefined
        }
        if (key === 'toString') {
          return () => field(c, ['toString'])
        }
        // gitlab.js compares `JSON.parse(JSON.stringify(res))`: a token that finds the case again.
        if (key === 'toJSON') {
          return () => TOKEN + cases.indexOf(c)
        }
        return field(c, [key])
      },
      set () {
        return true
      },
    })
  }

  const makeNpa = (mocked) => {
    const npa = (arg, where) => {
      const input = typeof arg === 'string' ? { arg } : { object: true }
      return record({ ...input, where: where ?? null, mocked })
    }
    npa.resolve = (name, spec, where) => record({ name, spec, where: where ?? null, mocked })
    npa.Result = class {
      toString () {
        return ''
      }
    }
    npa.toPurl = () => null
    return npa
  }

  // Sets `expect` at `path` on the case `actual` came from.
  const expect = (actual, expected) => {
    const at = typeof actual === 'string' && actual.startsWith(TOKEN)
      ? { c: cases[Number(actual.slice(TOKEN.length))], path: [] }
      : actual && actual[CASE]
    if (!at) {
      return
    }
    const { c, path } = at
    if (path.length === 0) {
      if (expected && typeof expected === 'object') {
        c.expect = { ...c.expect, ...expected }
      }
      return
    }
    c.expect = c.expect || {}
    let o = c.expect
    for (const k of path.slice(0, -1)) {
      o = o[k] = o[k] || {}
    }
    o[path[path.length - 1]] = expected
  }

  const t = {
    test (name, ...rest) {
      const fn = rest.find(f => typeof f === 'function')
      names.push(name)
      fn(t)
      names.pop()
    },
    mock (_, mocks) {
      // Only `path` swapped for posix is npa as it is; any other mock breaks it on purpose.
      return makeNpa(Object.keys(mocks || {}).some(k => k !== 'path'))
    },
    has: expect,
    match: expect,
    equal: expect,
    same: expect,
    throws (fn, want) {
      const w = want && typeof want === 'object' ? want : {}
      throwing = { ...(w.code ? { code: w.code } : {}), ...(w.message ? { message: w.message } : {}) }
      try {
        fn()
      } finally {
        throwing = null
      }
    },
    teardown (fn) {
      teardowns.push(fn)
    },
    ok () {},
    not () {},
    comment () {},
    end () {},
    plan () {},
    setMaxListeners () {},
  }
  t.test.test = t.test
  const tap = Object.assign((...a) => t.test(...a), t, { test: (...a) => t.test(...a) })

  const require = createRequire(join(src, 'test', file))
  const npa = makeNpa(false)
  const fake = {
    tap,
    '..': npa,
    // A fixed home: the `file:~/` cases name it.
    'node:os': { homedir: () => '/home/user' },
  }
  const req = (id) => (id in fake ? fake[id] : require(id))
  const code = readFileSync(join(src, 'test', file), 'utf8')
  const platformBefore = Object.getOwnPropertyDescriptor(process, 'platform')
  const cwdBefore = process.cwd
  try {
    // eslint-disable-next-line no-new-func
    new Function('require', 'module', 'exports', code)(req, { exports: {} }, {})
    for (const fn of teardowns) {
      fn()
    }
  } finally {
    Object.defineProperty(process, 'platform', platformBefore)
    process.cwd = cwdBefore
    teardowns = []
    names = []
  }
  // What the tests pin down about a spec string: a spec object, a result fed back to npa, or
  // npa with its url parser broken tests npa's code, not the reading of a spec.
  return cases
    .filter(c => !c.input.object && !c.input.mocked && (c.expect || c.throws))
    .map(({ test, input: { arg, name, spec, where }, platform, expect, throws }) => {
      const row = { test }
      if (arg !== undefined) {
        row.arg = arg
      } else {
        row.name = name
        row.spec = spec
      }
      row.where = where
      row.platform = platform
      if (throws) {
        row.throws = throws
      } else {
        delete expect.toString
        row.expect = expect
      }
      return row
    })
}

let total = 0
for (const [file, platform] of Object.entries(FILES)) {
  const rows = harness(file, platform)
  total += rows.length
  writeFileSync(join(out, file.replace(/\.js$/, '.json')), JSON.stringify(rows, null, 2) + '\n')
}
// As committed, whatever line endings the checkout has.
writeFileSync(join(out, 'LICENSE'), execFileSync('git', ['-C', src, 'show', `${COMMIT}:LICENSE`]))
console.log(`${total} cases from ${REPO} at ${COMMIT}`)
