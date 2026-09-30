// Writes tests/conformance/semver/*.json from node-semver's test tables.
//
//   git clone https://github.com/npm/node-semver /tmp/node-semver
//   git -C /tmp/node-semver checkout <COMMIT below>
//   node tests/conformance/gen/semver.mjs /tmp/node-semver
//
// Each row keeps the fixture's inputs. Its answer is node-semver's own, asked the way npm asks
// (npm-package-arg and npm-pick-manifest pass `loose: true`), so the tables hold what npm would
// do with that input. A row whose fixture is about strict mode and reads differently loose also
// carries the fixture's strict answer, last, for the record. node-semver is ISC-licensed; its
// license is kept in tests/conformance/semver/LICENSE.

import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = 'https://github.com/npm/node-semver'
const COMMIT = '6e05b7637396ac66522cff8731f07cfe0ef49a29'

const src = resolve(process.argv[2] ?? '')
const head = execFileSync('git', ['-C', src, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
if (head !== COMMIT) {
  throw new Error(`${src} is at ${head}, not ${COMMIT}`)
}
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'semver')
const require = createRequire(join(src, 'package.json'))
const semver = require('./index.js')
const fixture = (name) => require(`./test/fixtures/${name}.js`)

const isOpts = (o) => o !== null && typeof o === 'object' && !(o instanceof RegExp)
const incPrOf = (o) => isOpts(o) && !!o.includePrerelease
const npm = (o) => ({ loose: true, includePrerelease: incPrOf(o) })

// A table's rows, one per line, so a regeneration diffs by row.
const write = (name, columns, rows) => {
  const body = rows.map((r) => '    ' + JSON.stringify(r)).join(',\n')
  const text = `{\n  "source": "${REPO}/tree/${COMMIT}",\n  "columns": ${JSON.stringify(columns)},\n` +
    `  "rows": [\n${body}\n  ]\n}\n`
  writeFileSync(join(out, `${name}.json`), text)
  console.log(`${name}: ${rows.length} rows`)
}

// The loose answer, plus the fixture's own when that differs; a fixture that disagrees with the
// code at its own commit stops the run.
const row = (inputs, want, fixtureWant, ownAnswer) => {
  if (JSON.stringify(ownAnswer) !== JSON.stringify(fixtureWant)) {
    throw new Error(`fixture ${JSON.stringify(inputs)} wants ${fixtureWant}, node-semver says ${ownAnswer}`)
  }
  return JSON.stringify(want) === JSON.stringify(fixtureWant) ? [...inputs, want] : [...inputs, want, fixtureWant]
}

mkdirSync(out, { recursive: true })

write('comparisons', ['greater', 'lesser', 'compare'],
  fixture('comparisons').map(([a, b, o]) =>
    row([a, b], semver.compare(a, b, npm(o)), 1, semver.compare(a, b, o))))

write('equality', ['a', 'b', 'compare'],
  fixture('equality').map(([a, b, o]) =>
    row([a, b], semver.compare(a, b, npm(o)), 0, semver.compare(a, b, o))))

// The parse is [canonical text, prerelease ids]; build ids are not jpm's concern.
write('valid-versions', ['version', 'parse'],
  fixture('valid-versions').map(([v, major, minor, patch, pre]) => {
    const text = `${major}.${minor}.${patch}` + (pre.length ? `-${pre.join('.')}` : '')
    const [loose, strict] = [semver.parse(v, npm()), semver.parse(v)]
    return row([v], [loose.version, loose.prerelease], [text, pre], [strict.version, strict.prerelease])
  }))

// Non-string rows test JavaScript's types, which a Rust &str cannot be.
write('invalid-versions', ['version', 'valid'],
  fixture('invalid-versions').filter(([v]) => typeof v === 'string').map(([v, , o]) =>
    row([v], semver.valid(v, npm(o)), null, semver.valid(v, o))))

write('range-parse', ['range', 'includePrerelease', 'validRange'],
  fixture('range-parse').map(([r, want, o]) =>
    row([r, incPrOf(o)], semver.validRange(r, npm(o)), want, semver.validRange(r, o))))

for (const [name, want] of [['range-include', true], ['range-exclude', false]]) {
  write(name, ['range', 'version', 'includePrerelease', 'satisfies'],
    fixture(name).filter(([, v]) => typeof v === 'string').map(([r, v, o]) =>
      row([r, v, incPrOf(o)], semver.satisfies(v, r, npm(o)), want, semver.satisfies(v, r, o))))
}

write('range-intersection', ['a', 'b', 'intersects'],
  fixture('range-intersection').map(([a, b, want]) =>
    row([a, b], semver.intersects(a, b, npm()), want, semver.intersects(a, b))))

write('comparator-intersection', ['a', 'b', 'includePrerelease', 'intersects'],
  fixture('comparator-intersection').map(([a, b, want, incPr]) => {
    const o = { includePrerelease: !!incPr }
    return row([a, b, !!incPr], semver.intersects(a, b, npm(o)), want, semver.intersects(a, b, o))
  }))
