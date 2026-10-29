import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  SAST_RULES,
  assessAiProvenance,
  assessDependency,
  evaluate,
  findTyposquatTarget,
  parseAddedLines,
  parseManifest,
  renderReport,
  scanFile,
  toSarif,
} from '../src/index'

const DAY_MS = 86_400_000
const NOW = Date.UTC(2026, 9, 29)

function changedFile(filename: string, texts: string[]) {
  return {
    filename,
    previousFilename: undefined,
    status: 'modified',
    addedLines: texts.map((text, i) => ({ line: 10 + i, text })),
  }
}

function pullContext(files: ReturnType<typeof changedFile>[], commits: { sha: string; message: string }[]) {
  return { owner: 'o', repo: 'r', number: 1, baseSha: 'base', headSha: 'head', files, commits }
}

// ---------------------------------------------------------------------------
// Diff parsing
// ---------------------------------------------------------------------------

test('parseAddedLines returns added lines with new-file line numbers', () => {
  const patch = [
    '@@ -1,3 +1,4 @@',
    ' const a = 1',
    '-const b = 2',
    '+const b = 3',
    '+const c = 4',
    ' const d = 5',
    '\\ No newline at end of file',
  ].join('\n')

  assert.deepEqual(parseAddedLines(patch), [
    { line: 2, text: 'const b = 3' },
    { line: 3, text: 'const c = 4' },
  ])
})

test('parseAddedLines handles multiple hunks', () => {
  const patch = ['@@ -1 +1 @@', '+first', '@@ -20,0 +21,2 @@', '+x', '+y'].join('\n')
  assert.deepEqual(
    parseAddedLines(patch).map(line => line.line),
    [1, 21, 22],
  )
})

// ---------------------------------------------------------------------------
// Manifest parsing
// ---------------------------------------------------------------------------

test('parseManifest reads npm dependency sections', () => {
  const deps = parseManifest(
    'package.json',
    JSON.stringify({ dependencies: { lodash: '1' }, devDependencies: { '@scope/tool': '1' } }),
  )
  assert.deepEqual(deps.map(d => [d.ecosystem, d.name]), [
    ['npm', 'lodash'],
    ['npm', '@scope/tool'],
  ])
})

test('parseManifest reads requirements.txt, skipping comments, options and URLs', () => {
  const deps = parseManifest(
    'requirements.txt',
    'Django>=4.2  # web\n-r other.txt\ngit+https://example.com/x.git\nPython_Dateutil==2.9\n',
  )
  assert.deepEqual(deps.map(d => d.name), ['django', 'python-dateutil'])
})

test('parseManifest reads go.mod require blocks and ignores comments', () => {
  const deps = parseManifest(
    'go.mod',
    'module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/Foo/bar v0.1.0 // indirect\n)\nrequire golang.org/x/net v0.20.0\n',
  )
  assert.deepEqual(deps.map(d => d.name), [
    'github.com/gin-gonic/gin',
    'github.com/Foo/bar',
    'golang.org/x/net',
  ])
})

test('parseManifest reads Cargo dependency tables, inline and table forms', () => {
  const deps = parseManifest(
    'Cargo.toml',
    [
      '[package]',
      'name = "x"',
      '[dependencies]',
      'serde = "1"',
      'tokio = { version = "1" }',
      '[dependencies.reqwest]',
      'version = "0.11"',
      '[dev-dependencies]',
      'rand = "0.8"',
    ].join('\n'),
  )
  assert.deepEqual(deps.map(d => d.name), ['serde', 'tokio', 'reqwest', 'rand'])
})

test('parseManifest returns nothing for malformed package.json', () => {
  assert.deepEqual(parseManifest('package.json', '{not json'), [])
})

// ---------------------------------------------------------------------------
// Typosquatting
// ---------------------------------------------------------------------------

test('findTyposquatTarget catches substitutions, transpositions and separator swaps', () => {
  assert.equal(findTyposquatTarget('npm', 'lodsh'), 'lodash')
  assert.equal(findTyposquatTarget('pypi', 'reqeusts'), 'requests')
  assert.equal(findTyposquatTarget('pypi', 'python_dateutil'), 'python-dateutil')
})

test('findTyposquatTarget does not flag popular packages or unrelated names', () => {
  assert.equal(findTyposquatTarget('npm', 'lodash'), undefined)
  assert.equal(findTyposquatTarget('npm', 'mycustomlib'), undefined)
  // Names shorter than five characters are too ambiguous to compare.
  assert.equal(findTyposquatTarget('npm', 'vue'), undefined)
})

// ---------------------------------------------------------------------------
// Dependency verdicts
// ---------------------------------------------------------------------------

const npmDep = (name: string) => ({ ecosystem: 'npm' as const, name, manifest: 'package.json' })
const found = (ageDays?: number) => ({
  status: 'found' as const,
  createdAt: ageDays === undefined ? undefined : new Date(NOW - ageDays * DAY_MS),
  error: undefined,
})

test('assessDependency marks a non-existent package critical', () => {
  const result = assessDependency(npmDep('made-up-pkg'), { status: 'missing', createdAt: undefined, error: undefined }, true, NOW)
  assert.equal(result.severity, 'critical')
  assert.equal(result.label, '❌ Not in registry')
})

test('assessDependency treats unverifiable packages as critical only in strict mode', () => {
  const unknown = { status: 'unknown' as const, createdAt: undefined, error: 'timeout' }
  assert.equal(assessDependency(npmDep('some-lib'), unknown, true, NOW).severity, 'critical')
  assert.equal(assessDependency(npmDep('some-lib'), unknown, false, NOW).severity, 'medium')
})

test('assessDependency rates a typosquat of a new package critical and of an established one high', () => {
  assert.equal(assessDependency(npmDep('lodsh'), found(2), true, NOW).severity, 'critical')
  assert.equal(assessDependency(npmDep('lodsh'), found(2000), true, NOW).severity, 'high')
})

test('assessDependency flags a brand-new package that is otherwise verified', () => {
  const result = assessDependency(npmDep('fresh-lib'), found(3), true, NOW)
  assert.equal(result.severity, 'medium')
  assert.equal(result.label, '⚠️ New package')
})

test('assessDependency leaves an established, verified package clean', () => {
  const result = assessDependency(npmDep('some-lib'), found(900), true, NOW)
  assert.equal(result.severity, undefined)
  assert.equal(result.label, '✅ Verified')
})

// ---------------------------------------------------------------------------
// SAST rules
// ---------------------------------------------------------------------------

function ruleIds(texts: string[]): string[] {
  return scanFile(changedFile('src/a.ts', texts), SAST_RULES).map(f => f.rule)
}

test('scanFile flags a live-format secret and redacts it in the snippet', () => {
  const findings = scanFile(changedFile('src/a.ts', ['const k = "sk-' + 'a'.repeat(40) + '"']), SAST_RULES)
  assert.equal(findings[0].rule, 'live-secret-literal')
  assert.equal(findings[0].severity, 'critical')
  assert.equal(findings[0].snippet, '[REDACTED]')
})

test('scanFile flags placeholder credentials such as sk-test and Bearer test_token', () => {
  assert.ok(ruleIds(['const k = "sk-test_abcdef"']).includes('placeholder-credential'))
  assert.ok(ruleIds(['h = { Authorization: "Bearer test_token" }']).includes('placeholder-credential'))
})

test('scanFile flags interpolated and concatenated SQL but not parameterized queries', () => {
  assert.ok(ruleIds(['const q = `SELECT * FROM t WHERE id = ${id}`']).includes('sql-template-interpolation'))
  assert.ok(ruleIds(['const q = "SELECT * FROM t WHERE id = " + id']).includes('sql-string-concatenation'))
  assert.ok(ruleIds(['const q = "SELECT * FROM users WHERE name = \'" + name + "\'"']).includes('sql-string-concatenation'))
  assert.ok(ruleIds(['cur.execute("SELECT * FROM t WHERE id = %s" % uid)']).includes('sql-string-format'))
  assert.deepEqual(ruleIds(['db.query("SELECT * FROM t WHERE id = ?", [id])']), [])
})

test('scanFile flags an empty catch block, including a multi-line one', () => {
  assert.ok(ruleIds(['try { run() } catch (e) { /* ignore */ }']).includes('empty-catch-block'))
  assert.ok(ruleIds(['try {', '  run()', '} catch (e) {', '}']).includes('empty-catch-block'))
})

test('scanFile maps a multi-line match to the line where it starts', () => {
  const findings = scanFile(changedFile('src/a.ts', ['const ok = 1', 'try { run() } catch (e) {', '}']), SAST_RULES)
  const empty = findings.find(f => f.rule === 'empty-catch-block')
  assert.equal(empty?.line, 11)
})

test('scanFile flags bare Python except blocks and disabled TLS verification', () => {
  assert.ok(ruleIds(['try:', '    x()', 'except:', '    pass']).includes('empty-except-block'))
  assert.ok(ruleIds(['const agent = { rejectUnauthorized: false }']).includes('tls-verification-disabled'))
})

test('scanFile returns nothing for files without added lines', () => {
  assert.deepEqual(scanFile(changedFile('src/a.ts', []), SAST_RULES), [])
})

// ---------------------------------------------------------------------------
// Provenance heuristics
// ---------------------------------------------------------------------------

test('assessAiProvenance scores a plain, human-looking change as clean', () => {
  const ctx = pullContext(
    [changedFile('src/a.ts', ['export const add = (a: number, b: number) => a + b'])],
    [{ sha: '1', message: 'add helper for totals' }],
  )
  const result = assessAiProvenance(ctx)
  assert.equal(result.score, 0)
  assert.equal(result.label, undefined)
})

test('assessAiProvenance labels conversational boilerplate and syntax-restating comments', () => {
  const lines = [
    '// Here is the implementation',
    '// I hope this helps!',
    '// Initialize the counter variable',
    'let count = 0',
    '// Loop through the array',
    'for (const x of xs) count += x',
    '// Increment the counter',
    'count++',
  ]
  const result = assessAiProvenance(
    pullContext([changedFile('src/a.ts', lines)], [{ sha: '1', message: 'add counter' }]),
  )
  assert.ok(result.signals.some(s => s.name === 'Conversational boilerplate in comments'))
  assert.ok(result.signals.some(s => s.name === 'Comments restating basic syntax'))
  assert.ok(result.score >= 25)
  assert.equal(result.label, 'ai-assisted')
})

test('assessAiProvenance flags a monolithic commit touching many files', () => {
  const files = Array.from({ length: 25 }, (_, i) => changedFile(`src/f${i}.ts`, ['const x = 1']))
  const result = assessAiProvenance(pullContext(files, [{ sha: '1', message: 'big change' }]))
  assert.ok(result.signals.some(s => s.name === 'Monolithic commit'))
})

// ---------------------------------------------------------------------------
// Verdict and report
// ---------------------------------------------------------------------------

const cleanAi = { score: 0, label: undefined, signals: [] }

test('evaluate blocks on a critical dependency', () => {
  const dep = assessDependency(npmDep('made-up-pkg'), { status: 'missing', createdAt: undefined, error: undefined }, true, NOW)
  const verdict = evaluate(cleanAi, [dep], [])
  assert.equal(verdict.blocked, true)
  assert.match(verdict.reasons[0], /critical dependency/)
})

test('evaluate blocks on a critical SAST finding but not on a high one', () => {
  const base = { file: 'a.ts', line: 1, message: 'm', snippet: 's' }
  assert.equal(evaluate(cleanAi, [], [{ ...base, rule: 'x', severity: 'high' }]).blocked, false)
  assert.equal(evaluate(cleanAi, [], [{ ...base, rule: 'x', severity: 'critical' }]).blocked, true)
})

test('evaluate blocks when the AI score reaches the critical threshold', () => {
  assert.equal(evaluate({ score: 79, label: undefined, signals: [] }, [], []).blocked, false)
  assert.equal(evaluate({ score: 80, label: undefined, signals: [] }, [], []).blocked, true)
})

test('toSarif maps severities to levels, dedupes rules, and locates dependency findings', () => {
  const findings = [
    { rule: 'empty-catch-block', severity: 'high' as const, file: 'a.ts', line: 3, message: 'm', snippet: 's' },
    { rule: 'wildcard-cors-origin', severity: 'medium' as const, file: 'b.ts', line: 7, message: 'c', snippet: 's' },
    { rule: 'empty-catch-block', severity: 'high' as const, file: 'c.ts', line: 1, message: 'm', snippet: 's' },
  ]
  const dep = assessDependency(npmDep('made-up-pkg'), { status: 'missing', createdAt: undefined, error: undefined }, true, NOW)
  const sarif = toSarif(findings, [dep]) as {
    version: string
    runs: {
      tool: { driver: { rules: { id: string }[] } }
      results: { ruleId: string; level: string; locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[] }[]
    }[]
  }

  assert.equal(sarif.version, '2.1.0')
  const run = sarif.runs[0]
  assert.deepEqual(run.tool.driver.rules.map(r => r.id), ['empty-catch-block', 'wildcard-cors-origin', 'dependency-risk'])
  assert.deepEqual(run.results.map(r => r.level), ['error', 'warning', 'error', 'error'])
  assert.deepEqual(run.results[1].locations[0].physicalLocation, {
    artifactLocation: { uri: 'b.ts' },
    region: { startLine: 7 },
  })
  assert.equal(run.results[3].locations[0].physicalLocation.artifactLocation.uri, 'package.json')
})

test('renderReport includes the marker, verdict, and escapes table pipes', () => {
  const findings = [
    { rule: 'empty-catch-block', severity: 'high' as const, file: 'a|b.ts', line: 3, message: 'm', snippet: 'a | b' },
  ]
  const body = renderReport(cleanAi, [], findings, { blocked: false, reasons: [] })
  assert.ok(body.startsWith('<!-- ai-code-governance:report -->'))
  assert.match(body, /Verdict \| ✅ Passed/)
  assert.ok(body.includes('a\\|b.ts:3'))
})
