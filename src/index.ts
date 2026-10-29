import * as core from '@actions/core'
import * as github from '@actions/github'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'

/*
 * AI Code Governance Action
 *
 * Deterministic guardrails for pull requests that contain AI-assisted or
 * LLM-generated code. Every check here is a rule that can be read, tested and
 * reproduced. Provenance heuristics are advisory (they only route and label the
 * PR); dependency verification and insecure-pattern rules are the enforcing gates.
 *
 * Modules:
 *   1. AI contribution & provenance heuristics  -> labels + risk score
 *   2. Hallucinated / typosquatted dependencies -> registry verification
 *   3. Insecure-pattern SAST rules              -> added-line scanning
 *   4. Enforcement & reporting                  -> PR comment, outputs, exit status
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = 'low' | 'medium' | 'high' | 'critical'
type Octokit = ReturnType<typeof github.getOctokit>
type Ecosystem = 'npm' | 'pypi' | 'go' | 'crates'
type RegistryStatus = 'found' | 'missing' | 'unknown'
type AiLabel = 'ai-generated' | 'ai-assisted'

interface Config {
  token: string
  failOnRisk: boolean
  strictDependencyCheck: boolean
  customRulesPath: string | undefined
}

interface AddedLine {
  line: number
  text: string
}

interface ChangedFile {
  filename: string
  previousFilename: string | undefined
  status: string
  addedLines: AddedLine[]
}

interface CommitInfo {
  sha: string
  message: string
}

interface PullContext {
  owner: string
  repo: string
  number: number
  baseSha: string
  headSha: string
  files: ChangedFile[]
  commits: CommitInfo[]
}

interface AiSignal {
  name: string
  points: number
  detail: string
}

interface AiAssessment {
  score: number
  label: AiLabel | undefined
  signals: AiSignal[]
}

interface Dependency {
  ecosystem: Ecosystem
  name: string
  manifest: string
}

interface RegistryResult {
  status: RegistryStatus
  createdAt: Date | undefined
  error: string | undefined
}

interface DependencyAssessment {
  dependency: Dependency
  severity: Severity | undefined
  label: string
  typosquatOf: string | undefined
  notes: string[]
}

interface SastRule {
  id: string
  severity: Severity
  message: string
  pattern: RegExp
  redact: boolean
}

interface SastFinding {
  rule: string
  severity: Severity
  file: string
  line: number
  message: string
  snippet: string
}

interface Verdict {
  blocked: boolean
  reasons: string[]
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

const REPORT_MARKER = '<!-- ai-code-governance:report -->'
const LABEL_COLOR = '5319e7'
const LABEL_DESCRIPTIONS: Record<AiLabel, string> = {
  'ai-generated': 'Pull request contents show strong signs of LLM generation',
  'ai-assisted': 'Pull request contents show some signs of AI assistance',
}

const LABEL_GENERATED_THRESHOLD = 60
const LABEL_ASSISTED_THRESHOLD = 25
const CRITICAL_SCORE_THRESHOLD = 80

const NEW_PACKAGE_AGE_DAYS = 30
const MAX_REGISTRY_LOOKUPS = 150
const REGISTRY_CONCURRENCY = 8
const REGISTRY_TIMEOUT_MS = 10_000
const MAX_REPORT_ROWS = 50

// Files whose added lines are not scanned (docs, lockfiles, binaries, generated bundles).
const EXCLUDED_FILE =
  /\.(md|mdx|txt|lock|snap|svg|png|jpe?g|gif|pdf|min\.js)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|poetry\.lock)$/i

const COMMENT_LINE = /^\s*(?:\/\/|#|\/\*|\*|<!--|--|;)/
const GENERIC_COMMIT_MESSAGE =
  /^(?:update|updates|fix|fixes|changes?|wip|misc|cleanup|refactor|minor fixes?|code updates?|apply (?:suggested )?changes?|address (?:review )?comments?)\.?$/i

const AI_BOILERPLATE: RegExp[] = [
  /\bhere(?:'s| is| are) (?:the|an?|your|my|updated|complete|refactored|fixed|corrected) (?:implementation|code|solution|example|version|updated|complete|refactored|fixed|corrected)\b/i,
  /\b(?:as an ai(?: language)? model|i hope this helps|let me know if you (?:need|want|have)|feel free to (?:adjust|modify|ask))\b/i,
  /\b(?:certainly|absolutely|sure)!\s/i,
]

const VERBOSE_SYNTAX_COMMENT =
  /^\s*(?:\/\/|#|\*|\/\*)\s*(?:Initialize|Import|Define|Declare|Create a new|Loop through|Iterate (?:over|through)|Increment|Decrement|Return the|Set the|Get the|Check if|Assign|Call the|This (?:function|method|class|variable|constant) (?:is used to|will|returns|takes))\b/i

const PLACEHOLDER_MARKER = /\b(?:TODO: implement|FIXME: replace|replace with your|your[-_ ]?api[-_ ]?key here)\b/i

// Small seed lists of widely used packages, used only as typosquatting reference points.
const POPULAR_PACKAGES: Record<Ecosystem, string[]> = {
  npm: [
    'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug', 'moment',
    'request', 'underscore', 'bluebird', 'webpack', 'typescript', 'eslint', 'jest', 'mocha',
    'prettier', 'dotenv', 'uuid', 'yargs', 'minimist', 'semver', 'glob', 'rimraf', 'body-parser',
    'cors', 'jsonwebtoken', 'bcrypt', 'mongoose', 'sequelize', 'socket.io', 'vue', 'next',
    'nodemon', 'node-fetch', 'cheerio', 'puppeteer', 'zod', 'dayjs', 'qs', 'inquirer', 'ora',
    'fs-extra', 'classnames', 'tailwindcss', 'vite',
  ],
  pypi: [
    'requests', 'urllib3', 'numpy', 'pandas', 'django', 'flask', 'boto3', 'botocore', 'setuptools',
    'pyyaml', 'six', 'pytest', 'scipy', 'matplotlib', 'pillow', 'sqlalchemy', 'cryptography',
    'beautifulsoup4', 'selenium', 'fastapi', 'pydantic', 'httpx', 'aiohttp', 'celery', 'click',
    'jinja2', 'tensorflow', 'torch', 'scikit-learn', 'openai', 'anthropic', 'langchain',
    'python-dateutil', 'certifi', 'charset-normalizer',
  ],
  go: [
    'github.com/gin-gonic/gin', 'github.com/spf13/cobra', 'github.com/sirupsen/logrus',
    'github.com/stretchr/testify', 'github.com/gorilla/mux', 'github.com/go-chi/chi',
    'github.com/google/uuid', 'github.com/spf13/viper', 'github.com/redis/go-redis',
    'github.com/lib/pq', 'github.com/jackc/pgx', 'golang.org/x/net', 'golang.org/x/crypto',
  ],
  crates: [
    'serde', 'serde_json', 'tokio', 'rand', 'clap', 'regex', 'reqwest', 'anyhow', 'thiserror',
    'log', 'chrono', 'hyper', 'axum', 'syn', 'quote', 'futures', 'bytes', 'tracing', 'once_cell',
    'lazy_static',
  ],
}

// Built-in insecure-pattern rules. Keyword rules are case-sensitive on purpose:
// SQL keywords in uppercase are the common LLM output and this avoids matching
// ordinary identifiers such as `select(` or `update(`.
export const SAST_RULES: SastRule[] = [
  {
    id: 'live-secret-literal',
    severity: 'critical',
    message: 'Hardcoded credential that matches a live provider key format',
    pattern: /\b(?:sk-(?!(?:test|fake|dummy|example|placeholder|your)[-_])[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,})\b/,
    redact: true,
  },
  {
    id: 'placeholder-credential',
    severity: 'high',
    message: 'Placeholder or test credential committed to source (e.g. sk-…, Bearer test_token)',
    pattern: /\b(?:sk-(?:test|fake|dummy|example|placeholder|your[-_]?key)[\w-]*|Bearer\s+(?:test|fake|dummy|placeholder|example|your)[\w-]*|(?:api[_-]?key|secret|token|password)["']?\s*[:=]\s*["'](?:test|dummy|fake|placeholder|changeme|x{3,}|your[-_][\w-]*)[^"'\n]*["'])/i,
    redact: true,
  },
  {
    id: 'sql-template-interpolation',
    severity: 'high',
    message: 'Unparameterized SQL: template literal interpolation inside a query string',
    pattern: /`[^`\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`\n]*\$\{[^`\n]*`/,
    redact: false,
  },
  {
    id: 'sql-string-concatenation',
    severity: 'high',
    message: 'Unparameterized SQL: string concatenation inside a query string',
    // The closing quote must match the opening one, so a query containing the other quote type still matches.
    pattern: /(["'])(?:(?!\1)[^\n])*?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b(?:(?!\1)[^\n])*?\1\s*\+\s*[A-Za-z_$(]/,
    redact: false,
  },
  {
    id: 'sql-string-format',
    severity: 'high',
    message: 'Unparameterized SQL: %-formatting, .format() or f-string interpolation inside a query',
    pattern: /(?:\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*["']\s*(?:%\s*[\w(]|\.format\s*\()|\bf["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*\{)/,
    redact: false,
  },
  {
    id: 'empty-catch-block',
    severity: 'high',
    message: 'Exception swallowed silently (empty catch block)',
    pattern: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?:(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)\s*)*\}/,
    redact: false,
  },
  {
    id: 'empty-except-block',
    severity: 'high',
    message: 'Exception swallowed silently (bare or empty except block)',
    pattern: /\bexcept(?:\s+[\w.(), ]+)?(?:\s+as\s+\w+)?:\s*(?:#[^\n]*\s*)*(?:pass|\.\.\.)(?=\s*(?:\n|$))/,
    redact: false,
  },
  {
    id: 'shell-command-injection',
    severity: 'high',
    message: 'Possible command injection: interpolated value passed to a shell or exec call',
    pattern: /\bexec(?:Sync)?\s*\(\s*`[^`\n]*\$\{|\bsubprocess\.\w+\([^)\n]*shell\s*=\s*True/,
    redact: false,
  },
  {
    id: 'tls-verification-disabled',
    severity: 'high',
    message: 'TLS certificate verification disabled',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False/,
    redact: false,
  },
  {
    id: 'dynamic-code-execution',
    severity: 'medium',
    message: 'Dynamic code execution (eval / new Function)',
    pattern: /\b(?:eval|new Function)\s*\(/,
    redact: false,
  },
  {
    id: 'wildcard-cors-origin',
    severity: 'medium',
    message: 'Wildcard CORS origin',
    pattern: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i,
    redact: false,
  },
]

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function maxSeverity(current: Severity | undefined, next: Severity): Severity {
  return current === undefined || SEVERITY_RANK[next] > SEVERITY_RANK[current] ? next : current
}

function hasStatus(error: unknown, status: number): boolean {
  return typeof error === 'object' && error !== null && 'status' in error && (error as { status: unknown }).status === status
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && value in SEVERITY_RANK
}

function scannableFiles(ctx: PullContext): ChangedFile[] {
  return ctx.files.filter(file => file.status !== 'removed' && !EXCLUDED_FILE.test(file.filename))
}

async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++
      results[index] = await fn(items[index])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}

async function bestEffort(label: string, action: () => Promise<void>): Promise<void> {
  try {
    await action()
  } catch (error) {
    core.warning(`${label} failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

// ---------------------------------------------------------------------------
// Input and pull request data
// ---------------------------------------------------------------------------

function readConfig(): Config {
  return {
    token: core.getInput('github-token', { required: true }),
    failOnRisk: core.getBooleanInput('fail-on-risk'),
    strictDependencyCheck: core.getBooleanInput('strict-dependency-check'),
    customRulesPath: core.getInput('custom-rules-path') || undefined,
  }
}

/** Converts a unified diff patch into the added lines with their new-file line numbers. */
export function parseAddedLines(patch: string): AddedLine[] {
  const added: AddedLine[] = []
  let newLine = 0
  let inHunk = false

  for (const raw of patch.split('\n')) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw)
    if (hunk) {
      newLine = Number(hunk[1])
      inHunk = true
      continue
    }
    if (!inHunk || raw.startsWith('\\')) continue

    if (raw.startsWith('+')) {
      added.push({ line: newLine, text: raw.slice(1) })
      newLine++
    } else if (!raw.startsWith('-')) {
      newLine++
    }
  }
  return added
}

async function loadPullContext(octokit: Octokit): Promise<PullContext> {
  const { owner, repo } = github.context.repo
  const number = github.context.payload.pull_request?.number
  if (typeof number !== 'number') {
    throw new Error('This action must run on a pull_request event.')
  }

  const pr = await octokit.rest.pulls.get({ owner, repo, pull_number: number })
  const rawFiles = await octokit.paginate(octokit.rest.pulls.listFiles, { owner, repo, pull_number: number, per_page: 100 })
  const rawCommits = await octokit.paginate(octokit.rest.pulls.listCommits, { owner, repo, pull_number: number, per_page: 100 })

  const files: ChangedFile[] = rawFiles.map(file => {
    if (file.patch === undefined && file.status !== 'removed') {
      core.warning(`No diff available for ${file.filename} (binary or too large); its content is not scanned.`)
    }
    return {
      filename: file.filename,
      previousFilename: file.previous_filename,
      status: file.status,
      addedLines: file.patch ? parseAddedLines(file.patch) : [],
    }
  })

  return {
    owner,
    repo,
    number,
    baseSha: pr.data.base.sha,
    headSha: pr.data.head.sha,
    files,
    commits: rawCommits.map(commit => ({
      sha: commit.sha,
      message: commit.commit.message.split('\n')[0],
    })),
  }
}

// ---------------------------------------------------------------------------
// Module 1: AI contribution & provenance heuristics
// ---------------------------------------------------------------------------

export function assessAiProvenance(ctx: PullContext): AiAssessment {
  const lines = scannableFiles(ctx).flatMap(file => file.addedLines)
  const nonBlank = lines.filter(line => line.text.trim() !== '')
  const signals: AiSignal[] = []

  // Diff volume
  if (lines.length > 1500) {
    signals.push({ name: 'Large diff volume', points: 20, detail: `${lines.length} added lines` })
  } else if (lines.length > 500) {
    signals.push({ name: 'Large diff volume', points: 10, detail: `${lines.length} added lines` })
  }

  // Comment-level structural patterns
  let boilerplate = 0
  let verbose = 0
  let comments = 0
  let placeholders = 0
  for (const line of nonBlank) {
    if (COMMENT_LINE.test(line.text)) {
      comments++
      if (AI_BOILERPLATE.some(pattern => pattern.test(line.text))) boilerplate++
      if (VERBOSE_SYNTAX_COMMENT.test(line.text)) verbose++
    }
    if (PLACEHOLDER_MARKER.test(line.text)) placeholders++
  }

  if (boilerplate > 0) {
    signals.push({ name: 'Conversational boilerplate in comments', points: Math.min(30, boilerplate * 15), detail: `${boilerplate} line(s)` })
  }
  if (verbose > 0) {
    signals.push({ name: 'Comments restating basic syntax', points: Math.min(20, verbose * 2), detail: `${verbose} line(s)` })
  }
  if (nonBlank.length >= 30 && comments / nonBlank.length > 0.35) {
    signals.push({
      name: 'High comment density',
      points: 10,
      detail: `${Math.round((comments / nonBlank.length) * 100)}% of added lines are comments`,
    })
  }
  if (placeholders > 0) {
    signals.push({ name: 'Placeholder or TODO scaffolding', points: Math.min(15, placeholders * 5), detail: `${placeholders} line(s)` })
  }

  // Commit atomicity (agentic loops tend to produce one large or generically named commit)
  const commitCount = ctx.commits.length
  if (commitCount === 1 && ctx.files.length >= 20) {
    signals.push({ name: 'Monolithic commit', points: 15, detail: `one commit touching ${ctx.files.length} files` })
  }
  const genericCommits = ctx.commits.filter(commit => GENERIC_COMMIT_MESSAGE.test(commit.message.trim())).length
  if (commitCount >= 3 && genericCommits / commitCount >= 0.6) {
    signals.push({ name: 'Non-atomic commit history', points: 10, detail: `${genericCommits} of ${commitCount} commits have generic messages` })
  }

  const score = Math.min(100, signals.reduce((total, signal) => total + signal.points, 0))
  const label: AiLabel | undefined =
    score >= LABEL_GENERATED_THRESHOLD ? 'ai-generated' : score >= LABEL_ASSISTED_THRESHOLD ? 'ai-assisted' : undefined

  return { score, label, signals }
}

// ---------------------------------------------------------------------------
// Module 2: Hallucinated package & typosquatting verification
// ---------------------------------------------------------------------------

const MANIFEST_PATTERN = /^(?:package\.json|requirements.*\.txt|go\.mod|Cargo\.toml)$/

function isManifest(filePath: string): boolean {
  return MANIFEST_PATTERN.test(path.posix.basename(filePath))
}

function depKey(dep: Dependency): string {
  return `${dep.ecosystem}:${dep.name}`
}

function normalizePypi(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-')
}

function parsePackageJson(manifest: string, content: string): Dependency[] {
  let pkg: unknown
  try {
    pkg = JSON.parse(content)
  } catch {
    return []
  }
  if (typeof pkg !== 'object' || pkg === null) return []

  const deps: Dependency[] = []
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const entries = (pkg as Record<string, unknown>)[section]
    if (typeof entries !== 'object' || entries === null) continue
    for (const name of Object.keys(entries)) {
      deps.push({ ecosystem: 'npm', name, manifest })
    }
  }
  return deps
}

function parseRequirements(manifest: string, content: string): Dependency[] {
  const deps: Dependency[] = []
  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    if (!line || line.startsWith('-') || line.includes('://')) continue
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line)
    if (match) deps.push({ ecosystem: 'pypi', name: normalizePypi(match[1]), manifest })
  }
  return deps
}

function parseGoMod(manifest: string, content: string): Dependency[] {
  const deps: Dependency[] = []
  let inRequireBlock = false
  for (const raw of content.split('\n')) {
    const line = raw.replace(/\/\/.*$/, '').trim()
    if (line.startsWith('require (')) {
      inRequireBlock = true
      continue
    }
    if (inRequireBlock && line === ')') {
      inRequireBlock = false
      continue
    }

    let body: string | undefined
    if (inRequireBlock) body = line
    else if (line.startsWith('require ')) body = line.slice('require '.length).trim()
    if (!body) continue

    const match = /^(\S+)\s+v\S+/.exec(body)
    if (match) deps.push({ ecosystem: 'go', name: match[1], manifest })
  }
  return deps
}

function parseCargoToml(manifest: string, content: string): Dependency[] {
  const deps: Dependency[] = []
  let inDependencies = false
  for (const raw of content.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    const header = /^\[(.+)\]$/.exec(line)
    if (header) {
      const section = header[1]
      // Table form: [dependencies.serde]
      const table = /(?:^|\.)(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$/.exec(section)
      if (table) {
        deps.push({ ecosystem: 'crates', name: table[1], manifest })
        inDependencies = false
      } else {
        inDependencies = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(section)
      }
      continue
    }
    if (!inDependencies) continue
    const entry = /^([A-Za-z0-9_-]+)\s*=/.exec(line)
    if (entry) deps.push({ ecosystem: 'crates', name: entry[1], manifest })
  }
  return deps
}

export function parseManifest(filePath: string, content: string): Dependency[] {
  const base = path.posix.basename(filePath)
  if (base === 'package.json') return parsePackageJson(filePath, content)
  if (/^requirements.*\.txt$/.test(base)) return parseRequirements(filePath, content)
  if (base === 'go.mod') return parseGoMod(filePath, content)
  if (base === 'Cargo.toml') return parseCargoToml(filePath, content)
  return []
}

/** Optimal string alignment distance: insertions, deletions, substitutions and adjacent transpositions (e.g. "reqeusts"). */
function editDistance(a: string, b: string): number {
  const table: number[][] = []
  for (let i = 0; i <= a.length; i++) {
    table.push([])
    for (let j = 0; j <= b.length; j++) {
      if (i === 0 || j === 0) {
        table[i][j] = i + j
        continue
      }
      table[i][j] = Math.min(
        table[i - 1][j] + 1,
        table[i][j - 1] + 1,
        table[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      )
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        table[i][j] = Math.min(table[i][j], table[i - 2][j - 2] + 1)
      }
    }
  }
  return table[a.length][b.length]
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[-_.\/]/g, '')
}

/** Returns the popular package a name is suspiciously close to, or undefined. */
export function findTyposquatTarget(ecosystem: Ecosystem, name: string): string | undefined {
  const candidate = name.toLowerCase()
  const popular = POPULAR_PACKAGES[ecosystem]
  if (popular.includes(candidate)) return undefined

  const normalizedCandidate = normalizeName(candidate)
  for (const target of popular) {
    // Separator and case swaps such as "python_dateutil" for "python-dateutil"
    if (normalizeName(target) === normalizedCandidate) return target
  }
  for (const target of popular) {
    const maxDistance = target.length >= 9 ? 2 : 1
    if (candidate.length < 5 || Math.abs(target.length - candidate.length) > maxDistance) continue
    if (editDistance(candidate, target) <= maxDistance) return target
  }
  return undefined
}

async function fetchRegistry(url: string): Promise<Response> {
  return fetch(url, {
    headers: { 'user-agent': 'ai-code-governance-action', accept: 'application/json' },
    signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
  })
}

function unknownResult(error: string): RegistryResult {
  return { status: 'unknown', createdAt: undefined, error }
}

async function lookupNpm(name: string): Promise<RegistryResult> {
  const res = await fetchRegistry(`https://registry.npmjs.org/${name.replace('/', '%2F')}`)
  if (res.status === 404) return { status: 'missing', createdAt: undefined, error: undefined }
  if (!res.ok) return unknownResult(`HTTP ${res.status}`)
  const body = (await res.json()) as { time?: { created?: string } }
  return {
    status: 'found',
    createdAt: body.time?.created ? new Date(body.time.created) : undefined,
    error: undefined,
  }
}

async function lookupPypi(name: string): Promise<RegistryResult> {
  const res = await fetchRegistry(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`)
  if (res.status === 404) return { status: 'missing', createdAt: undefined, error: undefined }
  if (!res.ok) return unknownResult(`HTTP ${res.status}`)
  const body = (await res.json()) as { releases?: Record<string, { upload_time_iso_8601?: string }[]> }
  const firstUpload = Object.values(body.releases ?? {})
    .flat()
    .map(file => file.upload_time_iso_8601)
    .filter((time): time is string => Boolean(time))
    .map(time => new Date(time))
    .sort((a, b) => a.getTime() - b.getTime())[0]
  return { status: 'found', createdAt: firstUpload, error: undefined }
}

async function lookupCrates(name: string): Promise<RegistryResult> {
  const res = await fetchRegistry(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`)
  if (res.status === 404) return { status: 'missing', createdAt: undefined, error: undefined }
  if (!res.ok) return unknownResult(`HTTP ${res.status}`)
  const body = (await res.json()) as { crate?: { created_at?: string } }
  return {
    status: 'found',
    createdAt: body.crate?.created_at ? new Date(body.crate.created_at) : undefined,
    error: undefined,
  }
}

async function lookupGo(modulePath: string): Promise<RegistryResult> {
  // The module proxy requires uppercase letters to be escaped as "!" + lowercase.
  const escaped = modulePath.replace(/[A-Z]/g, letter => `!${letter.toLowerCase()}`)
  const res = await fetchRegistry(`https://proxy.golang.org/${escaped}/@v/list`)
  if (res.status === 404 || res.status === 410) return { status: 'missing', createdAt: undefined, error: undefined }
  if (!res.ok) return unknownResult(`HTTP ${res.status}`)
  return { status: 'found', createdAt: undefined, error: undefined }
}

async function lookupRegistry(dep: Dependency): Promise<RegistryResult> {
  try {
    switch (dep.ecosystem) {
      case 'npm':
        return await lookupNpm(dep.name)
      case 'pypi':
        return await lookupPypi(dep.name)
      case 'crates':
        return await lookupCrates(dep.name)
      case 'go':
        return await lookupGo(dep.name)
    }
  } catch (error) {
    return unknownResult(error instanceof Error ? error.message : String(error))
  }
}

export function assessDependency(dep: Dependency, registry: RegistryResult, strict: boolean, now: number): DependencyAssessment {
  const notes: string[] = []
  let severity: Severity | undefined
  const typosquatOf = findTyposquatTarget(dep.ecosystem, dep.name)
  const ageDays = registry.createdAt ? (now - registry.createdAt.getTime()) / 86_400_000 : undefined
  const recent = ageDays !== undefined && ageDays < NEW_PACKAGE_AGE_DAYS

  if (registry.status === 'missing') {
    severity = maxSeverity(severity, 'critical')
    notes.push('Not found in the public registry (likely hallucinated)')
  } else if (registry.status === 'unknown') {
    severity = maxSeverity(severity, strict ? 'critical' : 'medium')
    notes.push(`Registry lookup failed: ${registry.error ?? 'unknown error'}`)
  } else if (recent) {
    severity = maxSeverity(severity, 'medium')
    notes.push(`First published ${Math.floor(ageDays)} day(s) ago`)
  }

  if (typosquatOf) {
    // Typosquat suspicion is critical when the package is unverified or brand new, high otherwise.
    const risky = registry.status !== 'found' || recent
    severity = maxSeverity(severity, risky ? 'critical' : 'high')
    notes.push(`Name closely resembles popular package "${typosquatOf}"`)
  }

  const label =
    registry.status === 'missing' ? '❌ Not in registry'
    : typosquatOf ? '🚨 Typosquat suspect'
    : registry.status === 'unknown' ? '⚠️ Unverified'
    : recent ? '⚠️ New package'
    : '✅ Verified'

  return { dependency: dep, severity, label, typosquatOf, notes }
}

async function readFileAt(octokit: Octokit, ctx: PullContext, filePath: string, ref: string): Promise<string | undefined> {
  try {
    const res = await octokit.rest.repos.getContent({
      owner: ctx.owner,
      repo: ctx.repo,
      path: filePath,
      ref,
      mediaType: { format: 'raw' },
    })
    return typeof res.data === 'string' ? res.data : undefined
  } catch (error) {
    if (hasStatus(error, 404)) return undefined
    throw error
  }
}

async function assessDependencies(octokit: Octokit, ctx: PullContext, strict: boolean): Promise<DependencyAssessment[]> {
  // Compare manifests before and after the PR so only newly introduced dependencies are checked.
  const baseKeys = new Set<string>()
  const headDeps: Dependency[] = []

  for (const file of ctx.files) {
    if (file.status === 'removed' || !isManifest(file.filename)) continue

    const head = await readFileAt(octokit, ctx, file.filename, ctx.headSha)
    if (head !== undefined) headDeps.push(...parseManifest(file.filename, head))

    if (file.status !== 'added') {
      const basePath = file.previousFilename ?? file.filename
      const base = await readFileAt(octokit, ctx, basePath, ctx.baseSha)
      if (base !== undefined) {
        for (const dep of parseManifest(basePath, base)) baseKeys.add(depKey(dep))
      }
    }
  }

  const introduced = new Map<string, Dependency>()
  for (const dep of headDeps) {
    const key = depKey(dep)
    if (!baseKeys.has(key) && !introduced.has(key)) introduced.set(key, dep)
  }

  const all = [...introduced.values()]
  const checked = all.slice(0, MAX_REGISTRY_LOOKUPS)
  const skipped = all.slice(MAX_REGISTRY_LOOKUPS)
  if (skipped.length > 0) {
    core.warning(`Registry lookup limit reached; ${skipped.length} dependenc(ies) were not checked.`)
  }

  const now = Date.now()
  const assessed = await mapWithConcurrency(checked, REGISTRY_CONCURRENCY, async dep =>
    assessDependency(dep, await lookupRegistry(dep), strict, now),
  )
  const notChecked = skipped.map(dep =>
    assessDependency(dep, unknownResult('not checked: lookup limit reached'), strict, now),
  )
  return [...assessed, ...notChecked]
}

// ---------------------------------------------------------------------------
// Module 3: Insecure pattern SAST rules
// ---------------------------------------------------------------------------

function loadCustomRules(filePath: string): SastRule[] {
  const absolute = path.resolve(process.env.GITHUB_WORKSPACE ?? process.cwd(), filePath)
  const raw: unknown = JSON.parse(fs.readFileSync(absolute, 'utf8'))
  if (!Array.isArray(raw)) {
    throw new Error(`Custom rules file ${filePath} must contain a JSON array.`)
  }

  const rules: SastRule[] = []
  for (const entry of raw as Record<string, unknown>[]) {
    const { id, severity, message, pattern, flags, redact } = entry
    if (typeof id !== 'string' || typeof message !== 'string' || typeof pattern !== 'string' || !isSeverity(severity)) {
      core.warning(`Skipping invalid custom rule: ${JSON.stringify(entry).slice(0, 120)}`)
      continue
    }
    try {
      rules.push({
        id: `custom:${id}`,
        severity,
        message,
        pattern: new RegExp(pattern, typeof flags === 'string' ? flags : ''),
        redact: redact === true,
      })
    } catch (error) {
      core.warning(`Skipping custom rule "${id}": invalid regular expression (${error instanceof Error ? error.message : String(error)})`)
    }
  }
  return rules
}

function lineIndexAt(lineStarts: number[], position: number): number {
  let low = 0
  let high = lineStarts.length - 1
  while (low < high) {
    const mid = (low + high + 1) >> 1
    if (lineStarts[mid] <= position) low = mid
    else high = mid - 1
  }
  return low
}

/**
 * Scans only the added lines of a file. Lines are joined so multi-line rules
 * (such as empty catch blocks) can match; matches are mapped back to the
 * new-file line where they start.
 */
export function scanFile(file: ChangedFile, rules: SastRule[]): SastFinding[] {
  if (file.addedLines.length === 0) return []

  const text = file.addedLines.map(line => line.text).join('\n')
  const lineStarts: number[] = []
  let offset = 0
  for (const line of file.addedLines) {
    lineStarts.push(offset)
    offset += line.text.length + 1
  }

  const findings: SastFinding[] = []
  for (const rule of rules) {
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`
    const regex = new RegExp(rule.pattern.source, flags)
    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      const added = file.addedLines[lineIndexAt(lineStarts, match.index)]
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        file: file.filename,
        line: added.line,
        message: rule.message,
        snippet: rule.redact ? '[REDACTED]' : added.text.trim().slice(0, 160),
      })
    }
  }
  return findings
}

function scanPullRequest(ctx: PullContext, rules: SastRule[]): SastFinding[] {
  const seen = new Set<string>()
  const findings: SastFinding[] = []
  for (const file of scannableFiles(ctx)) {
    for (const finding of scanFile(file, rules)) {
      const key = `${finding.rule}|${finding.file}|${finding.line}`
      if (seen.has(key)) continue
      seen.add(key)
      findings.push(finding)
    }
  }
  return findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
}

// ---------------------------------------------------------------------------
// Module 4: Enforcement & reporting
// ---------------------------------------------------------------------------

export function evaluate(ai: AiAssessment, deps: DependencyAssessment[], findings: SastFinding[]): Verdict {
  const reasons: string[] = []

  const criticalDeps = deps.filter(dep => dep.severity === 'critical')
  if (criticalDeps.length > 0) {
    reasons.push(`${criticalDeps.length} critical dependency issue(s): ${criticalDeps.map(dep => dep.dependency.name).join(', ')}`)
  }

  const criticalFindings = findings.filter(finding => finding.severity === 'critical')
  if (criticalFindings.length > 0) {
    reasons.push(`${criticalFindings.length} critical insecure-pattern finding(s)`)
  }

  if (ai.score >= CRITICAL_SCORE_THRESHOLD) {
    reasons.push(`AI risk score ${ai.score} meets or exceeds the critical threshold of ${CRITICAL_SCORE_THRESHOLD}`)
  }

  return { blocked: reasons.length > 0, reasons }
}

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
}

function sarifLocation(file: string, line: number) {
  return { physicalLocation: { artifactLocation: { uri: file }, region: { startLine: line } } }
}

/**
 * Builds a SARIF 2.1.0 log so findings appear under Code scanning alerts.
 * Dependency findings are attached to the manifest file, since registry checks have no source line.
 */
export function toSarif(findings: SastFinding[], deps: DependencyAssessment[]): object {
  const rules = new Map<string, object>()
  const results: object[] = []

  for (const finding of findings) {
    rules.set(finding.rule, {
      id: finding.rule,
      shortDescription: { text: finding.message },
      defaultConfiguration: { level: SARIF_LEVEL[finding.severity] },
    })
    results.push({
      ruleId: finding.rule,
      level: SARIF_LEVEL[finding.severity],
      message: { text: finding.message },
      locations: [sarifLocation(finding.file, finding.line)],
    })
  }

  for (const dep of deps) {
    if (dep.severity === undefined) continue
    rules.set('dependency-risk', {
      id: 'dependency-risk',
      shortDescription: { text: 'New dependency failed registry verification' },
      defaultConfiguration: { level: 'warning' },
    })
    results.push({
      ruleId: 'dependency-risk',
      level: SARIF_LEVEL[dep.severity],
      message: { text: `${dep.dependency.name} (${dep.dependency.ecosystem}): ${dep.label}. ${dep.notes.join('; ')}` },
      locations: [sarifLocation(dep.dependency.manifest, 1)],
    })
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: { driver: { name: 'ai-code-governance', rules: [...rules.values()] } },
        results,
      },
    ],
  }
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').replace(/`/g, "'")
}

export function renderReport(
  ai: AiAssessment,
  deps: DependencyAssessment[],
  findings: SastFinding[],
  verdict: Verdict,
): string {
  const flaggedDeps = deps.filter(dep => dep.severity !== undefined)
  const lines: string[] = [REPORT_MARKER, '## 🛡️ AI Code Governance Report', '']

  lines.push('| Check | Result |', '| --- | --- |')
  lines.push(`| AI risk score | **${ai.score} / 100**${ai.label ? ` (\`${ai.label}\`)` : ''} |`)
  lines.push(`| New dependencies flagged | ${flaggedDeps.length} of ${deps.length} |`)
  lines.push(`| Insecure-pattern findings | ${findings.length} |`)
  lines.push(`| Verdict | ${verdict.blocked ? '❌ Blocked' : '✅ Passed'} |`)
  lines.push('')

  if (verdict.blocked) {
    lines.push('**Blocking reasons:**')
    for (const reason of verdict.reasons) lines.push(`- ${reason}`)
    lines.push('')
  }

  lines.push('### 🤖 Provenance signals', '')
  if (ai.signals.length === 0) {
    lines.push('No AI provenance signals detected.', '')
  } else {
    lines.push('| Signal | Points | Detail |', '| --- | --- | --- |')
    for (const signal of ai.signals) {
      lines.push(`| ${escapeCell(signal.name)} | +${signal.points} | ${escapeCell(signal.detail)} |`)
    }
    lines.push('')
  }

  lines.push('### 📦 New dependencies', '')
  if (deps.length === 0) {
    lines.push('No new dependencies introduced in manifest files.', '')
  } else {
    lines.push('| Ecosystem | Package | Manifest | Status | Notes |', '| --- | --- | --- | --- | --- |')
    for (const dep of flaggedDeps.slice(0, MAX_REPORT_ROWS)) {
      lines.push(
        `| ${dep.dependency.ecosystem} | \`${escapeCell(dep.dependency.name)}\` | ${escapeCell(dep.dependency.manifest)} | ${dep.label} | ${escapeCell(dep.notes.join('; '))} |`,
      )
    }
    const clean = deps.length - flaggedDeps.length
    if (flaggedDeps.length > MAX_REPORT_ROWS) lines.push(`| … | ${flaggedDeps.length - MAX_REPORT_ROWS} more flagged | | | |`)
    lines.push('', `${clean} additional new dependencies verified without issues.`, '')
  }

  lines.push('### 🔍 Insecure patterns', '')
  if (findings.length === 0) {
    lines.push('No insecure patterns detected in added lines.', '')
  } else {
    lines.push('| Severity | Rule | Location | Message | Snippet |', '| --- | --- | --- | --- | --- |')
    for (const finding of findings.slice(0, MAX_REPORT_ROWS)) {
      lines.push(
        `| ${finding.severity} | \`${finding.rule}\` | \`${escapeCell(finding.file)}:${finding.line}\` | ${escapeCell(finding.message)} | \`${escapeCell(finding.snippet)}\` |`,
      )
    }
    if (findings.length > MAX_REPORT_ROWS) {
      lines.push('', `Showing ${MAX_REPORT_ROWS} of ${findings.length} findings. See the job summary for the full list.`)
    }
    lines.push('')
  }

  lines.push('---', '_Provenance heuristics are advisory and only route or label the PR. Dependency and insecure-pattern rules are deterministic enforcement gates._')
  return lines.join('\n')
}

async function applyAiLabel(octokit: Octokit, ctx: PullContext, label: AiLabel | undefined): Promise<void> {
  const issue_number = ctx.number
  for (const other of (Object.keys(LABEL_DESCRIPTIONS) as AiLabel[]).filter(name => name !== label)) {
    try {
      await octokit.rest.issues.removeLabel({ owner: ctx.owner, repo: ctx.repo, issue_number, name: other })
    } catch (error) {
      if (!hasStatus(error, 404)) throw error
    }
  }
  if (!label) return

  try {
    await octokit.rest.issues.createLabel({
      owner: ctx.owner,
      repo: ctx.repo,
      name: label,
      color: LABEL_COLOR,
      description: LABEL_DESCRIPTIONS[label],
    })
  } catch (error) {
    if (!hasStatus(error, 422)) throw error // 422 means the label already exists
  }
  await octokit.rest.issues.addLabels({ owner: ctx.owner, repo: ctx.repo, issue_number, labels: [label] })
}

async function upsertReportComment(octokit: Octokit, ctx: PullContext, body: string): Promise<void> {
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner: ctx.owner,
    repo: ctx.repo,
    issue_number: ctx.number,
    per_page: 100,
  })
  const existing = comments.find(comment => comment.body?.includes(REPORT_MARKER))
  if (existing) {
    await octokit.rest.issues.updateComment({ owner: ctx.owner, repo: ctx.repo, comment_id: existing.id, body })
  } else {
    await octokit.rest.issues.createComment({ owner: ctx.owner, repo: ctx.repo, issue_number: ctx.number, body })
  }
}

async function run(): Promise<void> {
  const config = readConfig()
  const octokit = github.getOctokit(config.token)
  const ctx = await loadPullContext(octokit)

  const ai = assessAiProvenance(ctx)
  const deps = await assessDependencies(octokit, ctx, config.strictDependencyCheck)

  const rules = [...SAST_RULES]
  if (config.customRulesPath) rules.push(...loadCustomRules(config.customRulesPath))
  const findings = scanPullRequest(ctx, rules)

  const verdict = evaluate(ai, deps, findings)
  const flaggedCount = deps.filter(dep => dep.severity !== undefined).length

  core.setOutput('ai-risk-score', String(ai.score))
  core.setOutput('flagged-dependencies-count', String(flaggedCount))
  core.setOutput('security-findings-count', String(findings.length))

  const sarifPath = path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), 'ai-code-governance.sarif')
  fs.writeFileSync(sarifPath, JSON.stringify(toSarif(findings, deps), null, 2))
  core.setOutput('sarif-path', sarifPath)

  const report = renderReport(ai, deps, findings, verdict)
  await bestEffort('Applying AI label', () => applyAiLabel(octokit, ctx, ai.label))
  await bestEffort('Posting report comment', () => upsertReportComment(octokit, ctx, report))
  await bestEffort('Writing job summary', async () => {
    await core.summary.addRaw(report).write()
  })

  core.info(`AI risk score: ${ai.score}; flagged dependencies: ${flaggedCount}; findings: ${findings.length}`)

  if (verdict.blocked) {
    const message = `Governance check failed: ${verdict.reasons.join('; ')}`
    if (config.failOnRisk) core.setFailed(message)
    else core.warning(message)
  }
}

// Only run when executed as the bundled action, not when imported by tests.
if (require.main === module) {
  run().catch(error => core.setFailed(error instanceof Error ? error.message : String(error)))
}
