# AI Code Governance

A GitHub Action that applies deterministic, security-first guardrails to pull requests containing AI-assisted or LLM-generated code.

The action does not try to guess whether text was written by a model. It runs rules you can read, test and reproduce:

| Module | What it does | Enforcing? |
| --- | --- | --- |
| 1. Provenance heuristics | Scores the diff for conversational boilerplate, syntax-restating comments, placeholder scaffolding, diff volume and commit atomicity. Applies an `ai-assisted` or `ai-generated` label. | Advisory (routing only) |
| 2. Dependency verification | Extracts newly introduced dependencies from `package.json`, `requirements*.txt`, `go.mod` and `Cargo.toml`, then checks each against its public registry. Flags non-existent names, typosquats and very new packages. | Yes, for missing and typosquat-critical packages |
| 3. Insecure-pattern SAST | Scans added lines only for unparameterized SQL, hardcoded placeholder or live secrets, swallowed exceptions, command injection, disabled TLS verification and similar patterns. | Yes, for critical findings |
| 4. Enforcement & reporting | Posts or updates one Markdown report comment, writes a job summary, sets outputs and fails the check when a critical threshold is breached. | Yes, when `fail-on-risk` is `true` |

## Usage

```yaml
name: AI Code Governance

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  issues: write
  security-events: write

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: AI code governance
        id: governance
        uses: your-org/ai-code-governance@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-risk: 'true'
          strict-dependency-check: 'true'
          custom-rules-path: '.github/governance/rules.json'

      - name: Upload findings to Code scanning
        if: always() && steps.governance.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.governance.outputs.sarif-path }}
          category: ai-code-governance

      - name: Show outputs
        if: always()
        run: |
          echo "AI risk score: ${{ steps.governance.outputs.ai-risk-score }}"
          echo "Flagged dependencies: ${{ steps.governance.outputs.flagged-dependencies-count }}"
          echo "Security findings: ${{ steps.governance.outputs.security-findings-count }}"
```

The action must run on a `pull_request` event. It reads PR data through the API, so `actions/checkout` is only needed if you use `custom-rules-path`.

**Code scanning:** the upload step puts findings under the repository's Security → Code scanning tab. It needs `security-events: write`. The `if: always()` guards keep the upload and output steps running when the check blocks the PR, so the check still fails. Pull requests from forks can't write code scanning results, so the upload fails there.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `github-token` | yes | | Needs `pull-requests: write` and `issues: write`. |
| `fail-on-risk` | no | `true` | When `true`, the check fails if any critical threshold is breached. When `false`, the report is posted but the check passes. |
| `strict-dependency-check` | no | `true` | When `true`, a dependency that cannot be verified (registry error, timeout, or lookup limit) is critical. When `false`, it is only a medium warning. A confirmed non-existent package is always critical. |
| `custom-rules-path` | no | | Path to a JSON file of additional SAST rules, relative to the repository root. |

## Outputs

| Output | Description |
| --- | --- |
| `ai-risk-score` | Provenance score from 0 to 100. |
| `flagged-dependencies-count` | New dependencies with any finding (unverified, typosquat suspect, or first published within 30 days). |
| `security-findings-count` | Insecure-pattern findings across added lines. |

## Blocking policy

The check fails (when `fail-on-risk` is `true`) if any of these hold:

1. A new dependency is not found in its registry, or cannot be verified while `strict-dependency-check` is `true`.
2. A new dependency is a typosquat suspect and is unverified or published within 30 days. Typosquat suspects that are established packages are rated `high` and do not block.
3. A SAST rule with `severity: critical` matches an added line.
4. The AI risk score is 80 or higher.

High and medium findings are reported in the comment but do not block. Adjust this in `evaluate()` in `src/index.ts` if your policy differs.

## Custom rules

`custom-rules-path` points to a JSON array:

```json
[
  {
    "id": "no-console-in-handlers",
    "severity": "medium",
    "message": "Debug logging left in request handler",
    "pattern": "console\\.log\\(",
    "flags": "",
    "redact": false
  }
]
```

- `id` is reported as `custom:<id>`.
- `severity` is one of `low`, `medium`, `high`, `critical`.
- `pattern` is a JavaScript regular expression source string. Invalid rules are skipped with a warning.
- `redact: true` hides the matched line in the report. Use it for any rule that could match a secret.

**Security note:** the rules file is read from the PR's checkout. A pull request that edits or removes its own rules file can weaken its own checks. For enforcement, load the rules from the base branch, for example by checking out `${{ github.event.pull_request.base.sha }}` in a separate step and pointing `custom-rules-path` at that copy. Built-in rules always run.

## Fork pull requests

For PRs from forks, `GITHUB_TOKEN` is read-only. The analysis still runs, but labels and the PR comment will fail with a warning and the report goes to the job summary only. Use `pull_request_target` only with a hardened workflow that never runs fork code.

## Known limits

- Heuristics are signals, not proof. A human-written PR can score as AI-assisted, and an AI-written PR can score low. Use the label to route review, not to make a decision.
- Diff content is read from the GitHub API. Files without a patch (binary or very large) are not scanned, and the action logs a warning for each.
- SAST rules are regular expressions on added lines, not a parser. They are tuned to favor few false positives. For deep analysis, pair this with CodeQL or Semgrep.
- Registry checks cover npm, PyPI, crates.io and the Go module proxy. Go modules have no creation date, so the new-package rule does not apply to them. Typosquat matching uses a seed list of popular packages in `src/index.ts`. Extend it for your ecosystem.
- Lookups are capped at 150 per run.

## Development

```bash
npm install
npm run typecheck
npm run build
```

`npm run build` type-checks, then runs `ncc` to produce a single-file bundle in `dist/`.

## Compiling with ncc

`@vercel/ncc` bundles `src/index.ts` and all dependencies into `dist/index.js`. GitHub runs that file directly, so `node_modules` is not needed at runtime.

```bash
npm install
npm run build
```

This produces:

- `dist/index.js`: the bundled action
- `dist/index.js.map`: source map for stack traces
- `dist/sourcemap-register.js`: source map registration, required by the bundle
- `dist/licenses.txt`: third-party license notices

Commit `dist/` to the repository. Actions run from the committed bundle, so a release without a rebuilt `dist/` will run stale code.

## Publishing to the GitHub Marketplace

1. Make the repository public and ensure its root contains `action.yml`, `README.md` and `dist/`.
2. Ensure `action.yml` has `name`, `description`, `author`, `branding`, `inputs`, `outputs` and `runs` (the `name` must be unique in the Marketplace).
3. Commit and push, then create a release. Tag it with a full semver such as `v1.0.0`, and keep a moving major tag such as `v1`:

   ```bash
   git tag -a v1.0.0 -m "v1.0.0"
   git push origin v1.0.0
   git tag -fa v1 -m "v1 (latest 1.x)"
   git push origin v1 --force
   ```

4. On GitHub, open the release, select **Publish this Action to the GitHub Marketplace**, accept the Marketplace Developer Agreement if prompted, choose categories (for example *Security* and *Code quality*), and publish.
5. Before publishing, run the action on a test repository to verify the workflow and labels.

## Project layout

```
action.yml          Action metadata: inputs, outputs, runtime
package.json        Dependencies and build scripts
tsconfig.json       TypeScript configuration (strict)
src/index.ts        All four modules: heuristics, dependencies, SAST, reporting
dist/               ncc bundle, committed for Marketplace use
```
