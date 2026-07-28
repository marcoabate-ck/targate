# CLI reference

## Commands

<!-- targate:cli-reference:start -->
| Command | Summary | Supported options | Examples |
|---|---|---|---|
| `targate add <package>[@version]` | Analyze one package, then gate its installation. | `--package-manager <pm>`<br>`--json`<br>`--dry-run`<br>`--yes`<br>`--no-cache`<br>`--deep`<br>`--audit-code`<br>`--concurrency <n>`<br>`--no-ai-batch`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate add lodash`<br>`targate add left-pad@1.3.0 --dry-run`<br>`targate add esbuild --yes --deep` |
| `targate approve <package>[@version]` | Record a committable human approval without installing. | `--json`<br>`--yes`<br>`--allow-scripts`<br>`--sign`<br>`--no-cache`<br>`--deep`<br>`--audit-code`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate approve esbuild@0.27.3`<br>`targate approve esbuild@0.27.3 --sign` |
| `targate audit <package>[@version]` | AI-read a package's source for security issues, without installing. | `--json`<br>`--deep`<br>`--concurrency <n>`<br>`--no-ai-batch`<br>`--no-cache`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate audit left-pad`<br>`targate audit esbuild@0.27.3 --deep` |
| `targate install` | Vet the complete dependency tree, then gate a full install. | `--package-manager <pm>`<br>`--json`<br>`--dry-run`<br>`--yes`<br>`--no-cache`<br>`--update-lockfile`<br>`--frozen-lockfile`<br>`--allow-scripts`<br>`--audit-code`<br>`--concurrency <n>`<br>`--no-ai-batch`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate install`<br>`targate install --update-lockfile --dry-run` |
| `targate sandbox <package>[@version]` | Trial-install a package in a disposable Docker container. | `--image <image>`<br>`--timeout <seconds>`<br>`--network <mode>`<br>`--no-capture`<br>`--json` | `targate sandbox suspicious-package`<br>`targate sandbox esbuild --network none` |
| `targate ci [init]` | Gate dependency changes against a Git ref or scaffold CI. | `--base-ref <ref>`<br>`--json`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate ci --base-ref origin/main --fail-on-osv-error`<br>`targate ci init` |
| `targate policy init` | Scaffold a declarative team policy from a preset. | `--format <format>`<br>`--preset <name>` | `targate policy init`<br>`targate policy init --preset ai-agent` |
| `targate doctor` | Diagnose the local security and provider environment. | `--json`<br>`--ping`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning` | `targate doctor`<br>`targate doctor --ping` |
| `targate diff <pkg>@<v1> [<pkg>[@<v2>]]` | Compare package versions and rate the upgrade risk. | `--package-manager <pm>`<br>`--json`<br>`--fail-on <level>`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate diff lodash@4.17.20 lodash@4.17.21`<br>`targate diff lodash --fail-on medium` |
| `targate monitor` | Re-check trusted packages and report increased risk. | `--package-manager <pm>`<br>`--json`<br>`--all`<br>`--no-update`<br>`--concurrency <n>`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate monitor`<br>`targate monitor --all --no-update` |
| `targate graph [<package>[@version]]` | Render a dependency risk graph or explain why a package is present. | `--format <format>`<br>`--output <path>`<br>`--only <filters>`<br>`--why <package>`<br>`--open`<br>`--json`<br>`--package-manager <pm>`<br>`--no-reputation`<br>`--fail-on-osv-error`<br>`--concurrency <n>` | `targate graph`<br>`targate graph --only high-risk,scripts`<br>`targate graph --why minimist` |
| `targate recommend "<need>"` | Recommend analyzed packages for a need, safest first. | `--limit <n>`<br>`--json`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate recommend "date formatting"`<br>`targate recommend "immutable state" --limit 8 --json` |
| `targate history [<package>[@version]]` | Show recorded trust decisions and optionally verify signatures. | `--json`<br>`--verify` | `targate history`<br>`targate history esbuild --verify` |
| `targate explain <package>[@version] \| --last` | Explain a fresh or previously recorded decision without installing. | `--last`<br>`--json`<br>`--no-cache`<br>`--no-ai`<br>`--provider <name>`<br>`--model <name>`<br>`--base-url <url>`<br>`--api-key <key>`<br>`--reasoning`<br>`--fail-on-osv-error`<br>`--no-reputation` | `targate explain left-pad@1.3.0`<br>`targate explain --last` |
| `targate cache <info\|clear>` | Inspect or clear the AI assessment cache. | `--scope <scope>`<br>`--json` | `targate cache info`<br>`targate cache clear --scope project` |
| `targate agents init` | Scaffold instructions that make coding agents use targate. | `--format <format>` | `targate agents init`<br>`targate agents init --format all` |
<!-- targate:cli-reference:end -->

Package installation requires the explicit `targate add <package>` command. Bare package names and unknown commands fail before analysis; they are never interpreted as packages. `targate <command> --help` renders the command-specific options from the same registry as this table, and flags belonging to another command are rejected.

**Global flags:** `targate --help` / `-h` prints the command list above; `targate --version` / `-v` prints the installed version.

**Experimental commands:** `graph`, `recommend`, and `monitor` ship as **experimental** — outside the [1.0 stability guarantee](../README.md#stability--compatibility), their flags and output may change in a minor release. Every other command is part of the stable surface.

## Command details

### targate diff

What changed between two versions of a package, and how risky the change is. Built for reviewing upgrades — yours, Renovate's, or Dependabot's — **before** merging them. No AI, no policy escalation: a diff is a statement of facts with a deterministic risk rubric.

```bash
targate diff lodash@4.17.20 lodash@4.17.21   # two explicit versions
targate diff lodash@4.17.20                  # second version omitted → latest
targate diff lodash                          # bare: lockfile-installed → latest
```

Both versions run through the same signal pipeline as `targate add` (metadata, tarball quarantine, OSV, reputation — never any lifecycle script), then the diff compares: lifecycle scripts (added/removed/changed, commands shown verbatim), dependencies (flagging non-registry specifiers like `git+` / `http` / `file:`), maintainers, repository URL, native surface, advisories (new and resolved), size, provenance, deprecation, and the security score. The **risk rubric**: HIGH for a to-side malicious record, a new hard block, an added/changed lifecycle script, new script findings, or a dependency moved to a non-registry source; MEDIUM for added deps, maintainer/repo changes, lost provenance, new advisories, big size jumps, or a score drop ≥15 — and two MEDIUMs escalate to HIGH. Improvements (resolved advisories, shrinkage) are reported but never raise risk.

```text
Version diff — lodash 4.17.20 → 4.17.21 (upgrade)
from: 2020-08-13  ·  to: 2021-02-20
────────────────────────────────────────────────────────────
Advisories
  - resolved: GHSA-29mw-wpgm-hmr9
  - resolved: GHSA-35jh-r3h4-6jhm

Size  unpacked +6 kB, +5 files

Security score  65 → 70 (+5)

Diff risk: LOW
```

```
--fail-on <level>       Exit 2 when the diff risk is at this level or above
                        (low | medium | high; default: high)
--no-reputation         Skip external reputation lookups on both versions
--fail-on-osv-error     Treat an unreachable OSV lookup as a medium-risk unknown
--package-manager <pm>  (bare form) Force the lockfile to read the installed
                        version from
--json                  Machine-readable VersionDiff (see the schema table)
```

In CI, `targate diff <pkg> --fail-on medium --json` on a Renovate/Dependabot branch turns "the bot bumped it" into "the bump was reviewed". Exit codes: `0` below `--fail-on`, `2` at/above it, `1` operational (name mismatch, unknown version, not in the lockfile).

### targate monitor

Approving a package vouches for it _at a point in time_ — `targate monitor` re-checks the packages you already trust and reports what got **worse** since a stored baseline. One-shot by design (no daemon): run it on a schedule.

```bash
targate monitor            # approvals + direct dependencies
targate monitor --all      # the entire lockfile tree
```

It is a light metadata-only pass (registry packument + one batched OSV query + reputation lookups — no tarball download, no AI), snapshotted into `.targate/monitor-baseline.json` and diffed on the next run. Events by severity — **critical**: known-malicious record appeared; **warn**: new advisory, maintainer added/removed, repository changed, provenance removed, deprecation, archived/gone repo, suspicious new version (release after long inactivity, or a latest that isn't semver-greater), download collapse; **info**: new version, download spike, degraded lookups. Always-true risks (known-malicious, deprecated) fire on every run, baseline or not.

```text
Monitoring 1 package(s) ...

No risk changes since the last baseline.
Baseline updated → .targate/monitor-baseline.json
```

```
--all                   Monitor the entire lockfile tree, not just approvals +
                        direct dependencies
--no-update             Report events without advancing the baseline
--concurrency <n>       Packages checked in parallel (default: 16)
--no-reputation         Skip download/GitHub lookups (fewer events, faster)
--fail-on-osv-error     Treat an unreachable OSV lookup as a warning
--json                  Machine-readable events + baseline status
```

The baseline is gitignored by default; on ephemeral CI runners, commit it or cache it between runs — without one, every run starts fresh and only the always-on checks fire (see [team workflow](team-workflow.md#monitoring-risk-over-time--targate-monitor)). Exit codes: `0` no risk increase (a plain first run included), `2` any warn/critical event, `1` operational.

### targate explain

Why a package would be allowed or blocked, in plain language — the report's verdict unpacked into main reasons, the deterministic-vs-AI split, and the residual risks that remain **even on an allowed package**. Informational: installs nothing, records nothing, exits `0` whatever the decision.

```bash
targate explain left-pad@1.3.0     # analyze fresh, then explain
targate explain --last             # re-explain the previous add/approve run
                                   # (reads .targate/last-run.json — no network)
```

`--last` explains exactly what the previous run saw — same signals, same verdict, offline — which is the right tool when a gate just stopped you and you want the "why" without paying for a re-analysis.

```text
Why left-pad@1.3.0 → ALLOW
(risk: low · source: rules)
────────────────────────────────────────────────────────────
left-pad shows no high-risk install-time behavior.

Main reasons
  1. No lifecycle scripts, no known malicious records, repository metadata present.

Deterministic findings
  ✓ no lifecycle scripts
  ✓ no known malicious-package records (OSV/OpenSSF)
  ⚠ version is DEPRECATED: "use String.prototype.padStart()"
  …

Security score: 94/100
  …
Recommendation
  Safe to install normally.
```

When an AI provider produced the verdict, the explanation renders the **deterministic verdict block first** (what the rules engine concluded on its own) and the AI's interpretation separately — making visible that the AI can only ever be stricter. Takes the usual analysis flags (`--no-ai`, `--no-reputation`, `--no-cache`, `--fail-on-osv-error`, `--json`). Exit codes: `0` on success regardless of the decision, `1` on operational errors. Never `2`.

### targate recommend

The advisor: instead of gating a package you already picked, suggest what to pick — safest first, with scores and reasons.

```bash
targate recommend "date formatting"
targate recommend "immutable state management" --limit 8 --json
```

Candidates come from **two discovery sources, merged and deduped**: npm search relevance, and — when an AI provider is configured — the model, asked to propose exact package names for the need (`--no-ai` for search-only; an AI failure degrades to search-only, visibly, never fatally). The AI contributes **names only**: every candidate, whatever its source, is resolved on the registry (which rejects hallucinated names with a distinct reason) and analyzed with the full deterministic pipeline (quarantine, scripts/contents, OSV, reputation, maintainer intel, security score, rules verdict + team policy). Known-malicious, hard-block, deprecated, and policy-blocked candidates are excluded with the reason shown. Ranking is **fully deterministic** — security score, adoption (weekly downloads) as tie-breaker — the AI cannot boost, demote, or vouch for anything. Each result is tagged with its source (`npm search` / `AI-suggested` / `search+AI`).

```text
Recommendations for "left pad string" — 4 of 4 candidates eligible, safest first

  1. pad-right@0.2.2   score 98/100  ·  2.1M/wk  ·  allow  ·  npm search
     Right pad a string with zeros or a specified string. Fastest implementation.
       - no npm provenance attestation

  2. pad-left@2.1.0   score 96/100  ·  515K/wk  ·  allow  ·  npm search
     Left pad a string with zeros or a specified string. Fastest implementation.
       - single maintainer
       - no npm provenance attestation
  …

Next: targate add pad-right (gates the actual install)
```

```
--limit <n>             Candidates to analyze per source (default: 5, max: 15 —
                        each costs a real tarball download + full analysis)
--no-ai                 Search-only discovery (no AI-proposed candidates)
--no-reputation         Skip external reputation lookups per candidate
--fail-on-osv-error     Escalate candidates whose OSV lookup failed
--json                  Machine-readable report incl. aiSuggestions metadata
```

Discovery is search relevance + AI knowledge — targate ranks the safety of what was discovered; it cannot know every package that could serve the need. Exit codes: `0` on success (zero eligible candidates included — it is advisory; the gate lives in `add`), `1` when the npm search itself fails. Never `2`.

### targate graph

The dependency tree as an interactive **risk graph** — full documentation on its own page: [Dependency graph](dependency-graph.md).

```bash
targate graph                    # project tree → self-contained targate-graph.html
targate graph <pkg>[@version]    # a package you are considering, and its tree
targate graph --why <pkg>        # every chain that pulls <pkg> in, risk-annotated
```

Every package runs through the deterministic pipeline (no AI); the HTML is one offline file with pan/zoom, live filters (high-risk, scripts, native, deprecated, no-provenance, risk-increased), search, workspace views, per-node detail panels, and path-to-root highlighting.

```
--format <fmt>          html (default) | svg | dot | mermaid | json
--output <path>         Output file ("-" = stdout; html/svg default to
                        targate-graph.<ext>, dot/mermaid to stdout)
--only <filters>        Prune to matching nodes + their paths to the root
--why <pkg>             Risk-annotated dependency chains instead of a graph
--open                  Open the written html/svg in the browser
--no-reputation / --fail-on-osv-error / --concurrency / --package-manager
```

Exit codes: `0` on success — the graph is a lens, the gate lives in `add`/`install`/`ci` — `1` on operational errors. Never `2`.

### targate doctor

One command that answers "will targate work here, and at what fidelity?" — checks the runtime, every external service the pipeline depends on, and the local configuration, then says what each failure would degrade.

```bash
targate doctor           # config + connectivity checks (free)
targate doctor --ping    # also one real (paid) AI completion, end to end
```

Checks: Node version (≥22.13), package manager (lockfile + binary), npm registry reachability, **registry configuration** (`.npmrc` default/override/scoped registries and whether credentials are configured — presence only, values are never printed), OSV/OpenSSF reachability, AI provider resolution (and `--ping` for a live completion), GitHub API quota, team policy validity, executable-config mode, `.targate/` and user-cache writability, and CI mode.

```text
# abbreviated — a real run also prints Package manager, Executable config and
# User cache dir rows, and a trailing "--ping" hint
targate doctor

  ✓ Node version                     Node v22.13.0 (>=22.13.0 required)
  ✓ npm registry                     registry.npmjs.org reachable (628ms)
  ✓ Registry configuration (.npmrc)  default registry (registry.npmjs.org), no scoped registries
  ✓ OSV / OpenSSF                    api.osv.dev reachable (515ms)
  ℹ AI provider                      no AI provider configured — deterministic rules engine only
  ℹ GitHub API                       GITHUB_TOKEN not set — 58/60 unauthenticated requests/h
  ℹ Team policy                      no policy file — defaults apply (targate policy init)
  ✓ Project .targate/                .targate writable
  ℹ CI mode                          not running in CI

targate is ready.
```

```
--ping                  Also send one real (paid) test completion to the resolved
                        AI provider to verify it end to end (default: config-only
                        check, no model call)
--json                  Machine-readable checks[] + summary
```

Statuses: `✓` pass, `⚠` warn (usable, degraded), `✖` fail (something will break), `ℹ` info (a fact, not a problem — e.g. rules-only mode is a supported configuration). Exit codes: `0` when every check passes or only warns, `1` when at least one check fails.

## Exit codes

`0` ok, `1` error, `2` blocked (or suspicious sandbox / failed CI check).

- `doctor`: `0` when every check passes or only warns, `1` when at least one check fails.
- `explain`: `0` on success **regardless of the decision** (it is informational — the gate lives in `add`/`install`/`ci`), `1` on operational errors. Never `2`.
- `diff`: `0` when the diff risk is below `--fail-on` (default: `low`/`medium`), `2` at or above it (default: `high`), `1` on operational errors (name mismatch, unknown version, not in the lockfile).
- `history`: `0` on success (an empty history included); with `--verify`, `2` when any signature is invalid or verification errored, `1` on operational errors.
- `recommend`: `0` on success (even with zero eligible candidates — it is advisory; the gate lives in `add`), `1` when the npm search itself fails. Never `2`.
- `graph`: `0` on success whatever the tree contains (a lens, not a gate), `1` on operational errors. Never `2`.
- `monitor`: `0` when no risk increased (including a plain first run that only creates the baseline), `2` when any `warn`/`critical` event fired, `1` on operational errors.
- `sandbox`: `0` clean, `2` on a timeout, suspicious log line, or unexpected network destination, `1` when Docker is unavailable or the install failed with no findings.

`--dry-run` is a pure preview: analyze and report only — it never prompts, never installs, and records nothing. To approve a package without installing it, use [`targate approve`](team-workflow.md#approving-a-package--targate-approve).

## JSON output schema

Every command that supports `--json` prints **exactly one JSON document on stdout** — no progress lines, no prompts. Each document is wrapped in a flat envelope:

```json
{
  "schemaVersion": 1,
  "command": "add",
  "…": "…payload keys follow at the same level"
}
```

**Stability rules.** Within a `schemaVersion`, changes are **additive only** — new keys may appear at any level and consumers must ignore keys they don't recognize. Any removal, rename, or type change of an existing key bumps `schemaVersion`. Compare it with `===`, not `>=`.

Payload keys per command (in addition to `schemaVersion` + `command`):

| `command`   | Payload keys                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add`       | `metadata`, `signals`, `assessment`, `score`, `deep` (per-package results of a `--deep` run, else `null`), `behaviorFingerprint` (present when analysis completed), `planFingerprint` + `artifactFingerprint` (with `--deep`), `install` (`installed` / `skipped` / `blocked` / `failed`, with command and child exit code when applicable), `artifactLedger` after a real install                                                                                  |
| `approve`   | `metadata`, `signals`, `assessment`, `score`, `deep`, `behaviorFingerprint` (present when analysis completed), `outcome` (`hard-blocked` \| `already-allowed` \| `approvable`), `approval` (the recorded entry, or `null`)                                                                                                                                                                                                                                          |
| `install`   | `packageManager`, `source`, `total`, `results[]`, `decision`, `exitCode`, `planFingerprint`, `artifactFingerprint`, `install` (`installed` / `skipped` / `blocked` / `failed`, with command and child exit code when applicable), `artifactLedger` after a real install                                                                                                                                                                                             |
| `ci`        | `baseRef`, `changes[]`, `results[]`, `exitCode`                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `explain`   | `source` (`fresh` \| `last-run`), `originCommand`, `analyzedAt`, `packages[]` (each `{metadata, signals, assessment, score}`)                                                                                                                                                                                                                                                                                                                                       |
| `diff`      | `diff` (a `VersionDiff`: `from`/`to`, per-category changes, `score`, `diffRisk`, `riskReasons`), `failOn`, `exitCode`                                                                                                                                                                                                                                                                                                                                               |
| `monitor`   | `packages`, `source` (`{approval, direct, lockfile}` counts), `baseline` (`{created, path, previousUpdatedAt, updated}`), `events[]` (each `{package, kind, severity, detail}`), `errors[]`, `summary`, `exitCode`                                                                                                                                                                                                                                                  |
| `doctor`    | `checks[]` (each `{id, label, status, message, durationMs}`), `summary`, `exitCode`                                                                                                                                                                                                                                                                                                                                                                                 |
| `history`   | `package` (filter, or absent), `total`, `allowedSigners` (path, `--verify` only), `entries[]` (each the approval record + `key`/`name`/`version`, optional `context` `{targateVersion, decision, risk, score, source, aiProvider, aiModel, policyFile, policyHash, reasons}`, optional `signature`, optional `verification` `{status, signer, detail}`), `exitCode`                                                                                                 |
| `recommend` | `query`, `analyzed`, `recommendations[]` (ranked; each `{name, version, description, weeklyDownloads, source, score, assessment, signals}`), `rejected[]` (each `{name, version, reason, source}`), `aiSuggestions` (`{status: "ok"\|"skipped"\|"unavailable", provider?, model?, names[], detail?}`), `exitCode`                                                                                                                                                   |
| `sandbox`   | `spec`, `image`, `networkMode`, `captureRequested`, `timedOut`, `suspicious[]`, `network` (observed `{captureActive, dnsQueries, connections, httpRequests, errors}` or `null`), `log`, `exitCode`                                                                                                                                                                                                                                                                  |
| `graph`     | `source` (`project` \| `resolved` \| `package`), `packageManager?`, `roots[]`, `workspaces[]`, `baselineCompared`, `only?`, `stats`, `nodes[]` (each `{id, name, version?, kind, score?, risk, decision?, hasLifecycleScripts?, hasNativeCode?, knownMalicious?, advisories?, deprecated?, hasProvenance?, direct?, workspaces?, riskIncreased?, reasons?, error?}`), `edges[]` (`{from, to}`), `exitCode` — with `--why`: `why`, `chains[][]`, `truncated` instead |
| `cache`     | `action`, `scope`, plus action-specific keys (`path`/`cleared` or cache stats)                                                                                                                                                                                                                                                                                                                                                                                      |

Key structures worth knowing:

- **`assessment`** — `{risk, decision, summary, reasons[], recommendedAction, suggestedAlternatives?, source}`; `assessment.decision` is one of `allow`, `allow_with_warnings`, `require_approval`, `block`.
- **`score`** — `{total (0–100), categories[] (each {name, label, score, max, notes?}), floorReason?}`. Informational: a risk-signal aggregation, never the decision.
- **`signals.reputation`** — reputational/temporal signals: `versionAgeDays`, `latestVersion`, `latestVersionAgeDays` (days since the package's latest release — maintenance recency, informational), `releaseAfterInactivityDays`, `releaseGapAnomaly`, `maintainerCount`, `maintainerChange`, `repositoryMismatch`, `hasProvenance`, `deprecated`, `downloads {status, weeklyDownloads?, trend?}`, `repo {status, archived?}`, and (root-package analyses only) `maintainerIntel {status, maintainers[], truncated, newMaintainerNoTrackRecord[]}`. Lookup `status` values distinguish `ok` from `unavailable`/`rate-limited`/`skipped` — an unknown is never reported as clean.
- **`signals.artifact`** — identity of the exact tarball inspected: canonical SHA-512 `digest`, registry/tarball URLs, available registry/lockfile/public/historical integrity values, evidence `reasons`, and `trust` (`public-equivalent`, `lockfile-verified`, `history-verified`, `registry-consistent`, `private-only`, `unverified`, `public-unavailable`, or `mutated`). `mutated` is a hard block.
- **`assessment.deterministic`** — present on AI-sourced assessments: `{decision, risk, reasons}`, the rules engine's own verdict on the same signals (the AI can only make the final decision stricter than this).
- **`metadata.registryUrl` / `metadata.registrySource`** — which registry served the packument and why (`scope` = a per-scope `.npmrc` rule, `global` = a `registry=` override, `default` = npmjs). See [Private registries](private-registries.md).
- **`signals.internalScope`** — set when the package matched the policy's `internalScopes`: OSV/downloads/maintainer/GitHub lookups were deliberately skipped and typosquat similarity does not apply.
- **`behaviorFingerprint`** — `{schemaVersion, artifactSha512?, installScripts[] (each {name, commandHash, referencedFileHashes}), dangerousCapabilities[] (network/child_process/eval), lowRiskCapabilities[] (env), provenanceState (present\|none), complete}`. Records what an attacker must change to execute code, for a future "approve the behavior, not the version" comparison. **Recorded and surfaced only — no decision consults it yet.**
- **approval entries** (in `approve`/`history` payloads and `.targate/approvals.json`) — may carry `context` (the trust history: tool version, verdict, score, AI provider/model, policy file + sha256), `signature` (`{format: "ssh", signer, signature}`), and `behaviorFingerprint` (the record above, covered by the signature when signed). All additions are optional and additive — schemaVersion stays 1.
