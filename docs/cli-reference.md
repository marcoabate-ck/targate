# CLI reference

## Commands

```
targate add <package>[@version]         Analyze a package, then gate the install
(targate <package> without a subcommand is a shorthand for targate add)
targate approve <package>[@version]     Analyze and record a committable approval WITHOUT installing
targate install                         Vet the whole dependency tree, then gate a full install
targate sandbox <package>[@version]     Trial install in a disposable Docker container
targate ci [--base-ref <ref>]           Analyze dependencies changed vs a git ref (for PRs)
targate ci init                         Scaffold .github/workflows/targate.yml
targate diff <pkg>@<v1> [<pkg>[@<v2>]]  What changed between two versions (second spec/
                                    version omitted → latest; bare <pkg> → installed vs latest)
targate monitor [--all]                 Re-check monitored packages against a stored
                                    baseline and report risk that increased over time
targate explain <package>[@version]     Explain why a package would be allowed or blocked
                                    (analyzes fresh; installs nothing, records nothing)
targate explain --last                  Explain the most recent add/approve run
                                    (reads .targate/last-run.json — no network)
targate recommend "<need>"              Suggest packages for a need, safest first
                                    (npm-search candidates → full deterministic
                                    analysis → ranked by security score; no AI)
targate history [<package>[@version]]   Trust history: every recorded approval — who,
                                    when, verdict, policy, AI provider. --verify
                                    checks SSH signatures against the committed
                                    .targate/allowed-signers file
targate doctor [--ping]                 Check the environment: Node, package manager,
                                    registry, OSV, AI provider, GitHub, policy,
                                    cache dirs, CI mode. Exits 1 on any failure.
targate policy init [--format <fmt>]    Scaffold the team policy (yaml | json | js | ts)
                                    --preset default | strict | react-native | ci |
                                    ai-agent starts from a ready-made policy pack
targate cache info                      Show the AI response cache location + size
targate cache clear [--scope <s>]       Delete the AI response cache (user | project)
targate agents init [--format <list>]   Scaffold agent-instruction files (skill, agents,
                                    cursor, windsurf, copilot, cline, or all)
```

| Command | What it gates | Docs |
|---|---|---|
| `add` | one new package (+ `--deep` for its tree) | [Transitive & install](transitive-and-install.md) |
| `approve` | records a committable approval without installing | [Team workflow](team-workflow.md#approving-a-package--targate-approve) |
| `install` | a full-project install (the whole tree at once) | [Transitive & install](transitive-and-install.md#full-tree-install--targate-install) |
| `sandbox` | a disposable Docker trial install | [Sandbox](sandbox.md) |
| `ci` | dependencies a change adds/updates, in a PR | [CI integration](ci.md) |
| `diff` | nothing — compares two versions of a package | — |
| `monitor` | nothing — flags risk that rose since a baseline | — |
| `explain` | nothing — explains a verdict (fresh or last run) | — |
| `history` | nothing — lists the trust history (and verifies signatures) | [Team workflow](team-workflow.md#trust-history--targate-history) |
| `recommend` | nothing — suggests packages for a need, safest first | — |
| `doctor` | nothing — diagnoses the environment | — |
| `policy init` | scaffolds the team policy file (`--preset` for policy packs) | [Team workflow](team-workflow.md#team-policy--targatepolicy) |
| `cache` | inspect / clear the AI response cache | [AI response cache](ai-cache.md#invalidating-the-cache) |
| `agents init` | scaffolds agent-instruction files | [AI coding agents](agents.md) |

## Options (add & ci)

```
--package-manager <pm>  Force pnpm | npm | yarn (default: auto-detect from lockfile)
--json                  Machine-readable output (metadata + signals + assessment)
--dry-run               Analyze and report only — never prompt, never install
                        (to approve without installing, use `targate approve`)
--yes                   Skip confirmation for allow/allow-with-warnings
                        (approve: skip the lifecycle-scripts prompt)
--no-ai                 Skip the AI reasoning layer, use rules only
--no-cache              Ignore cached AI assessments for this run (recompute);
                        fresh results still refresh the cache
--provider <name>       anthropic | deepseek | openai | ollama | custom
--model <name>          Override the model for the selected provider
--base-url <url>        API base URL (required for --provider custom)
--api-key <key>         API key (prefer env vars over this flag)
--reasoning             Enable model reasoning where the provider supports it
                        (see ai-providers.md#reasoning-support---reasoning)
--deep                  (add, approve) Also analyze the full transitive dependency
                        tree; the strictest verdict in the tree gates it
--concurrency <n>       (add --deep, install) Packages analyzed in parallel
                        (default: 16). Lower it if a cloud AI provider rate-limits you.
--no-ai-batch           (add --deep, install) Assess each package in its own AI
                        request instead of batching several per request (stricter
                        per-package isolation; slower/costlier)
--no-reputation         Skip the external reputation lookups (npm downloads API,
                        GitHub repo status). Registry-derived reputation signals
                        (version age, maintainer change, deprecation, provenance)
                        are still computed. Set GITHUB_TOKEN (or GH_TOKEN) to raise
                        the GitHub rate limit from 60 req/h; without it, large
                        --deep runs report the archived status as UNKNOWN once the
                        quota is exhausted — never as "fine".
--allow-scripts         (approve) Record the approval as scripts-allowed (default:
                        no-scripts) — (install) run lifecycle scripts
--frozen-lockfile       (install) Immutable install (npm ci / --frozen-lockfile)
--base-ref <ref>        (ci) Git ref to diff against (default: origin/main)
```

## Options (doctor)

```
--ping                  Also send one real (paid) test completion to the resolved
                        AI provider to verify it end to end (default: config-only
                        check, no model call)
```

## Options (approve & history)

```
--sign                  (approve) Cryptographically sign the approval entry with
                        your SSH key (TARGATE_SIGNING_KEY, git user.signingkey,
                        or ~/.ssh/id_*). The signature covers the whole entry —
                        version, mode, date, context — in the "targate-approval"
                        namespace, and verifies against the committed
                        .targate/allowed-signers file. A signing failure aborts
                        the recording; nothing is written unsigned.
--verify                (history) Verify each entry's signature. Exit 2 when any
                        signature is invalid or verification errored; unsigned
                        entries are reported but do not fail (use the policy's
                        requireSignedApprovals to enforce signatures).
```

## Options (recommend)

```
--limit <n>             Candidates to analyze (default: 5, max: 15 — each costs
                        a real tarball download + full analysis)
--no-reputation         Skip external reputation lookups per candidate
--fail-on-osv-error     Escalate candidates whose OSV lookup failed
```

Candidate discovery is npm search relevance; targate ranks the **safety** of what search returned (full pipeline per candidate: quarantine, scripts/contents, OSV, reputation, maintainer intel, security score, rules verdict + team policy). Known-malicious, hard-block, deprecated, and policy-blocked candidates are excluded with the reason shown. Ranking is security score, adoption (weekly downloads) as tie-breaker. Deliberately **no AI** — recommendations are reproducible.

## Options (policy init)

```
--format <fmt>          yaml (default) | json | js | ts
--preset <name>         Policy pack to start from: default | strict |
                        react-native | ci | ai-agent (default: default)
```

## Options (diff)

```
--fail-on <level>       Exit 2 when the diff risk is at this level or above
                        (low | medium | high; default: high)
--no-reputation         Skip external reputation lookups on both versions
--fail-on-osv-error     Treat an unreachable OSV lookup as a medium-risk unknown
```

## Options (monitor)

```
--all                   Monitor the entire lockfile tree, not just approvals +
                        direct dependencies
--no-update             Report events without advancing the baseline
--concurrency <n>       Packages checked in parallel (default: 16)
--no-reputation         Skip download/GitHub lookups (fewer events, faster)
--fail-on-osv-error     Treat an unreachable OSV lookup as a warning
```

## Options (sandbox)

```
--image <image>         Docker image (default: node:20-alpine)
--timeout <seconds>     Kill the sandbox after N seconds (default: 300)
--network <mode>        open (default, full egress) | none (offline trial)
```

## Exit codes

`0` ok, `1` error, `2` blocked (or suspicious sandbox / failed CI check).

- `doctor`: `0` when every check passes or only warns, `1` when at least one check fails.
- `explain`: `0` on success **regardless of the decision** (it is informational — the gate lives in `add`/`install`/`ci`), `1` on operational errors. Never `2`.
- `diff`: `0` when the diff risk is below `--fail-on` (default: `low`/`medium`), `2` at or above it (default: `high`), `1` on operational errors (name mismatch, unknown version, not in the lockfile).
- `history`: `0` on success (an empty history included); with `--verify`, `2` when any signature is invalid or verification errored, `1` on operational errors.
- `recommend`: `0` on success (even with zero eligible candidates — it is advisory; the gate lives in `add`), `1` when the npm search itself fails. Never `2`.
- `monitor`: `0` when no risk increased (including a plain first run that only creates the baseline), `2` when any `warn`/`critical` event fired, `1` on operational errors.
- `sandbox`: `0` clean, `2` on a timeout, suspicious log line, or unexpected network destination, `1` when Docker is unavailable or the install failed with no findings.

`--dry-run` is a pure preview: analyze and report only — it never prompts, never installs, and records nothing. To approve a package without installing it, use [`targate approve`](team-workflow.md#approving-a-package--targate-approve).

## JSON output schema

Every command that supports `--json` prints **exactly one JSON document on stdout** — no progress lines, no prompts. Each document is wrapped in a flat envelope:

```json
{ "schemaVersion": 1, "command": "add", "…": "…payload keys follow at the same level" }
```

**Stability rules.** Within a `schemaVersion`, changes are **additive only** — new keys may appear at any level and consumers must ignore keys they don't recognize. Any removal, rename, or type change of an existing key bumps `schemaVersion`. Compare it with `===`, not `>=`.

Payload keys per command (in addition to `schemaVersion` + `command`):

| `command` | Payload keys |
|---|---|
| `add` | `metadata`, `signals`, `assessment`, `score`, `deep` (per-package results of a `--deep` run, else `null`) |
| `approve` | `metadata`, `signals`, `assessment`, `score`, `deep`, `outcome` (`hard-blocked` \| `already-allowed` \| `approvable`), `approval` (the recorded entry, or `null`) |
| `install` | `packageManager`, `source`, `total`, `results[]`, `decision`, `exitCode` |
| `ci` | `baseRef`, `changes[]`, `results[]`, `exitCode` |
| `explain` | `source` (`fresh` \| `last-run`), `originCommand`, `analyzedAt`, `packages[]` (each `{metadata, signals, assessment, score}`) |
| `diff` | `diff` (a `VersionDiff`: `from`/`to`, per-category changes, `score`, `diffRisk`, `riskReasons`), `failOn`, `exitCode` |
| `monitor` | `packages`, `source` (`{approval, direct, lockfile}` counts), `baseline` (`{created, path, previousUpdatedAt, updated}`), `events[]` (each `{package, kind, severity, detail}`), `errors[]`, `summary`, `exitCode` |
| `doctor` | `checks[]` (each `{id, label, status, message, durationMs}`), `summary`, `exitCode` |
| `history` | `package` (filter, or absent), `total`, `allowedSigners` (path, `--verify` only), `entries[]` (each the approval record + `key`/`name`/`version`, optional `context` `{targateVersion, decision, risk, score, source, aiProvider, aiModel, policyFile, policyHash, reasons}`, optional `signature`, optional `verification` `{status, signer, detail}`), `exitCode` |
| `recommend` | `query`, `analyzed`, `recommendations[]` (ranked; each `{name, version, description, weeklyDownloads, score, assessment, signals}`), `rejected[]` (each `{name, version, reason}`), `exitCode` |
| `sandbox` | `spec`, `image`, `networkMode`, `captureRequested`, `timedOut`, `suspicious[]`, `network` (observed `{captureActive, dnsQueries, connections, httpRequests, errors}` or `null`), `log`, `exitCode` |
| `cache` | `action`, `scope`, plus action-specific keys (`path`/`cleared` or cache stats) |

Key structures worth knowing:

- **`assessment`** — `{risk, decision, summary, reasons[], recommendedAction, suggestedAlternatives?, source}`; `assessment.decision` is one of `allow`, `allow_with_warnings`, `require_approval`, `block`.
- **`score`** — `{total (0–100), categories[] (each {name, label, score, max, notes?}), floorReason?}`. Informational: a risk-signal aggregation, never the decision.
- **`signals.reputation`** — reputational/temporal signals: `versionAgeDays`, `releaseAfterInactivityDays`, `releaseGapAnomaly`, `maintainerCount`, `maintainerChange`, `repositoryMismatch`, `hasProvenance`, `deprecated`, `downloads {status, weeklyDownloads?, trend?}`, `repo {status, archived?}`, and (root-package analyses only) `maintainerIntel {status, maintainers[], truncated, newMaintainerNoTrackRecord[]}`. Lookup `status` values distinguish `ok` from `unavailable`/`rate-limited`/`skipped` — an unknown is never reported as clean.
- **`assessment.deterministic`** — present on AI-sourced assessments: `{decision, risk, reasons}`, the rules engine's own verdict on the same signals (the AI can only make the final decision stricter than this).
- **`metadata.registryUrl` / `metadata.registrySource`** — which registry served the packument and why (`scope` = a per-scope `.npmrc` rule, `global` = a `registry=` override, `default` = npmjs). See [Private registries](private-registries.md).
- **`signals.internalScope`** — set when the package matched the policy's `internalScopes`: OSV/downloads/maintainer/GitHub lookups were deliberately skipped and typosquat similarity does not apply.
- **approval entries** (in `approve`/`history` payloads and `.targate/approvals.json`) — may carry `context` (the trust history: tool version, verdict, score, AI provider/model, policy file + sha256) and `signature` (`{format: "ssh", signer, signature}`). All additions are optional and additive — schemaVersion stays 1.
