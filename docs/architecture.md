# Architecture

targate is a pipeline. A package name goes in; a gated install decision comes out. Each stage produces **signals** (facts) that flow into a **rules engine** (the deterministic security floor) and then, optionally, an **AI reviewer** (advisory, clamped). The block — or the install — happens at the very end, once.

For the step-by-step behaviour of each stage see [How it works](how-it-works.md); this page is the map and, crucially, the line between **what is deterministic and what is probabilistic**.

## The pipeline

```mermaid
flowchart TD
  CLI["CLI (targate add / approve / install / ci)"] --> RES[Package resolver — npm registry metadata]
  RES --> FET[Tarball fetcher — checksum-verified vs manifest]
  RES --> OSV["OSV / OpenSSF lookup — malicious records + advisories"]
  RES --> REP[Reputation + maintainer intelligence]
  FET --> QUA["Quarantine extractor — isolated temp dir, strict paths, scripts never run"]
  QUA --> IDX["Bounded package file index — one filesystem traversal"]
  IDX --> STAT["Static analyzers — lifecycle scripts, contents, native surface, RN hardening"]
  STAT --> SIG[Signals]
  OSV --> SIG
  REP --> SIG
  SIG --> RULES["Rules engine — deterministic verdict + hard-block floor"]
  RULES --> AI["AI reviewer — advisory, can only make it stricter"]
  AI --> POL["Team policy — escalation-only, allow-list can clear soft blocks"]
  POL --> DEC{Decision}
  DEC -->|allow / allow_with_warnings| INST[Installer — runs the real package manager]
  DEC -->|require_approval| APPR["Installer with --ignore-scripts, or record an approval"]
  DEC -->|block| STOP[Blocker — nothing is installed, exit 2]
```

## Stages

| Stage | Responsibility |
|---|---|
| **CLI** | Parses the command (`add`, `approve`, `install`, `sandbox`, `ci`, `policy`, `agents`), flags, and provider selection. |
| **Package resolver** | Fetches registry metadata: version, repository, maintainers, publish dates, scripts, dependencies. |
| **Tarball fetcher** | Streams the tarball under timeout/byte budgets, computes canonical SHA-512, and verifies every available registry, lockfile, public-mirror, and historical checksum before anything can execute. A mismatch becomes a deterministic hard block. |
| **Quarantine extractor** | Extracts into an isolated temp dir with compressed/expanded/file-count/per-file limits, ignores archive links, and verifies canonical real-path containment. Contents are only ever *read* — lifecycle scripts are never executed. |
| **Package file index** | Traverses the extracted tree once under shared file/byte limits and indexes path, basename, extension, and size. Content, native-surface, and RN-hardening analyzers consume the same index. A truncated index becomes explicit `UNKNOWN`, never a partial clean result. |
| **Static analyzers** | Detect lifecycle scripts and inspect their command strings; scan contents for `process.env` / `child_process` / network / `eval` / obfuscation; map the React Native native surface; check for typosquatting. |
| **OSV / OpenSSF lookup** | Queries for known-malicious records (`MAL-*`, GHSA malware) and vulnerability advisories. |
| **Reputation lookups** | Registry-derived signals (version age, maintainer change, provenance, deprecation, repo mismatch) plus optional npm-downloads and GitHub-archived lookups. Fail-open: an unreachable or rate-limited lookup yields an explicit **UNKNOWN**, never "clean". `--no-reputation` skips the external calls. |
| **Signals** | The structured, machine-readable set of facts every downstream stage consumes (also the shape emitted by `--json`). |
| **Security Score** | A 0–100 aggregation of the signals with a per-category breakdown — **informational only**, computed before the verdict and never consulted by the rules engine, the AI clamp, or policy. |
| **Rules engine** | Maps signals to a deterministic verdict and marks any **hard block**. This is the security floor. |
| **AI reviewer** | Optional. Reasons over the same signals for a contextual verdict — strictly advisory and clamped (below). |
| **Team policy** | Applied on top of the assessment; escalation-only, with the one documented exception that an allow-list entry can clear a *soft* block. See [Policy reference](policy-reference.md). |
| **Installer / Blocker** | Runs the real package manager for an allow, `--ignore-scripts` for require-approval, or nothing at all for a block. |

All network clients share bounded fetch/read helpers. If download, extraction, or static inspection exceeds a configured budget, the pipeline emits `analysisDegraded`, renders the missing evidence as `UNKNOWN`, and sets a deterministic `require_approval` floor before AI or team policy runs.

After exact metadata resolution, independent work starts concurrently: the tarball download, OSV, reputation, maintainer intelligence, public-registry evidence, and the historical artifact lookup. Verification still joins all required evidence before the artifact can be trusted. Full-tree AI cache lookups and writes are bulk operations, so a warm run reads the cache once and makes no model calls.

CLI commands share an analysis session for policy/cache loading, signed-approval loading, stage rendering, root analysis, and last-run persistence. Human rendering is separated by domain under `src/report/`, while `src/report.ts` remains the compatibility barrel.

Repeatable 10/100/500/1000-package performance targets and metrics are documented in the [benchmark guide](../benchmarks/README.md).

## Deterministic vs. probabilistic

This is the load-bearing design decision. **Security guarantees come from the deterministic half; the AI only ever adds caution.**

### Deterministic (the security floor)

- Checksum verification of the tarball.
- Quarantine extraction — scripts never run, regardless of anything.
- The static signal extraction (scripts, contents, native surface, typosquat distance).
- The OSV/OpenSSF malicious/advisory lookup.
- The **rules engine** verdict and the **hard-block** classification.
- The **clamp**: `clampDecision` re-runs the rules engine and, if it returns BLOCK, forces the final decision to BLOCK regardless of what the model said.
- Team policy escalation.

These run identically with `--no-ai`, with no provider configured, and in CI. The output is reproducible.

### Probabilistic (advisory only)

- The **AI reviewer**'s verdict and prose reasoning.

That's the whole probabilistic surface. It exists to catch *combinations* of signals a flat rule misses ("recent publish **plus** missing repo **plus** a postinstall") and to explain them in words.

## What the AI can and cannot do

**Can:**
- Make a verdict **stricter** — escalate an `allow` to `require_approval` or `block` when the combination of signals looks risky.
- Explain its reasoning in the report (`source: ai`).

**Cannot:**
- **Downgrade any deterministic verdict.** A jailbroken, prompt-injected, or simply wrong model cannot turn `allow_with_warnings`, `require_approval`, or `block` into a weaker result — the clamp overrides it. See [Decision policy](decisions.md).
- Run any package code (there is no execution stage before the decision).
- Reach a decision when a provider is misconfigured or fails — targate falls back to the rules engine and notes it.

## Where policy applies, and where the block actually happens

- **Policy** is applied at one point — after the AI/rules assessment, before the decision is finalized. It can only make the decision stricter, except that `allowKnownPackages` can clear a **soft** (heuristic) block. A **hard** block (known-malicious record, or a `curl … | bash`-style download-and-execute) is immune to policy, the allow list, approvals, and the AI alike. See [Policy reference](policy-reference.md) and [Hard vs soft blocks](decisions.md#hard-vs-soft-blocks).
- **The block** happens exactly once, at the Installer/Blocker stage. Up to that point nothing untrusted has executed; a `block` verdict simply means the installer is never invoked and the process exits `2`.

## Scope

By default only the requested top-level package flows through this pipeline. `--deep` and `targate install` run the *same* pipeline over the full transitive tree; the strictest verdict in the tree gates the whole install. See [Transitive dependencies & full-tree install](transitive-and-install.md) and the [Security model](security.md#scope-and-limitations).
