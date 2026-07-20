# What's next

The roadmap of features we intend to build on top of today's `targate`, grouped into four phases. These are **directional, not commitments** — order and scope will shift as we learn. We tick each box as it ships; an unchecked box is a plan, not a promise.

Want the reasoning behind the ordering (impact, adoption, technical dependencies, enterprise value)? It's captured in the internal roadmap document.

## Phase 1 — Stabilize the product

Make targate reliably usable by developers, CI, and AI agents.

- [x] **Readable + stable JSON output** — a stable human format and a stable machine-readable `--json` schema for CI, bots, agents, and future tooling. *(A `--json` mode already exists — see [CLI reference](cli-reference.md); this item is about locking the schema as a contract.)*
- [x] **`targate doctor`** — one command that checks the environment: Node version, package manager, registry reachability, AI provider/model, OSV access, filesystem permissions, policy validity, CI mode.
- [x] **Security Score** — a 0–100 risk-aggregation score with a per-category breakdown. Documented as a *risk-signal aggregation score, not a proof of safety*.
- [x] **Reputation scoring** — aggregate reputational and temporal signals (package/version age, recent maintainer change, repository mismatch, download spike/drop, provenance, archived repo, deprecation, release after long inactivity).
- [x] **Explain mode** — `targate explain <pkg>` / `targate explain --last`: why a package was approved or blocked, main reasons, and residual risks.

## Phase 2 — Make targate intelligent

The features that set targate apart from a plain vulnerability scanner.

- [x] **Explain AI reasoning** — separate *deterministic findings* from *AI interpretation* in the output, making visible that the AI interprets signals but never overrides a deterministic hard block.
- [x] **Diff mode** — `targate diff pkg@a pkg@b`: what changed between two versions (new lifecycle scripts, files, dependencies, maintainers, repo, native surface, vulnerabilities, size). Built for CI, Renovate, and Dependabot review.
- [x] **Maintainer intelligence** — maintainer-level risk: count, portfolio popularity, and new-maintainer-with-no-track-record detection. *(Account creation-date and cross-package attack-pattern signals are out of scope — npm exposes no public account API.)*
- [x] **Network capture in the sandbox** — observe (not block) network activity during the install: DNS query names, destination hosts/ports, and per-direction byte counts, via an in-container DNS forwarder + logging HTTP(S) proxy. *(Observation only — traffic to hardcoded IPs or ignoring the proxy is not captured; documented in [sandbox](sandbox.md).)*
- [x] **AI source-code audit** — opt-in `--audit-code` (on `add`/`approve`/`install`) plus a dedicated `targate audit <pkg>` and a policy `codeAudit` scope (`off`/`flagged`/`direct`/`all`). The AI reads a bounded, risky subset of the actual source (install-time scripts, files that touch env/child_process/network/eval, minified files, entry points) rather than the whole module, fenced as untrusted DATA. Findings only ever **escalate** the verdict through the deterministic clamp — a hard block can never be audited into an approval. Results are cached by the artifact content digest, so identical bytes cost one model call. Default off; scoped to flagged packages so the whole transitive tree is never audited by surprise.
- [x] **Risk evolution** — shipped as one-shot **`targate monitor`** (no watch daemon): re-checks approvals + direct deps (or `--all`) against `.targate/monitor-baseline.json` and flags new vulnerabilities, maintainer changes, deprecation, archived repos, removed provenance, suspicious new versions, and download drops.

## Phase 3 — Make targate adoptable by teams

Turn targate into something teams and companies can standardize on.

- [x] **Trust history** — every approval records who, when, the verdict at review time (decision/risk/score/reasons), targate version, AI provider+model, and the policy file + sha256; `targate history [pkg] [--verify]` shows it. The committed `.targate/approvals.json` + git history is the audit log.
- [x] **Signed approvals** — shipped with **SSH signatures** (`ssh-keygen -Y`, the same keys as git SSH commit signing) over the canonical approval entry, verified against a committed `.targate/allowed-signers`; `requireSignedApprovals` in the policy makes `add`/`install`/`ci` ignore unsigned or tampered entries. *(GPG and Sigstore/SLSA attestations deliberately out of scope for now.)*
- [x] **Policy packs** — `targate policy init --preset default | strict | react-native | ci | ai-agent`, each a complete validated policy with a self-describing header.
- [x] **Private-registry support** — `.npmrc` resolution (per-scope registries, global override, nerf-darted `_authToken`/`_auth`/`username+_password` credentials, `${ENV}` expansion) for metadata + tarball fetches; npmjs-only lookups skip visibly for scope-mapped packages; per-scope trust shipped as policy `internalScopes` (name-privacy: no OSV/downloads/maintainer/GitHub queries, no typosquat check — all shown in report and score).

## Phase 4 — Expand the platform

Reach, discoverability, and long-term value.

- [x] **Dependency graph** — `targate graph`: the tree as an interactive risk graph. Self-contained HTML (pan/zoom, live filters, search, per-node detail panels, path-to-root highlighting, dark/light), static SVG, Graphviz DOT, Mermaid (GitHub PRs + `$GITHUB_STEP_SUMMARY`), JSON; monorepo/workspace views; high-risk / lifecycle-script / native / deprecated / no-provenance / risk-increased filters (`--only` + live toggles); monitor-baseline "risk increased" overlay; `--why <pkg>` risk-annotated chains; CI artifact recipe scaffolded by `targate ci init`. Deterministic analysis only (no AI).
- [x] **Recommend & alternatives** — `targate recommend "<need>"`: candidates from npm search **plus AI-proposed names** (when a provider is configured; hallucinations rejected on registry lookup, `--no-ai` for search-only), each analyzed with the **full deterministic pipeline** (quarantine, scripts/contents, OSV, reputation, maintainer intel, security score, rules verdict + team policy) and ranked safest-first (score, adoption tie-break); malicious / hard-block / deprecated / policy-blocked candidates excluded with reasons. The AI contributes names only — scoring and ranking stay deterministic and reproducible.
- [ ] **VS Code extension** — in-editor warnings on new `package.json` deps, hover scores, a "Review with targate" command, and repo-policy integration. (Depends on stable JSON output.)

---

Positioning: *targate is an AI-assisted dependency intelligence and decision layer for developers, teams, and coding agents.* That layer ships today with pre-install security as its first application — it already helps you **inspect and approve** packages before they enter the codebase. The direction we're building toward adds **intent-aware recommendation**: helping you *choose* the right package, with project context, not only vet the one you already named.
