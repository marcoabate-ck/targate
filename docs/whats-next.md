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
- [x] **Risk evolution** — shipped as one-shot **`targate monitor`** (no watch daemon): re-checks approvals + direct deps (or `--all`) against `.targate/monitor-baseline.json` and flags new vulnerabilities, maintainer changes, deprecation, archived repos, removed provenance, suspicious new versions, and download drops.

## Phase 3 — Make targate adoptable by teams

Turn targate into something teams and companies can standardize on.

- [ ] **Trust history** — an auditable record of who approved a package, when, under which policy, with which signals, tool version, and AI provider/model.
- [ ] **Signed approvals** — cryptographically signed approvals (Git signing / GPG / Sigstore / SLSA-style attestations) so trust history is verifiable, not just declarative.
- [ ] **Policy packs** — ready-made presets: `default`, `strict`, `react-native`, `ci`, `ai-agent` (e.g. `targate init --policy strict`).
- [ ] **Private-registry support** — npm private registries, GitHub Packages, Verdaccio, internal scoped packages, per-scope trust levels and allowlists, `.npmrc` credentials.

## Phase 4 — Expand the platform

Reach, discoverability, and long-term value.

- [ ] **Dependency graph** — visualize risk across the dependency tree (text now; later SVG/HTML, CI artifacts, monorepo/workspace views, high-risk and lifecycle-script filters).
- [ ] **Recommend & alternatives** — `targate recommend "<need>"`: suggest safer packages for a need, with scores and reasons, turning targate from a gatekeeper into a dependency advisor. (After scoring, reputation, and explainability land.)
- [ ] **VS Code extension** — in-editor warnings on new `package.json` deps, hover scores, a "Review with targate" command, and repo-policy integration. (Depends on stable JSON output.)

---

Positioning we're building toward: *targate is a dependency intelligence layer that helps developers and AI agents choose, inspect, and approve packages before they enter the codebase.*
