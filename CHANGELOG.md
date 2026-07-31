# Changelog

All notable changes to `targate` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): from `1.0.0` on, a
breaking change to the [stability surface](README.md#stability--compatibility)
(CLI, `--json` schema, or policy/approval/denial file formats) requires a major
version bump.

The published version is set from the release tag by the release pipeline
(`.github/workflows/release.yml`); the `version` field in `package.json` is not
bumped by hand.

## [0.10.0] - 2026-07-31

### Added

- **Known-vulnerability severity in the trust process** — OSV advisories now
  carry a severity (`low`/`moderate`/`high`/`critical`/`unknown`, from the GHSA
  label or a CVSS score). The security score deducts **proportionally** to
  severity instead of a flat amount, and the verdict reason names the worst
  severity. By default a known **critical** vulnerability now stops for human
  review (`require_approval`) instead of auto-installing with a warning — it is
  not a hard block, since a CVE is often unavoidable, so block stays a policy
  choice. Lower severities still `allow_with_warnings` by default. Two opt-in
  policy knobs gate the rest — `dependencyPolicy.requireApprovalForAdvisorySeverity`
  and `blockForAdvisorySeverity` (block wins if both match) — and the `ai-agent`
  preset stops the agent on a **high**+ known vulnerability. When a team gates
  advisories, an advisory OSV could not grade (`unknown` severity) fails safe to
  `require_approval` rather than slipping through. `--json` gains an optional
  `severity` on each advisory (backward-compatible). The report also names the worst advisory severity
  inline, and the "static findings" list now shows a count-reconciled preview
  (`… and N more`) that points to `targate explain --last`, which lists every
  flagged file and why; a capped count renders as `N+`.

- **Registry proxy** — `targate proxy` (`setup` / `teardown` / `start` / `stop` /
  `status` / `ensure` / `cert` / `approvals` / `approve` / `deny`): a transparent,
  package-manager-agnostic enforcement point. Point your registry at a local
  HTTPS proxy and every install is vetted with the full deterministic pipeline
  before a tarball's bytes reach the machine — a raw `npm install`, a script, or
  a CI job that never calls `targate add` is still gated, with no wrapper and no
  lifecycle-script dependency. npm, pnpm, yarn, and bun all route through it. It
  analyzes the exact bytes it will serve (integrity-keyed verdict cache: analyzed
  once, ever), auto-migrates private/scoped registries from `.npmrc` and relays
  the credential upstream, holds `require_approval` packages for an out-of-band
  `targate proxy approve|deny` over a loopback-only token-gated control API, and
  automates local-CA trust (`cert install`). Bind is loopback-only by default. See
  [docs/proxy.md](docs/proxy.md). Requires `openssl` for certificate generation.

- **AI source-code audit** — opt-in `--audit-code` (on `add` / `approve` /
  `install`), a dedicated `targate audit <pkg>`, and a policy `codeAudit` scope
  (`off` / `flagged` / `direct` / `all`). The AI reads a bounded, risky subset of
  the actual source (install-time scripts, files touching env/child_process/
  network/eval, minified files, entry points), fenced as untrusted DATA.
  Findings only ever **escalate** the verdict through the deterministic clamp —
  a hard block can never be audited into an approval. Results are cached by the
  artifact content digest, so identical bytes cost one model call.
- **Interactive install triage** — arrow-key approve / deny / skip with a live
  per-package detail panel, plus a committable `.targate/denials.json` store for
  persistent rejections.
- **Published-artifact gate** — `pnpm pack:check` asserts the npm tarball ships
  only `dist/**` + `README.md` + `LICENSE` + `package.json` and that the bin
  runs; wired into CI and `prepublishOnly`.
- **`targate --version` / `-v`** — prints the installed version (the standalone
  binaries embed it at build time).
- **Behavior fingerprint + opt-in reuse** — every analysis now records a behavior
  fingerprint (install-script command + referenced-file hashes, tiered capability
  set, provenance state) on the approval and in `--json`. With the opt-in policy
  `dependencyPolicy.trustBehaviorFingerprint`, a routine version bump of an
  already-approved package whose behavior is unchanged is auto-cleared instead of
  re-prompting. It only ever clears a **soft** verdict: an install-script change,
  a new dangerous capability, a provenance downgrade, an incomplete analysis, or
  any hard block all still re-prompt. Off by default (approvals stay
  version-exact).

- **"last updated" in the report header.** Alongside `published: N days ago` (the
  analyzed version's age), the report now shows `last updated: N days ago (latest
  <version>)` when the analyzed version is not the latest release — surfacing
  whether a package is actively maintained vs stale. Informational only (it does
  not drive the verdict); also exposed as `signals.reputation.latestVersion` /
  `latestVersionAgeDays` in `--json`.

### Changed

- **Transient npm-metadata timeouts are retried before degrading.** A one-off
  registry timeout used to degrade a package to UNKNOWN (`require_approval`) —
  flaky on a large lockfile in CI. The metadata fetch now retries a
  network-timeout a few times (deterministic errors like 404/auth still fail
  fast); if every attempt times out it degrades to UNKNOWN as before, so the
  fail-closed guarantee is unchanged.
- **Lifecycle-script severity now follows when the hook runs.** Only install-time
  hooks (`preinstall`/`install`/`postinstall`) execute when a consumer installs
  the published registry tarball. Pack/publish-time hooks (`prepare`/`prepack`/
  `postpack`) run at publish or on a git/local install, never on a registry
  install — so a fetch-and-execute construct (`curl … | bash`) in a pack-time
  hook is no longer a hard block, `requireApprovalForLifecycleScripts` no longer
  escalates a pack-time-only package, and the Security Score's install-behavior
  category no longer deducts for pack-time hooks or their command findings. The
  verdict engine already treated pack-time hooks as ALLOW-WITH-WARNINGS; the
  hard-block predicate, the policy toggle, and the score now agree with it.
- **`published:` in the report now shows the analyzed version's publish age**,
  not the package's first-ever release date (`time.created`). Previously every
  version of a package rendered the same package-age figure, which read as the
  version's publish date but was not. When the analyzed version is the latest, the
  line is marked `(latest)`. The package's maturity is preserved as a distinct
  `first release: N days ago` field (shown when it differs from this version's age),
  so the age signal isn't lost. Day counts are also pluralized (`1 day ago`).
- **React Native compatibility notes no longer fire on non-RN native packages.**
  The New-Architecture (`codegenConfig`) and Expo (config-plugin / bare-workflow)
  notes are now gated on real React Native signals — a `react-native` dependency,
  `codegenConfig`, RN/Expo config files, a React-dependent podspec, or RN
  bridge/JSI symbols in native source — never on marketing `keywords`. A plain
  native package (e.g. a CLI shipping iOS/Android helper files) still gets the
  framework-agnostic "native code detected" signal but not React-Native-framework
  guidance that does not apply to it.
- Dependency-metadata drift (`dependencies` / `optionalDependencies` /
  `peerDependencies`) on **checksum-verified** bytes is now approvable
  `require_approval` drift instead of a `mutated` hard block; real identity /
  hidden-install-hook / unverified-byte cases remain hard blocks.
- A shallow `ALLOW` / `ALLOW WITH WARNINGS` now states that **only the named
  package was analyzed**, not its transitive tree (suppressed under `--deep`), so
  a clean verdict is not read as "the whole install is safe".
- `graph`, `recommend`, and `monitor` are now labeled **experimental** (in help
  and the CLI reference) — outside the 1.0 stability guarantee.

### Removed

- **Executable repository config** (`targate.policy.{ts,js,mjs,cjs}` and
  `.targate/approvals|denials.{ts,js,mjs,cjs}`) and the `jiti` runtime dependency.
  Configuration is now **declarative only** (`.yaml`/`.yml`/`.json`, parsed never
  executed), removing the only path by which a repository could run code through a
  targate config file. The `TARGATE_ALLOW_EXEC_CONFIG` / `TARGATE_NO_EXEC_CONFIG` env
  vars and the `definePolicy` / `defineApprovals` helpers are gone; `targate policy
init` supports `--format yaml|json`. A leftover legacy executable file is ignored
  and flagged by `targate doctor` — convert it to YAML/JSON.

### Security

- **Installer signature is mandatory and fail-closed.** `install.sh` now verifies
  a minisign signature over the checksums with the embedded public key (and then
  the SHA-256) before installing; a missing `minisign`, a missing signature, or a
  bad signature aborts. Non-`https` `TARGATE_BASE_URL` is rejected.
- **Hardened sandbox.** The trial install runs as a **non-root** user on a
  **read-only** root filesystem (only two tmpfs work dirs writable); base image
  bumped to `node:22-alpine` (Node 20 is EOL); a spec starting with `-` is rejected.
- **Supply chain of the tool itself.** Every GitHub Actions `uses:` is pinned to a
  commit SHA; Dependabot now covers the npm dependency tree; the Pages workflow was
  reduced to least privilege; and a CI coverage gate guards `src/network.ts` (SSRF /
  redirect handling) and `src/signing.ts`.
- **Dependency CVE bumps.** `tar` 7.5.19 → 7.5.22 (runtime, used by the tarball
  quarantine extractor — GHSA fix), and the build/docs toolchains bumped
  `postcss` 8.5.16 → 8.5.23 and `brace-expansion` 5.0.7 → 5.0.8.
- **Docs site migrated from Docusaurus to Starlight (Astro).** This removes the
  `@docusaurus/core` → `serve-handler` → `minimatch@3` → `brace-expansion@1.1.16`
  chain that carried an unfixable high-severity DoS advisory (no patched 1.x, and
  5.x was API-incompatible with `minimatch@3`). The new docs dependency tree has
  no known vulnerabilities. The docs are build/tooling only and never shipped in
  the npm package.

### Packaging

- `files: ["dist"]`, npm metadata (`repository` / `homepage` / `bugs`), and a
  `prepublishOnly` chain (typecheck → test → build → pack:check).
- Homebrew and winget publishing are **off for the pre-1.0 npm soft-launch**
  (the release jobs are gated behind the `PUBLISH_BREW_WINGET` repo variable and
  the docs no longer list those methods). npm, the install script, and direct
  binary downloads remain. Re-enable later with
  `gh variable set PUBLISH_BREW_WINGET --body true`.
- **Dispatchable `Tag release` workflow** — cut a release from the Actions tab
  with no local git: it derives the version from the top CHANGELOG heading (or an
  explicit input), validates it, and creates + pushes the `vX.Y.Z` tag, which
  triggers the existing release pipeline. Requires a `RELEASE_TOKEN` secret
  (fine-grained PAT / App token with `contents: write`) so the tag push triggers
  downstream workflows — the default `GITHUB_TOKEN` would not.

## [0.1.0]

- Initial pre-release: pre-install security analysis for npm packages
  (`add` / `install` / `approve` / `ci`), deterministic rules engine
  with an AI advisory layer clamped to it, artifact-identity verification,
  transitive/full-tree analysis, team policy, signed approvals, sandbox, graph,
  diff, monitor, recommend, and a stable `--json` schema.
