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

## [Unreleased]

### Added

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

### Changed

- Dependency-metadata drift (`dependencies` / `optionalDependencies` /
  `peerDependencies`) on **checksum-verified** bytes is now approvable
  `require_approval` drift instead of a `mutated` hard block; real identity /
  hidden-install-hook / unverified-byte cases remain hard blocks.
- A shallow `ALLOW` / `ALLOW WITH WARNINGS` now states that **only the named
  package was analyzed**, not its transitive tree (suppressed under `--deep`), so
  a clean verdict is not read as "the whole install is safe".
- `graph`, `recommend`, and `monitor` are now labeled **experimental** (in help
  and the CLI reference) — outside the 1.0 stability guarantee.

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

### Packaging

- `files: ["dist"]`, npm metadata (`repository` / `homepage` / `bugs`), and a
  `prepublishOnly` chain (typecheck → test → build → pack:check).

## [0.1.0]

- Initial pre-release: pre-install security analysis for npm packages
  (`add` / `install` / `approve` / `ci`), deterministic rules engine
  with an AI advisory layer clamped to it, artifact-identity verification,
  transitive/full-tree analysis, team policy, signed approvals, sandbox, graph,
  diff, monitor, recommend, and a stable `--json` schema.
