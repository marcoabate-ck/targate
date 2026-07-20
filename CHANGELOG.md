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

### Changed

- Dependency-metadata drift (`dependencies` / `optionalDependencies` /
  `peerDependencies`) on **checksum-verified** bytes is now approvable
  `require_approval` drift instead of a `mutated` hard block; real identity /
  hidden-install-hook / unverified-byte cases remain hard blocks.

### Packaging

- `files: ["dist"]`, npm metadata (`repository` / `homepage` / `bugs`), and a
  `prepublishOnly` chain (typecheck → test → build → pack:check).

## [0.1.0]

- Initial pre-release: pre-install security analysis for npm packages
  (`add` / `install` / `approve` / `ci` / `check`), deterministic rules engine
  with an AI advisory layer clamped to it, artifact-identity verification,
  transitive/full-tree analysis, team policy, signed approvals, sandbox, graph,
  diff, monitor, recommend, and a stable `--json` schema.
