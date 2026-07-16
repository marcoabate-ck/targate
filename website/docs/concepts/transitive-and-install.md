---
title: Transitive analysis & install
sidebar_position: 3
description: Gating a single package's tree with --deep, and vetting the whole lockfile with targate install.
---

# Transitive analysis & install

## `--deep`: analyze the transitive tree

`targate add <pkg>` gates the named package. Add `--deep` to also analyze its transitive dependencies:

```bash
targate add esbuild --yes --deep
```

Every transitive dependency runs through the **same** signal pipeline (quarantine, scripts, contents, OSV, reputation). A package whose analysis fails or can't complete is reported as `require_approval` — **unknown is never treated as clean**. A clean tree never softens the root package's own verdict; the worst decision across the tree drives the outcome. Use `--concurrency <n>` to tune parallelism and `--no-ai-batch` to disable AI batching.

## `targate install`: gate the whole lockfile

Where `add` starts from one package, `install` starts from your **lockfile** and vets the complete dependency tree, then gates a full install:

```bash
targate install --dry-run                 # review the whole tree, install nothing
targate install                           # gate, then run the real install
targate install --update-lockfile --dry-run  # resolve a fresh plan and review it
```

- `--dry-run` reviews and reports without installing — this is what you run in CI.
- `--frozen-lockfile` mirrors the package manager's frozen install.
- `--update-lockfile` resolves a staged install plan (in a throwaway directory, scripts disabled) to produce the lockfile to review.

The install is refused if anything is blocked or unapproved. Interactively, targate offers to approve the approvable packages in one step; the rest must be cleared with committed approvals. See **[Approvals & policy](./approvals-and-policy)**.

## pnpm build scripts

pnpm (v10+) does not run dependency build scripts unless you approve them. targate's gate is about *security review*; pnpm's build approval is a *separate* mechanism your install still needs. On pnpm 11+, build approval lives in `pnpm-workspace.yaml`:

```yaml
# pnpm-workspace.yaml
allowBuilds:
  esbuild: true
```

A package can be **approved in targate** (its security review is cleared) while its **build stays gated by pnpm** — the two controls are independent by design.

## Scoring & structured output

Every analysis also produces a 0–100 **security score** and a full set of machine-readable signals. Add `--json` to any analysis command for a structured result you can pipe into other tooling:

```bash
targate add lodash --json | jq '.results[0].assessment.decision'
```
