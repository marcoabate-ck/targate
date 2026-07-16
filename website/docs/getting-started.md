---
title: Getting started
sidebar_position: 2
description: Install the targate CLI and gate your first package.
---

# Getting started

## Requirements

- **Node.js ≥ 22.13** (the toolchain requires it).
- A package manager: npm, pnpm, or yarn. targate detects which one your project uses from its lockfile.
- Optional: an AI provider (hosted or local). Without one, targate runs on its deterministic rules engine.

## Install

```bash
npm install -g targate
# or run ad-hoc, no global install:
npx targate add <package>
```

## Gate your first package

```bash
targate add lodash
```

targate analyzes the package first and only runs the real install if it passes. To **preview** a package without installing anything, add `--dry-run`:

```bash
targate add left-pad@1.3.0 --dry-run
```

## Record an approval without installing

Teams often want to vouch for a package in one place and commit that decision, separate from installing. `approve` writes a committable record to `.targate/approvals.json`:

```bash
targate approve esbuild@0.27.3
targate approve esbuild@0.27.3 --sign   # add an SSH signature
```

See **[Approvals & policy](./concepts/approvals-and-policy)** for how approvals are read, merged, and enforced.

## Gate the whole tree

`add` gates one package. To vet **every** dependency in your lockfile and then gate a full install:

```bash
targate install --dry-run     # review the whole tree, install nothing
targate install               # gate, then install
```

See **[Transitive analysis & install](./concepts/transitive-and-install)**.

## Check your environment

```bash
targate doctor          # diagnose Node, package manager, registry, AI provider, policy
targate doctor --ping   # also make a live AI completion call
```

## Exit codes

targate is built to be scripted and dropped into CI:

| Code | Meaning |
|------|---------|
| `0` | OK — allowed (or installed, or a clean dry run) |
| `1` | Error — bad input, unreachable dependency, misuse |
| `2` | Blocked — a package was blocked, a sandbox looked suspicious, or a CI check failed |

## Explicit by design

Package installation always uses the explicit `targate add <package>` form. Bare package names and unknown commands fail **before** any analysis starts — they are never silently interpreted as a package to install. Run `targate <command> --help` for the options a command accepts.
