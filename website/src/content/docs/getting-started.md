---
title: Getting started
description: Install the targate CLI and gate your first package.
---

## Requirements

- A package manager: npm, pnpm, or yarn. targate detects which one your project uses from its lockfile, and calls it (plus `git`) at runtime — keep both installed.
- **Node.js ≥ 22.13** for the npm install method. The standalone binaries (install script, direct download) bundle their own runtime and do **not** require Node.
- Optional: an AI provider (hosted or local). Without one, targate runs on its deterministic rules engine.

## Install

targate ships three ways — all give you the same `targate` CLI. The install-script and direct-download methods go live with the first tagged release.

### npm — every platform (needs Node ≥ 22.13)

```bash
npm install -g targate
# or run ad-hoc, no global install:
npx targate add <package>
```

### Install script — macOS & Linux

Detects your OS/arch, downloads the matching binary, and verifies its SHA-256 before installing:

```bash
curl -fsSL https://raw.githubusercontent.com/marcoabate-ck/targate/main/install.sh | sh
```

Override the target with environment variables when needed: `TARGATE_VERSION`, `TARGATE_INSTALL_DIR`.

### Direct download

Grab a standalone binary from the [latest release](https://github.com/marcoabate-ck/targate/releases/latest) and verify it against the release `SHA256SUMS` (a `SHA256SUMS.minisig` minisign signature is published too):

| Platform | Asset |
|----------|-------|
| macOS arm64 | `targate-darwin-arm64` |
| macOS x64 | `targate-darwin-x64` |
| Linux arm64 | `targate-linux-arm64` |
| Linux x64 | `targate-linux-x64` |
| Windows x64 | `targate-windows-x64.exe` |

```bash
# verify then install (example: macOS arm64)
grep targate-darwin-arm64 SHA256SUMS | shasum -a 256 -c -
install -m 0755 targate-darwin-arm64 /usr/local/bin/targate
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

See **[Approvals & policy](/concepts/approvals-and-policy/)** for how approvals are read, merged, and enforced.

## Gate the whole tree

`add` gates one package by default — but a malicious dependency usually hides **deeper** in the tree. **Strongly recommended before pulling a dependency into a real project or CI:** add `--deep` so the same analysis runs over every transitive dependency:

```bash
targate add <package> --deep   # gate the package AND its whole transitive tree
```

To vet **every** dependency already in your lockfile and then gate a full install:

```bash
targate install --dry-run     # review the whole tree, install nothing
targate install               # gate, then install
```

:::tip[Why isn't --deep the default?]
A deep run resolves and analyzes the entire transitive tree — more registry/tarball/OSV traffic and, with an AI provider, more model calls. Keeping it opt-in lets the quick "is this package OK?" check stay fast and cheap; the [response cache](/concepts/transitive-and-install/) amortizes the cost on repeat runs, and a shallow `ALLOW` reminds you the tree wasn't analyzed.
:::

See **[Transitive analysis & install](/concepts/transitive-and-install/)**.

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
