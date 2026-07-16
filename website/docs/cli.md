---
title: CLI commands
sidebar_position: 4
description: Every targate command at a glance, with exit codes and where to find full flags.
---

# CLI commands

Every command shares one philosophy: **inspect before you execute**. Installation is always explicit (`targate add`); bare names and unknown commands fail before any analysis.

| Command | What it does |
|---|---|
| `targate add <package>[@version]` | Analyze one package, then gate its installation. |
| `targate approve <package>[@version]` | Record a committable human approval without installing. |
| `targate install` | Vet the complete dependency tree, then gate a full install. |
| `targate sandbox <package>[@version]` | Trial-install a package in a disposable Docker container. |
| `targate ci [init]` | Gate dependency changes against a Git ref, or scaffold CI. |
| `targate policy init` | Scaffold a declarative team policy from a preset. |
| `targate doctor` | Diagnose the local security and provider environment. |
| `targate diff <pkg>@<v1> [<pkg>[@<v2>]]` | Compare package versions and rate the upgrade risk. |
| `targate monitor` | Re-check trusted packages and report increased risk. |
| `targate graph [<package>[@version]]` | Render a dependency risk graph, or explain why a package is present. |
| `targate recommend "<need>"` | Recommend analyzed packages for a need, safest first. |
| `targate history [<package>[@version]]` | Show recorded trust decisions and optionally verify signatures. |
| `targate explain <package>[@version] \| --last` | Explain a fresh or recorded decision without installing. |
| `targate cache <info\|clear>` | Inspect or clear the AI assessment cache. |
| `targate agents init` | Scaffold instructions that make coding agents use targate. |

Run `targate <command> --help` for the exact options a command accepts — the help is rendered from the same command registry as this table, and a flag that belongs to another command is rejected rather than ignored.

## Shared analysis flags

Most analysis commands accept: `--json` (structured output), `--dry-run`, `--yes`, `--no-cache`, `--no-ai` (rules-only), `--provider` / `--model` / `--base-url` / `--api-key` / `--reasoning` (AI provider), `--fail-on-osv-error` (fail closed on an unreachable malicious-package lookup), `--no-reputation`, and `--package-manager <pm>`. `add`/`install` also take `--deep` and `--concurrency <n>`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | OK — allowed, installed, or a clean dry run |
| `1` | Error — bad input, unreachable dependency, misuse |
| `2` | Blocked — a package was blocked, a sandbox looked suspicious, or a CI check failed |

The `2` code is what you gate CI on: a non-zero-but-not-error signal that a human decision is required.

:::tip
For task-specific walkthroughs — CI, private registries, monorepos, coding agents, sandboxing, upgrade review — see **[Scenarios](./scenarios)**.
:::
