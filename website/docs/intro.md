---
slug: /
title: What is targate?
sidebar_label: What is targate?
sidebar_position: 1
description: Why targate exists and what problem it solves — gating dependencies before their install scripts run.
---

# targate — gate every dependency before it runs

**targate is an AI-assisted dependency intelligence and decision layer for developers, teams, and coding agents.** Its first shipped application is **pre-install security**: it analyzes an npm package **before** it touches your machine, produces an allow / warn / approve / block decision, and only runs the real install if the package passes.

## The problem

Installing a package is not a passive download. npm runs the package's **lifecycle scripts** (`preinstall`, `install`, `postinstall`) on your machine as part of `npm install`. That code executes with your shell, your environment variables, your credentials, and your network — before you have read a single line of it.

That install moment is exactly where modern supply-chain attacks land:

- **Malicious postinstall scripts** that read `~/.npmrc`, `~/.aws`, `~/.ssh`, or `process.env` and exfiltrate them.
- **Typosquats** — a package one character away from a popular one, published recently.
- **Compromised versions** of otherwise-trusted packages, or a compromised registry mirror that serves a rewritten tarball.
- **Hidden native surface** in React Native packages — prebuilt binaries, podspecs, or Gradle files that run build-time code on developer machines and in CI.

You cannot review what you have not yet seen, and by the time `npm install` finishes, the untrusted code has already run.

## What targate does

targate inserts a gate at that moment. Instead of `npm install <pkg>`, you run:

```bash
targate add <pkg>
```

targate resolves the package from npm, downloads its tarball into an isolated **quarantine** (lifecycle scripts never run), statically inspects the scripts and file contents, checks OSV/OpenSSF for known-malicious and vulnerability records, maps any React Native native surface, and produces a decision. Only if the package passes does the real install run.

```text
Pre-install review — lodash@4.18.1
────────────────────────────────────────────────────────────
Analysis
  ✓ no lifecycle scripts
  ✓ no known malicious-package records (OSV/OpenSSF)
  ✓ no typosquatting suspicion
  ✓ repository metadata present
  ✓ no native code

Decision: ALLOW   (risk: low, source: rules)
```

## Why it can be trusted

- **Deterministic security floor.** A rules engine decides first; the AI reviewer can only make a verdict *stricter*, never weaker. A jailbroken or prompt-injected model cannot turn a block into an allow.
- **Nothing untrusted executes during analysis.** Tarballs are SHA-512 identified and checked against every available registry, lockfile, public-mirror, and historical digest before being read in a resource-bounded quarantine.
- **Auditable trust.** Every approval records who, when, the verdict, the tool version, the AI model, and the policy hash — and can be SSH-signed so a hand-edited approvals file cannot green a poisoned dependency.
- **Local-AI capable.** The AI reasoning can run entirely on a local model; with no provider configured, targate runs on the deterministic rules engine alone and sends nothing to any model.
- **Fails visibly, never silently clean.** A timeout or exceeded limit is reported as `UNKNOWN` and requires approval; it is never presented as safe.

## Where to go next

- **[Getting started](./getting-started)** — install the CLI and gate your first package.
- **[How it works](./how-it-works)** — the full analysis pipeline, step by step.
- **[Scenarios](./scenarios)** — CI gating, private registries, monorepos, coding agents, sandboxing.
- **[API reference](./api)** — the exported TypeScript types (config itself is declarative YAML/JSON).

:::note What ships today vs. the vision
targate is a dependency **intelligence and decision** layer. Pre-install security is the first application built on it, not the whole category. Everything in this guide is implemented and tested; directional roadmap items are called out as such.
:::
