---
slug: /
title: What is targate?
sidebar_label: What is targate?
sidebar_position: 1
description: Install-time supply-chain security for npm — open source, AI-optional, and run from your terminal. It vets every dependency before its code can run.
---

# targate — install-time supply-chain security for npm, in your terminal

**targate is open-source, AI-optional supply-chain security that runs where you install.** It vets every npm dependency **before** its code can run — analyzing the tarball, lifecycle scripts, and resolved lockfile, and checking reputation and known-malicious records — then returns an allow / warn / approve / block decision and only runs the real install if the package passes.

Four things define it:

- **Install-time** — the gate sits at the exact moment `npm install` would otherwise run a package's lifecycle scripts on your machine, before code executes.
- **Supply-chain, not application security** — it reasons about what a third-party dependency does when you install it, not about bugs in the code you write.
- **AI-optional** — a deterministic rules engine decides on its own; an AI reviewer, when configured, can only make a verdict stricter, and can run on a local model.
- **Terminal-native & open source** — one CLI in the workflow and CI you already have. No dashboard, no account, no SaaS.

## Supply chain security, not application security

Application-security tools — SAST, linters, AI code reviewers — analyze **the code you write**, looking for bugs in your own source. targate answers a different question: **is it safe to bring this third-party dependency onto my machine at all?** That risk lands at install time, before any of your code runs, and it needs checks an application-security scanner does not perform:

- **Tarball pre-analysis** — the exact published artifact is fetched into an isolated quarantine and inspected _before_ it can be installed.
- **Install simulation without execution** — lifecycle scripts are read, never run; an optional sandbox observes a real `npm install` in a throwaway container and reports what it tried to do.
- **Lifecycle-script verification** — `preinstall`/`install`/`postinstall` command strings and the files they reference are statically analyzed for fetch-and-execute and credential-access patterns.
- **Lockfile pre-download analysis** — with `--deep` / `targate install`, the resolved lockfile is analyzed _before_ the real download, so a malicious transitive dependency is caught before it lands.
- **Reputation as an install gate** — package and maintainer reputation, age, provenance, and known-malicious records **decide** the install, not merely annotate a report.

The two are complementary: an app-sec scanner keeps your own code clean; targate keeps untrusted third-party code from running on your machine in the first place.

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
Install-time supply-chain security is what targate is today. Under the hood it is a dependency **intelligence and decision** layer, and that engine can grow beyond the install gate. Everything in this guide is implemented and tested; directional roadmap items are called out as such.
:::
