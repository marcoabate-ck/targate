---
title: AI & privacy
description: How the AI reviewer is constrained, how to run it locally, and what leaves your machine.
---

## The AI can only make verdicts stricter

targate's AI reviewer is **advisory and clamped**. The deterministic rules engine decides first and its verdict is a floor. The AI sees the same signals and may:

- **raise** severity (e.g. turn an `allow_with_warnings` into `require_approval` because the context looks off), or
- add human-readable reasoning to an existing verdict.

It can **never** lower the floor. A model that is jailbroken, prompt-injected by a malicious README, or simply wrong cannot turn `require_approval` or `block` into `allow`. The clamped result always carries both the deterministic verdict and the AI interpretation, so you can see exactly what each contributed.

## Running without AI

With **no provider configured**, targate runs on the rules engine alone and contacts no model. This is a fully supported mode — the deterministic floor *is* the security guarantee; the AI only ever adds caution.

```bash
targate add lodash --no-ai   # force rules-only for a single run
```

## Running the AI locally

The reasoning can run entirely on a **local** model (e.g. via an OpenAI-compatible local server), so **your code and dependency graph never leave your machine**:

```bash
targate add lodash --provider <name> --base-url http://localhost:11434 --model <model>
targate doctor --ping        # verify the provider with a live completion
```

Provider, model, base URL, and API key are all overridable per-command; `--reasoning` enables extended reasoning where the provider supports it.

## What does reach the network

targate is honest about its network use. Even in rules-only mode it fetches:

- **package metadata** and **tarballs** from the (public or private) registry,
- **OSV/OpenSSF** malicious-package and vulnerability data,
- optional **reputation** signals (download stats, GitHub repo data) — disable with `--no-reputation`.

For **internal-scope** packages, name-leaking lookups are skipped so a private package name is not sent to third parties. Only the AI step can be pointed at a local model; the registry/OSV lookups are inherent to analyzing a package at all.

## The AI response cache

Identical analyses reuse a cached AI assessment instead of re-calling the model:

```bash
targate cache info               # where the cache lives and its stats
targate cache clear --scope project
targate add lodash --no-cache    # bypass for one run
```

The cache is keyed on the exact signals; a change in the package or its signals is a cache miss. Cache scope is `user` (private to you) or `project` (shared per checkout — gitignore it).
