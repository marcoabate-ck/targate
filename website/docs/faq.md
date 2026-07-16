---
title: FAQ
sidebar_position: 6
description: Common questions about targate — trust, privacy, scope, and limitations.
---

# FAQ

### Does targate run the package's install scripts?

No. Analysis happens in a **quarantine**: the tarball is downloaded, its bytes are verified against independent evidence, and it is extracted **without running any lifecycle script**, with strict path handling and bounded resources. Scripts only run during the *real* install, which happens only after the package passes the gate.

### Can a clever `postinstall` or a prompt-injected README trick the AI into allowing it?

No. The deterministic **rules engine** decides first and its verdict is a floor. The AI can only make a verdict *stricter*, never weaker — see **[AI & privacy](./concepts/ai-and-privacy)**. And a hard block (mutated bytes, known-malicious, remote-code execution) can't be overridden by anything.

### Do I need an AI provider?

No. With no provider configured, targate runs on the rules engine alone and contacts no model. An AI provider only ever adds caution and context. The reasoning can also run on a **local** model so your code never leaves your machine.

### Does my source code get sent anywhere?

Your source code and dependency graph are not sent to any model when you run rules-only or with a local model. targate does fetch **package metadata, tarballs, and OSV/vulnerability data** from the registry and OSV — that is inherent to analyzing a dependency. Internal-scope package names are excluded from third-party lookups.

### Why did a perfectly normal package (like esbuild or fsevents) get flagged?

Native-binary installers legitimately read environment variables and fetch a platform binary at install time — indistinguishable from exfiltration by static pattern. targate marks these as **soft blocks / require-approval**, which you clear with a committed approval. See **[Decisions & trust](./concepts/decisions-and-trust)**.

### Does targate replace `npm audit` or Dependabot?

No — it complements them. `npm audit` and Dependabot report **known vulnerabilities** in what you already installed. targate gates the **install itself**: it inspects lifecycle scripts, contents, artifact identity, and native surface *before* the code runs, catching malicious packages and compromised artifacts that a CVE feed hasn't cataloged yet.

### What about transitive dependencies?

`targate add --deep` analyzes a package's transitive tree, and `targate install` vets your entire lockfile. A dependency whose analysis can't complete is treated as `require_approval` — unknown is never treated as clean.

### How is trust kept honest across a team?

Approvals are committed to `.targate/approvals.json`, record their full circumstances (who, when, verdict, tool version, model, policy hash), and can be **SSH-signed**. With `requireSignedApprovals`, CI rejects unsigned or tampered approvals — so a hand-edited file can't green a poisoned dependency. Inspect it with `targate history`.

### What are targate's limits?

targate bounds every input (network bodies, tarball size, extracted tree, per-file size, scan time). Exceeding a limit is reported as `UNKNOWN` and requires approval — never silently marked clean. Static analysis cannot prove the absence of malice in obfuscated code; that is why the sandbox, monitoring, and signed approvals exist alongside it. See the repository's threat-model and security docs for the full scope.
