# Full review example

A plain `npm install <pkg>` resolves the package and **runs its lifecycle scripts immediately** — you find out what it did afterward, if at all. `targate add <pkg>` runs the same install only *after* an analysis, and never at all if the package is blocked.

The runs below are real `targate` output (rules engine only, `--no-ai`, `--dry-run` so nothing is installed). Your version numbers and day counts will differ as packages and advisories move.

> The examples use `--no-ai` so the output is fully deterministic and reproducible. With an AI provider configured (`source: ai`), the model weighs the same signals contextually, but every deterministic verdict remains a floor it can never downgrade. See [Decision policy](../decisions.md).

## 1. A clean package → ALLOW

```bash
targate add lodash --dry-run
```

```text
Pre-install review — lodash@4.17.21
────────────────────────────────────────────────────────────
Lodash modular utilities.
license: MIT  ·  published: 1977 days ago  ·  deps: 0  ·  repo: git+https://github.com/lodash/lodash.git

Analysis
  ✓ no lifecycle scripts
  ✓ no known malicious-package records (OSV/OpenSSF)
  ✓ no typosquatting suspicion
  ✓ repository metadata present
  ✓ OSV/OpenSSF lookup completed
  ✓ no native code
  static findings:
    - lodash.min.js: appears minified/obfuscated

Decision: ALLOW   (risk: low, source: rules)

lodash shows no high-risk install-time behavior.

Reasons
  • No lifecycle scripts, no known malicious records, repository metadata present.

Recommendation
  Safe to install normally.


Dry run — recommended command: pnpm add lodash@4.17.21
```

A mature, script-free package with matching repository metadata and no malicious records: `ALLOW`. Without `--dry-run`, targate would run the real install right after this report.

## 2. A React Native package with native surface → REQUIRE APPROVAL

Native code is expected for a React Native package — targate doesn't block it, it surfaces it for a human to acknowledge.

```bash
targate add react-native-mmkv --dry-run
```

```text
Pre-install review — react-native-mmkv@4.3.2
────────────────────────────────────────────────────────────
⚡️ The fastest key/value storage for React Native.
license: MIT  ·  published: 1961 days ago  ·  deps: 0  ·  repo: git+https://github.com/mrousavy/react-native-mmkv.git

Analysis
  ✓ no lifecycle scripts
  ✓ no known malicious-package records (OSV/OpenSSF)
  ✓ no typosquatting suspicion
  ✓ repository metadata present
  ✓ OSV/OpenSSF lookup completed
  ℹ native code detected (iOS, Android, Podspec, Gradle, CMake)
  ⚠ react-native.config.js: references remote URLs
  ℹ Native module without codegenConfig — likely an old-architecture bridge module; check New Architecture interop.
  ℹ Native code without an Expo config plugin — requires a bare workflow or a custom dev client in Expo projects.
  static findings:
    - lib/isTest.js: reads process.env
    - src/isTest.ts: reads process.env

Decision: REQUIRE MANUAL APPROVAL   (risk: medium, source: rules)

react-native-mmkv has signals that need human review before installation.

Reasons
  • react-native.config.js: references remote URLs

Recommendation
  Install with scripts disabled (--ignore-scripts) or have a security reviewer approve the package.


Dry run — recommended command: pnpm add react-native-mmkv@4.3.2 --ignore-scripts
  To approve react-native-mmkv@4.3.2 without installing it, run `targate approve react-native-mmkv@4.3.2`.
```

`REQUIRE MANUAL APPROVAL` is not "unsafe" — it's "a human should look once." The clean way to clear it for the team is to record a committable, version-pinned approval:

```bash
targate approve react-native-mmkv@4.3.2
```

Now a teammate's `targate add` — and CI — treat that exact version as reviewed. See [Team workflow](../team-workflow.md#approving-a-package--targate-approve).

## 3. A known-malicious package → BLOCK

```bash
targate add flatmap-stream --dry-run
```

```text
Pre-install review — flatmap-stream@0.0.1-security
────────────────────────────────────────────────────────────
security holding package
published: 2779 days ago  ·  deps: 0  ·  repo: git+https://github.com/npm/security-holder.git

Analysis
  ✓ no lifecycle scripts
  ⚠ KNOWN MALICIOUS: MAL-2025-20690
  ✓ no typosquatting suspicion
  ✓ repository metadata present
  ✓ OSV/OpenSSF lookup completed
  ⚠ vulnerability advisories: GHSA-mh6f-8j2x-4483

Decision: BLOCK   (risk: high, source: rules)

flatmap-stream is reported as a known malicious package.

Reasons
  • OSV malicious-package record: MAL-2025-20690 — Malicious code in flatmap-stream (npm)

Recommendation
  Do not install this package under any circumstances.


Installation blocked. This package was not installed.
```

An OSV/OpenSSF malicious-package record is a **hard block** — it can never be downgraded by the AI, cleared by an allow-list entry, or approved. targate exits with code `2` and installs nothing. See [Hard vs soft blocks](../decisions.md#hard-vs-soft-blocks).

(The malicious code shipped in `flatmap-stream@0.1.1`; npm has since replaced the package with a harmless security-holder stub, which is what the version line above resolves to. targate blocks on the OSV **record** for the name regardless — the record outlives the takedown, which is exactly the point.)

## The difference, in one line

The general contrast, for any package carrying a malicious record or a fetch-and-execute script:

| | plain `npm install <pkg>` | `targate add <pkg>` |
|---|---|---|
| Lifecycle scripts | run immediately, as you | read, never executed |
| Known-malicious check | none | OSV/OpenSSF, every run |
| Outcome | installed, then maybe audited | **blocked before anything runs** (exit `2`) |

## Next

- [Decision policy](../decisions.md) — how each verdict is chosen, and hard vs soft blocks.
- [CLI reference](../cli-reference.md) — every command, flag, and exit code.
- [`--deep` & full-tree install](../transitive-and-install.md) — vet the whole dependency tree, not just the package you named.
