# How it works

```
developer intent → package inspection → AI risk reasoning → safe install decision
```

`targate` analyzes an npm package **before** it touches your machine, then produces an allow / warn / approve / block decision and only runs the real install if the package passes. For the component-level map and the deterministic-vs-probabilistic split, see [Architecture](architecture.md).

1. **Resolves metadata** from the npm registry (version, repository, maintainers, publish dates, scripts, dependencies).
2. **Starts independent I/O concurrently**: tarball quarantine, OSV, reputation, maintainer intelligence, public-registry checksum evidence, and historical artifact evidence overlap after exact metadata resolution. The tarball remains checksum-verified before it can be trusted, extraction uses strict path checking, and lifecycle scripts are never executed.
3. **Detects lifecycle scripts** (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`), statically inspects the **command strings** themselves (`curl … | bash`, `wget`, `node -e`, credential-file reads) and the files they reference.
4. **Indexes the extracted package once**, under shared file/byte limits. Content, native-surface, and React Native hardening analyzers consume that same bounded index. The content pass scans for `process.env` access, `child_process` usage, network calls, `eval`, and minified/obfuscated code — with special weight on install-time files.
5. **Checks OSV / OpenSSF** for known malicious-package records (`MAL-*` and GHSA malware advisories) and vulnerability advisories.
6. **Maps the React Native native surface**: `ios/`, `android/`, Podspecs, Gradle, CMake, `react-native.config.js`, binary artifacts, and Android permissions from `AndroidManifest.xml`. See [React Native hardening](react-native.md).
7. **Checks for typosquatting** against a curated list of popular RN/npm packages (edit distance).
8. **Gathers reputation signals**: registry-derived (version age, release-after-inactivity anomaly, maintainer change since the previous release, repository mismatch, npm provenance, deprecation) plus optional external lookups — npm weekly downloads with spike/drop detection, and the GitHub repo's archived status (set `GITHUB_TOKEN` to raise the unauthenticated 60 req/h limit). External lookups are fail-open: when one is unreachable or rate-limited the signal is reported as **UNKNOWN**, never as clean. Skip them with `--no-reputation`. A **Security Score** (0–100, per-category breakdown) aggregates all signals — informational only, it never changes the decision.
9. **Reasons over the signals with an AI provider** (structured JSON output). If no provider is configured, a deterministic rules engine produces the decision instead. **Every deterministic verdict is a floor** — the AI may make it stricter, but can never downgrade `allow_with_warnings`, `require_approval`, or `block`. See [AI providers](ai-providers.md) and [Decision policy](decisions.md).
10. **Gates the install**: `allow` / `allow_with_warnings` ask for confirmation, `require_approval` defaults to `--ignore-scripts`, `block` never installs.

By default only the **requested top-level package** is analyzed; `--deep` extends the same pipeline to the full transitive tree — see [Transitive dependencies & full-tree install](transitive-and-install.md) and [Scope and limitations](security.md#scope-and-limitations).
