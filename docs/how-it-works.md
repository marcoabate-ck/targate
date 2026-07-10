# How it works

```
developer intent → package inspection → AI risk reasoning → safe install decision
```

`targate` analyzes an npm package **before** it touches your machine, then produces an allow / warn / approve / block decision and only runs the real install if the package passes. For the component-level map and the deterministic-vs-probabilistic split, see [Architecture](architecture.md).

1. **Resolves metadata** from the npm registry (version, repository, maintainers, publish dates, scripts, dependencies).
2. **Downloads the tarball into quarantine** (isolated temp dir, checksum-verified against the registry manifest's `dist.integrity`/`shasum` before anything reads it, extracted with strict path checking, lifecycle scripts are never executed).
3. **Detects lifecycle scripts** (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`), statically inspects the **command strings** themselves (`curl … | bash`, `wget`, `node -e`, credential-file reads) and the files they reference.
4. **Scans package contents** for `process.env` access, `child_process` usage, network calls, `eval`, and minified/obfuscated code — with special weight on install-time files.
5. **Checks OSV / OpenSSF** for known malicious-package records (`MAL-*` and GHSA malware advisories) and vulnerability advisories.
6. **Maps the React Native native surface**: `ios/`, `android/`, Podspecs, Gradle, CMake, `react-native.config.js`, binary artifacts, and Android permissions from `AndroidManifest.xml`. See [React Native hardening](react-native.md).
7. **Checks for typosquatting** against a curated list of popular RN/npm packages (edit distance).
8. **Reasons over the signals with an AI provider** (structured JSON output). If no provider is configured, a deterministic rules engine produces the decision instead. **Every deterministic BLOCK is a hard floor** — the AI can make a decision stricter but can never downgrade a rules-engine BLOCK to a weaker verdict. See [AI providers](ai-providers.md) and [Decision policy](decisions.md).
9. **Gates the install**: `allow` / `allow_with_warnings` ask for confirmation, `require_approval` defaults to `--ignore-scripts`, `block` never installs.

By default only the **requested top-level package** is analyzed; `--deep` extends the same pipeline to the full transitive tree — see [Transitive dependencies & full-tree install](transitive-and-install.md) and [Scope and limitations](security.md#scope-and-limitations).
