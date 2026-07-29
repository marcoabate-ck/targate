---
title: React Native hardening
description: Why native surface matters and what targate inspects in React Native packages.
---

targate's first audience is **React Native teams**, and RN dependencies carry risk that pure-JS analysis misses: a package can ship **native code** that runs build-time logic on developer machines and in CI, long before any JavaScript executes.

## What targate maps

When it analyzes a package, targate builds a **native surface** from the extracted tarball:

- **iOS/Android directories** and source files (`.m`, `.mm`, `.swift`, `.h`).
- **`.podspec`** files — reviewed for `prepare_command` and `script_phase` (arbitrary shell at `pod install` time) and for vendored or insecure-source frameworks.
- **`build.gradle` / `settings.gradle`** — reviewed for remote downloads and build-time execution.
- **`CMakeLists.txt`** and JSI usage (`jsi/jsi.h`, `facebook::jsi`).
- **Prebuilt binaries** and shipped `.framework` / `.xcframework` bundles.
- **Autolinking config** (`react-native.config.js`).
- **Android permissions**, with dangerous permissions called out.

## How it affects the verdict

- Build-time code execution declared in a podspec or Gradle file is treated like a lifecycle script — it runs on the developer machine — and raises the verdict to **require approval**.
- Native surface on its own (frameworks, permissions, binaries) surfaces as **warnings** so you can confirm they are expected for the package.
- All findings use platform-independent (`/`-separated) paths, so results are identical whether the analysis runs on Linux, macOS, or Windows.

## Visualizing the tree

For a whole project, the dependency risk graph highlights native and script-bearing packages:

```bash
targate graph --only native,scripts
targate graph --only high-risk --format svg --output risk.svg
```

The graph renders as self-contained interactive HTML, static SVG, Graphviz DOT, Mermaid (for GitHub PRs), or JSON — see **[Scenarios](/scenarios/)**.
