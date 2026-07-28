# React Native hardening

Beyond the basic native-surface detection, every analysis reviews:

- **Podspecs** — `prepare_command` / `script_phase` (arbitrary shell at pod-install/build time), network downloads, vendored frameworks/libraries, insecure URLs
- **Gradle files** — command execution during the build, remote script application (`apply from: 'https://…'`), insecure `http://` Maven repositories, build-time downloads
- **Android permissions** — classified against a dangerous-permission list (camera, mic, location, SMS, contacts, …) and highlighted in the report
- **iOS frameworks** — pre-built `.framework`/`.xcframework` bundles (binary code you cannot read)
- **Autolinking config** — `react-native.config.js` registering CLI commands or spawning processes
- **Compatibility notes** — New Architecture (codegenConfig / JSI usage), Expo (expo-module.config.json / config plugin / bare-workflow requirement); informational, shown in the report

The New-Architecture and Expo compatibility notes are emitted **only for packages that are actually React Native modules** — detected from real signals (a `react-native` dependency, `codegenConfig`, RN/Expo config files, a React-dependent podspec, or RN bridge / JSI symbols in the native source), never from marketing `keywords`. A plain native package that merely ships iOS/Android files (e.g. a CLI with helper native code) still gets the framework-agnostic "native code detected" signal, but no React-Native-framework guidance that would not apply to it. The Podspec / Gradle / permission / framework findings above are framework-agnostic and always run on native code.

Build-time execution findings (script phases, remote Gradle scripts) escalate to `require_approval` — they are the native equivalent of lifecycle scripts.
