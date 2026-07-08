# React Native hardening

Beyond the basic native-surface detection, every analysis reviews:

- **Podspecs** — `prepare_command` / `script_phase` (arbitrary shell at pod-install/build time), network downloads, vendored frameworks/libraries, insecure URLs
- **Gradle files** — command execution during the build, remote script application (`apply from: 'https://…'`), insecure `http://` Maven repositories, build-time downloads
- **Android permissions** — classified against a dangerous-permission list (camera, mic, location, SMS, contacts, …) and highlighted in the report
- **iOS frameworks** — pre-built `.framework`/`.xcframework` bundles (binary code you cannot read)
- **Autolinking config** — `react-native.config.js` registering CLI commands or spawning processes
- **Compatibility notes** — New Architecture (codegenConfig / JSI usage), Expo (expo-module.config.json / config plugin / bare-workflow requirement); informational, shown in the report

Build-time execution findings (script phases, remote Gradle scripts) escalate to `require_approval` — they are the native equivalent of lifecycle scripts.
