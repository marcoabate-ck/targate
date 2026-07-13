# Threat model

What targate is designed to catch, and — just as importantly — what it does **not** guarantee. A tool that overstates its guarantees is worse than one that states them plainly, because teams build habits on the promise. This page is the honest summary; the mechanics and edge cases live in the [Security model, scope & limitations](security.md).

## Threats targate is designed to address

targate sits at the **install decision point** — the moment a package would otherwise fetch, extract, and run lifecycle scripts on your machine. It targets supply-chain risk introduced *at or before* that moment:

- **Malicious lifecycle scripts** — `preinstall`/`install`/`postinstall`/`prepare`/`prepack`/`postpack` hooks. The command strings and the files they reference are read (never executed); fetch-and-execute patterns (`curl … | bash`, `wget … | sh`, `node -e`) are a **hard block**.
- **Suspicious install-time behavior** — install-time code that reads `process.env` **and** makes network calls, spawns child processes, or is minified/obfuscated.
- **Known-malicious packages** — OSV/OpenSSF `MAL-*` and GHSA-malware records (a hard block).
- **Compromised npm mirrors** — the private tarball is checked against its private metadata and the independently fetched public `name@version` checksum; divergence is a hard block, including on first contact.
- **Known vulnerabilities** — GHSA/OSV advisories surfaced on the package and version you're about to install.
- **Typosquatting** — names a short edit-distance away from popular packages, weighted with recency.
- **Compromised / hijacked releases** — a trusted package shipping a bad *version*: approvals are version-specific, and every run re-checks OSV, so a new release is re-reviewed rather than grandfathered in.
- **Unexpected React Native native surface** — dangerous Android permissions, Podspec `script_phase`/`prepare_command` shelling out, Gradle/CMake, insecure URLs, and unreadable pre-built binaries. See [React Native hardening](react-native.md).
- **Suspicious metadata** — repository URL that doesn't match the package, missing repository, very recent publish combined with scripts.
- **Policy violations** — anything your team's [policy](policy-reference.md) declares must be blocked or approved.
- **Unreviewed installs by AI agents** — the [agent contract](agents.md) makes targate a gate an agent must route through instead of calling the package manager directly.

## What targate does not guarantee

targate is a **decision aid**, not a malware sandbox or a proof of safety. It deliberately does not claim to:

- **Eliminate all runtime vulnerabilities.** It reviews the install decision, not your application's behaviour once the dependency is running.
- **Replace a manual security review.** An `allow` means "no high-risk install-time signals," not "audited."
- **Guarantee a package stays safe.** A package approved today can ship a malicious new version tomorrow. Same-version byte replacement is detected through lockfile/public/history digests, but a genuinely new version still needs review.
- **Catch an obfuscated or cleverly hidden payload.** Static detection is heuristic and bypassable (string-splitting, encoding, dynamic dispatch). Traversal and scan time are bounded; crossing a configured budget is visible and approval-required, but a payload that stays within the budget can still evade pattern matching. A clean static result is not proof of safety.
- **Cover the whole tree by default.** Only the package you name is analyzed unless you use `--deep` / `targate install`; a clean direct package can still pull a malicious transitive dependency.
- **Disassemble native binaries.** Pre-built `.xcframework`/`.so`/`.aar` are flagged as unreadable, not inspected.
- **Authenticate approvers.** `approvedBy` comes from `$USER` and is informational — trust comes from reviewing the committed `.targate/approvals.json` diff, not the recorded name.
- **Protect against threats outside its scope.** It does not analyze non-npm registries, git/tarball/file specifiers, or `workspace:` protocols; it does not defend against malicious code already in your own project, or a maintainer compromised *after* you approved a version.

## Trust boundaries

- **Untrusted, never executed:** package tarball contents and lifecycle scripts. They are checksum-verified, quarantined, and only ever read during analysis.
- **Repo-controlled configuration is declarative by default:** `.yaml`/`.json` policy and approval files are parsed, never executed. Legacy `.ts`/`.js` sources are ignored unless a trusted operator explicitly sets `TARGATE_ALLOW_EXEC_CONFIG=1`, which also produces a warning.
- **Resource exhaustion is bounded, not classified as safe:** slow/oversized responses and pathological archives stop at configured limits and become visible `UNKNOWN` / approval-required results.
- **The security floor is deterministic.** The rules engine and the hard-block clamp decide first; the AI is advisory and can only make a verdict stricter. See [Architecture](architecture.md#deterministic-vs-probabilistic) and [Decision policy](decisions.md).

## The full detail

Every limitation above has a precise, mechanical explanation — OSV failure handling, scan bounds, batched-AI isolation, tarball integrity, registry scope, compatibility. Read [Security model, scope & limitations](security.md) for the exact behaviour.
