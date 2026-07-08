# Security model, scope & limitations

## OSV lookup failures

OSV/OpenSSF is targate's source of known-malicious-package intelligence — its **single strongest deterministic guarantee**. When the lookup cannot be completed (offline, network error, OSV outage), targate marks the malicious-package status as **unknown**, not clean:

- the report shows `OSV/OpenSSF lookup unavailable — malicious-package status UNKNOWN`;
- the rules engine adds an explicit warning to the decision;
- by default targate still **fails open** (proceeds with the rest of the analysis) so an OSV outage doesn't block all installs;
- pass `--fail-on-osv-error` (recommended in CI, and set by the generated workflow) to **fail closed**: an unreachable OSV lookup escalates the decision to `require_approval` so a package is never silently trusted while the strongest check was skipped.

## Scope and limitations

`targate` is a decision aid that moves supply-chain review to the install decision point. It is **not** a malware sandbox or a guarantee of safety. Know exactly what it does and does not do:

- **By default, only the requested top-level package is analyzed.** A clean direct package can still pull in a malicious transitive dependency. Use [`--deep`](transitive-and-install.md#transitive-dependencies----deep) to run the full pre-install pipeline on every package of the resolved tree (slower, more network/AI traffic — softened by the response cache). Without `--deep`, treat a targate "allow" as "the package you named looks fine", not "the whole tree is fine"; targate still surfaces the direct-dependency count and prints the post-install lockfile diff (direct + transitive added). `targate ci` always analyzes only the changed top-level dependencies — pair it with a lockfile scanner / `npm audit` / OSV-Scanner for transitive coverage in CI.
- **Static detection is heuristic and bypassable.** The content and command scanners are regex/substring based. They reliably catch the common, un-obfuscated patterns (`curl … | bash`, `process.env` + network, `child_process`) but a determined attacker can evade them with obfuscation, string-splitting, encoding, or dynamic dispatch. A clean static result is not proof of safety.
- **Content scan is bounded.** To stay fast, the scanner skips files larger than 2 MB and stops after 2000 files per package. A payload hidden past those limits will not be scanned. (Very large minified bundles are still flagged as minified/obfuscated by other checks.)
- **Native analysis is source-level.** Podspec/Gradle review is static; pre-built `.xcframework`/`.so`/`.aar` binaries are flagged as "binary code you cannot read" but their contents are not disassembled.
- **`approvedBy` is not authenticated.** The approver name in `.targate/approvals.json` comes from `$USER` and is informational only — it is trivially spoofable and must not be treated as a cryptographic attestation. Trust in an approval comes from code review of the committed `.targate/approvals.json` diff, not from the recorded name.
- **Approvals are version-specific by design.** A new version of an approved package requires a new approval; this is intentional (a compromised release is a new version). CI flags the drift.
- **AI output is advisory and clamped.** The deterministic rules engine is the security floor; the AI can only make decisions stricter (see [Decision policy](decisions.md)). With `--no-ai`, or no provider configured, targate runs entirely on the rules engine.
- **npm registry only.** Other registries, git/tarball/file specifiers, and monorepo `workspace:` protocols are not analyzed.

## Compatibility notes

- **Node**: requires Node ≥ 20 (uses the global `fetch` and `node:util` `parseArgs`).
- **Anthropic SDK**: pinned to `@anthropic-ai/sdk` `^0.110`; the Anthropic provider uses `output_config.format` (server-enforced structured output) and adaptive thinking, which require a recent SDK/model. Other providers go through the OpenAI-compatible client and validate JSON client-side.
- **Docker**: only the `sandbox` command needs Docker; every other command runs without it.
