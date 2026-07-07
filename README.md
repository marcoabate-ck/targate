# bye — Before You Execute

AI-gated package installation built on top of React Native teams needs. `bye` analyzes an npm package **before** it touches your machine: metadata, lifecycle scripts, tarball contents, React Native native surface, and known malicious-package records — then produces an allow / warn / approve / block decision and only runs the real install if the package passes.

## Quick start

```bash
pnpm install
pnpm build

# Analyze without installing
pnpm dev add react-native-mmkv --dry-run

# Full flow (analysis + gated install)
pnpm dev add react-native-mmkv
```

Or link the binary: `pnpm link --global` → `bye add <package>`.

## What it does

```
developer intent → package inspection → AI risk reasoning → safe install decision
```

1. **Resolves metadata** from the npm registry (version, repository, maintainers, publish dates, scripts, dependencies).
2. **Downloads the tarball into quarantine** (isolated temp dir, extracted with strict path checking, lifecycle scripts are never executed).
3. **Detects lifecycle scripts** (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`), statically inspects the **command strings** themselves (`curl … | bash`, `wget`, `node -e`, credential-file reads) and the files they reference.
4. **Scans package contents** for `process.env` access, `child_process` usage, network calls, `eval`, and minified/obfuscated code — with special weight on install-time files.
5. **Checks OSV / OpenSSF** for known malicious-package records (`MAL-*` and GHSA malware advisories) and vulnerability advisories.
6. **Maps the React Native native surface**: `ios/`, `android/`, Podspecs, Gradle, CMake, `react-native.config.js`, binary artifacts, and Android permissions from `AndroidManifest.xml`.
7. **Checks for typosquatting** against a curated list of popular RN/npm packages (edit distance).
8. **Reasons over the signals with an AI provider** (structured JSON output). If no provider is configured, a deterministic rules engine produces the decision instead. **Every deterministic BLOCK is a hard floor** — the AI can make a decision stricter but can never downgrade a rules-engine BLOCK to a weaker verdict.
9. **Gates the install**: `allow` / `allow_with_warnings` ask for confirmation, `require_approval` defaults to `--ignore-scripts`, `block` never installs.

By default only the **requested top-level package** is analyzed; `--deep` extends the same pipeline to the full transitive tree — see [Transitive dependencies](#transitive-dependencies----deep) and [Scope and limitations](#scope-and-limitations).

## Usage

```
bye add <package>[@version]         Analyze a package, then gate the install
(bye <package> without a subcommand is a shorthand for bye add)
bye sandbox <package>[@version]     Trial install in a disposable Docker container
bye ci [--base-ref <ref>]           Analyze dependencies changed vs a git ref (for PRs)
bye ci init                         Scaffold .github/workflows/bye.yml
bye policy init [--format <fmt>]    Scaffold the team policy (yaml | json | js | ts)

Options (add & ci):
--package-manager <pm>  Force pnpm | npm | yarn (default: auto-detect from lockfile)
--json                  Machine-readable output (metadata + signals + assessment)
--dry-run               Analyze and report only, never install
--yes                   Skip confirmation for allow/allow-with-warnings
--no-ai                 Skip the AI reasoning layer, use rules only
--provider <name>       anthropic | deepseek | openai | ollama | custom
--model <name>          Override the model for the selected provider
--base-url <url>        API base URL (required for --provider custom)
--api-key <key>         API key (prefer env vars over this flag)
--reasoning             Enable model reasoning where the provider supports it
                        (see "Reasoning support" below)
--deep                  (add) Also analyze the full transitive dependency tree;
                        the strictest verdict in the tree gates the install
--base-ref <ref>        (ci) Git ref to diff against (default: origin/main)

Options (sandbox):
--image <image>         Docker image (default: node:20-alpine)
--timeout <seconds>     Kill the sandbox after N seconds (default: 300)
--network <mode>        open (default, full egress) | none (offline trial)
```

Exit codes: `0` ok, `1` error, `2` blocked (or suspicious sandbox / failed CI check).

## AI providers

The reasoning layer is pluggable, the shipped tool supports swapping in a hosted alternative or a fully local model. Provider selection, in priority order:

1. `--provider <name>` — explicit override, always wins.
2. Otherwise auto-detected from environment variables:

| Provider | Env var | Base URL | Default model | Notes |
|---|---|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `api.anthropic.com` | `claude-opus-4-8` | Structured output enforced server-side via `output_config.format`; adaptive thinking always on. |
| `deepseek` | `DEEPSEEK_API_KEY` | `https://api.deepseek.com` | `deepseek-chat` (`deepseek-reasoner` with `--reasoning`) | OpenAI-compatible API. |
| `openai` | `OPENAI_API_KEY` | `https://api.openai.com/v1` | `gpt-4o-mini` | OpenAI-compatible API. |
| `ollama` | `OLLAMA_HOST` / `OLLAMA_MODEL` | `http://localhost:11434/v1` (or `$OLLAMA_HOST/v1`) | `$OLLAMA_MODEL` or `llama3.1` | Fully local, no API key. Auto-detected only if one of the env vars is set; otherwise pass `--provider ollama`. |
| `custom` | `AI_API_KEY` (optional) | `--base-url` (required) | `--model` (required) | Any OpenAI-compatible endpoint: LM Studio, vLLM, llama.cpp server, self-hosted gateways. |

3. If nothing is configured, `bye` runs entirely on the deterministic rules engine — no network call to any AI provider is made.

Misconfiguration of a *selected* provider (e.g. `--provider deepseek` without `DEEPSEEK_API_KEY`) is reported explicitly instead of silently downgrading; a provider that is configured but fails at runtime (network error, malformed output) falls back to the rules engine, and the report notes it.

### Structured output per backend

- **anthropic** — the JSON schema is enforced server-side (`output_config.format`), so the response is guaranteed valid.
- **all OpenAI-compatible backends** — JSON is requested via `response_format: {type: "json_object"}` plus the schema embedded in the prompt, then validated client-side ([src/providers/validate.ts](src/providers/validate.ts)): code fences and `<think>` blocks are stripped, enum fields (`risk`, `decision`) are checked. Malformed output falls back to the rules engine rather than driving an install decision.

### Reasoning support (`--reasoning`)

There is no standard reasoning knob across OpenAI-compatible backends, so the flag maps to the closest native mechanism of each provider:

| Provider | Effect of `--reasoning` |
|---|---|
| `anthropic` | None needed — adaptive thinking is always enabled. |
| `openai` | Sends `reasoning_effort: "medium"` (for reasoning-capable models). |
| `deepseek` | Switches the default model to `deepseek-reasoner` and drops JSON mode (unsupported by the reasoner) — the schema in the prompt plus client-side validation guarantee the output shape. An explicit `--model` is kept as-is. |
| `ollama` / `custom` | No request change (generic servers may reject unknown parameters). Use a reasoning model (`deepseek-r1`, `qwq`, `qwen3`, …): it thinks on its own, and inline `<think>…</think>` blocks are stripped before parsing. |

### Examples

```bash
# Local model, no cloud dependency at all
ollama pull llama3.1
bye add react-native-mmkv --provider ollama

# Local reasoning model
bye add react-native-mmkv --provider ollama --model qwen3:8b --reasoning

# DeepSeek (auto-detected from the env var)
DEEPSEEK_API_KEY=sk-... bye add react-native-mmkv

# DeepSeek with reasoning (uses deepseek-reasoner)
DEEPSEEK_API_KEY=sk-... bye add react-native-mmkv --reasoning

# Any other OpenAI-compatible server
bye add react-native-mmkv --provider custom --base-url http://localhost:1234/v1 --model local-model

# Rules engine only, no AI call at all
bye add react-native-mmkv --no-ai
```

## Decision policy

| Decision | Trigger (rules engine) |
|---|---|
| **BLOCK** | Known malicious record (OSV/OpenSSF); typosquat-like name + recent publish; a lifecycle command that fetches and executes remote code (`curl … \| bash`, `wget … \| sh`, `node -e`); install-time code reading `process.env` **and** calling the network; recent package with scripts and no repository |
| **REQUIRE APPROVAL** | Lifecycle scripts present; suspicious lifecycle command constructs (shell invocation, credential-file reads); name similar to a popular package; package created very recently; suspicious install-time findings |
| **ALLOW WITH WARNINGS** | Native code present; missing repository metadata; vulnerability advisories; large direct-dependency count; OSV lookup unavailable |
| **ALLOW** | No scripts, no records, consistent metadata |

With an AI provider configured, the model weighs the same signals contextually (e.g. "this postinstall just compiles native bindings"). The clamp is one-directional: **the AI can escalate but never de-escalate a deterministic BLOCK.** Concretely, `clampDecision` re-runs the rules engine and, if it returns BLOCK, forces the final decision to BLOCK regardless of what the model returned — so a model that is jailbroken, prompt-injected, or simply wrong cannot turn a rules-engine BLOCK into ALLOW. The AI is still free to reach BLOCK or REQUIRE APPROVAL on its own when the rules engine was more permissive.

## AI response cache

Interactive runs cache the AI's assessment so re-reviewing the same dependency (re-runs, `--deep` trees sharing packages across projects) doesn't pay for a new completion. The cache key is the **full evaluation context**:

```
provider / model / reasoning flag / name@version / sha256(signals)
```

so the same lib checked with a different provider or model is always a fresh call, and any change in the deterministic evidence (a new OSV record, different tarball findings) is a cache miss by construction — a stale "allow" cannot survive new evidence. Two further guarantees:

- **Cached answers are re-clamped on read.** The deterministic BLOCK floor is enforced at decision time, never trusted from disk — a hand-edited or poisoned cache entry cannot bypass it.
- **CI never uses the cache.** `bye ci` strips cache settings unconditionally; a CI verdict is always a fresh assessment.

Only successful AI responses are cached — rules-engine fallbacks are free to recompute and errors are never remembered. Configured through the `aiCache` section of the team policy:

```yaml
# bye.policy.yaml
aiCache:
  enabled: true      # master switch (default: true)
  scope: user        # user: ~/.bye/ai-cache.json (default) | project: <repo>/.bye/ai-cache.json
  ttlHours: 24       # entries older than this are ignored and pruned (default: 24)
  exclude: []        # package names never cached (e.g. internal libs under review)
```

With `scope: project` the cache lives in the repo's `.bye/` directory — add `.bye/ai-cache.json` to `.gitignore` unless you deliberately want to share it.

## Transitive dependencies — `--deep`

```bash
bye add glob --deep --dry-run
```

By default bye analyzes only the package you named. With `--deep` it first resolves the **exact dependency tree** a real install would produce — npm itself does the resolution (`--package-lock-only --ignore-scripts` in a throwaway directory: only a lockfile is generated, no `node_modules`, nothing from the tree executes) — then runs the same per-package pipeline (quarantine, OSV, signals, AI/rules, team policy) on **every unique `name@version`** in the tree, a few packages at a time.

The final decision is the **strictest verdict across the whole tree**: a blocked transitive dependency blocks the install exactly like a blocked root; a `require_approval` anywhere in the tree escalates the run. Flagged packages are listed in the reasons (`--json` includes the full per-package results under `deep`).

Cost: a deep run downloads and analyzes N tarballs and, with an AI provider configured, makes up to N model calls — the [AI response cache](#ai-response-cache) makes repeated and shared dependencies cheap. If npm cannot resolve the tree, the run fails loudly rather than silently degrading to top-level-only coverage.

## Team workflow

### Approval cache — `.bye/approvals.*`

When a developer approves a `require_approval` package interactively, the approval (name@version, mode, who, when) is recorded in `.bye/approvals.json`. **Commit the file**: the rest of the team — and CI — treat that exact version as already reviewed. A new version requires a new approval.

Approvals can also be hand-curated in `.bye/approvals.{ts,js,mjs,cjs,yaml,yml,json}` — all existing files are read and **merged**, with the tool-managed `approvals.json` winning on conflicts (a fresh interactive approval must always take effect). Automatic recording only ever writes `approvals.json`; the other formats are read-only sources. For typed files:

```ts
// .bye/approvals.ts
import { defineApprovals } from "bye";

export default defineApprovals({
  "core-js@3.49.0": { mode: "no-scripts", approvedAt: "2026-07-07T00:00:00Z", approvedBy: "marco" },
});
```

### pnpm `approve-builds` integration

On pnpm projects, an interactive approval also updates `pnpm-workspace.yaml` through pnpm's native mechanism:

- approved **with** scripts → the package is added to `onlyBuiltDependencies`
- approved **without** scripts → added to `ignoredBuiltDependencies` (installed, scripts silently skipped, no interactive pnpm prompt)

### Lockfile diff preview

After every real install, `bye` prints which packages the install actually added to the lockfile (direct + transitive), so surprise transitive dependencies are visible immediately.

### Team policy — `bye.policy.*`

`bye policy init [--format yaml|json|js|ts]` scaffolds the policy file from the proposal (§9 phase 6). Supported formats, first match wins: `bye.policy.{ts,js,mjs,cjs,yaml,yml,json}`.

```yaml
# bye.policy.yaml
dependencyPolicy:
  blockRecentlyPublishedPackages: false
  minPackageAgeDays: 7
  requireApprovalForNativeCode: false
  requireApprovalForLifecycleScripts: true
  blockMissingRepositoryForRuntimeDeps: false
  allowKnownPackages: [react, react-native]
  blockPackages: []
aiCache: # see "AI response cache"
  enabled: true
  scope: user
  ttlHours: 24
  exclude: []
```

```ts
// bye.policy.ts — fully typed
import type { PolicyFile } from "bye";

const policy: PolicyFile = {
  dependencyPolicy: { minPackageAgeDays: 7, requireApprovalForLifecycleScripts: true },
};

export default policy;
```

`.ts`/`.js` files are executed through [jiti](https://github.com/unjs/jiti) (default export; the type import is erased at runtime, so the file loads even where `bye` isn't installed as a dependency), and every format goes through the same schema validation. The policy is applied **on top of** the AI/rules assessment and can only make decisions stricter — with one exception: `allowKnownPackages` pre-approves packages. That downgrade has hard limits, because the allow list is **name-based** (it would otherwise trust every future version of a package, including a compromised release):

- a **known-malicious record** can never be overridden — the package stays blocked;
- **any other deterministic BLOCK** (e.g. a `curl … | bash` postinstall, install-time env + network access) can't be waved through either: the allow list caps at `require_approval`, so a human must approve **that exact version** — and the version-pinned `.bye/approvals.json`, not the blanket allow list, is what records the decision.

## React Native hardening

Beyond the basic native-surface detection, every analysis reviews:

- **Podspecs** — `prepare_command` / `script_phase` (arbitrary shell at pod-install/build time), network downloads, vendored frameworks/libraries, insecure URLs
- **Gradle files** — command execution during the build, remote script application (`apply from: 'https://…'`), insecure `http://` Maven repositories, build-time downloads
- **Android permissions** — classified against a dangerous-permission list (camera, mic, location, SMS, contacts, …) and highlighted in the report
- **iOS frameworks** — pre-built `.framework`/`.xcframework` bundles (binary code you cannot read)
- **Autolinking config** — `react-native.config.js` registering CLI commands or spawning processes
- **Compatibility notes** — New Architecture (codegenConfig / JSI usage), Expo (expo-module.config.json / config plugin / bare-workflow requirement); informational, shown in the report

Build-time execution findings (script phases, remote Gradle scripts) escalate to `require_approval` — they are the native equivalent of lifecycle scripts.

## Sandboxed trial install

```bash
bye sandbox suspicious-package
```

Runs `npm install` in a **disposable Docker container** (`node:20-alpine`): no host environment variables, no SSH agent, no npm/GitHub tokens, no host filesystem mounted, all Linux capabilities dropped, no privilege escalation, 1 CPU / 1 GB cap, killed after a timeout. The package spec is passed as a container environment variable, never interpolated into the container's shell script, so a hostile spec string cannot inject commands. Lifecycle scripts run with `--foreground-scripts` so their full output lands in the log, which is then scanned for exfiltration patterns (credential file references, raw network connections, base64 decoding, …); the container also reports filesystem writes outside the project directory. Exit code `2` means the log contains something you should read before installing on your machine.

**Network — read this before relying on the sandbox as a jail.** By default the container has **full outbound network access** (docker's bridge network): npm needs it to download the package and its dependencies, and a malicious install script can use that same access to exfiltrate or phone home. The sandbox keeps that activity *off your host and out of your real environment*, and surfaces it in the log — it is an **observation sandbox, not a network jail**. It does not restrict *which* hosts the install can reach, and there is no per-host allowlist. `--network none` runs a fully offline trial (useful to confirm a script does **not** need the network — a phone-home attempt then fails loudly), but a normal cold install cannot fetch its dependencies with the network off.

## CI integration

```bash
bye ci --base-ref origin/main --fail-on-osv-error   # in a PR: analyze added/updated dependencies
bye ci init                                          # scaffold .github/workflows/bye.yml
```

`bye ci` diffs `package.json` against the base ref, resolves the **exact version that will be installed** from the lockfile (`pnpm-lock.yaml` / `package-lock.json` / `yarn.lock`) when present, runs the full analysis pipeline on every added/updated dependency, and fails the build (exit `2`) when a package is **blocked** or **requires an approval that is not in the committed `.bye/approvals.json`** (approval drift). Without a lockfile it analyzes the declared version range and logs that it did so. The generated GitHub Actions workflow triggers on PRs touching `package.json` or a lockfile, passes `--fail-on-osv-error`, and can take a provider API key secret to enable AI reasoning. The same command works on any CI system via exit codes and `--json`.

> CI protects the repository. The local gate protects the developer — `bye ci` is the second line of defense, not a replacement for `bye add <pkg>`.

## OSV lookup failures

OSV/OpenSSF is bye's source of known-malicious-package intelligence — its **single strongest deterministic guarantee**. When the lookup cannot be completed (offline, network error, OSV outage), bye marks the malicious-package status as **unknown**, not clean:

- the report shows `OSV/OpenSSF lookup unavailable — malicious-package status UNKNOWN`;
- the rules engine adds an explicit warning to the decision;
- by default bye still **fails open** (proceeds with the rest of the analysis) so an OSV outage doesn't block all installs;
- pass `--fail-on-osv-error` (recommended in CI, and set by the generated workflow) to **fail closed**: an unreachable OSV lookup escalates the decision to `require_approval` so a package is never silently trusted while the strongest check was skipped.

## Scope and limitations

`bye` is a decision aid that moves supply-chain review to the install decision point. It is **not** a malware sandbox or a guarantee of safety. Know exactly what it does and does not do:

- **By default, only the requested top-level package is analyzed.** A clean direct package can still pull in a malicious transitive dependency. Use [`--deep`](#transitive-dependencies----deep) to run the full pre-install pipeline on every package of the resolved tree (slower, more network/AI traffic — softened by the response cache). Without `--deep`, treat a bye "allow" as "the package you named looks fine", not "the whole tree is fine"; bye still surfaces the direct-dependency count and prints the post-install lockfile diff (direct + transitive added). `bye ci` always analyzes only the changed top-level dependencies — pair it with a lockfile scanner / `npm audit` / OSV-Scanner for transitive coverage in CI.
- **Static detection is heuristic and bypassable.** The content and command scanners are regex/substring based. They reliably catch the common, un-obfuscated patterns (`curl … | bash`, `process.env` + network, `child_process`) but a determined attacker can evade them with obfuscation, string-splitting, encoding, or dynamic dispatch. A clean static result is not proof of safety.
- **Content scan is bounded.** To stay fast, the scanner skips files larger than 2 MB and stops after 2000 files per package. A payload hidden past those limits will not be scanned. (Very large minified bundles are still flagged as minified/obfuscated by other checks.)
- **Native analysis is source-level.** Podspec/Gradle review is static; pre-built `.xcframework`/`.so`/`.aar` binaries are flagged as "binary code you cannot read" but their contents are not disassembled.
- **`approvedBy` is not authenticated.** The approver name in `.bye/approvals.json` comes from `$USER` and is informational only — it is trivially spoofable and must not be treated as a cryptographic attestation. Trust in an approval comes from code review of the committed `.bye/approvals.json` diff, not from the recorded name.
- **Approvals are version-specific by design.** A new version of an approved package requires a new approval; this is intentional (a compromised release is a new version). CI flags the drift.
- **AI output is advisory and clamped.** The deterministic rules engine is the security floor; the AI can only make decisions stricter (see [Decision policy](#decision-policy)). With `--no-ai`, or no provider configured, bye runs entirely on the rules engine.
- **npm registry only.** Other registries, git/tarball/file specifiers, and monorepo `workspace:` protocols are not analyzed.

## Compatibility notes

- **Node**: requires Node ≥ 20 (uses the global `fetch` and `node:util` `parseArgs`).
- **Anthropic SDK**: pinned to `@anthropic-ai/sdk` `^0.110`; the Anthropic provider uses `output_config.format` (server-enforced structured output) and adaptive thinking, which require a recent SDK/model. Other providers go through the OpenAI-compatible client and validate JSON client-side.
- **Docker**: only the `sandbox` command needs Docker; every other command runs without it.

## Development

```bash
pnpm test        # vitest suite (200 tests, incl. an end-to-end CI check on a fixture repo)
pnpm typecheck
pnpm dev add <pkg>   # run from source
```
