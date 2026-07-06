# bye — Before You Execute

AI-gated package installation built on top of React Native teams needs. `bye` analyzes an npm package **before** it touches your machine: metadata, lifecycle scripts, tarball contents, React Native native surface, and known malicious-package records — then produces an allow / warn / approve / block decision and only runs the real install if the package passes.

## Quick start

```bash
pnpm install
pnpm build

# Analyze without installing
pnpm dev react-native-mmkv --dry-run

# Full flow (analysis + gated install)
pnpm dev react-native-mmkv
```

Or link the binary: `pnpm link --global` → `bye <package>`.

## What it does

```
developer intent → package inspection → AI risk reasoning → safe install decision
```

1. **Resolves metadata** from the npm registry (version, repository, maintainers, publish dates, scripts, dependencies).
2. **Downloads the tarball into quarantine** (isolated temp dir, extracted with strict path checking, lifecycle scripts are never executed).
3. **Detects lifecycle scripts** (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`) and statically inspects the commands and the files they reference.
4. **Scans package contents** for `process.env` access, `child_process` usage, network calls, `eval`, and minified/obfuscated code — with special weight on install-time files.
5. **Checks OSV / OpenSSF** for known malicious-package records (`MAL-*` and GHSA malware advisories) and vulnerability advisories.
6. **Maps the React Native native surface**: `ios/`, `android/`, Podspecs, Gradle, CMake, `react-native.config.js`, binary artifacts, and Android permissions from `AndroidManifest.xml`.
7. **Checks for typosquatting** against a curated list of popular RN/npm packages (edit distance).
8. **Reasons over the signals with an AI provider** (structured JSON output). If no provider is configured, a deterministic rules engine produces the decision instead — and the AI can never be more permissive than the hard policy (known-malicious ⇒ always BLOCK).
9. **Gates the install**: `allow` / `allow_with_warnings` ask for confirmation, `require_approval` defaults to `--ignore-scripts`, `block` never installs.

## Usage

```
bye <package>[@version] [options]

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
```

Exit codes: `0` ok, `1` error, `2` blocked.

## AI providers

The reasoning layer is pluggable, the shipped tool supports swapping in a hosted alternative or a fully local model. Provider selection, in priority order:

1. `--provider <name>` — explicit override, always wins.
2. Otherwise auto-detected from environment variables:

| Provider | Env var | Base URL | Default model | Notes |
|---|---|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `api.anthropic.com` | `claude-opus-4-8` | The workshop default. Structured output enforced server-side via `output_config.format`; adaptive thinking always on. |
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
bye react-native-mmkv --provider ollama

# Local reasoning model
bye react-native-mmkv --provider ollama --model qwen3:8b --reasoning

# DeepSeek (auto-detected from the env var)
DEEPSEEK_API_KEY=sk-... bye react-native-mmkv

# DeepSeek with reasoning (uses deepseek-reasoner)
DEEPSEEK_API_KEY=sk-... bye react-native-mmkv --reasoning

# Any other OpenAI-compatible server
bye react-native-mmkv --provider custom --base-url http://localhost:1234/v1 --model local-model

# Rules engine only, no AI call at all
bye react-native-mmkv --no-ai
```

## Decision policy

| Decision | Trigger (rules engine) |
|---|---|
| **BLOCK** | Known malicious record (OSV/OpenSSF); typosquat-like name + recent publish; install-time code reading `process.env` **and** calling the network; recent package with scripts and no repository |
| **REQUIRE APPROVAL** | Lifecycle scripts present; name similar to a popular package; package created very recently; suspicious install-time findings |
| **ALLOW WITH WARNINGS** | Native code present; missing repository metadata; vulnerability advisories; large dependency tree |
| **ALLOW** | No scripts, no records, consistent metadata |

With an AI provider configured, the model weighs the same signals contextually (e.g. "this postinstall just compiles native bindings") but is clamped by the policy above regardless of provider.

## Development

```bash
pnpm test        # vitest unit suite
pnpm typecheck
pnpm dev <pkg>   # run from source
```
