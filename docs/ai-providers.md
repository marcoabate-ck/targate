# AI providers

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

3. If nothing is configured, `targate` runs entirely on the deterministic rules engine — no network call to any AI provider is made.

Misconfiguration of a *selected* provider (e.g. `--provider deepseek` without `DEEPSEEK_API_KEY`) is reported explicitly instead of silently downgrading; a provider that is configured but fails at runtime (network error, malformed output) falls back to the rules engine, and the report notes it.

## Structured output per backend

- **anthropic** — the JSON schema is enforced server-side (`output_config.format`), so the response is guaranteed valid.
- **all OpenAI-compatible backends** — JSON is requested via `response_format: {type: "json_object"}` plus the schema embedded in the prompt, then validated client-side ([src/providers/validate.ts](../src/providers/validate.ts)): code fences and `<think>` blocks are stripped, enum fields (`risk`, `decision`) are checked. Malformed output falls back to the rules engine rather than driving an install decision.

## Reasoning support (`--reasoning`)

There is no standard reasoning knob across OpenAI-compatible backends, so the flag maps to the closest native mechanism of each provider:

| Provider | Effect of `--reasoning` |
|---|---|
| `anthropic` | None needed — adaptive thinking is always enabled. |
| `openai` | Sends `reasoning_effort: "medium"` (for reasoning-capable models). |
| `deepseek` | Switches the default model to `deepseek-reasoner` and drops JSON mode (unsupported by the reasoner) — the schema in the prompt plus client-side validation guarantee the output shape. An explicit `--model` is kept as-is. |
| `ollama` / `custom` | No request change (generic servers may reject unknown parameters). Use a reasoning model (`deepseek-r1`, `qwq`, `qwen3`, …): it thinks on its own, and inline `<think>…</think>` blocks are stripped before parsing. |

## Examples

```bash
# Local model, no cloud dependency at all
ollama pull llama3.1
targate add react-native-mmkv --provider ollama

# Local reasoning model
targate add react-native-mmkv --provider ollama --model qwen3:8b --reasoning

# DeepSeek (auto-detected from the env var)
DEEPSEEK_API_KEY=sk-... targate add react-native-mmkv

# DeepSeek with reasoning (uses deepseek-reasoner)
DEEPSEEK_API_KEY=sk-... targate add react-native-mmkv --reasoning

# Any other OpenAI-compatible server
targate add react-native-mmkv --provider custom --base-url http://localhost:1234/v1 --model local-model

# Rules engine only, no AI call at all
targate add react-native-mmkv --no-ai
```

The AI's assessment is cached between runs to save tokens — see [AI response cache](ai-cache.md).
