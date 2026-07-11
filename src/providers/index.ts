import { AnthropicProvider } from "./anthropic.js";
import { OpenAiCompatibleProvider } from "./openai-compatible.js";
import type { AiProvider, ProviderName } from "./types.js";

export type { AiProvider, ProviderName } from "./types.js";

export interface ProviderSelection {
  provider?: ProviderName;
  model?: string;
  baseUrl?: string;
  apiKey?: string;
  /**
   * Opt-in reasoning/thinking. Anthropic always reasons (adaptive thinking
   * is on by default there); for the others this maps to the closest
   * provider-specific mechanism — see OpenAiCompatibleOptions.reasoning.
   */
  reasoning?: boolean;
}

interface Preset {
  /** Env var holding the API key; omit for providers that don't need one. */
  envKey?: string;
  defaultBaseUrl: () => string;
  defaultModel: () => string;
}

function ollamaBaseUrl(): string {
  const host = process.env.OLLAMA_HOST?.replace(/\/+$/, "");
  if (!host) return "http://localhost:11434/v1";
  return host.endsWith("/v1") ? host : `${host}/v1`;
}

const PRESETS: Record<Exclude<ProviderName, "custom" | "anthropic">, Preset> = {
  deepseek: {
    envKey: "DEEPSEEK_API_KEY",
    defaultBaseUrl: () => "https://api.deepseek.com",
    defaultModel: () => "deepseek-chat",
  },
  openai: {
    envKey: "OPENAI_API_KEY",
    defaultBaseUrl: () => "https://api.openai.com/v1",
    defaultModel: () => "gpt-4o-mini",
  },
  ollama: {
    defaultBaseUrl: ollamaBaseUrl,
    defaultModel: () => process.env.OLLAMA_MODEL ?? "llama3.1",
  },
};

/**
 * Auto-detect which provider to use when none is explicitly requested, in
 * priority order. Anthropic first (the workshop default), then hosted
 * alternatives, then a local Ollama instance if one is configured.
 */
export function autoDetectProvider(): ProviderName | null {
  if (process.env.ANTHROPIC_API_KEY) return "anthropic";
  if (process.env.DEEPSEEK_API_KEY) return "deepseek";
  if (process.env.OPENAI_API_KEY) return "openai";
  if (process.env.OLLAMA_HOST || process.env.OLLAMA_MODEL) return "ollama";
  return null;
}

/**
 * Build the AI provider for this run. Returns null when no provider is
 * requested and none can be auto-detected (caller should fall back to the
 * deterministic rules engine, not treat this as an error). Throws when a
 * provider IS selected (explicitly or via auto-detect) but is missing
 * required configuration, so misconfiguration is visible rather than
 * silently downgrading to rules.
 */
export function resolveProvider(selection: ProviderSelection): AiProvider | null {
  const name = selection.provider ?? autoDetectProvider();
  if (!name) return null;

  if (name === "anthropic") {
    return new AnthropicProvider({
      apiKey: selection.apiKey ?? process.env.ANTHROPIC_API_KEY,
      model: selection.model,
    });
  }

  if (name === "custom") {
    if (!selection.baseUrl) {
      throw new Error('--provider custom requires --base-url (e.g. "http://localhost:1234/v1")');
    }
    if (!selection.model) {
      throw new Error("--provider custom requires --model");
    }
    return new OpenAiCompatibleProvider({
      baseURL: selection.baseUrl,
      apiKey: selection.apiKey ?? process.env.AI_API_KEY,
      model: selection.model,
      label: "custom",
      reasoning: selection.reasoning,
    });
  }

  const preset = PRESETS[name];
  const apiKey = selection.apiKey ?? (preset.envKey ? process.env[preset.envKey] : undefined);
  if (preset.envKey && !apiKey) {
    throw new Error(
      `${name} provider requires ${preset.envKey} to be set (or pass --api-key)`,
    );
  }

  // DeepSeek exposes reasoning as a separate model rather than a request
  // parameter, and deepseek-reasoner does not support response_format —
  // JSON correctness relies on the schema in the prompt + client validation.
  const deepseekReasoning = name === "deepseek" && selection.reasoning === true;

  return new OpenAiCompatibleProvider({
    baseURL: selection.baseUrl ?? preset.defaultBaseUrl(),
    apiKey,
    model: selection.model ?? (deepseekReasoning ? "deepseek-reasoner" : preset.defaultModel()),
    label: name,
    reasoning: selection.reasoning,
    disableJsonMode: deepseekReasoning,
  });
}

/**
 * The provider name + model a run WOULD use, for audit metadata (trust
 * history). Construction only — no network. Never throws: a misconfigured
 * provider simply yields null (the run itself surfaces the real error).
 */
export function describeProvider(
  selection: ProviderSelection,
): { provider: string; model: string } | null {
  try {
    const p = resolveProvider(selection);
    return p ? { provider: p.name, model: p.model } : null;
  } catch {
    return null;
  }
}
