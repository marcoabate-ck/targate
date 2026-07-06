import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { autoDetectProvider, resolveProvider } from "../src/providers/index.js";
import type { OpenAiCompatibleProvider } from "../src/providers/openai-compatible.js";
import { stripThinkBlocks } from "../src/providers/validate.js";

const ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "DEEPSEEK_API_KEY",
  "OPENAI_API_KEY",
  "OLLAMA_HOST",
  "OLLAMA_MODEL",
  "AI_API_KEY",
] as const;

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe("autoDetectProvider", () => {
  it("returns null when nothing is configured", () => {
    expect(autoDetectProvider()).toBeNull();
  });

  it("prefers anthropic over everything else", () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-x";
    process.env.DEEPSEEK_API_KEY = "sk-ds-x";
    process.env.OPENAI_API_KEY = "sk-oa-x";
    expect(autoDetectProvider()).toBe("anthropic");
  });

  it("falls back to deepseek when anthropic is absent", () => {
    process.env.DEEPSEEK_API_KEY = "sk-ds-x";
    process.env.OPENAI_API_KEY = "sk-oa-x";
    expect(autoDetectProvider()).toBe("deepseek");
  });

  it("falls back to openai when only that key is set", () => {
    process.env.OPENAI_API_KEY = "sk-oa-x";
    expect(autoDetectProvider()).toBe("openai");
  });

  it("falls back to a local ollama instance when configured", () => {
    process.env.OLLAMA_HOST = "http://localhost:11434";
    expect(autoDetectProvider()).toBe("ollama");
  });
});

describe("resolveProvider", () => {
  it("returns null when no provider is requested or detectable", () => {
    expect(resolveProvider({})).toBeNull();
  });

  it("builds an anthropic provider when the key is present", () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-x";
    const provider = resolveProvider({});
    expect(provider?.name).toBe("anthropic");
  });

  it("builds a deepseek provider from its API key", () => {
    process.env.DEEPSEEK_API_KEY = "sk-ds-x";
    const provider = resolveProvider({});
    expect(provider?.name).toBe("deepseek");
  });

  it("throws when deepseek is selected explicitly without a key", () => {
    expect(() => resolveProvider({ provider: "deepseek" })).toThrow(/DEEPSEEK_API_KEY/);
  });

  it("throws when openai is selected explicitly without a key", () => {
    expect(() => resolveProvider({ provider: "openai" })).toThrow(/OPENAI_API_KEY/);
  });

  it("builds an ollama provider without requiring an API key", () => {
    const provider = resolveProvider({ provider: "ollama" });
    expect(provider?.name).toBe("ollama");
  });

  it("respects an explicit --provider override even if another key is set", () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-x";
    const provider = resolveProvider({ provider: "ollama" });
    expect(provider?.name).toBe("ollama");
  });

  it("requires --base-url and --model for the custom provider", () => {
    expect(() => resolveProvider({ provider: "custom" })).toThrow(/--base-url/);
    expect(() => resolveProvider({ provider: "custom", baseUrl: "http://x" })).toThrow(
      /--model/,
    );
  });

  it("builds a custom provider when base-url and model are given", () => {
    const provider = resolveProvider({
      provider: "custom",
      baseUrl: "http://localhost:1234/v1",
      model: "local-model",
    });
    expect(provider?.name).toBe("custom");
  });

  it("passes explicit --api-key through instead of requiring the env var", () => {
    const provider = resolveProvider({ provider: "deepseek", apiKey: "sk-explicit" });
    expect(provider?.name).toBe("deepseek");
  });

  it("switches deepseek to the reasoner model when reasoning is requested", () => {
    const provider = resolveProvider({
      provider: "deepseek",
      apiKey: "sk-x",
      reasoning: true,
    }) as OpenAiCompatibleProvider;
    expect(provider.model).toBe("deepseek-reasoner");
  });

  it("keeps an explicit --model even with reasoning on", () => {
    const provider = resolveProvider({
      provider: "deepseek",
      apiKey: "sk-x",
      reasoning: true,
      model: "deepseek-chat",
    }) as OpenAiCompatibleProvider;
    expect(provider.model).toBe("deepseek-chat");
  });
});

describe("stripThinkBlocks", () => {
  it("removes <think> chains local reasoning models emit before the JSON", () => {
    const raw = `<think>\nLet me weigh the signals... the package has no scripts.\n</think>\n{"risk":"low"}`;
    expect(stripThinkBlocks(raw)).toBe('{"risk":"low"}');
  });

  it("leaves plain output untouched", () => {
    expect(stripThinkBlocks('{"risk":"low"}')).toBe('{"risk":"low"}');
  });
});
