import { describe, expect, it } from "vitest";
import {
  applyEnvOverrides,
  ConfigError,
  defaultConfig,
  resolveConfig,
} from "../src/config.js";

describe("resolveConfig", () => {
  it("returns defaults for empty input", () => {
    const c = resolveConfig(undefined);
    expect(c.runtime.model).toBe("qwen3.6:35b-a3b-coding-nvfp4");
    expect(c.orchestration.maxConcurrency).toBe(1);
    expect(c.approval.mode).toBe("adaptive");
  });

  it("merges overrides", () => {
    const c = resolveConfig({
      runtime: { model: "custom-model", baseUrl: "http://host:1234/" },
      orchestration: { maxConcurrency: 2, defaultTimeoutMs: 5000 },
      approval: { mode: "always" },
    });
    expect(c.runtime.model).toBe("custom-model");
    expect(c.runtime.baseUrl).toBe("http://host:1234"); // trailing slash stripped
    expect(c.orchestration.maxConcurrency).toBe(2);
    expect(c.approval.mode).toBe("always");
  });

  it("rejects an unknown version", () => {
    expect(() => resolveConfig({ version: 2 })).toThrow(ConfigError);
  });
  it("rejects a bad concurrency", () => {
    expect(() => resolveConfig({ orchestration: { maxConcurrency: 0 } })).toThrow(/maxConcurrency/);
    expect(() => resolveConfig({ orchestration: { maxConcurrency: 999 } })).toThrow(/maxConcurrency/);
  });
  it("rejects a bad timeout", () => {
    expect(() => resolveConfig({ orchestration: { defaultTimeoutMs: 10 } })).toThrow(/defaultTimeoutMs/);
  });
  it("rejects a missing/empty model", () => {
    expect(() => resolveConfig({ runtime: { model: "" } })).toThrow(/model/);
  });
  it("rejects a malformed base URL", () => {
    expect(() => resolveConfig({ runtime: { baseUrl: "not a url" } })).toThrow(/baseUrl/);
    expect(() => resolveConfig({ runtime: { baseUrl: "ftp://x" } })).toThrow(/http/);
  });
  it("rejects an absolute run directory", () => {
    expect(() => resolveConfig({ orchestration: { runDirectory: "/abs" } })).toThrow(/relative/);
  });
  it("rejects an unknown provider", () => {
    expect(() => resolveConfig({ runtime: { provider: "openai" } })).toThrow(/ollama/);
  });
  it("rejects an invalid approval mode", () => {
    expect(() => resolveConfig({ approval: { mode: "sometimes" } })).toThrow(/adaptive/);
  });
  it("rejects a bad role name and conflicting read-only + write tool", () => {
    expect(() => resolveConfig({ roles: { "Bad Name": { readOnly: true } } })).toThrow(/role name/);
    expect(() =>
      resolveConfig({ roles: { auditor: { readOnly: true, allowTools: ["Write"] } } }),
    ).toThrow(/conflicting/);
  });
  it("accepts a custom role", () => {
    const c = resolveConfig({ roles: { auditor: { readOnly: true, description: "audits" } } });
    expect(c.roles.auditor.readOnly).toBe(true);
  });
});

describe("applyEnvOverrides", () => {
  it("applies model and concurrency from the environment", () => {
    const c = applyEnvOverrides(defaultConfig(), {
      LOCAL_AGENT_MODEL: "env-model",
      LOCAL_AGENT_MAX_CONCURRENCY: "3",
    } as NodeJS.ProcessEnv);
    expect(c.runtime.model).toBe("env-model");
    expect(c.orchestration.maxConcurrency).toBe(3);
  });
  it("validates env-provided values", () => {
    expect(() =>
      applyEnvOverrides(defaultConfig(), { LOCAL_AGENT_MAX_CONCURRENCY: "0" } as NodeJS.ProcessEnv),
    ).toThrow();
  });
});
