import { describe, expect, it } from "vitest";
import { assertNoSecrets, buildWorkerEnv, isSecretName } from "../src/env.js";

const runtime = { baseUrl: "http://localhost:11434", authToken: "ollama", model: "m" };

describe("isSecretName", () => {
  it("flags known secrets, prefixes, and generic token/key families", () => {
    for (const n of ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "NPM_TOKEN"]) {
      expect(isSecretName(n)).toBe(true);
    }
    expect(isSecretName("AWS_SECRET_ACCESS_KEY")).toBe(true);
    expect(isSecretName("GOOGLE_APPLICATION_CREDENTIALS")).toBe(true);
    expect(isSecretName("MY_SERVICE_TOKEN")).toBe(true);
    expect(isSecretName("DB_PASSWORD")).toBe(true);
  });
  it("does not flag ordinary variables", () => {
    for (const n of ["PATH", "HOME", "LANG", "PUBLIC_KEY", "EDITOR"]) {
      expect(isSecretName(n)).toBe(false);
    }
  });
});

describe("buildWorkerEnv", () => {
  it("never mutates the parent environment", () => {
    const parent = { PATH: "/usr/bin", ANTHROPIC_API_KEY: "sk-secret" };
    const snapshot = { ...parent };
    buildWorkerEnv({ runtime, parentEnv: parent });
    expect(parent).toEqual(snapshot);
  });

  it("forwards allowlisted vars and drops secrets", () => {
    const parent = {
      PATH: "/usr/bin",
      HOME: "/home/u",
      ANTHROPIC_API_KEY: "sk-xxx",
      GITHUB_TOKEN: "ghp_xxx",
      AWS_SECRET_ACCESS_KEY: "aws",
      RANDOM_VAR: "nope",
    };
    const { env, droppedSecrets, forwarded } = buildWorkerEnv({ runtime, parentEnv: parent });
    expect(forwarded).toContain("PATH");
    expect(forwarded).toContain("HOME");
    expect(env.ANTHROPIC_API_KEY).toBe(""); // explicit empty
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.RANDOM_VAR).toBeUndefined(); // not on allowlist
    expect(droppedSecrets).toContain("ANTHROPIC_API_KEY");
    expect(droppedSecrets).toContain("GITHUB_TOKEN");
    expect(droppedSecrets).toContain("AWS_SECRET_ACCESS_KEY");
  });

  it("sets the Ollama routing variables last", () => {
    const { env } = buildWorkerEnv({ runtime, parentEnv: { PATH: "/x" } });
    expect(env.ANTHROPIC_BASE_URL).toBe("http://localhost:11434");
    expect(env.ANTHROPIC_AUTH_TOKEN).toBe("ollama");
    expect(env.LOCAL_AGENT_MODEL).toBe("m");
  });

  it("cannot be tricked into forwarding a secret via allowExtra", () => {
    const { env, droppedSecrets } = buildWorkerEnv({
      runtime,
      parentEnv: { GITHUB_TOKEN: "ghp" },
      allowExtra: ["GITHUB_TOKEN"],
    });
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(droppedSecrets).toContain("GITHUB_TOKEN");
  });

  it("assertNoSecrets passes for a built env and throws when a secret is injected", () => {
    const { env } = buildWorkerEnv({ runtime, parentEnv: { PATH: "/x" } });
    expect(() => assertNoSecrets(env)).not.toThrow();
    expect(() => assertNoSecrets({ ...env, GITHUB_TOKEN: "leak" })).toThrow(/leaked a secret/);
  });
});
