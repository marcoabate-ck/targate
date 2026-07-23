import { describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import {
  assembleSystemPrompt,
  availableRoles,
  CROSS_PLATFORM_GUIDANCE,
  INJECTION_DEFENSE,
  resolveRole,
} from "../src/roles.js";

const config = defaultConfig();

describe("resolveRole", () => {
  it("resolves the built-in roles with their read/write posture", () => {
    expect(resolveRole("discovery", config)?.readOnly).toBe(true);
    expect(resolveRole("implementer", config)?.readOnly).toBe(false);
    expect(resolveRole("reviewer", config)?.readOnly).toBe(true);
    expect(resolveRole("nope", config)).toBeNull();
  });
  it("resolves a config-defined custom role", () => {
    const c = { ...config, roles: { ...config.roles, auditor: { readOnly: true, description: "x" } } };
    expect(resolveRole("auditor", c)?.readOnly).toBe(true);
    expect(availableRoles(c)).toContain("auditor");
  });
});

describe("assembleSystemPrompt", () => {
  it("always carries the prompt-injection defense", () => {
    const prompt = assembleSystemPrompt({ role: resolveRole("discovery", config)! });
    expect(prompt).toContain(INJECTION_DEFENSE.slice(0, 30));
  });

  it("appends cross-platform guidance for writer roles only", () => {
    const impl = assembleSystemPrompt({ role: resolveRole("implementer", config)! });
    const disc = assembleSystemPrompt({ role: resolveRole("discovery", config)! });
    expect(impl).toContain(CROSS_PLATFORM_GUIDANCE);
    expect(disc).not.toContain(CROSS_PLATFORM_GUIDANCE);
  });

  it("reviewer is told to flag cross-platform hazards", () => {
    const prompt = assembleSystemPrompt({ role: resolveRole("reviewer", config)! });
    expect(prompt).toMatch(/cross-platform hazards/i);
  });

  it("includes in-scope AGENTS.md and repo role instructions when provided", () => {
    const prompt = assembleSystemPrompt({
      role: resolveRole("implementer", config)!,
      agentsContext: "USE targate for installs",
      repoRoleInstructions: "repo-specific note",
    });
    expect(prompt).toContain("USE targate for installs");
    expect(prompt).toContain("repo-specific note");
  });
});
