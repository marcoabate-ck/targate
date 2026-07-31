import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  initPolicy,
  parsePolicy,
  POLICY_PRESETS,
  PolicyError,
  validatePolicyObject,
} from "../src/policy.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "targate-packs-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("policy packs", () => {
  it("ships exactly the advertised presets", () => {
    expect(Object.keys(POLICY_PRESETS).sort()).toEqual(
      ["ai-agent", "ci", "default", "react-native", "strict"].sort(),
    );
    for (const def of Object.values(POLICY_PRESETS)) {
      expect(def.description.length).toBeGreaterThan(10);
    }
  });

  it("every preset passes the policy schema validation", () => {
    for (const [name, def] of Object.entries(POLICY_PRESETS)) {
      expect(() => validatePolicyObject(def.policy, name), name).not.toThrow();
    }
  });

  it("strict is stricter than default on every boolean gate", () => {
    const d = POLICY_PRESETS.default.policy.dependencyPolicy;
    const s = POLICY_PRESETS.strict.policy.dependencyPolicy;
    for (const key of [
      "blockRecentlyPublishedPackages",
      "requireApprovalForNativeCode",
      "requireApprovalForLifecycleScripts",
      "blockMissingRepositoryForRuntimeDeps",
    ] as const) {
      expect(Boolean(s[key]), key).toBe(true);
      expect(Boolean(s[key]) >= Boolean(d[key]), key).toBe(true);
    }
    expect(s.requireSignedApprovals).toBe(true);
    expect(s.allowKnownPackages).toEqual([]); // strict pre-approves nothing
    expect((s.minPackageAgeDays ?? 0) >= (d.minPackageAgeDays ?? 0)).toBe(true);
  });

  it("react-native gates native code; ci disables the AI cache; ai-agent stops on judgment calls", () => {
    expect(POLICY_PRESETS["react-native"].policy.dependencyPolicy.requireApprovalForNativeCode).toBe(true);
    expect(POLICY_PRESETS.ci.policy.aiCache?.enabled).toBe(false);
    expect(POLICY_PRESETS.ci.policy.dependencyPolicy.allowKnownPackages).toEqual([]);
    const agent = POLICY_PRESETS["ai-agent"].policy.dependencyPolicy;
    expect(agent.requireApprovalForLifecycleScripts).toBe(true);
    expect(agent.requireApprovalForNativeCode).toBe(true);
    expect(agent.blockRecentlyPublishedPackages).toBe(true);
    expect(agent.requireApprovalForAdvisorySeverity).toBe("high");
  });

  it("initPolicy writes a preset that round-trips through the YAML parser", async () => {
    const file = await initPolicy(dir, "yaml", "strict");
    expect(file).toContain("targate.policy.yaml");
    const content = await readFile(file!, "utf8");
    expect(content).toContain("preset: strict");
    const parsed = parsePolicy(content);
    expect(parsed.dependencyPolicy.requireSignedApprovals).toBe(true);
  });

  it("initPolicy writes valid json for a preset", async () => {
    const file = await initPolicy(dir, "json", "ai-agent");
    const doc = JSON.parse(await readFile(file!, "utf8"));
    expect(() => validatePolicyObject(doc)).not.toThrow();
    expect(doc.dependencyPolicy.minPackageAgeDays).toBe(14);
  });

  it("initPolicy rejects an unknown preset before touching the filesystem", async () => {
    await expect(initPolicy(dir, "yaml", "bogus")).rejects.toThrow(PolicyError);
    await expect(initPolicy(dir, "yaml", "bogus")).rejects.toThrow(/Available presets/);
  });

  it("initPolicy still refuses to overwrite an existing policy", async () => {
    await initPolicy(dir, "yaml", "default");
    expect(await initPolicy(dir, "yaml", "strict")).toBeNull();
  });

  it("validatePolicyObject accepts the new requireSignedApprovals and internalScopes fields", () => {
    const ok = validatePolicyObject({
      dependencyPolicy: { requireSignedApprovals: true, internalScopes: ["@acme"] },
    });
    expect(ok.dependencyPolicy.internalScopes).toEqual(["@acme"]);
    expect(() =>
      validatePolicyObject({ dependencyPolicy: { requireSignedApprovals: "yes" } }),
    ).toThrow(PolicyError);
    expect(() =>
      validatePolicyObject({ dependencyPolicy: { internalScopes: ["acme"] } }),
    ).toThrow(/starting with "@"/);
  });
});
