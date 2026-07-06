import { describe, expect, it } from "vitest";
import { clampDecision, evaluateRules } from "../src/rules.js";
import { makeSignals } from "./helpers.js";

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

describe("clampDecision", () => {
  it("overrides permissive AI decisions for known malicious packages", () => {
    const signals = makeSignals({
      knownMalicious: true,
      maliciousRecords: [{ id: "MAL-2024-1" }],
    });
    const clamped = clampDecision(
      {
        risk: "low",
        decision: "allow",
        summary: "looks fine",
        reasons: [],
        recommendedAction: "install",
        source: "ai",
      },
      signals,
    );
    expect(clamped.decision).toBe("block");
    expect(clamped.risk).toBe("high");
  });

  it("keeps AI decision when no hard signals fire", () => {
    const clamped = clampDecision(
      {
        risk: "medium",
        decision: "allow_with_warnings",
        summary: "ok",
        reasons: ["native code"],
        recommendedAction: "review",
        source: "ai",
      },
      makeSignals(),
    );
    expect(clamped.decision).toBe("allow_with_warnings");
  });
});
