import { describe, expect, it } from "vitest";
import {
  resolveApproval,
  type ApprovalRecord,
  type ApprovalsMap,
} from "../src/approvals.js";
import { applyRootApproval } from "../src/approval-orchestration.js";
import type { BehaviorFingerprint } from "../src/fingerprint.js";
import type { PackageAnalysis } from "../src/pipeline.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

function fp(overrides: Partial<BehaviorFingerprint> = {}): BehaviorFingerprint {
  return {
    schemaVersion: 1,
    installScripts: [],
    dangerousCapabilities: [],
    lowRiskCapabilities: [],
    provenanceState: "none",
    complete: true,
    ...overrides,
  };
}

function approval(
  version: string,
  record: Partial<ApprovalRecord> & {
    behaviorFingerprint?: BehaviorFingerprint;
  },
): ApprovalsMap {
  return {
    [`pkg@${version}`]: {
      mode: "no-scripts",
      approvedAt: "2026-01-01T00:00:00Z",
      approvedBy: "reviewer",
      ...record,
    },
  };
}

const REUSE = { allowFingerprintReuse: true };

describe("resolveApproval — fingerprint reuse (P2)", () => {
  it("prefers an exact version approval, even when another version would match", () => {
    const approvals: ApprovalsMap = {
      ...approval("1.0.0", { behaviorFingerprint: fp() }),
      ...approval("2.0.0", { mode: "normal", behaviorFingerprint: fp() }),
    };
    const resolved = resolveApproval(approvals, "pkg", "2.0.0", fp(), REUSE);
    expect(resolved?.via).toBe("exact");
    expect(resolved?.record.mode).toBe("normal");
  });

  it("reuses a prior version whose behavior fingerprint matches", () => {
    const approvals = approval("1.0.0", { behaviorFingerprint: fp() });
    const resolved = resolveApproval(approvals, "pkg", "2.0.0", fp(), REUSE);
    expect(resolved?.via).toBe("fingerprint");
    expect(resolved?.matchedVersion).toBe("1.0.0");
  });

  it("does not reuse when the policy flag is off (strict version-exact)", () => {
    const approvals = approval("1.0.0", { behaviorFingerprint: fp() });
    expect(resolveApproval(approvals, "pkg", "2.0.0", fp(), {})).toBeNull();
  });

  it("does not reuse without a candidate fingerprint", () => {
    const approvals = approval("1.0.0", { behaviorFingerprint: fp() });
    expect(
      resolveApproval(approvals, "pkg", "2.0.0", undefined, REUSE),
    ).toBeNull();
  });

  it("does not reuse a legacy approval that has no fingerprint", () => {
    const approvals = approval("1.0.0", {}); // no behaviorFingerprint
    expect(resolveApproval(approvals, "pkg", "2.0.0", fp(), REUSE)).toBeNull();
  });

  it("does not reuse on escalation into the dangerous capability set", () => {
    const approvals = approval("1.0.0", { behaviorFingerprint: fp() });
    const candidate = fp({ dangerousCapabilities: ["network"] });
    expect(
      resolveApproval(approvals, "pkg", "2.0.0", candidate, REUSE),
    ).toBeNull();
  });

  it("does not reuse when an install script changed", () => {
    const approvals = approval("1.0.0", {
      behaviorFingerprint: fp({
        installScripts: [
          {
            name: "postinstall",
            commandHash: "aaaa",
            referencedFileHashes: { "i.js": "v1" },
          },
        ],
      }),
    });
    const candidate = fp({
      installScripts: [
        {
          name: "postinstall",
          commandHash: "aaaa",
          referencedFileHashes: { "i.js": "v2" },
        },
      ],
    });
    expect(
      resolveApproval(approvals, "pkg", "2.0.0", candidate, REUSE),
    ).toBeNull();
  });

  it("does not reuse on a provenance downgrade", () => {
    const approvals = approval("1.0.0", {
      behaviorFingerprint: fp({ provenanceState: "present" }),
    });
    const candidate = fp({ provenanceState: "none" });
    expect(
      resolveApproval(approvals, "pkg", "2.0.0", candidate, REUSE),
    ).toBeNull();
  });

  it("fails closed when the candidate fingerprint is incomplete", () => {
    const approvals = approval("1.0.0", { behaviorFingerprint: fp() });
    const candidate = fp({ complete: false });
    expect(
      resolveApproval(approvals, "pkg", "2.0.0", candidate, REUSE),
    ).toBeNull();
  });

  it("prefers the strictest mode when several prior versions match", () => {
    const approvals: ApprovalsMap = {
      ...approval("1.0.0", { mode: "normal", behaviorFingerprint: fp() }),
      ...approval("1.5.0", { mode: "no-scripts", behaviorFingerprint: fp() }),
    };
    const resolved = resolveApproval(approvals, "pkg", "2.0.0", fp(), REUSE);
    expect(resolved?.via).toBe("fingerprint");
    expect(resolved?.record.mode).toBe("no-scripts");
  });
});

describe("applyRootApproval — fingerprint reuse under the floor", () => {
  function analysis(
    decision: RiskAssessment["decision"],
    signalsOverride = {},
  ): PackageAnalysis {
    return {
      metadata: {
        name: "pkg",
        version: "2.0.0",
      } as PackageAnalysis["metadata"],
      signals: makeSignals({
        package: "pkg",
        version: "2.0.0",
        ...signalsOverride,
      }),
      assessment: {
        risk: "high",
        decision,
        summary: "s",
        reasons: ["r"],
        recommendedAction: "review",
        source: "rules",
      },
      score: {
        total: 50,
        categories: [],
      } as unknown as PackageAnalysis["score"],
      fingerprint: fp(),
    };
  }

  const record: ApprovalRecord = {
    mode: "no-scripts",
    approvedAt: "2026-01-01T00:00:00Z",
    approvedBy: "reviewer",
    behaviorFingerprint: fp(),
  };

  it("clears a soft require_approval via a fingerprint match, with a transparent reason", () => {
    const out = applyRootApproval(analysis("require_approval"), {
      record,
      via: "fingerprint",
      matchedVersion: "1.0.0",
    });
    expect(out.assessment.decision).toBe("allow_with_warnings");
    expect(out.assessment.reasons.join(" ")).toContain(
      "matching behavior fingerprint of pkg@1.0.0",
    );
    expect(out.enforceNoScripts).toBe(true); // prior mode was no-scripts
  });

  it("NEVER clears a hard block, even on a perfect fingerprint match", () => {
    // knownMalicious -> isHardBlock true -> the match must not clear it.
    const out = applyRootApproval(analysis("block", { knownMalicious: true }), {
      record,
      via: "fingerprint",
      matchedVersion: "1.0.0",
    });
    expect(out.assessment.decision).toBe("block");
    expect(out.assessment.reasons.join(" ")).not.toContain(
      "behavior fingerprint",
    );
  });
});
