import { describe, expect, it } from "vitest";
import {
  aggregateTreeTrust,
  isApprovalApplicable,
  resolvePackageTrust,
} from "../src/trust-decision.js";
import type { Decision, RiskAssessment } from "../src/types.js";

function assessment(decision: Decision): RiskAssessment {
  return {
    decision,
    risk: decision === "block" ? "high" : decision === "allow" ? "low" : "medium",
    summary: decision,
    reasons: [`reason: ${decision}`],
    recommendedAction: "review",
    source: "rules",
  };
}

const noScripts = { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" };

describe("trust decision domain", () => {
  it("treats an approved soft block as resolved while preserving its verdict", () => {
    expect(resolvePackageTrust(assessment("block"), false, noScripts)).toMatchObject({
      decision: "block",
      approved: true,
      unresolved: false,
      hardBlocked: false,
      scriptPolicy: "deny",
    });
  });

  it("never lets an approval resolve a hard block", () => {
    expect(resolvePackageTrust(assessment("block"), true, noScripts)).toMatchObject({
      approved: false,
      unresolved: true,
      hardBlocked: true,
      scriptPolicy: "deny",
    });
  });

  it("aggregates the strictest verdict and denies scripts globally", () => {
    const aggregate = aggregateTreeTrust([
      resolvePackageTrust(assessment("allow"), false, null),
      resolvePackageTrust(assessment("require_approval"), false, noScripts),
    ]);
    expect(aggregate).toMatchObject({
      decision: "require_approval",
      unresolved: false,
      approved: true,
      scriptPolicy: "deny",
    });
  });

  it("rejects malformed persisted approvals", () => {
    expect(isApprovalApplicable({ mode: "unknown", approvedAt: 42 })).toBe(false);
    expect(isApprovalApplicable(noScripts)).toBe(true);
  });
});
