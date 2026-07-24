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

// The whole-tree aggregator is the fail-safe that gates a --deep / full install:
// the strictest verdict wins, one denied-scripts package denies globally, and a
// single hard block or unapproved package keeps the whole tree unresolved. These
// exercise a realistic mixed tree rather than a 2-package pair.
describe("aggregateTreeTrust — mixed tree", () => {
  it("resolves when every approval-needing package is approved (strictest verdict, scripts denied globally)", () => {
    const aggregate = aggregateTreeTrust([
      resolvePackageTrust(assessment("allow"), false, null),
      resolvePackageTrust(assessment("allow_with_warnings"), false, null),
      resolvePackageTrust(assessment("require_approval"), false, noScripts),
      resolvePackageTrust(assessment("block"), false, noScripts), // soft block, approved
    ]);
    expect(aggregate).toMatchObject({
      decision: "block", // strictest across the tree
      hardBlocked: false,
      unresolved: false,
      approved: true,
      scriptPolicy: "deny", // one no-scripts approval denies scripts for the whole tree
    });
  });

  it("stays unresolved when any approval-needing package is NOT approved", () => {
    const aggregate = aggregateTreeTrust([
      resolvePackageTrust(assessment("allow"), false, null),
      resolvePackageTrust(assessment("require_approval"), false, noScripts), // approved
      resolvePackageTrust(assessment("require_approval"), false, null), // NOT approved
    ]);
    expect(aggregate).toMatchObject({
      decision: "require_approval",
      hardBlocked: false,
      unresolved: true,
      approved: false,
    });
  });

  it("a single hard block dominates the tree even when everything else is approved", () => {
    const aggregate = aggregateTreeTrust([
      resolvePackageTrust(assessment("allow"), false, null),
      resolvePackageTrust(assessment("require_approval"), false, noScripts), // approved
      resolvePackageTrust(assessment("block"), true, noScripts), // HARD block — cannot resolve
    ]);
    expect(aggregate).toMatchObject({
      decision: "block",
      hardBlocked: true,
      unresolved: true,
      approved: false,
    });
  });

  it("keeps scripts allowed when no approval denies them", () => {
    const aggregate = aggregateTreeTrust([
      resolvePackageTrust(assessment("allow"), false, null),
      resolvePackageTrust(assessment("require_approval"), false, {
        mode: "normal",
        approvedAt: "2026-01-01T00:00:00Z",
      }),
    ]);
    expect(aggregate).toMatchObject({ decision: "require_approval", approved: true, scriptPolicy: "allow" });
  });
});
