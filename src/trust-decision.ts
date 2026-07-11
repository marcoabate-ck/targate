import { DECISION_SEVERITY, type Decision, type RiskAssessment } from "./types.js";

export type ScriptPolicy = "allow" | "deny";
export type ApprovalMode = "normal" | "no-scripts";

export interface ApplicableApproval {
  mode: ApprovalMode;
  approvedAt: string;
  approvedBy?: string;
}

export interface PackageTrustResult {
  decision: Decision;
  hardBlocked: boolean;
  unresolved: boolean;
  approved: boolean;
  scriptPolicy: ScriptPolicy;
  reasons: string[];
}

function isValidIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  return /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value));
}

/** Runtime boundary for persisted approvals. Invalid/unknown modes fail safe. */
export function isApprovalApplicable(
  approval: unknown,
  _packageVersion?: string,
): approval is ApplicableApproval {
  if (typeof approval !== "object" || approval === null || Array.isArray(approval)) return false;
  const candidate = approval as Record<string, unknown>;
  return (
    (candidate.mode === "normal" || candidate.mode === "no-scripts") &&
    isValidIsoTimestamp(candidate.approvedAt) &&
    (candidate.approvedBy === undefined || typeof candidate.approvedBy === "string")
  );
}

/** Resolve one reviewed package without erasing its original assessment. */
export function resolvePackageTrust(
  assessment: RiskAssessment,
  hardBlocked: boolean,
  approval: unknown,
): PackageTrustResult {
  const applicable = isApprovalApplicable(approval);
  const needsApproval =
    assessment.decision === "require_approval" || assessment.decision === "block";
  const approved = applicable && !hardBlocked;

  return {
    decision: assessment.decision,
    hardBlocked,
    unresolved: hardBlocked || (needsApproval && !approved),
    approved,
    scriptPolicy: applicable && approval.mode === "no-scripts" ? "deny" : "allow",
    reasons: [...assessment.reasons],
  };
}

/** Fail-safe whole-tree aggregation. One scripts-denied package denies globally. */
export function aggregateTreeTrust(results: PackageTrustResult[]): PackageTrustResult {
  let decision: Decision = "allow";
  let hardBlocked = false;
  let unresolved = false;
  let approved = true;
  let scriptPolicy: ScriptPolicy = "allow";
  const reasons: string[] = [];

  for (const result of results) {
    if (DECISION_SEVERITY[result.decision] > DECISION_SEVERITY[decision]) {
      decision = result.decision;
    }
    hardBlocked ||= result.hardBlocked;
    unresolved ||= result.unresolved;
    if (result.decision === "require_approval" || result.decision === "block") {
      approved &&= result.approved;
    }
    if (result.scriptPolicy === "deny") scriptPolicy = "deny";
    reasons.push(...result.reasons);
  }

  return { decision, hardBlocked, unresolved, approved, scriptPolicy, reasons };
}
