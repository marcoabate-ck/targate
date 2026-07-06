/**
 * Public entry point of the "bye" package: the types (and tiny helpers)
 * that typed config files import.
 *
 *   // bye.policy.ts
 *   import type { PolicyFile } from "bye";
 *   const policy: PolicyFile = { dependencyPolicy: { minPackageAgeDays: 7 } };
 *   export default policy;
 */
export type { DependencyPolicy, PolicyFile } from "./policy.js";
export type { ApprovalRecord, ApprovalsMap } from "./approvals.js";
export type { Decision, RiskAssessment, RiskLevel, Signals } from "./types.js";

import type { PolicyFile } from "./policy.js";
import type { ApprovalsMap } from "./approvals.js";

/** Identity helper that gives full type inference in bye.policy.{ts,js}. */
export function definePolicy(policy: PolicyFile): PolicyFile {
  return policy;
}

/** Identity helper for hand-curated .bye/approvals.{ts,js} files. */
export function defineApprovals(approvals: ApprovalsMap): ApprovalsMap {
  return approvals;
}
