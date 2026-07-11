/**
 * Public entry point of the "targate" package: the types (and tiny helpers)
 * that typed config files import.
 *
 *   // targate.policy.ts
 *   import type { PolicyFile } from "targate";
 *   const policy: PolicyFile = { dependencyPolicy: { minPackageAgeDays: 7 } };
 *   export default policy;
 */
export type { DependencyPolicy, PolicyFile } from "./policy.js";
export type { AiCachePolicy } from "./ai-cache.js";
export type { ApprovalRecord, ApprovalsMap } from "./approvals.js";
export type { Decision, RiskAssessment, RiskLevel, Signals } from "./types.js";
export type { ScriptPolicy } from "./trust-decision.js";

import type { PolicyFile } from "./policy.js";
import type { ApprovalsMap } from "./approvals.js";

/** Identity helper that gives full type inference in targate.policy.{ts,js}. */
export function definePolicy(policy: PolicyFile): PolicyFile {
  return policy;
}

/** Identity helper for hand-curated .targate/approvals.{ts,js} files. */
export function defineApprovals(approvals: ApprovalsMap): ApprovalsMap {
  return approvals;
}
