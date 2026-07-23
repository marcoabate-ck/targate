/**
 * Adaptive orchestration & approval policy.
 *
 * This is reusable *decision guidance*, not an opaque autonomous classifier.
 * The lead (Opus) supplies a structured read of the task; the policy returns a
 * risk tier, a suggested worker flow, and — crucially — whether human approval
 * is mandatory. Certain conditions ALWAYS force approval regardless of the
 * lead's risk estimate, so a low-confidence "it's fine" cannot wave through a
 * security-relevant change.
 */

import { createHash } from "node:crypto";
import type { ApprovalMode } from "./config.js";

export type RiskTier = "trivial" | "small" | "medium" | "large";

export interface TaskSignals {
  /** Rough count of files the change will touch. */
  likelyFiles?: number;
  /** Changes architecture, module boundaries, or core control flow. */
  architectural?: boolean;
  /** Touches auth, credentials, security policy, verdict precedence, etc. */
  securitySensitive?: boolean;
  /** Adds or changes dependencies. */
  dependencyChange?: boolean;
  /** Changes a public/exported API in a breaking way. */
  publicApiBreaking?: boolean;
  /** Performs a destructive or irreversible operation. */
  destructive?: boolean;
  /** Changes CI or release behaviour. */
  affectsCiOrRelease?: boolean;
  /** Changes package-execution boundaries or credential handling. */
  changesExecutionOrCredentials?: boolean;
  /** The lead's own uncertainty about scope or approach. */
  highUncertainty?: boolean;
  /** Purely explanatory — no file changes intended. */
  explanatoryOnly?: boolean;
  /** Repo instructions demand approval for this class of change. */
  repoRequiresApproval?: boolean;
}

export interface PolicyDecision {
  riskTier: RiskTier;
  approvalRequired: boolean;
  approvalReason?: string;
  /** Ordered role flow the lead may follow (a suggestion, not a mandate). */
  suggestedFlow: string[];
  /** Whether workers are worth using at all (vs the lead doing it directly). */
  useWorkers: boolean;
  notes: string[];
}

/** Conditions that force human approval no matter the estimated risk tier. */
function mandatoryApprovalReason(s: TaskSignals): string | null {
  if (s.securitySensitive) return "security-sensitive change";
  if (s.changesExecutionOrCredentials) return "changes package-execution boundary or credential handling";
  if (s.destructive) return "destructive or irreversible operation";
  if (s.dependencyChange) return "adds or changes dependencies";
  if (s.publicApiBreaking) return "breaking public API change";
  if (s.affectsCiOrRelease) return "affects CI or release behaviour";
  if (s.architectural) return "broad architectural change";
  return null;
}

function classifyTier(s: TaskSignals): RiskTier {
  if (s.explanatoryOnly) return "trivial";
  const files = s.likelyFiles ?? 1;
  if (
    s.architectural ||
    s.securitySensitive ||
    s.changesExecutionOrCredentials ||
    s.publicApiBreaking ||
    s.affectsCiOrRelease ||
    files > 8
  ) {
    return "large";
  }
  if (s.dependencyChange || s.highUncertainty || files > 3) return "medium";
  if (files <= 1 && !s.highUncertainty) return "small";
  return "small";
}

/**
 * Default role flows. Review is intentionally the LEAD's job — Opus reviews the
 * workers' structured results and performs the final correctness/security pass
 * itself, which is both higher quality and far faster than a full review on the
 * local model. The `reviewer` role stays available for explicit use
 * (`run reviewer`, or a `--flow` that names it), and the correction loop still
 * engages when a reviewer worker is added to a flow.
 */
const FLOWS: Record<RiskTier, string[]> = {
  trivial: [], // lead handles directly
  small: ["implementer"],
  medium: ["discovery", "implementer", "tester"],
  large: ["discovery", "implementer", "tester"],
};

/**
 * Produce a policy decision for a task. `mode` comes from config:
 * - "always": approval always required
 * - "never": approval never required (still returns the reason for the record)
 * - "adaptive": mandatory triggers + tier drive the requirement
 */
export function decide(signals: TaskSignals, mode: ApprovalMode = "adaptive"): PolicyDecision {
  const tier = classifyTier(signals);
  const mandatory = mandatoryApprovalReason(signals);
  const notes: string[] = [];

  let approvalRequired: boolean;
  let approvalReason: string | undefined;

  if (mode === "always") {
    approvalRequired = true;
    approvalReason = mandatory ?? "approval mode is 'always'";
  } else if (mode === "never") {
    approvalRequired = false;
    if (mandatory) notes.push(`approval mode 'never' overrode a mandatory trigger: ${mandatory}`);
  } else {
    approvalRequired = mandatory !== null || tier === "large" || signals.highUncertainty === true;
    approvalReason = mandatory ?? (tier === "large" ? "large-scope change" : signals.highUncertainty ? "high uncertainty" : undefined);
  }

  const useWorkers = tier !== "trivial";
  if (!useWorkers) notes.push("trivial task — the lead can handle it directly without workers");

  return {
    riskTier: tier,
    approvalRequired,
    approvalReason,
    suggestedFlow: FLOWS[tier],
    useWorkers,
    notes,
  };
}

/** Stable hash of an approved plan, recorded so drift can be detected. */
export function planHash(planText: string): string {
  return "sha256:" + createHash("sha256").update(planText, "utf8").digest("hex");
}

/** True when the current plan text no longer matches the approved hash. */
export function planChanged(currentPlan: string, approvedHash: string): boolean {
  return planHash(currentPlan) !== approvedHash;
}
