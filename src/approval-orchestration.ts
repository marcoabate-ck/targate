import path from "node:path";
import {
  buildApprovalContext,
  recordApproval,
  removeApproval,
  type ApprovalRecord,
} from "./approvals.js";
import { recordDenial, removeDenial } from "./denials.js";
import { recordBuildApproval } from "./pnpm-builds.js";
import { policyFileDigest, type LoadedPolicy } from "./policy.js";
import { isHardBlock } from "./rules.js";
import type { PackageAnalysis } from "./pipeline.js";
import type { BehaviorFingerprint } from "./fingerprint.js";
import type { TransitiveResult } from "./transitive.js";
import type { PackageManager, RiskAssessment } from "./types.js";
import { resolvePackageTrust } from "./trust-decision.js";

export function clearAssessmentWithApproval(
  assessment: RiskAssessment,
  name: string,
  version: string,
  approval: ApprovalRecord,
): RiskAssessment {
  return {
    ...assessment,
    decision: "allow_with_warnings",
    risk: assessment.risk === "high" ? "medium" : assessment.risk,
    reasons: [
      ...assessment.reasons,
      `[team] ${name}@${version} already approved${approval.approvedBy ? ` by ${approval.approvedBy}` : ""} on ${approval.approvedAt.slice(0, 10)} (${approval.mode}).`,
    ],
  };
}

export function applyRootApproval(
  analysis: PackageAnalysis,
  approval: ApprovalRecord | null,
): { assessment: RiskAssessment; enforceNoScripts: boolean } {
  const trust = resolvePackageTrust(
    analysis.assessment,
    isHardBlock(analysis.signals),
    approval,
  );
  const softBlock =
    analysis.assessment.decision === "block" && !trust.hardBlocked;
  const canClear =
    approval &&
    (analysis.assessment.decision === "require_approval" || softBlock);
  return {
    assessment: canClear
      ? clearAssessmentWithApproval(
          analysis.assessment,
          analysis.metadata.name,
          analysis.metadata.version,
          approval,
        )
      : analysis.assessment,
    enforceNoScripts: canClear
      ? approval.mode === "no-scripts"
      : trust.scriptPolicy === "deny",
  };
}

export function applyTransitiveApproval(
  result: TransitiveResult,
  approval: ApprovalRecord,
): void {
  result.approved = true;
  result.approvalMode = approval.mode;
  result.scriptPolicy = approval.mode === "no-scripts" ? "deny" : "allow";
  if (
    !result.hardBlock &&
    ["require_approval", "block"].includes(result.assessment.decision)
  ) {
    result.assessment = clearAssessmentWithApproval(
      result.assessment,
      result.name,
      result.version,
      approval,
    );
  }
}

export interface NoScriptsApprovalTarget {
  name: string;
  version: string;
  assessment: RiskAssessment;
  approved?: boolean;
  approvalMode?: "normal" | "no-scripts";
  scriptPolicy?: "allow" | "deny";
  unresolved?: boolean;
  /** Named `fingerprint` to match TransitiveResult/PackageAnalysis so those flow
   *  in as targets directly (they are mutated in place — no spread). */
  fingerprint?: BehaviorFingerprint;
}

/** Record a selected set once, sharing policy hashing and pnpm enforcement. */
export async function recordNoScriptsApprovals(
  targets: NoScriptsApprovalTarget[],
  options: {
    policy: LoadedPolicy | null;
    packageManager: PackageManager;
    cwd?: string;
    clearAssessment?: boolean;
  },
): Promise<void> {
  const cwd = options.cwd ?? process.cwd();
  const policyHash = options.policy
    ? await policyFileDigest(options.policy.file)
    : undefined;
  for (const target of targets) {
    await recordApproval(target.name, target.version, "no-scripts", cwd, {
      context: buildApprovalContext({
        assessment: target.assessment,
        policyFile: options.policy
          ? path.basename(options.policy.file)
          : undefined,
        policyHash,
      }),
      behaviorFingerprint: target.fingerprint,
    });
    target.approved = true;
    target.approvalMode = "no-scripts";
    target.scriptPolicy = "deny";
    target.unresolved = false;
    if (options.clearAssessment) {
      target.assessment = {
        ...target.assessment,
        decision: "allow_with_warnings",
        risk:
          target.assessment.risk === "high" ? "medium" : target.assessment.risk,
        reasons: [
          ...target.assessment.reasons,
          "[team] approved now (no-scripts) — recorded in .targate/approvals.json.",
        ],
      };
    }
    if (options.packageManager === "pnpm")
      await recordBuildApproval(target.name, "ignored");
  }
}

export interface TriageApprovalTarget {
  name: string;
  version: string;
  assessment: RiskAssessment;
  /** Allow the package's lifecycle scripts ("normal") vs record as "no-scripts". */
  scripts: boolean;
  fingerprint?: BehaviorFingerprint;
}

export interface TriageDenialTarget {
  name: string;
  version: string;
  assessment: RiskAssessment;
}

/**
 * Record the outcome of the interactive install triage in one pass: approvals
 * (honoring each item's per-item scripts choice) into .targate/approvals.json,
 * denials into .targate/denials.json. Approvals and denials are mutually
 * exclusive per name@version, so each write clears any opposite entry.
 */
export async function recordTriageDecisions(
  approvals: TriageApprovalTarget[],
  denials: TriageDenialTarget[],
  options: {
    policy: LoadedPolicy | null;
    packageManager: PackageManager;
    cwd?: string;
  },
): Promise<void> {
  const cwd = options.cwd ?? process.cwd();
  const policyFile = options.policy
    ? path.basename(options.policy.file)
    : undefined;
  const policyHash = options.policy
    ? await policyFileDigest(options.policy.file)
    : undefined;

  for (const target of approvals) {
    const mode = target.scripts ? "normal" : "no-scripts";
    await recordApproval(target.name, target.version, mode, cwd, {
      context: buildApprovalContext({
        assessment: target.assessment,
        policyFile,
        policyHash,
      }),
      behaviorFingerprint: target.fingerprint,
    });
    await removeDenial(target.name, target.version, cwd);
    if (options.packageManager === "pnpm") {
      await recordBuildApproval(
        target.name,
        target.scripts ? "approved" : "ignored",
      );
    }
  }

  for (const target of denials) {
    await recordDenial(target.name, target.version, cwd, {
      context: buildApprovalContext({
        assessment: target.assessment,
        policyFile,
        policyHash,
      }),
    });
    await removeApproval(target.name, target.version, cwd);
  }
}
