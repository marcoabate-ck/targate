import path from "node:path";
import {
  buildApprovalContext,
  recordApproval,
  type ApprovalRecord,
} from "./approvals.js";
import { recordBuildApproval } from "./pnpm-builds.js";
import { policyFileDigest, type LoadedPolicy } from "./policy.js";
import { isHardBlock } from "./rules.js";
import type { PackageAnalysis } from "./pipeline.js";
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
  const softBlock = analysis.assessment.decision === "block" && !trust.hardBlocked;
  const canClear = approval &&
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
  if (!result.hardBlock && ["require_approval", "block"].includes(result.assessment.decision)) {
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
  const policyHash = options.policy ? await policyFileDigest(options.policy.file) : undefined;
  for (const target of targets) {
    await recordApproval(target.name, target.version, "no-scripts", cwd, {
      context: buildApprovalContext({
        assessment: target.assessment,
        policyFile: options.policy ? path.basename(options.policy.file) : undefined,
        policyHash,
      }),
    });
    target.approved = true;
    target.approvalMode = "no-scripts";
    target.scriptPolicy = "deny";
    target.unresolved = false;
    if (options.clearAssessment) {
      target.assessment = {
        ...target.assessment,
        decision: "allow_with_warnings",
        risk: target.assessment.risk === "high" ? "medium" : target.assessment.risk,
        reasons: [
          ...target.assessment.reasons,
          "[team] approved now (no-scripts) — recorded in .targate/approvals.json.",
        ],
      };
    }
    if (options.packageManager === "pnpm") await recordBuildApproval(target.name, "ignored");
  }
}

