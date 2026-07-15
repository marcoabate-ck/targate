import type { SecurityScore } from "../score.js";
import type { PackageMetadata, RiskAssessment, Signals } from "../types.js";
import { DECISION_LABEL, decisionColor, renderSignalLines } from "./assessment.js";
import { bold, cyan, dim, yellow } from "./colors.js";
import { renderScoreLines } from "./score.js";

export function residualRisks(signals: Signals): string[] {
  const risks: string[] = [];
  if (signals.analysisDegraded?.length) risks.push(`analysis incomplete: ${signals.analysisDegraded.join("; ")}`);
  if (signals.hasNativeCode) risks.push("native/compiled code cannot be fully vetted by static analysis");
  if (signals.hasLifecycleScripts) risks.push("lifecycle scripts will run on installs that allow them");
  if (signals.osvUnavailable) risks.push("the malicious-package status was UNKNOWN at analysis time (OSV unavailable)");
  if (signals.internalScope) risks.push("internal scope: OSV/downloads/maintainer checks were skipped by policy — nothing external vouches for this package");
  if (signals.content.hasMinifiedCode) risks.push("minified/obfuscated code limits what static analysis can see");
  if (signals.content.hasProcessEnvAccess && signals.content.hasNetworkCalls) risks.push("code reads environment variables AND makes network calls — an exfiltration surface");
  if (signals.recentPublish) risks.push("recently published — little community exposure yet");
  if (["rate-limited", "unavailable"].includes(signals.reputation.repo.status)) risks.push("the repository's archived status could not be checked");
  return risks;
}

export interface ExplanationOptions {
  approval?: { mode: string; approvedAt: string; approvedBy?: string } | null;
  fromLastRun?: { command: string; timestamp: string };
}

export function renderExplanation(
  metadata: PackageMetadata,
  signals: Signals,
  assessment: RiskAssessment,
  score?: SecurityScore,
  options: ExplanationOptions = {},
): string {
  const lines: string[] = [];
  const paint = decisionColor(assessment.decision);
  const adjustments = assessment.reasons.filter((reason) => /^\[(policy|team)\]/.test(reason));
  const engineReasons = assessment.reasons.filter((reason) => !/^\[(policy|team)\]/.test(reason));
  lines.push("");
  lines.push(bold(`Why ${metadata.name}@${metadata.version} → `) + paint(bold(DECISION_LABEL[assessment.decision])));
  lines.push(dim(`(risk: ${assessment.risk} · source: ${assessment.source}${options.fromLastRun ? ` · from last ${options.fromLastRun.command} run, ${options.fromLastRun.timestamp}` : ""})`));
  lines.push(dim("─".repeat(60)), assessment.summary, "");
  if (assessment.source === "ai" && assessment.deterministic) {
    const deterministic = assessment.deterministic;
    lines.push(bold("Deterministic verdict (rules engine)"));
    lines.push(`  ${decisionColor(deterministic.decision)(DECISION_LABEL[deterministic.decision])}` + dim(` (risk: ${deterministic.risk})`));
    for (const reason of deterministic.reasons) lines.push(dim(`  • ${reason}`));
    lines.push(dim("  The AI interprets these signals but can only make the verdict stricter."), "");
  }
  lines.push(bold(assessment.source === "ai" ? "AI reasoning" : "Main reasons"));
  if (engineReasons.length === 0) lines.push(dim("  (no findings — nothing raised a flag)"));
  engineReasons.forEach((reason, index) => lines.push(`  ${index + 1}. ${reason}`));
  lines.push("");
  if (adjustments.length > 0) {
    lines.push(bold("Team & policy adjustments"));
    for (const adjustment of adjustments) lines.push(`  • ${adjustment}`);
    lines.push("");
  }
  if (options.approval) {
    lines.push(cyan(`ℹ a committed team approval exists for this exact version (${options.approval.mode}, ${options.approval.approvedAt.slice(0, 10)}${options.approval.approvedBy ? `, by ${options.approval.approvedBy}` : ""})`), "");
  }
  lines.push(bold("Deterministic findings"), ...renderSignalLines(signals), "");
  const risks = residualRisks(signals);
  if (risks.length > 0) {
    lines.push(bold("Residual risks"));
    for (const risk of risks) lines.push(yellow(`  • ${risk}`));
    lines.push("");
  }
  if (score) lines.push(...renderScoreLines(score), "");
  lines.push(bold("Recommendation"), `  ${assessment.recommendedAction}`);
  if (assessment.suggestedAlternatives?.length) {
    lines.push("", bold("Suggested alternatives"));
    for (const alternative of assessment.suggestedAlternatives) lines.push(`  • ${alternative}`);
  }
  lines.push("");
  return lines.join("\n");
}

