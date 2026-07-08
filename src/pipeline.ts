import path from "node:path";
import { buildSignals } from "./analyze/index.js";
import { assessRisk, type AssessOptions } from "./ai.js";
import { osvUnavailable, queryOsv, type OsvResult } from "./osv.js";
import { applyPolicy, type LoadedPolicy } from "./policy.js";
import { quarantineTarball } from "./quarantine.js";
import { fetchPackageMetadata } from "./registry.js";
import { applyOsvFailurePolicy } from "./rules.js";
import type { PackageMetadata, RiskAssessment, Signals } from "./types.js";

/**
 * The single per-package analysis pipeline, shared by `targate add`, `targate ci`
 * and the transitive (--deep) walker:
 *
 *   registry metadata → tarball quarantine → OSV lookup → deterministic
 *   signals → AI/rules assessment (+ OSV failure policy) → team policy.
 *
 * Emits progress through onStage so each command renders it its own way.
 */

export type AnalysisStage =
  | "metadata"
  | "quarantine"
  | "osv"
  | "osv-failed"
  | "signals"
  | "assessment"
  | "policy";

export interface AnalyzePackageOptions {
  assess: AssessOptions;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Already-loaded team policy (applied on top of the assessment). */
  policy?: LoadedPolicy | null;
  onStage?: (stage: AnalysisStage, detail?: string) => void;
}

export interface PackageAnalysis {
  metadata: PackageMetadata;
  signals: Signals;
  assessment: RiskAssessment;
}

export async function analyzePackage(
  name: string,
  version: string | undefined,
  opts: AnalyzePackageOptions,
): Promise<PackageAnalysis> {
  const metadata = await fetchPackageMetadata(name, version);
  opts.onStage?.("metadata", `${metadata.name}@${metadata.version}`);

  const quarantine = await quarantineTarball(metadata.tarballUrl);
  opts.onStage?.("quarantine");

  try {
    let osv: OsvResult;
    try {
      osv = await queryOsv(metadata.name, metadata.version);
      opts.onStage?.("osv");
    } catch {
      osv = osvUnavailable();
      opts.onStage?.("osv-failed");
    }

    const signals = await buildSignals(metadata, quarantine.packageDir, osv);
    opts.onStage?.("signals");

    let assessment = await assessRisk(signals, opts.assess);
    assessment = applyOsvFailurePolicy(assessment, signals, opts.failOnOsvError ?? false);
    opts.onStage?.("assessment", assessment.source);

    if (opts.policy) {
      assessment = applyPolicy(assessment, signals, opts.policy.policy);
      opts.onStage?.("policy", path.basename(opts.policy.file));
    }

    return { metadata, signals, assessment };
  } finally {
    await quarantine.cleanup();
  }
}
