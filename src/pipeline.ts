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
  /**
   * Pre-fetched OSV result (e.g. from a batched queryOsvBatch over a whole
   * tree). When provided, the per-package OSV round-trip is skipped.
   */
  osv?: OsvResult;
  onStage?: (stage: AnalysisStage, detail?: string) => void;
}

export interface PackageAnalysis {
  metadata: PackageMetadata;
  signals: Signals;
  assessment: RiskAssessment;
}

export interface PackageSignals {
  metadata: PackageMetadata;
  signals: Signals;
}

/**
 * The I/O half of the pipeline: registry metadata -> tarball quarantine ->
 * OSV -> deterministic signals. Split out from analyzePackage so a tree walk
 * can build every package's signals first (concurrently) and then batch the
 * AI assessment across them. The tarball is cleaned up here; only the small
 * signals object is retained.
 */
export async function buildPackageSignals(
  name: string,
  version: string | undefined,
  opts: Pick<AnalyzePackageOptions, "failOnOsvError" | "osv" | "onStage">,
): Promise<PackageSignals> {
  const metadata = await fetchPackageMetadata(name, version);
  opts.onStage?.("metadata", `${metadata.name}@${metadata.version}`);

  const quarantine = await quarantineTarball(metadata.tarballUrl, {
    integrity: metadata.integrity,
    shasum: metadata.shasum,
  });
  opts.onStage?.("quarantine");

  try {
    let osv: OsvResult;
    if (opts.osv) {
      osv = opts.osv;
      opts.onStage?.(osv.unavailable ? "osv-failed" : "osv");
    } else {
      try {
        osv = await queryOsv(metadata.name, metadata.version);
        opts.onStage?.("osv");
      } catch {
        osv = osvUnavailable();
        opts.onStage?.("osv-failed");
      }
    }

    const signals = await buildSignals(metadata, quarantine.packageDir, osv);
    opts.onStage?.("signals");
    return { metadata, signals };
  } finally {
    await quarantine.cleanup();
  }
}

/**
 * Turn deterministic signals into a final assessment: AI/rules verdict (with
 * the AI cache + clamp inside assessRisk) -> OSV-failure policy -> team
 * policy. Shared by analyzePackage and the batched tree path so both apply
 * the exact same post-assessment escalations.
 */
export async function finalizeAssessment(
  signals: Signals,
  assessment: RiskAssessment,
  opts: Pick<AnalyzePackageOptions, "failOnOsvError" | "policy" | "onStage">,
): Promise<RiskAssessment> {
  let result = applyOsvFailurePolicy(assessment, signals, opts.failOnOsvError ?? false);
  opts.onStage?.("assessment", result.source);
  if (opts.policy) {
    result = applyPolicy(result, signals, opts.policy.policy);
    opts.onStage?.("policy", path.basename(opts.policy.file));
  }
  return result;
}

export async function analyzePackage(
  name: string,
  version: string | undefined,
  opts: AnalyzePackageOptions,
): Promise<PackageAnalysis> {
  const { metadata, signals } = await buildPackageSignals(name, version, opts);
  const assessment = await finalizeAssessment(signals, await assessRisk(signals, opts.assess), opts);
  return { metadata, signals, assessment };
}
