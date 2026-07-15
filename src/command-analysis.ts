import { resolveCacheSettings } from "./ai-cache.js";
import type { AssessOptions } from "./ai.js";
import { loadApprovals, type ApprovalsMap } from "./approvals.js";
import { writeLastRun, type LastRunFile } from "./last-run.js";
import {
  analyzePackage,
  type AnalysisStage,
  type AnalyzePackageOptions,
  type PackageAnalysis,
} from "./pipeline.js";
import { loadPolicy, type LoadedPolicy } from "./policy.js";
import { cyan, dim, red, yellow } from "./report.js";
import { applySignedApprovalsPolicy } from "./signing.js";
import { createTreeProgress } from "./progress.js";
import {
  analyzeTransitiveDeps,
  type AnalyzeTransitiveOptions,
  type TransitiveResult,
  type TreePackage,
} from "./transitive.js";

export interface AnalysisSession {
  cwd: string;
  policy: LoadedPolicy | null;
  assess: AssessOptions;
  approvals?: ApprovalsMap;
}

export async function prepareAnalysisSession(
  assess: AssessOptions,
  options: {
    cwd?: string;
    noCache?: boolean;
    approvals?: "raw" | "policy";
  } = {},
): Promise<AnalysisSession> {
  const cwd = options.cwd ?? process.cwd();
  const policy = await loadPolicy(cwd);
  let approvals: ApprovalsMap | undefined;
  if (options.approvals) {
    const loaded = await loadApprovals(cwd);
    approvals = options.approvals === "policy"
      ? await applySignedApprovalsPolicy(
          loaded,
          policy?.policy.dependencyPolicy.requireSignedApprovals,
          cwd,
        )
      : loaded;
  }
  return {
    cwd,
    policy,
    approvals,
    assess: {
      ...assess,
      cache: resolveCacheSettings(policy?.policy.aiCache, { refresh: options.noCache }),
      cwd,
    },
  };
}

export function createAnalysisStageReporter(
  note: (line: string) => void,
  options: { failOnOsvError?: boolean } = {},
): (stage: AnalysisStage, detail?: string) => void {
  return (stage, detail) => {
    switch (stage) {
      case "metadata":
        note(dim(`  ✓ npm metadata resolved (${detail})`));
        break;
      case "quarantine":
        note(dim("  ✓ tarball downloaded to quarantine"));
        break;
      case "osv":
        note(dim("  ✓ OSV/OpenSSF malicious-package lookup done"));
        break;
      case "osv-failed":
        note(
          (options.failOnOsvError ? red : yellow)(
            "  ⚠ OSV lookup failed — malicious-package status is UNKNOWN",
          ),
        );
        break;
      case "internal-scope":
        note(cyan(`  ℹ internal scope — ${detail}`));
        break;
      case "reputation":
        note(dim("  ✓ reputation lookups done (npm downloads, GitHub)"));
        break;
      case "reputation-degraded":
        note(yellow(`  ⚠ reputation lookups degraded — ${detail} (signals UNKNOWN)`));
        break;
      case "resource-limit":
        note(yellow(`  ⚠ analysis stopped at a safety limit — ${detail} (result UNKNOWN)`));
        break;
      case "signals":
        note(dim("  ✓ package contents inspected (scripts, native surface, RN hardening)"));
        break;
      case "assessment":
        note(dim(`  ✓ risk assessment complete (${detail})`));
        break;
      case "policy":
        note(dim(`  ✓ team policy applied (${detail})`));
        break;
    }
  };
}

export async function analyzeRootPackage(
  target: { name: string; version?: string },
  session: AnalysisSession,
  options: Omit<AnalyzePackageOptions, "assess" | "policy" | "cwd"> = {},
): Promise<PackageAnalysis> {
  return analyzePackage(target.name, target.version, {
    ...options,
    assess: session.assess,
    policy: session.policy,
    cwd: session.cwd,
  });
}

export async function analyzeDependencyTree(
  packages: TreePackage[],
  session: AnalysisSession,
  options: Omit<
    AnalyzeTransitiveOptions,
    "assess" | "policy" | "cwd" | "onProgress" | "onResult"
  > & {
    json: boolean;
    renderResult?: (result: TransitiveResult) => string | undefined;
  },
): Promise<TransitiveResult[]> {
  if (packages.length === 0) return [];
  const { json, renderResult, ...analysisOptions } = options;
  const progress = createTreeProgress({ json });
  const started = Date.now();
  try {
    return await analyzeTransitiveDeps(packages, {
      ...analysisOptions,
      assess: session.assess,
      policy: session.policy,
      cwd: session.cwd,
      onProgress: (phase, done, total) => progress.update(phase, done, total),
      onResult: renderResult
        ? (result) => {
            const line = renderResult(result);
            if (line) progress.log(line);
          }
        : undefined,
    });
  } finally {
    progress.done(
      json
        ? undefined
        : dim(`  ✓ ${packages.length} transitive dependencies reviewed in ${Math.round((Date.now() - started) / 1000)}s`),
    );
  }
}

export async function persistAnalysisRun(
  command: LastRunFile["command"],
  analysis: PackageAnalysis,
  assessment = analysis.assessment,
  cwd: string = process.cwd(),
): Promise<void> {
  await writeLastRun(
    command,
    [{
      metadata: analysis.metadata,
      signals: analysis.signals,
      assessment,
      score: analysis.score,
    }],
    cwd,
  );
}
