import { getApproval, type ApprovalsMap } from "./approvals.js";
import type { AssessOptions } from "./ai.js";
import { snapshotLockfile } from "./lockfile.js";
import {
  packagesFromLockfile,
  resolveInstallPlan,
  type InstallPlan,
} from "./install-plan.js";
import type { LoadedPolicy } from "./policy.js";
import { analyzeTransitiveDeps, type TreePackage, type TransitiveResult } from "./transitive.js";
import type { Decision, PackageManager } from "./types.js";
import {
  aggregateTreeTrust,
  resolvePackageTrust,
  type ApprovalMode,
  type ScriptPolicy,
} from "./trust-decision.js";

/**
 * Full-project ("bootstrap") install vetting for `targate install` — analyze the
 * ENTIRE dependency tree the way `pnpm install` / `npm install` would restore
 * it, BEFORE running the install that executes every package's lifecycle
 * scripts. This is the highest-exposure moment (the whole transitive tree's
 * install scripts run at once), and `targate add` / `targate ci` don't cover it:
 * `add` is one new package, `ci` is only the deps a change touches.
 *
 * Reuses the same per-package pipeline, AI cache, and aggregation as
 * `--deep`; the only new work is enumerating the full tree.
 */

export interface ProjectTree {
  packages: TreePackage[];
  /** "lockfile": read from the committed lockfile; "resolved": the project PM resolved it. */
  source: "lockfile" | "resolved";
}

/** Parse a lockfile's full set of packages into a sorted, de-duplicated tree. */
export function treeFromLockfile(pm: PackageManager, content: string): TreePackage[] {
  return packagesFromLockfile(pm, content);
}

/**
 * Enumerate the full dependency tree of the project in `cwd`. Prefers the
 * committed lockfile (the source of truth for what will land on disk). With
 * no lockfile, the project's actual package manager resolves the manifest in
 * a throwaway directory with scripts disabled.
 */
export async function resolveProjectTree(
  pm: PackageManager,
  cwd: string = process.cwd(),
): Promise<ProjectTree> {
  const lockContent = await snapshotLockfile(pm, cwd);
  if (lockContent) {
    return { packages: treeFromLockfile(pm, lockContent), source: "lockfile" };
  }

  const plan = await resolveInstallPlan({ packageManager: pm, cwd, updateLockfile: true });
  return { packages: plan.packages, source: "resolved" };
}

export interface InstallVetResult extends TransitiveResult {
  /** True when an applicable committed approval exists and no hard block invalidates it. */
  approved: boolean;
  approvalMode?: ApprovalMode;
  scriptPolicy: ScriptPolicy;
  unresolved: boolean;
}

/**
 * Aggregate the whole-tree verdict (pure, so it is easy to test):
 * - decision = the STRICTEST decision anywhere in the tree.
 * - exitCode 2 when any package is a HARD block, or is a soft block /
 *   require_approval WITHOUT a committed approval; otherwise 0. A soft block
 *   that carries a committed approval passes (e.g. esbuild once approved).
 */
export function aggregateInstallDecision(results: InstallVetResult[]): {
  decision: Decision;
  exitCode: number;
} {
  const aggregate = aggregateTreeTrust(
    results.map((r) => ({
      decision: r.assessment.decision,
      hardBlocked: r.hardBlock === true,
      unresolved:
        r.unresolved ??
        (r.hardBlock === true ||
          ((r.assessment.decision === "block" || r.assessment.decision === "require_approval") &&
            !r.approved)),
      approved: r.approved,
      scriptPolicy: r.scriptPolicy ?? (r.approvalMode === "no-scripts" ? "deny" : "allow"),
      reasons: [...r.assessment.reasons],
    })),
  );
  return { decision: aggregate.decision, exitCode: aggregate.unresolved ? 2 : 0 };
}

export interface InstallReport {
  packageManager: PackageManager;
  source: "lockfile" | "resolved";
  total: number;
  results: InstallVetResult[];
  decision: Decision;
  exitCode: number;
  planFingerprint: string;
  artifactFingerprint: string;
}

export interface VetInstallOptions {
  packageManager: PackageManager;
  cwd: string;
  assess: AssessOptions;
  approvals: ApprovalsMap;
  policy?: LoadedPolicy | null;
  failOnOsvError?: boolean;
  concurrency?: number;
  /** Force isolated per-package AI calls instead of batching (--no-ai-batch). */
  noAiBatch?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  onResult?: (result: InstallVetResult, index: number, total: number) => void;
  /** Live progress (spinner/ETA) — see AnalyzeTransitiveOptions.onProgress. */
  onProgress?: (phase: "scan" | "assess" | "analyze", done: number, total: number) => void;
  /** Injection point for tests — defaults to the real transitive walker. */
  analyzeAll?: typeof analyzeTransitiveDeps;
  /** Pre-resolved immutable plan; avoids resolving a second tree. */
  plan?: InstallPlan;
}

/** Enumerate the tree, vet every unique package, and aggregate the verdict. */
export async function vetInstall(opts: VetInstallOptions): Promise<InstallReport> {
  const plan = opts.plan ?? await resolveInstallPlan({
    packageManager: opts.packageManager,
    cwd: opts.cwd,
    updateLockfile: false,
  });
  const packages = plan.packages;
  const source = plan.source === "existing" ? "lockfile" : "resolved";
  const analyzeAll = opts.analyzeAll ?? analyzeTransitiveDeps;

  const raw = await analyzeAll(packages, {
    assess: opts.assess,
    failOnOsvError: opts.failOnOsvError,
    policy: opts.policy ?? undefined,
    concurrency: opts.concurrency,
    noAiBatch: opts.noAiBatch,
    noReputation: opts.noReputation,
    cwd: opts.cwd,
    lockfileTrusted: plan.source === "existing",
    onProgress: opts.onProgress,
    onResult: (r, i, total) => {
      const approval = getApproval(opts.approvals, r.name, r.version);
      const trust = resolvePackageTrust(r.assessment, r.hardBlock === true, approval);
      opts.onResult?.({
        ...r,
        approved: trust.approved,
        approvalMode: trust.approved ? approval?.mode : undefined,
        scriptPolicy: trust.scriptPolicy,
        unresolved: trust.unresolved,
      }, i, total);
    },
  });

  const results: InstallVetResult[] = raw.map((r) => {
    const approval = getApproval(opts.approvals, r.name, r.version);
    const trust = resolvePackageTrust(r.assessment, r.hardBlock === true, approval);
    return {
      ...r,
      approved: trust.approved,
      approvalMode: trust.approved ? approval?.mode : undefined,
      scriptPolicy: trust.scriptPolicy,
      unresolved: trust.unresolved,
    };
  });
  const { decision, exitCode } = aggregateInstallDecision(results);

  return {
    packageManager: opts.packageManager,
    source,
    total: results.length,
    results,
    decision,
    exitCode,
    planFingerprint: plan.fingerprint,
    artifactFingerprint: plan.artifactFingerprint,
  };
}
