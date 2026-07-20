import { getApproval, type ApprovalsMap } from "./approvals.js";
import { getDenial, type DenialsMap } from "./denials.js";
import type { AssessOptions } from "./ai.js";
import { snapshotLockfile } from "./lockfile.js";
import {
  packagesFromLockfile,
  resolveInstallPlan,
  type InstallPlan,
} from "./install-plan.js";
import type { LoadedPolicy } from "./policy.js";
import { analyzeTransitiveDeps, type TreePackage, type TransitiveResult } from "./transitive.js";
import type { CodeAuditScope, Decision, PackageManager } from "./types.js";
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
  /** True when a committed denial (.targate/denials.json) explicitly rejects this version. */
  denied?: boolean;
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
  /** Committed denials — flag rejected versions so the caller can skip re-prompting. */
  denials?: DenialsMap;
  policy?: LoadedPolicy | null;
  failOnOsvError?: boolean;
  concurrency?: number;
  /** Force isolated per-package AI calls instead of batching (--no-ai-batch). */
  noAiBatch?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  /** AI source-code audit scope for the tree (default "off"). */
  codeAudit?: CodeAuditScope;
  onResult?: (result: InstallVetResult, index: number, total: number) => void;
  /** Live progress (spinner/ETA) — see AnalyzeTransitiveOptions.onProgress. */
  onProgress?: (phase: "scan" | "assess" | "analyze", done: number, total: number) => void;
  /** Injection point for tests — defaults to the real transitive walker. */
  analyzeAll?: typeof analyzeTransitiveDeps;
  /** Pre-resolved immutable plan; avoids resolving a second tree. */
  plan?: InstallPlan;
}

/** Apply committed approval/denial context to one raw result. Pure. */
function resolveVetResult(
  r: TransitiveResult,
  approvals: ApprovalsMap,
  denials?: DenialsMap,
): InstallVetResult {
  const approval = getApproval(approvals, r.name, r.version);
  const trust = resolvePackageTrust(r.assessment, r.hardBlock === true, approval);
  const denial = denials ? getDenial(denials, r.name, r.version) : null;
  return {
    ...r,
    approved: trust.approved,
    approvalMode: trust.approved ? approval?.mode : undefined,
    scriptPolicy: trust.scriptPolicy,
    unresolved: trust.unresolved,
    // A denial only matters while the package is still unresolved — an
    // approval (or a clean verdict) always wins over a stale denial.
    denied: trust.unresolved && denial !== null,
  };
}

/** Names declared in the root manifest's dependency fields (the project's directs). */
function directDependencyNames(manifestContent: string): Set<string> {
  const names = new Set<string>();
  try {
    const manifest = JSON.parse(manifestContent) as Record<string, unknown>;
    for (const field of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ]) {
      const deps = manifest[field];
      if (deps && typeof deps === "object" && !Array.isArray(deps)) {
        for (const name of Object.keys(deps)) names.add(name);
      }
    }
  } catch {
    /* a malformed manifest just yields no direct tags */
  }
  return names;
}

/** Enumerate the tree, vet every unique package, and aggregate the verdict. */
export async function vetInstall(opts: VetInstallOptions): Promise<InstallReport> {
  const plan = opts.plan ?? await resolveInstallPlan({
    packageManager: opts.packageManager,
    cwd: opts.cwd,
    updateLockfile: false,
  });
  // Tag the project's direct dependencies so codeAudit scope "direct" can target
  // them; the lockfile tree itself does not preserve the direct/transitive line.
  const directNames = directDependencyNames(plan.manifestContent);
  const packages =
    directNames.size > 0
      ? plan.packages.map((p) => (directNames.has(p.name) ? { ...p, isDirect: true } : p))
      : plan.packages;
  const source = plan.source === "existing" ? "lockfile" : "resolved";
  const analyzeAll = opts.analyzeAll ?? analyzeTransitiveDeps;

  const raw = await analyzeAll(packages, {
    assess: opts.assess,
    failOnOsvError: opts.failOnOsvError,
    policy: opts.policy ?? undefined,
    concurrency: opts.concurrency,
    noAiBatch: opts.noAiBatch,
    noReputation: opts.noReputation,
    codeAudit: opts.codeAudit,
    cwd: opts.cwd,
    lockfileTrusted: plan.source === "existing",
    onProgress: opts.onProgress,
    onResult: (r, i, total) => {
      opts.onResult?.(resolveVetResult(r, opts.approvals, opts.denials), i, total);
    },
  });

  const results: InstallVetResult[] = raw.map((r) =>
    resolveVetResult(r, opts.approvals, opts.denials),
  );
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
