import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { getApproval, type ApprovalsMap } from "./approvals.js";
import type { AssessOptions } from "./ai.js";
import { extractLockfileEntries, lockfileName, snapshotLockfile } from "./lockfile.js";
import type { LoadedPolicy } from "./policy.js";
import { analyzeTransitiveDeps, type TreePackage, type TransitiveResult } from "./transitive.js";
import { DECISION_SEVERITY, type Decision, type PackageManager } from "./types.js";

const execFileAsync = promisify(execFile);

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
  /** "lockfile": read from the committed lockfile; "resolved": npm resolved the manifest. */
  source: "lockfile" | "resolved";
}

/** Parse a lockfile's full set of packages into a sorted, de-duplicated tree. */
export function treeFromLockfile(pm: PackageManager, content: string): TreePackage[] {
  const seen = new Set<string>();
  const packages: TreePackage[] = [];
  for (const entry of extractLockfileEntries(pm, content)) {
    if (seen.has(entry)) continue;
    seen.add(entry);
    const at = entry.lastIndexOf("@");
    if (at <= 0) continue;
    packages.push({ name: entry.slice(0, at), version: entry.slice(at + 1) });
  }
  return packages.sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
}

const NPM_BIN = process.platform === "win32" ? "npm.cmd" : "npm";
const RESOLVE_TIMEOUT_MS = 180_000;

/**
 * Enumerate the full dependency tree of the project in `cwd`. Prefers the
 * committed lockfile (the source of truth for what will land on disk). With
 * no lockfile, npm resolves the manifest in a throwaway directory
 * (`--package-lock-only --ignore-scripts`: only a lockfile is produced,
 * nothing executes) so the tree still reflects real resolved versions.
 */
export async function resolveProjectTree(
  pm: PackageManager,
  cwd: string = process.cwd(),
): Promise<ProjectTree> {
  const lockContent = await snapshotLockfile(pm, cwd);
  if (lockContent) {
    return { packages: treeFromLockfile(pm, lockContent), source: "lockfile" };
  }

  const manifestPath = path.join(cwd, "package.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`No package.json found in ${cwd}`);
  }
  const manifest = await readFile(manifestPath, "utf8");

  const dir = await mkdtemp(path.join(tmpdir(), "targate-install-"));
  try {
    await writeFile(path.join(dir, "package.json"), manifest);
    try {
      await execFileAsync(
        NPM_BIN,
        ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error"],
        { cwd: dir, timeout: RESOLVE_TIMEOUT_MS },
      );
    } catch (err) {
      throw new Error(
        `targate install: npm could not resolve the dependency tree (no ${lockfileName(pm)} present): ${
          err instanceof Error ? err.message.split("\n")[0] : String(err)
        }`,
      );
    }
    const lock = await readFile(path.join(dir, "package-lock.json"), "utf8");
    return { packages: treeFromLockfile("npm", lock), source: "resolved" };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export interface InstallVetResult extends TransitiveResult {
  /** True when a require_approval/blocked package is in the committed approvals. */
  approved: boolean;
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
  let decision: Decision = "allow";
  let exitCode = 0;
  for (const r of results) {
    if (DECISION_SEVERITY[r.assessment.decision] > DECISION_SEVERITY[decision]) {
      decision = r.assessment.decision;
    }
    if (
      r.hardBlock ||
      ((r.assessment.decision === "block" || r.assessment.decision === "require_approval") &&
        !r.approved)
    ) {
      exitCode = 2;
    }
  }
  return { decision, exitCode };
}

export interface InstallReport {
  packageManager: PackageManager;
  source: "lockfile" | "resolved";
  total: number;
  results: InstallVetResult[];
  decision: Decision;
  exitCode: number;
}

export interface VetInstallOptions {
  packageManager: PackageManager;
  cwd: string;
  assess: AssessOptions;
  approvals: ApprovalsMap;
  policy?: LoadedPolicy | null;
  failOnOsvError?: boolean;
  concurrency?: number;
  onResult?: (result: InstallVetResult, index: number, total: number) => void;
  /** Injection point for tests — defaults to the real transitive walker. */
  analyzeAll?: typeof analyzeTransitiveDeps;
}

/** Enumerate the tree, vet every unique package, and aggregate the verdict. */
export async function vetInstall(opts: VetInstallOptions): Promise<InstallReport> {
  const { packages, source } = await resolveProjectTree(opts.packageManager, opts.cwd);
  const analyzeAll = opts.analyzeAll ?? analyzeTransitiveDeps;

  const raw = await analyzeAll(packages, {
    assess: opts.assess,
    failOnOsvError: opts.failOnOsvError,
    policy: opts.policy ?? undefined,
    concurrency: opts.concurrency,
    onResult: (r, i, total) => {
      const approved = getApproval(opts.approvals, r.name, r.version) !== null;
      opts.onResult?.({ ...r, approved }, i, total);
    },
  });

  const results: InstallVetResult[] = raw.map((r) => ({
    ...r,
    approved: getApproval(opts.approvals, r.name, r.version) !== null,
  }));
  const { decision, exitCode } = aggregateInstallDecision(results);

  return {
    packageManager: opts.packageManager,
    source,
    total: results.length,
    results,
    decision,
    exitCode,
  };
}
