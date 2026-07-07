import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { extractLockfileEntries } from "./lockfile.js";
import { analyzePackage, type AnalyzePackageOptions } from "./pipeline.js";
import type { Decision, RiskAssessment } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * Transitive dependency analysis (`bye add --deep`).
 *
 * The tree is resolved by npm itself with `--package-lock-only`: only a
 * lockfile is produced — no node_modules, no tarball unpacking by npm, and
 * `--ignore-scripts` on top, so nothing from the tree executes. This gives
 * the EXACT versions a real install would place on disk (same resolver),
 * instead of a homegrown approximation of semver range resolution. Each
 * unique name@version then goes through the same per-package pipeline as
 * the root — where the AI response cache makes shared/repeated dependencies
 * cheap.
 */

export interface TreePackage {
  name: string;
  version: string;
}

/** Pure part of the resolution: lockfile content -> unique packages, root excluded. */
export function parseResolvedTree(
  lockContent: string,
  rootName: string,
  rootVersion: string,
): TreePackage[] {
  const packages: TreePackage[] = [];
  for (const entry of extractLockfileEntries("npm", lockContent)) {
    const at = entry.lastIndexOf("@");
    if (at <= 0) continue;
    const name = entry.slice(0, at);
    const version = entry.slice(at + 1);
    if (name === rootName && version === rootVersion) continue; // root is analyzed separately
    packages.push({ name, version });
  }
  return packages.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

const NPM_BIN = process.platform === "win32" ? "npm.cmd" : "npm";
const RESOLVE_TIMEOUT_MS = 120_000;

/**
 * Resolve the full dependency tree of name@version in a throwaway project.
 * Throws with a clear message when resolution fails — a --deep run must
 * never silently degrade to top-level-only coverage.
 */
export async function resolveTransitiveTree(
  name: string,
  version: string,
): Promise<TreePackage[]> {
  const dir = await mkdtemp(path.join(tmpdir(), "bye-deep-"));
  try {
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "bye-deep-resolution", version: "0.0.0", private: true }),
    );
    try {
      await execFileAsync(
        NPM_BIN,
        [
          "install",
          `${name}@${version}`,
          "--package-lock-only", // lockfile only: no node_modules is written
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          "--loglevel=error",
        ],
        { cwd: dir, timeout: RESOLVE_TIMEOUT_MS },
      );
    } catch (err) {
      throw new Error(
        `--deep: npm could not resolve the dependency tree of ${name}@${version}: ${
          err instanceof Error ? err.message.split("\n")[0] : String(err)
        }`,
      );
    }
    const lock = await readFile(path.join(dir, "package-lock.json"), "utf8");
    return parseResolvedTree(lock, name, version);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export interface TransitiveResult {
  name: string;
  version: string;
  assessment: RiskAssessment;
  error?: string;
}

/** Small concurrency pool — the tree can be large, the registry should not be hammered. */
async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

export interface AnalyzeTransitiveOptions extends AnalyzePackageOptions {
  concurrency?: number;
  onResult?: (result: TransitiveResult, index: number, total: number) => void;
  /** Injection point for tests — defaults to the real pipeline. */
  analyze?: typeof analyzePackage;
}

/**
 * Run the per-package pipeline over every package of the resolved tree.
 * A package whose analysis fails (registry error, missing tarball) is
 * reported as require_approval — unknown is not clean.
 */
export async function analyzeTransitiveDeps(
  packages: TreePackage[],
  opts: AnalyzeTransitiveOptions,
): Promise<TransitiveResult[]> {
  const analyze = opts.analyze ?? analyzePackage;
  let done = 0;
  return mapLimit(packages, opts.concurrency ?? 4, async (pkg) => {
    let result: TransitiveResult;
    try {
      const analysis = await analyze(pkg.name, pkg.version, {
        assess: opts.assess,
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
      });
      result = { name: pkg.name, version: pkg.version, assessment: analysis.assessment };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result = {
        name: pkg.name,
        version: pkg.version,
        error: message,
        assessment: {
          risk: "high",
          decision: "require_approval",
          summary: `Analysis of transitive dependency ${pkg.name}@${pkg.version} failed`,
          reasons: [message],
          recommendedAction: "Investigate manually.",
          source: "rules",
        },
      };
    }
    opts.onResult?.(result, done++, packages.length);
    return result;
  });
}

const DECISION_ORDER: Record<Decision, number> = {
  allow: 0,
  allow_with_warnings: 1,
  require_approval: 2,
  block: 3,
};

const MAX_LISTED_FINDINGS = 10;

/**
 * Fold the transitive results into the root assessment: the final decision
 * is the STRICTEST across the whole tree (a malicious transitive dependency
 * blocks the install exactly like a malicious root). Escalations only —
 * a clean tree never softens the root's own verdict.
 */
export function aggregateWithTransitive(
  root: RiskAssessment,
  results: TransitiveResult[],
): RiskAssessment {
  const flagged = results
    .filter((r) => r.assessment.decision !== "allow")
    .sort((a, b) => DECISION_ORDER[b.assessment.decision] - DECISION_ORDER[a.assessment.decision]);

  if (flagged.length === 0) {
    return {
      ...root,
      reasons: [
        ...root.reasons,
        `[deep] all ${results.length} transitive dependencies analyzed — none flagged.`,
      ],
    };
  }

  const worst = flagged[0].assessment.decision;
  const escalate = DECISION_ORDER[worst] > DECISION_ORDER[root.decision];

  const reasons = [
    ...root.reasons,
    ...flagged.slice(0, MAX_LISTED_FINDINGS).map(
      (r) =>
        `[deep] ${r.name}@${r.version}: ${r.assessment.decision} — ${r.assessment.reasons[0] ?? r.assessment.summary}`,
    ),
  ];
  if (flagged.length > MAX_LISTED_FINDINGS) {
    // Never truncate silently — say exactly how much is not shown.
    reasons.push(
      `[deep] … and ${flagged.length - MAX_LISTED_FINDINGS} more flagged transitive dependencies (use --json for the full list).`,
    );
  }

  if (!escalate) return { ...root, reasons };
  return {
    ...root,
    decision: worst,
    risk: worst === "block" ? "high" : root.risk === "low" ? "medium" : root.risk,
    reasons: [
      `Escalated by --deep: transitive dependency tree contains a ${worst} verdict.`,
      ...reasons,
    ],
  };
}
