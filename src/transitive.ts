import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { assessManyWithCache, resolveBatchProvider, type AssessOptions } from "./ai.js";
import { DEFAULT_CONCURRENCY, mapLimit } from "./concurrency.js";
import { extractLockfileEntries } from "./lockfile.js";
import { queryOsvBatch, type OsvResult } from "./osv.js";
import {
  analyzePackage,
  buildPackageSignals,
  finalizeAssessment,
  type AnalyzePackageOptions,
} from "./pipeline.js";
import type { AiProvider } from "./providers/types.js";
import { isHardBlock } from "./rules.js";
import { DECISION_SEVERITY, type RiskAssessment, type Signals } from "./types.js";

const execFileAsync = promisify(execFile);

/** Packages assessed per AI request in the batched path. */
const DEFAULT_BATCH_SIZE = 8;

/**
 * Transitive dependency analysis (`targate add --deep`).
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
  const dir = await mkdtemp(path.join(tmpdir(), "targate-deep-"));
  try {
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "targate-deep-resolution", version: "0.0.0", private: true }),
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
  /** True when the block is a HARD block (never overridable by an approval). */
  hardBlock?: boolean;
  error?: string;
}

export interface AnalyzeTransitiveOptions extends AnalyzePackageOptions {
  concurrency?: number;
  /** Force isolated per-package AI calls instead of batching (--no-ai-batch). */
  noAiBatch?: boolean;
  onResult?: (result: TransitiveResult, index: number, total: number) => void;
  /**
   * Live progress: the batched path reports "scan" (download+signals) then
   * "assess" (AI); the per-package path reports "analyze". Drives the
   * spinner/ETA line in the CLI.
   */
  onProgress?: (phase: "scan" | "assess" | "analyze", done: number, total: number) => void;
  /** Injection point for tests — the per-package pipeline (non-batch path). */
  analyze?: typeof analyzePackage;
  /** Injection points for tests of the batched path. */
  buildSignals?: typeof buildPackageSignals;
  assessMany?: typeof assessManyWithCache;
  resolveProvider?: (opts: AssessOptions) => AiProvider | null;
  /** Injection point for tests — the whole-tree OSV lookup. */
  osvBatch?: typeof queryOsvBatch;
}

/** A package whose analysis failed — reported as require_approval (unknown is not clean). */
function errorResult(pkg: TreePackage, message: string): TransitiveResult {
  return {
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

/**
 * Run the analysis pipeline over every package of the resolved tree. OSV is
 * queried for the whole tree in one batched request up front; when an AI
 * provider is configured (and --no-ai-batch is not set) the assessment is
 * batched several packages per prompt. Otherwise each package goes through the
 * per-package pipeline. Either way the deterministic hard-block floor is
 * enforced per package.
 */
export async function analyzeTransitiveDeps(
  packages: TreePackage[],
  opts: AnalyzeTransitiveOptions,
): Promise<TransitiveResult[]> {
  const concurrency = opts.concurrency ?? DEFAULT_CONCURRENCY;

  // One OSV round-trip for the whole tree. On failure, an empty map means each
  // package falls back to its own queryOsv inside the pipeline (today's behavior).
  let osvMap = new Map<string, OsvResult>();
  try {
    osvMap = await (opts.osvBatch ?? queryOsvBatch)(packages);
  } catch {
    /* per-package fallback */
  }
  const osvFor = (pkg: TreePackage) => osvMap.get(`${pkg.name}@${pkg.version}`);

  const provider = opts.noAiBatch
    ? null
    : (opts.resolveProvider ?? resolveBatchProvider)(opts.assess);

  if (provider) {
    return analyzeTreeBatched(provider, packages, osvFor, concurrency, opts);
  }

  // Non-batch path: per-package pipeline (still gets batched OSV + concurrency).
  const analyze = opts.analyze ?? analyzePackage;
  let done = 0;
  return mapLimit(packages, concurrency, async (pkg) => {
    let result: TransitiveResult;
    try {
      const analysis = await analyze(pkg.name, pkg.version, {
        assess: opts.assess,
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
        osv: osvFor(pkg),
      });
      result = {
        name: pkg.name,
        version: pkg.version,
        assessment: analysis.assessment,
        hardBlock: isHardBlock(analysis.signals),
      };
    } catch (err) {
      result = errorResult(pkg, err instanceof Error ? err.message : String(err));
    }
    opts.onResult?.(result, done++, packages.length);
    opts.onProgress?.("analyze", done, packages.length);
    return result;
  });
}

/**
 * Batched path: build every package's signals concurrently, assess the built
 * ones in batches (fewer AI round-trips + one shared prompt), then finalize
 * (OSV-failure + team policy) and clamp each package on its own signals.
 */
async function analyzeTreeBatched(
  provider: AiProvider,
  packages: TreePackage[],
  osvFor: (pkg: TreePackage) => OsvResult | undefined,
  concurrency: number,
  opts: AnalyzeTransitiveOptions,
): Promise<TransitiveResult[]> {
  const buildSignals = opts.buildSignals ?? buildPackageSignals;
  const assessMany = opts.assessMany ?? assessManyWithCache;

  // Phase A — signals for every package (the network I/O), concurrently.
  type Built =
    | { pkg: TreePackage; signals: Signals; ok: true }
    | { pkg: TreePackage; error: string; ok: false };
  let scanned = 0;
  const built = await mapLimit(packages, concurrency, async (pkg): Promise<Built> => {
    let result: Built;
    try {
      const { signals } = await buildSignals(pkg.name, pkg.version, {
        failOnOsvError: opts.failOnOsvError,
        osv: osvFor(pkg),
      });
      result = { pkg, signals, ok: true };
    } catch (err) {
      result = { pkg, error: err instanceof Error ? err.message : String(err), ok: false };
    }
    opts.onProgress?.("scan", ++scanned, packages.length);
    return result;
  });

  // Phase B — batched AI assessment over the successfully-built packages.
  const okItems = built.filter((b): b is Extract<Built, { ok: true }> => b.ok);
  const rawAssessments = okItems.length
    ? await assessMany(
        provider,
        okItems.map((b) => b.signals),
        opts.assess,
        DEFAULT_BATCH_SIZE,
        concurrency,
        (done, total) => opts.onProgress?.("assess", done, total),
      )
    : [];

  // Phase C — finalize each (OSV-failure + team policy) and assemble in order.
  const finalByKey = new Map<string, TransitiveResult>();
  await Promise.all(
    okItems.map(async (b, i) => {
      const assessment = await finalizeAssessment(b.signals, rawAssessments[i], {
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
      });
      finalByKey.set(`${b.pkg.name}@${b.pkg.version}`, {
        name: b.pkg.name,
        version: b.pkg.version,
        assessment,
        hardBlock: isHardBlock(b.signals),
      });
    }),
  );

  const results = packages.map((pkg, i) => {
    const failed = built[i];
    const result =
      finalByKey.get(`${pkg.name}@${pkg.version}`) ??
      errorResult(pkg, !failed.ok ? failed.error : "assessment missing");
    return result;
  });
  results.forEach((r, i) => opts.onResult?.(r, i, packages.length));
  return results;
}

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
    .sort(
      (a, b) => DECISION_SEVERITY[b.assessment.decision] - DECISION_SEVERITY[a.assessment.decision],
    );

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
  const escalate = DECISION_SEVERITY[worst] > DECISION_SEVERITY[root.decision];

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
