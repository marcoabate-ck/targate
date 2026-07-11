import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { getApproval, loadApprovals } from "./approvals.js";
import { applySignedApprovalsPolicy } from "./signing.js";
import type { AssessOptions } from "./ai.js";
import { detectPackageManager } from "./installer.js";
import { lockfileVersionIndex, resolveInstalledVersion, snapshotLockfile } from "./lockfile.js";
import { analyzePackage } from "./pipeline.js";
import { loadPolicy } from "./policy.js";
import { isHardBlock } from "./rules.js";
import type { RiskAssessment } from "./types.js";

const execFileAsync = promisify(execFile);

export interface DependencyChange {
  name: string;
  /** Range as written in package.json (e.g. "^1.2.3"). */
  range: string;
  kind: "added" | "updated";
  previousRange?: string;
  section: "dependencies" | "devDependencies";
}

interface PackageJsonDeps {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/** Pure diff of the dependency sections of two package.json documents. */
export function diffDependencies(base: PackageJsonDeps, head: PackageJsonDeps): DependencyChange[] {
  const changes: DependencyChange[] = [];
  for (const section of ["dependencies", "devDependencies"] as const) {
    const before = base[section] ?? {};
    const after = head[section] ?? {};
    for (const [name, range] of Object.entries(after)) {
      if (!(name in before)) {
        changes.push({ name, range, kind: "added", section });
      } else if (before[name] !== range) {
        changes.push({ name, range, kind: "updated", previousRange: before[name], section });
      }
    }
  }
  return changes;
}

async function gitShow(ref: string, file: string, cwd: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("git", ["show", `${ref}:${file}`], { cwd });
    return stdout;
  } catch {
    return null;
  }
}

export interface CiPackageResult {
  name: string;
  version: string;
  /** How `version` was determined: exact lockfile match, declared range, etc. */
  versionSource: "lockfile" | "range" | "ambiguous-lockfile";
  change: DependencyChange;
  assessment: RiskAssessment;
  approved: boolean;
  error?: string;
}

export interface CiReport {
  baseRef: string;
  changes: DependencyChange[];
  results: CiPackageResult[];
  /** 0 = pass, 1 = analysis error, 2 = at least one blocked/unapproved package. */
  exitCode: number;
}

export interface CiOptions {
  baseRef?: string;
  cwd?: string;
  assess?: AssessOptions;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  log?: (line: string) => void;
}

/**
 * Phase-5 CI check: diff package.json against a base ref, run the full
 * pre-install analysis on every added/updated dependency, and fail the
 * build when a package is blocked — or requires an approval that is not in
 * the committed .targate/approvals.json (approval drift).
 */
export async function runCiCheck(opts: CiOptions = {}): Promise<CiReport> {
  const cwd = opts.cwd ?? process.cwd();
  const baseRef = opts.baseRef ?? "origin/main";
  const log = opts.log ?? (() => {});

  const baseRaw = await gitShow(baseRef, "package.json", cwd);
  const headRaw = existsSync(path.join(cwd, "package.json"))
    ? await readFile(path.join(cwd, "package.json"), "utf8")
    : null;
  if (!headRaw) throw new Error("No package.json found in the working tree");

  const base = baseRaw ? (JSON.parse(baseRaw) as PackageJsonDeps) : {};
  const head = JSON.parse(headRaw) as PackageJsonDeps;
  const changes = diffDependencies(base, head);

  if (!baseRaw) {
    log(`note: could not read package.json at ${baseRef} — treating all dependencies as added`);
  }

  // Resolve exact installed versions from the lockfile when one is present.
  const pm = detectPackageManager(cwd);
  const lockContent = await snapshotLockfile(pm, cwd);
  const lockIndex = lockContent ? lockfileVersionIndex(pm, lockContent) : null;
  if (!lockIndex) {
    log(`note: no ${pm} lockfile found — analyzing declared version ranges, not resolved versions`);
  }

  const policy = await loadPolicy(cwd);
  // In CI the signature requirement matters most — an attacker who can push
  // an approvals.json edit must not be able to green a poisoned dependency.
  const approvals = await applySignedApprovalsPolicy(
    await loadApprovals(cwd),
    policy?.policy.dependencyPolicy.requireSignedApprovals,
    cwd,
  );
  const results: CiPackageResult[] = [];
  let exitCode = 0;

  // The AI response cache is NEVER used in CI: strip any cache settings so a
  // CI verdict always comes from a fresh assessment, whatever the caller
  // passed in.
  const assess: AssessOptions = { ...(opts.assess ?? { useAi: false }), cache: undefined };

  for (const change of changes) {
    const resolved = resolveInstalledVersion(change.name, change.range, lockIndex);
    log(
      `analyzing ${change.name}@${resolved.version || change.range} (${change.kind}, version from ${resolved.source})`,
    );
    try {
      const { metadata, signals, assessment } = await analyzePackage(
        change.name,
        resolved.version || undefined,
        { assess, failOnOsvError: opts.failOnOsvError, policy, noReputation: opts.noReputation },
      );

      // A hard block always fails CI. A soft block or require_approval fails
      // only when it lacks a committed approval (approval drift).
      const approved = getApproval(approvals, metadata.name, metadata.version) !== null;
      const hard = isHardBlock(signals);
      if (
        hard ||
        ((assessment.decision === "block" || assessment.decision === "require_approval") && !approved)
      ) {
        exitCode = 2;
      }
      results.push({
        name: metadata.name,
        version: metadata.version,
        versionSource: resolved.source,
        change,
        assessment,
        approved,
      });
    } catch (err) {
      exitCode = exitCode === 2 ? 2 : 1;
      results.push({
        name: change.name,
        version: change.range,
        versionSource: "range",
        change,
        assessment: {
          risk: "high",
          decision: "require_approval",
          summary: "Analysis failed",
          reasons: [err instanceof Error ? err.message : String(err)],
          recommendedAction: "Investigate manually.",
          source: "rules",
        },
        approved: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { baseRef, changes, results, exitCode };
}

const WORKFLOW_TEMPLATE = `name: targate — dependency pre-install review

on:
  pull_request:
    paths:
      - "package.json"
      - "pnpm-lock.yaml"
      - "package-lock.json"
      - "yarn.lock"

jobs:
  targate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Analyze changed dependencies
        # --fail-on-osv-error: if OSV is unreachable, treat malicious-package
        # status as unknown and require approval rather than trusting silently.
        env:
          # Context values go through env, never interpolated into the run
          # line (the canonical GitHub Actions script-injection defense).
          BASE_REF: \${{ github.base_ref }}
          # Optional: set ANTHROPIC_API_KEY (or another provider key) to add
          # AI reasoning on top of the deterministic rules engine.
          # ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
        run: npx targate ci --base-ref "origin/$BASE_REF" --fail-on-osv-error
`;

/** Scaffold .github/workflows/targate.yml. Returns the path, or null if it exists. */
export async function initCiWorkflow(cwd: string = process.cwd()): Promise<string | null> {
  const file = path.join(cwd, ".github", "workflows", "targate.yml");
  if (existsSync(file)) return null;
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, WORKFLOW_TEMPLATE);
  return file;
}
