import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { buildSignals } from "./analyze/index.js";
import { getApproval, loadApprovals } from "./approvals.js";
import { assessRisk, type AssessOptions } from "./ai.js";
import { queryOsv, type OsvResult } from "./osv.js";
import { applyPolicy, loadPolicy } from "./policy.js";
import { quarantineTarball } from "./quarantine.js";
import { fetchPackageMetadata } from "./registry.js";
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

/** "^1.2.3" / "~1.2.3" / "1.2.3" -> "1.2.3"; anything else -> undefined (analyze latest). */
export function rangeToVersion(range: string): string | undefined {
  const match = range.match(/^[\^~]?(\d+\.\d+\.\d+(?:-[\w.]+)?)$/);
  return match?.[1];
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
  log?: (line: string) => void;
}

/**
 * Phase-5 CI check: diff package.json against a base ref, run the full
 * pre-install analysis on every added/updated dependency, and fail the
 * build when a package is blocked — or requires an approval that is not in
 * the committed .bye/approvals.json (approval drift).
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

  const approvals = await loadApprovals(cwd);
  const policy = await loadPolicy(cwd);
  const results: CiPackageResult[] = [];
  let exitCode = 0;

  for (const change of changes) {
    log(`analyzing ${change.name}@${change.range} (${change.kind})`);
    try {
      const metadata = await fetchPackageMetadata(change.name, rangeToVersion(change.range));
      const quarantine = await quarantineTarball(metadata.tarballUrl);
      try {
        let osv: OsvResult;
        try {
          osv = await queryOsv(metadata.name, metadata.version);
        } catch {
          osv = { knownMalicious: false, maliciousRecords: [], advisories: [] };
        }
        const signals = await buildSignals(metadata, quarantine.packageDir, osv);
        let assessment = await assessRisk(signals, opts.assess ?? { useAi: false });
        if (policy) assessment = applyPolicy(assessment, signals, policy.policy);

        const approved = getApproval(approvals, metadata.name, metadata.version) !== null;
        if (
          assessment.decision === "block" ||
          (assessment.decision === "require_approval" && !approved)
        ) {
          exitCode = 2;
        }
        results.push({
          name: metadata.name,
          version: metadata.version,
          change,
          assessment,
          approved,
        });
      } finally {
        await quarantine.cleanup();
      }
    } catch (err) {
      exitCode = exitCode === 2 ? 2 : 1;
      results.push({
        name: change.name,
        version: change.range,
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

const WORKFLOW_TEMPLATE = `name: bye — dependency pre-install review

on:
  pull_request:
    paths:
      - "package.json"
      - "pnpm-lock.yaml"
      - "package-lock.json"
      - "yarn.lock"

jobs:
  bye:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Analyze changed dependencies
        run: npx bye ci --base-ref "origin/\${{ github.base_ref }}"
        # Optional: set ANTHROPIC_API_KEY (or another provider key) to add
        # AI reasoning on top of the deterministic rules engine.
        # env:
        #   ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
`;

/** Scaffold .github/workflows/bye.yml. Returns the path, or null if it exists. */
export async function initCiWorkflow(cwd: string = process.cwd()): Promise<string | null> {
  const file = path.join(cwd, ".github", "workflows", "bye.yml");
  if (existsSync(file)) return null;
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, WORKFLOW_TEMPLATE);
  return file;
}
