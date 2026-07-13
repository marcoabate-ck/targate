import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
import type { SecurityScore } from "./score.js";
import type { PackageMetadata, RiskAssessment, Signals } from "./types.js";
import { isRecord, isStringArray, isValidIsoTimestamp, isValidRiskAssessment, isValidSignals } from "./persisted-validation.js";

/**
 * The last analysis run, persisted so `targate explain --last` can explain it
 * without re-fetching anything. Project-scoped (`.targate/last-run.json`,
 * gitignored) — "last run" is naturally per-project.
 */

export const LAST_RUN_SCHEMA_VERSION = 1;

export interface LastRunPackage {
  metadata: PackageMetadata;
  signals: Signals;
  assessment: RiskAssessment;
  score: SecurityScore;
}

export interface LastRunFile {
  schemaVersion: number;
  command: "add" | "approve";
  timestamp: string;
  /** Array to leave room for multi-package (install/ci) records later. */
  packages: LastRunPackage[];
}

export class LastRunError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LastRunError";
  }
}

export function lastRunPath(cwd: string = process.cwd()): string {
  return path.join(cwd, ".targate", "last-run.json");
}

/**
 * Best-effort: recording the run must never fail the gate. Atomic
 * tmp-then-rename write, mirroring the AI cache.
 */
export async function writeLastRun(
  command: LastRunFile["command"],
  packages: LastRunPackage[],
  cwd?: string,
): Promise<void> {
  try {
    const file = lastRunPath(cwd);
    await mkdir(path.dirname(file), { recursive: true });
    const record: LastRunFile = {
      schemaVersion: LAST_RUN_SCHEMA_VERSION,
      command,
      timestamp: new Date().toISOString(),
      packages,
    };
    const tmp = `${file}.${randomUUID()}.tmp`;
    await writeFile(tmp, JSON.stringify(record, null, 2));
    await rename(tmp, file);
  } catch {
    /* best-effort */
  }
}

/** Throws LastRunError with an actionable message when unusable. */
export async function readLastRun(cwd?: string): Promise<LastRunFile> {
  const file = lastRunPath(cwd);
  let raw: string;
  try {
    raw = await readFile(file, "utf8");
  } catch {
    throw new LastRunError(
      `no recorded run found — run \`targate add <pkg>\` or \`targate approve <pkg>\` first (${file})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new LastRunError(
      `${file} is corrupt — re-run the analysis (\`targate explain <pkg>\` analyzes fresh)`,
    );
  }
  const record = parsed as LastRunFile;
  if (
    !isRecord(record) ||
    record?.schemaVersion !== LAST_RUN_SCHEMA_VERSION ||
    (record.command !== "add" && record.command !== "approve") ||
    !isValidIsoTimestamp(record.timestamp) ||
    !Array.isArray(record.packages) ||
    record.packages.length === 0 ||
    record.packages.some((pkg) => !isValidLastRunPackage(pkg))
  ) {
    throw new LastRunError(
      `${file} was written by a different targate version — re-run the analysis (\`targate explain <pkg>\` analyzes fresh)`,
    );
  }
  return record;
}

function isValidLastRunPackage(value: unknown): value is LastRunPackage {
  if (!isRecord(value) || !isRecord(value.metadata) || !isRecord(value.score)) return false;
  const metadata = value.metadata;
  const score = value.score;
  return (
    typeof metadata.name === "string" &&
    typeof metadata.version === "string" &&
    isStringArray(metadata.maintainers) &&
    typeof metadata.tarballUrl === "string" &&
    isRecord(metadata.scripts) && Object.values(metadata.scripts).every((v) => typeof v === "string") &&
    typeof metadata.dependencyCount === "number" &&
    isStringArray(metadata.directDependencies) &&
    isRecord(metadata.registryReputation) &&
    typeof metadata.registryReputation.hasProvenance === "boolean" &&
    isValidSignals(value.signals) &&
    isValidRiskAssessment(value.assessment) &&
    typeof score.total === "number" &&
    Array.isArray(score.categories) &&
    score.categories.every(
      (category) => isRecord(category) && typeof category.name === "string" &&
        typeof category.label === "string" && typeof category.score === "number" &&
        typeof category.max === "number" &&
        (category.notes === undefined || isStringArray(category.notes)),
    ) &&
    (score.floorReason === undefined || typeof score.floorReason === "string")
  );
}
