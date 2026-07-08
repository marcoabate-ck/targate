import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { loadConfigFile } from "./config-loader.js";
import type { InstallMode } from "./installer.js";

export const APPROVALS_DIR = ".targate";
export const APPROVALS_BASENAME = "approvals";

/**
 * Readable approval sources, merged in this order (later files win on
 * conflicts). approvals.json comes last because it's the file the tool
 * writes to — a fresh interactive approval must always take effect.
 */
export const APPROVALS_FILENAMES = [
  `${APPROVALS_BASENAME}.ts`,
  `${APPROVALS_BASENAME}.js`,
  `${APPROVALS_BASENAME}.mjs`,
  `${APPROVALS_BASENAME}.cjs`,
  `${APPROVALS_BASENAME}.yaml`,
  `${APPROVALS_BASENAME}.yml`,
  `${APPROVALS_BASENAME}.json`,
] as const;

export interface ApprovalRecord {
  /** "normal" (scripts allowed) or "no-scripts". */
  mode: Extract<InstallMode, "normal" | "no-scripts">;
  approvedAt: string;
  approvedBy?: string;
}

/** Keyed by "name@version" — approvals are version-specific by design. */
export type ApprovalsMap = Record<string, ApprovalRecord>;

function jsonPath(cwd: string): string {
  return path.join(cwd, APPROVALS_DIR, `${APPROVALS_BASENAME}.json`);
}

function isApprovalsMap(value: unknown): value is ApprovalsMap {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Load team approvals from .targate/approvals.{ts,js,mjs,cjs,yaml,yml,json}.
 * All existing files are merged: hand-curated ts/js/yaml sources first,
 * then the tool-managed approvals.json on top.
 */
export async function loadApprovals(cwd: string = process.cwd()): Promise<ApprovalsMap> {
  const merged: ApprovalsMap = {};
  for (const name of APPROVALS_FILENAMES) {
    const file = path.join(cwd, APPROVALS_DIR, name);
    if (!existsSync(file)) continue;
    try {
      const doc = await loadConfigFile(file);
      if (isApprovalsMap(doc)) Object.assign(merged, doc);
    } catch {
      // A broken approvals source must never crash the analysis — it only
      // means the affected packages will ask for approval again.
    }
  }
  return merged;
}

export function getApproval(approvals: ApprovalsMap, name: string, version: string) {
  return approvals[`${name}@${version}`] ?? null;
}

/**
 * Record a human approval. Writes are always to .targate/approvals.json — the
 * only format a tool can safely update. ts/js/yaml sources are read-only,
 * hand-curated files; loadApprovals() merges them all.
 */
export async function recordApproval(
  name: string,
  version: string,
  mode: ApprovalRecord["mode"],
  cwd: string = process.cwd(),
): Promise<void> {
  const file = jsonPath(cwd);
  let existing: ApprovalsMap = {};
  if (existsSync(file)) {
    try {
      const doc = JSON.parse(await readFile(file, "utf8"));
      if (isApprovalsMap(doc)) existing = doc;
    } catch {
      /* unreadable json — rewrite it */
    }
  }
  existing[`${name}@${version}`] = {
    mode,
    approvedAt: new Date().toISOString(),
    approvedBy: process.env.USER ?? process.env.USERNAME,
  };
  await mkdir(path.join(cwd, APPROVALS_DIR), { recursive: true });
  const sorted = Object.fromEntries(
    Object.entries(existing).sort(([a], [b]) => a.localeCompare(b)),
  );
  await writeFile(file, JSON.stringify(sorted, null, 2) + "\n");
}
