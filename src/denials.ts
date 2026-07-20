import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { execConfigDisabled, isExecConfigFile, loadConfigFile } from "./config-loader.js";
import type { ApprovalContext } from "./approvals.js";
import { APPROVALS_DIR } from "./approvals.js";
import { isValidIsoTimestamp } from "./persisted-validation.js";

/**
 * Persistent, committable DENIALS — the negative counterpart of
 * .targate/approvals.json. When a human explicitly rejects a flagged package
 * version (in the interactive install triage, "deny"), we record it here so it
 * is never re-offered for approval and the intent is committed for the team.
 *
 * A denial does not, by itself, change the install gate: a require_approval /
 * block without an approval is already refused. What it buys is UX + audit —
 * the package is shown as "denied by <who>" instead of prompting again, and
 * the decision travels with the repo like an approval does.
 *
 * Approvals and denials are mutually exclusive per name@version: recording one
 * removes the other (see removeDenial / approvals.removeApproval).
 */

export const DENIALS_BASENAME = "denials";

/** Readable denial sources, merged in this order (later files win). Mirrors approvals. */
export const DENIALS_FILENAMES = [
  `${DENIALS_BASENAME}.ts`,
  `${DENIALS_BASENAME}.js`,
  `${DENIALS_BASENAME}.mjs`,
  `${DENIALS_BASENAME}.cjs`,
  `${DENIALS_BASENAME}.yaml`,
  `${DENIALS_BASENAME}.yml`,
  `${DENIALS_BASENAME}.json`,
] as const;

export interface DenialRecord {
  deniedAt: string;
  deniedBy?: string;
  /** Optional free-text note on why the version was rejected. */
  reason?: string;
  /** Trust history — the circumstances of the denial (same shape as an approval's). */
  context?: ApprovalContext;
}

/** Keyed by "name@version" — denials are version-specific, like approvals. */
export type DenialsMap = Record<string, DenialRecord>;

function jsonPath(cwd: string): string {
  return path.join(cwd, APPROVALS_DIR, `${DENIALS_BASENAME}.json`);
}

function isDenialsDoc(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Runtime boundary for persisted denials. Invalid/unknown shapes fail safe (ignored). */
export function isDenialApplicable(denial: unknown): denial is DenialRecord {
  if (typeof denial !== "object" || denial === null || Array.isArray(denial)) return false;
  const candidate = denial as Record<string, unknown>;
  return (
    isValidIsoTimestamp(candidate.deniedAt) &&
    (candidate.deniedBy === undefined || typeof candidate.deniedBy === "string") &&
    (candidate.reason === undefined || typeof candidate.reason === "string")
  );
}

/**
 * Load team denials from .targate/denials.{ts,js,mjs,cjs,yaml,yml,json}.
 * Hand-curated sources first, then the tool-managed denials.json on top.
 */
export async function loadDenials(cwd: string = process.cwd()): Promise<DenialsMap> {
  const merged: DenialsMap = {};
  const noExec = execConfigDisabled();
  for (const name of DENIALS_FILENAMES) {
    const file = path.join(cwd, APPROVALS_DIR, name);
    if (!existsSync(file)) continue;
    if (noExec && isExecConfigFile(file)) {
      // Skipping only loses denials (packages ask again) — the safe direction.
      console.error(
        `[targate] ignoring .targate/${name}: executable config is disabled by default; use YAML/JSON or set TARGATE_ALLOW_EXEC_CONFIG=1.`,
      );
      continue;
    }
    try {
      const doc = await loadConfigFile(file);
      if (!isDenialsDoc(doc)) {
        console.error(`[targate] ignoring malformed ${file}: expected a denials mapping`);
        continue;
      }
      for (const [key, record] of Object.entries(doc)) {
        if (isDenialApplicable(record)) merged[key] = record;
        else console.error(`[targate] ignoring invalid denial ${file}#${key}`);
      }
    } catch (err) {
      console.error(
        `[targate] ignoring malformed ${file}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return merged;
}

export function getDenial(denials: DenialsMap, name: string, version: string): DenialRecord | null {
  const denial = denials[`${name}@${version}`];
  return isDenialApplicable(denial) ? denial : null;
}

/** Read .targate/denials.json for a write, dropping any invalid entries. */
async function readWritableDenials(file: string): Promise<DenialsMap> {
  if (!existsSync(file)) return {};
  try {
    const doc = JSON.parse(await readFile(file, "utf8"));
    if (!isDenialsDoc(doc)) return {};
    return Object.fromEntries(
      Object.entries(doc).filter(([key, value]) => {
        const valid = isDenialApplicable(value);
        if (!valid) console.error(`[targate] ignoring invalid denial ${file}#${key}`);
        return valid;
      }),
    ) as DenialsMap;
  } catch {
    return {}; // unreadable json — rewrite it
  }
}

async function writeDenials(file: string, cwd: string, denials: DenialsMap): Promise<void> {
  await mkdir(path.join(cwd, APPROVALS_DIR), { recursive: true });
  const sorted = Object.fromEntries(
    Object.entries(denials).sort(([a], [b]) => a.localeCompare(b)),
  );
  await writeFile(file, JSON.stringify(sorted, null, 2) + "\n");
}

export interface RecordDenialExtras {
  reason?: string;
  context?: ApprovalContext;
}

/**
 * Record a human denial of an exact version. Writes are always to
 * .targate/denials.json (the only format a tool can safely update). Returns
 * the record as written.
 */
export async function recordDenial(
  name: string,
  version: string,
  cwd: string = process.cwd(),
  extras: RecordDenialExtras = {},
): Promise<DenialRecord> {
  const file = jsonPath(cwd);
  const existing = await readWritableDenials(file);
  const record: DenialRecord = {
    deniedAt: new Date().toISOString(),
    deniedBy: process.env.USER ?? process.env.USERNAME,
    ...(extras.reason ? { reason: extras.reason } : {}),
    ...(extras.context ? { context: extras.context } : {}),
  };
  existing[`${name}@${version}`] = record;
  await writeDenials(file, cwd, existing);
  return record;
}

/** Remove a denial for name@version from denials.json (if present). Returns true if one was removed. */
export async function removeDenial(
  name: string,
  version: string,
  cwd: string = process.cwd(),
): Promise<boolean> {
  const file = jsonPath(cwd);
  if (!existsSync(file)) return false;
  const existing = await readWritableDenials(file);
  const key = `${name}@${version}`;
  if (!(key in existing)) return false;
  delete existing[key];
  await writeDenials(file, cwd, existing);
  return true;
}
