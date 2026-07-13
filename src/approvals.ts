import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { execConfigDisabled, isExecConfigFile, loadConfigFile } from "./config-loader.js";
import type { ApprovalMode } from "./trust-decision.js";
import { isApprovalApplicable } from "./trust-decision.js";
import type { Decision, RiskAssessment, RiskLevel } from "./types.js";
import { TARGATE_VERSION } from "./version.js";

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

/**
 * True in CI environments (the standard CI env var, "false" respected).
 * Approvals are a HUMAN vouching for a version — they must never be created
 * in unattended CI, only read from the reviewed, committed approvals file.
 */
export function isCiEnvironment(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.CI) && env.CI !== "false";
}

/**
 * Trust history: the auditable circumstances of an approval. Every field is
 * optional — old approvals (and hand-curated ones) simply have no context.
 * The record is written into the committed approvals.json, so git history on
 * that file IS the audit log; the context makes each entry self-describing.
 */
export interface ApprovalContext {
  /** targate version that performed the analysis. */
  targateVersion?: string;
  /** The decision the analysis reached BEFORE the human cleared it. */
  decision?: Decision;
  risk?: RiskLevel;
  /** Informational 0–100 security score at approval time. */
  score?: number;
  /** Whether the verdict came from the AI reviewer or the rules engine. */
  source?: "ai" | "rules";
  /** AI provider/model that produced the assessment (absent on rules-only runs). */
  aiProvider?: string;
  aiModel?: string;
  /** Team policy in force: file basename + sha256 of its bytes at approval time. */
  policyFile?: string;
  policyHash?: string;
  /** Top assessment reasons (capped) — why the package needed a human at all. */
  reasons?: string[];
}

/**
 * A cryptographic signature over the approval entry (SSH signature format —
 * the same keys used for git SSH commit signing). Produced by
 * `targate approve --sign`, verified against `.targate/allowed-signers`.
 */
export interface ApprovalSignature {
  /** Signature scheme — only SSH signatures are supported today. */
  format: "ssh";
  /** Identity the signature was made under (git user.email, or $USER) — the
   *  principal `ssh-keygen -Y verify` matches against allowed-signers. */
  signer: string;
  /** Armored SSH signature over the canonical approval payload. */
  signature: string;
}

export interface ApprovalRecord {
  /** "normal" (scripts allowed) or "no-scripts". */
  mode: ApprovalMode;
  approvedAt: string;
  approvedBy?: string;
  /** Trust history — circumstances of the approval (tool, verdict, policy). */
  context?: ApprovalContext;
  /** Cryptographic signature over the entry (see targate approve --sign). */
  signature?: ApprovalSignature;
}

/** Cap the reasons kept in an approval's trust-history context. */
const CONTEXT_MAX_REASONS = 5;

/**
 * Build the trust-history context for an approval from whatever the calling
 * flow has at hand. Pure; every input is optional.
 */
export function buildApprovalContext(input: {
  assessment?: RiskAssessment;
  score?: number;
  policyFile?: string;
  policyHash?: string;
  aiProvider?: string;
  aiModel?: string;
}): ApprovalContext {
  const a = input.assessment;
  return {
    targateVersion: TARGATE_VERSION,
    ...(a
      ? {
          decision: a.decision,
          risk: a.risk,
          source: a.source,
          reasons: a.reasons.slice(0, CONTEXT_MAX_REASONS),
        }
      : {}),
    ...(input.score !== undefined ? { score: input.score } : {}),
    ...(input.policyFile ? { policyFile: input.policyFile, policyHash: input.policyHash } : {}),
    ...(input.aiProvider ? { aiProvider: input.aiProvider, aiModel: input.aiModel } : {}),
  };
}

/** Keyed by "name@version" — approvals are version-specific by design. */
export type ApprovalsMap = Record<string, ApprovalRecord>;

function jsonPath(cwd: string): string {
  return path.join(cwd, APPROVALS_DIR, `${APPROVALS_BASENAME}.json`);
}

function isApprovalsMap(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Load team approvals from .targate/approvals.{ts,js,mjs,cjs,yaml,yml,json}.
 * All existing files are merged: hand-curated ts/js/yaml sources first,
 * then the tool-managed approvals.json on top.
 */
export async function loadApprovals(cwd: string = process.cwd()): Promise<ApprovalsMap> {
  const merged: ApprovalsMap = {};
  const noExec = execConfigDisabled();
  for (const name of APPROVALS_FILENAMES) {
    const file = path.join(cwd, APPROVALS_DIR, name);
    if (!existsSync(file)) continue;
    if (noExec && isExecConfigFile(file)) {
      // Skipping only loses approvals (packages ask again) — the safe direction.
      console.error(
        `[targate] ignoring .targate/${name}: executable config is disabled by default; use YAML/JSON or set TARGATE_ALLOW_EXEC_CONFIG=1.`,
      );
      continue;
    }
    try {
      const doc = await loadConfigFile(file);
      if (!isApprovalsMap(doc)) {
        console.error(`[targate] ignoring malformed ${file}: expected an approvals mapping`);
        continue;
      }
      for (const [key, record] of Object.entries(doc)) {
        if (isApprovalApplicable(record)) merged[key] = record as ApprovalRecord;
        else console.error(`[targate] ignoring invalid approval ${file}#${key}`);
      }
    } catch (err) {
      // A broken approvals source must never crash the analysis — it only
      // means the affected packages will ask for approval again.
      console.error(
        `[targate] ignoring malformed ${file}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  return merged;
}

export function getApproval(approvals: ApprovalsMap, name: string, version: string) {
  const approval = approvals[`${name}@${version}`];
  return isApprovalApplicable(approval, version) ? approval : null;
}

export interface RecordApprovalExtras {
  /** Trust history — see buildApprovalContext(). */
  context?: ApprovalContext;
  /** Sign the entry before writing (targate approve --sign). Receives the
   *  "name@version" key and the unsigned record; returns the signature. A
   *  signing failure aborts the write — a "signed" approval must never be
   *  silently recorded unsigned. */
  sign?: (key: string, record: ApprovalRecord) => Promise<ApprovalSignature>;
}

/**
 * Record a human approval. Writes are always to .targate/approvals.json — the
 * only format a tool can safely update. ts/js/yaml sources are read-only,
 * hand-curated files; loadApprovals() merges them all. Returns the record as
 * written.
 */
export async function recordApproval(
  name: string,
  version: string,
  mode: ApprovalRecord["mode"],
  cwd: string = process.cwd(),
  extras: RecordApprovalExtras = {},
): Promise<ApprovalRecord> {
  const file = jsonPath(cwd);
  let existing: ApprovalsMap = {};
  if (existsSync(file)) {
    try {
      const doc = JSON.parse(await readFile(file, "utf8"));
      if (isApprovalsMap(doc)) {
        existing = Object.fromEntries(Object.entries(doc).filter(([key, value]) => {
          const valid = isApprovalApplicable(value);
          if (!valid) console.error(`[targate] ignoring invalid approval ${file}#${key}`);
          return valid;
        })) as ApprovalsMap;
      }
    } catch {
      /* unreadable json — rewrite it */
    }
  }
  const key = `${name}@${version}`;
  const record: ApprovalRecord = {
    mode,
    approvedAt: new Date().toISOString(),
    approvedBy: process.env.USER ?? process.env.USERNAME,
    ...(extras.context ? { context: extras.context } : {}),
  };
  if (extras.sign) {
    record.signature = await extras.sign(key, record);
  }
  existing[key] = record;
  await mkdir(path.join(cwd, APPROVALS_DIR), { recursive: true });
  const sorted = Object.fromEntries(
    Object.entries(existing).sort(([a], [b]) => a.localeCompare(b)),
  );
  await writeFile(file, JSON.stringify(sorted, null, 2) + "\n");
  return record;
}
