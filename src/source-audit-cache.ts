import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  cacheFileFor,
  enqueueWrite,
  type AiCacheSettings,
} from "./ai-cache.js";
import { isRecord, isValidIsoTimestamp } from "./persisted-validation.js";
import type { SourceAuditFinding, SourceAuditSeverity } from "./types.js";

/**
 * Cache for AI source-code audit findings (the opt-in `--audit-code` pass).
 * Kept SEPARATE from the signal-assessment cache: it is keyed by the artifact's
 * CONTENT DIGEST, not name@version, so the exact same bytes — even republished
 * or shared across a transitive tree — are audited by the model only once.
 *
 * Reuses the ai-cache scope/atomic-write/serialized-write machinery. The key
 * carries provider/model/digest plus a prompt version and a selection version,
 * so changing the audit prompt or which files we send invalidates cleanly. A
 * fixed digest never changes, so the TTL only guards long-term drift.
 */

const SOURCE_AUDIT_CACHE_BASENAME = "source-audit-cache.json";
/** Long by design: the digest pins the bytes; nothing about them changes. */
export const SOURCE_AUDIT_TTL_HOURS = 24 * 30;

export interface SourceAuditCacheKeyInput {
  provider: string;
  model: string;
  /** Canonical artifact digest (signals.artifact.digest). */
  digest: string;
  promptVersion: string;
  selectionVersion: string;
}

export function sourceAuditCacheKey(input: SourceAuditCacheKeyInput): string {
  // Digest already binds the bytes; hash the whole tuple for a compact,
  // filesystem-safe key while keeping a readable prefix.
  const hash = createHash("sha256")
    .update(
      `${input.provider}\0${input.model}\0${input.digest}\0${input.promptVersion}\0${input.selectionVersion}`,
    )
    .digest("hex")
    .slice(0, 32);
  return `code-audit/${input.provider}/${input.model}/${hash}`;
}

interface CacheEntry {
  findings: SourceAuditFinding[];
  cachedAt: string;
}

const SEVERITIES: SourceAuditSeverity[] = ["info", "low", "medium", "high"];

function isValidFinding(value: unknown): value is SourceAuditFinding {
  if (!isRecord(value)) return false;
  return (
    SEVERITIES.includes(value.severity as SourceAuditSeverity) &&
    typeof value.file === "string" &&
    typeof value.summary === "string" &&
    (value.line === undefined || typeof value.line === "number")
  );
}

function isValidEntry(value: unknown): value is CacheEntry {
  return (
    isRecord(value) &&
    isValidIsoTimestamp(value.cachedAt) &&
    Array.isArray(value.findings) &&
    value.findings.every(isValidFinding)
  );
}

function isFresh(entry: CacheEntry, ttlHours: number, now: number): boolean {
  const age = now - new Date(entry.cachedAt).getTime();
  return Number.isFinite(age) && age >= 0 && age <= ttlHours * 3_600_000;
}

async function readCacheFile(file: string): Promise<Record<string, CacheEntry>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    if (existsSync(file)) {
      console.error(
        `[targate] ignoring malformed ${file}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    return {};
  }
  if (!isRecord(parsed) || !isRecord(parsed.entries)) return {};
  const entries: Record<string, CacheEntry> = {};
  for (const [key, value] of Object.entries(parsed.entries)) {
    if (isValidEntry(value)) entries[key] = value;
    else console.error(`[targate] ignoring invalid source-audit cache entry ${file}#${key}`);
  }
  return entries;
}

/** Fresh cached findings for the key, or null (miss/expired/excluded/disabled/refresh). */
export async function readCachedSourceAudit(
  key: string,
  settings: AiCacheSettings,
  packageName: string,
  cwd: string = process.cwd(),
): Promise<SourceAuditFinding[] | null> {
  if (!settings.enabled || settings.refresh || settings.exclude.includes(packageName)) return null;
  const entries = await readCacheFile(cacheFileFor(settings, SOURCE_AUDIT_CACHE_BASENAME, cwd));
  const entry = entries[key];
  if (!entry || !isFresh(entry, SOURCE_AUDIT_TTL_HOURS, Date.now())) return null;
  return entry.findings;
}

/**
 * Persist audit findings. Best-effort (a write failure never fails the audit),
 * expired entries pruned on write, serialized per-file, atomic rename.
 */
export async function writeCachedSourceAudit(
  key: string,
  findings: SourceAuditFinding[],
  settings: AiCacheSettings,
  packageName: string,
  cwd: string = process.cwd(),
): Promise<void> {
  if (!settings.enabled || settings.exclude.includes(packageName)) return;
  const file = cacheFileFor(settings, SOURCE_AUDIT_CACHE_BASENAME, cwd);
  return enqueueWrite(file, async () => {
    try {
      const existing = await readCacheFile(file);
      const now = Date.now();
      const entries: Record<string, CacheEntry> = {};
      for (const [k, entry] of Object.entries(existing)) {
        if (isFresh(entry, SOURCE_AUDIT_TTL_HOURS, now)) entries[k] = entry;
      }
      entries[key] = { findings, cachedAt: new Date(now).toISOString() };
      await mkdir(path.dirname(file), { recursive: true });
      const tmp = `${file}.${randomUUID()}.tmp`;
      await writeFile(tmp, JSON.stringify({ entries }, null, 2) + "\n");
      await rename(tmp, file);
    } catch {
      /* best-effort */
    }
  });
}
