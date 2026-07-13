import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { RiskAssessment, Signals } from "./types.js";
import { isRecord, isValidIsoTimestamp, isValidRiskAssessment } from "./persisted-validation.js";

/**
 * Cache for AI risk assessments — repeated reviews of the same package
 * (re-runs, transitive trees sharing dependencies) reuse the model's answer
 * instead of paying for a new completion.
 *
 * The key is the FULL evaluation context, not just the package:
 *   provider / model / reasoning flag / name@version / hash of the signals.
 * The same lib checked with a different provider or model never reuses the
 * first provider's answer, and any change in the deterministic signals
 * (new OSV record, different tarball findings) is a cache miss by
 * construction — a stale "allow" cannot survive new evidence.
 *
 * Only successful AI responses are cached: rules-engine fallbacks are free
 * to recompute, and errors must never be remembered. CI runs never use the
 * cache (runCiCheck simply never passes settings in).
 */

/** Shape of the `aiCache` section of targate.policy.* — all fields optional. */
export interface AiCachePolicy {
  /** Master switch. Default: true. */
  enabled?: boolean;
  /**
   * Where the cache lives:
   * - "user" (default): ~/.targate/ai-cache.json — private to the developer.
   * - "project": <repo>/.targate/ai-cache.json — shared per checkout (gitignore it).
   */
  scope?: "user" | "project";
  /** Entries older than this are ignored and pruned. Default: 24. */
  ttlHours?: number;
  /** Package names that must never be served from (or written to) the cache. */
  exclude?: string[];
}

/** Fully-resolved settings (policy + defaults). */
export interface AiCacheSettings {
  enabled: boolean;
  scope: "user" | "project";
  ttlHours: number;
  exclude: string[];
  /**
   * When true (the `--no-cache` flag), ignore existing cache entries for this
   * run — every package is reassessed. Fresh results are still written, so the
   * cache stays warm for the next run.
   */
  refresh: boolean;
}

export const DEFAULT_CACHE_SETTINGS: AiCacheSettings = {
  enabled: true,
  scope: "user",
  ttlHours: 24,
  exclude: [],
  refresh: false,
};

export function resolveCacheSettings(
  policy?: AiCachePolicy,
  overrides?: { refresh?: boolean },
): AiCacheSettings {
  return {
    enabled: policy?.enabled ?? DEFAULT_CACHE_SETTINGS.enabled,
    scope: policy?.scope ?? DEFAULT_CACHE_SETTINGS.scope,
    ttlHours: policy?.ttlHours ?? DEFAULT_CACHE_SETTINGS.ttlHours,
    exclude: policy?.exclude ?? DEFAULT_CACHE_SETTINGS.exclude,
    refresh: overrides?.refresh ?? DEFAULT_CACHE_SETTINGS.refresh,
  };
}

export function cacheFilePath(settings: AiCacheSettings, cwd: string = process.cwd()): string {
  const base = settings.scope === "project" ? cwd : homedir();
  return path.join(base, ".targate", "ai-cache.json");
}

export interface CacheKeyInput {
  provider: string;
  model: string;
  reasoning: boolean;
  signals: Signals;
}

/**
 * Deterministic cache key. The readable prefix makes the cache file
 * inspectable; the signals hash makes any change in deterministic evidence
 * a miss.
 */
export function cacheKey(input: CacheKeyInput): string {
  const signalsHash = createHash("sha256")
    .update(JSON.stringify(input.signals))
    .digest("hex")
    .slice(0, 16);
  const reasoning = input.reasoning ? "reasoning" : "no-reasoning";
  return `${input.provider}/${input.model}/${reasoning}/${input.signals.package}@${input.signals.version}/${signalsHash}`;
}

interface CacheEntry {
  assessment: RiskAssessment;
  cachedAt: string;
}

interface CacheFile {
  entries: Record<string, CacheEntry>;
}

function isFresh(entry: CacheEntry, ttlHours: number, now: number): boolean {
  const age = now - new Date(entry.cachedAt).getTime();
  return Number.isFinite(age) && age >= 0 && age <= ttlHours * 3_600_000;
}

async function readCacheFile(
  file: string,
  warn: (message: string) => void = (message) => console.error(message),
): Promise<CacheFile> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    if (existsSync(file)) {
      warn(`[targate] ignoring malformed ${file}: ${err instanceof Error ? err.message : String(err)}`);
    }
    return { entries: {} };
  }
  if (!isRecord(parsed) || !isRecord(parsed.entries)) {
    warn(`[targate] ignoring malformed ${file}: expected an entries mapping`);
    return { entries: {} };
  }
  const entries: Record<string, CacheEntry> = {};
  for (const [key, value] of Object.entries(parsed.entries)) {
    if (
      !isRecord(value) ||
      !isValidIsoTimestamp(value.cachedAt) ||
      !isValidRiskAssessment(value.assessment)
    ) {
      warn(`[targate] ignoring invalid AI cache entry ${file}#${key}`);
      continue;
    }
    entries[key] = value as unknown as CacheEntry;
  }
  return { entries };
}

export interface CachedAssessment {
  assessment: RiskAssessment;
  cachedAt: string;
}

/** Fresh cached assessment for the key, or null (miss, expired, excluded, disabled). */
export async function readCachedAssessment(
  key: string,
  settings: AiCacheSettings,
  packageName: string,
  cwd: string = process.cwd(),
): Promise<CachedAssessment | null> {
  // `refresh` (--no-cache) forces a miss so the package is reassessed; the
  // fresh result is still written by writeCachedAssessment.
  if (!settings.enabled || settings.refresh || settings.exclude.includes(packageName)) return null;
  const { entries } = await readCacheFile(cacheFilePath(settings, cwd));
  const entry = entries[key];
  if (!entry || !isFresh(entry, settings.ttlHours, Date.now())) return null;
  return { assessment: entry.assessment, cachedAt: entry.cachedAt };
}

/**
 * Serialize writes per cache file. The `--deep` walker analyzes packages
 * concurrently, so several assessWithCache calls can finish at once; without
 * this, their read-modify-write races and all but one entry is lost (which
 * would silently re-cost tokens on the next run — the opposite of the point).
 * All writes in a run share one process, so an in-process promise chain per
 * file is sufficient.
 */
const writeQueues = new Map<string, Promise<void>>();

function enqueueWrite(file: string, task: () => Promise<void>): Promise<void> {
  const prev = writeQueues.get(file) ?? Promise.resolve();
  const next = prev.then(task, task); // run regardless of a prior write's outcome
  writeQueues.set(
    file,
    next.finally(() => {
      if (writeQueues.get(file) === next) writeQueues.delete(file);
    }),
  );
  return next;
}

/**
 * Persist an AI assessment. Best-effort: a cache write failure must never
 * fail the analysis. Expired entries are pruned on every write. Writes to the
 * same file are serialized (see enqueueWrite) and land via an atomic rename
 * so a concurrent reader never observes a half-written file.
 */
export async function writeCachedAssessment(
  key: string,
  assessment: RiskAssessment,
  settings: AiCacheSettings,
  packageName: string,
  cwd: string = process.cwd(),
): Promise<void> {
  if (!settings.enabled || settings.exclude.includes(packageName)) return;
  const file = cacheFilePath(settings, cwd);
  return enqueueWrite(file, async () => {
    try {
      const doc = await readCacheFile(file);
      const now = Date.now();
      const entries: Record<string, CacheEntry> = {};
      for (const [k, entry] of Object.entries(doc.entries)) {
        if (isFresh(entry, settings.ttlHours, now)) entries[k] = entry;
      }
      entries[key] = { assessment, cachedAt: new Date(now).toISOString() };
      await mkdir(path.dirname(file), { recursive: true });
      const tmp = `${file}.${randomUUID()}.tmp`;
      await writeFile(tmp, JSON.stringify({ entries }, null, 2) + "\n");
      await rename(tmp, file); // atomic replace — readers see old or new, never partial
    } catch {
      /* best-effort */
    }
  });
}

/** Delete the cache file for the given scope. Reports the path and whether it existed. */
export async function clearCache(
  settings: AiCacheSettings,
  cwd: string = process.cwd(),
): Promise<{ path: string; existed: boolean }> {
  const file = cacheFilePath(settings, cwd);
  const existed = existsSync(file);
  if (existed) await rm(file, { force: true });
  return { path: file, existed };
}

export interface CacheStats {
  path: string;
  exists: boolean;
  /** Total entries on disk. */
  total: number;
  /** Entries still within the TTL (the rest would be pruned on the next write). */
  fresh: number;
}

/** Inspect the cache file for the given scope (path, entry counts). */
export async function cacheStats(
  settings: AiCacheSettings,
  cwd: string = process.cwd(),
): Promise<CacheStats> {
  const file = cacheFilePath(settings, cwd);
  if (!existsSync(file)) return { path: file, exists: false, total: 0, fresh: 0 };
  const { entries } = await readCacheFile(file);
  const now = Date.now();
  const all = Object.values(entries);
  return {
    path: file,
    exists: true,
    total: all.length,
    fresh: all.filter((e) => isFresh(e, settings.ttlHours, now)).length,
  };
}
