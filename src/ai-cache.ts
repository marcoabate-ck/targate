import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { RiskAssessment, Signals } from "./types.js";

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

/** Shape of the `aiCache` section of bye.policy.* — all fields optional. */
export interface AiCachePolicy {
  /** Master switch. Default: true. */
  enabled?: boolean;
  /**
   * Where the cache lives:
   * - "user" (default): ~/.bye/ai-cache.json — private to the developer.
   * - "project": <repo>/.bye/ai-cache.json — shared per checkout (gitignore it).
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
}

export const DEFAULT_CACHE_SETTINGS: AiCacheSettings = {
  enabled: true,
  scope: "user",
  ttlHours: 24,
  exclude: [],
};

export function resolveCacheSettings(policy?: AiCachePolicy): AiCacheSettings {
  return {
    enabled: policy?.enabled ?? DEFAULT_CACHE_SETTINGS.enabled,
    scope: policy?.scope ?? DEFAULT_CACHE_SETTINGS.scope,
    ttlHours: policy?.ttlHours ?? DEFAULT_CACHE_SETTINGS.ttlHours,
    exclude: policy?.exclude ?? DEFAULT_CACHE_SETTINGS.exclude,
  };
}

export function cacheFilePath(settings: AiCacheSettings, cwd: string = process.cwd()): string {
  const base = settings.scope === "project" ? cwd : homedir();
  return path.join(base, ".bye", "ai-cache.json");
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

async function readCacheFile(file: string): Promise<CacheFile> {
  try {
    const doc = JSON.parse(await readFile(file, "utf8")) as CacheFile;
    if (typeof doc === "object" && doc !== null && typeof doc.entries === "object") {
      return { entries: doc.entries ?? {} };
    }
  } catch {
    /* missing or corrupt cache — treated as empty */
  }
  return { entries: {} };
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
  if (!settings.enabled || settings.exclude.includes(packageName)) return null;
  const { entries } = await readCacheFile(cacheFilePath(settings, cwd));
  const entry = entries[key];
  if (!entry || !isFresh(entry, settings.ttlHours, Date.now())) return null;
  return { assessment: entry.assessment, cachedAt: entry.cachedAt };
}

/**
 * Persist an AI assessment. Best-effort: a cache write failure must never
 * fail the analysis. Expired entries are pruned on every write.
 */
export async function writeCachedAssessment(
  key: string,
  assessment: RiskAssessment,
  settings: AiCacheSettings,
  packageName: string,
  cwd: string = process.cwd(),
): Promise<void> {
  if (!settings.enabled || settings.exclude.includes(packageName)) return;
  try {
    const file = cacheFilePath(settings, cwd);
    const doc = await readCacheFile(file);
    const now = Date.now();
    const entries: Record<string, CacheEntry> = {};
    for (const [k, entry] of Object.entries(doc.entries)) {
      if (isFresh(entry, settings.ttlHours, now)) entries[k] = entry;
    }
    entries[key] = { assessment, cachedAt: new Date(now).toISOString() };
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ entries }, null, 2) + "\n");
  } catch {
    /* best-effort */
  }
}
