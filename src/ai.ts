import {
  cacheKey,
  type CachedAssessment,
  readCachedAssessment,
  readCachedAssessments,
  writeCachedAssessment,
  writeCachedAssessments,
  type AssessmentCacheWrite,
  type AiCacheSettings,
} from "./ai-cache.js";
import { DEFAULT_CONCURRENCY, mapLimit } from "./concurrency.js";
import { resolveProvider, type ProviderSelection } from "./providers/index.js";
import type { AiProvider, SourceAuditInput } from "./providers/types.js";
import { batchAssessmentId, SOURCE_AUDIT_PROMPT_VERSION } from "./providers/prompt.js";
import { SOURCE_SELECTION_VERSION } from "./analyze/source-select.js";
import {
  readCachedSourceAudit,
  sourceAuditCacheKey,
  writeCachedSourceAudit,
} from "./source-audit-cache.js";
import { clampDecision, evaluateRules } from "./rules.js";
import type { RiskAssessment, Signals, SourceAuditFinding } from "./types.js";

export interface AssessOptions extends ProviderSelection {
  /** When false, skip AI entirely and use the deterministic rules engine. */
  useAi: boolean;
  /**
   * AI response cache settings. Omit to disable caching entirely — CI runs
   * never pass this, so they always get a fresh assessment.
   */
  cache?: AiCacheSettings;
  /** Project root, used for the project-scoped cache file. */
  cwd?: string;
}

/**
 * Call the provider, going through the AI-response cache when settings are
 * provided. Only the raw, validated model output is cached — clamping runs
 * on every path (cached answers included) so the deterministic floor is
 * enforced at decision time, never trusted from disk.
 */
export async function assessWithCache(
  provider: AiProvider,
  signals: Signals,
  opts: Pick<AssessOptions, "cache" | "cwd" | "reasoning">,
): Promise<RiskAssessment> {
  const key = opts.cache
    ? cacheKey({
        provider: provider.name,
        model: provider.model,
        reasoning: opts.reasoning ?? false,
        signals,
        namespace: provider.cacheNamespace,
      })
    : null;

  if (key && opts.cache) {
    const hit = await readCachedAssessment(key, opts.cache, signals.package, opts.cwd);
    if (hit) return shapeCacheHit(provider, hit, signals);
  }

  const assessment = await provider.assess(signals);
  if (key && opts.cache) {
    await writeCachedAssessment(key, assessment, opts.cache, signals.package, opts.cwd);
  }
  return clampDecision(assessment, signals);
}

/** Cache-hit shaping shared by the single and batched paths: annotate + clamp. */
function shapeCacheHit(
  provider: AiProvider,
  hit: CachedAssessment,
  signals: Signals,
): RiskAssessment {
  return clampDecision(
    {
      ...hit.assessment,
      reasons: [
        ...hit.assessment.reasons,
        `[cache] reused ${provider.name}/${provider.model} assessment from ${hit.cachedAt.slice(0, 16).replace("T", " ")} — signals unchanged.`,
      ],
    },
    signals,
  );
}

/**
 * Run the AI source-code audit for one package through the content-addressed
 * cache. Keyed on the artifact digest (+ provider/model/prompt/selection
 * version), so identical bytes are audited by the model only once. Returns the
 * findings (possibly empty — a clean audit is cached too so it is not repaid).
 * Only successful results are cached; errors propagate to the caller, which
 * degrades to no audit rather than a poisoned empty cache entry.
 */
export async function auditSourceWithCache(
  provider: AiProvider,
  input: SourceAuditInput,
  digest: string,
  opts: Pick<AssessOptions, "cache" | "cwd">,
): Promise<SourceAuditFinding[]> {
  if (!provider.analyzeSource || input.files.length === 0) return [];
  const key = opts.cache
    ? sourceAuditCacheKey({
        provider: provider.name,
        model: provider.model,
        digest,
        promptVersion: SOURCE_AUDIT_PROMPT_VERSION,
        selectionVersion: SOURCE_SELECTION_VERSION,
        namespace: provider.cacheNamespace,
      })
    : null;

  if (key && opts.cache) {
    const hit = await readCachedSourceAudit(key, opts.cache, input.package, opts.cwd);
    if (hit) return hit;
  }

  const findings = await provider.analyzeSource(input);
  if (key && opts.cache) {
    await writeCachedSourceAudit(key, findings, opts.cache, input.package, opts.cwd);
  }
  return findings;
}

/** Resolve a provider for batched assessment, or null when batching can't apply
 * (AI disabled, or no provider configured / misconfigured — the caller then
 * uses the per-package path, which reports misconfiguration per package). */
export function resolveBatchProvider(opts: AssessOptions): AiProvider | null {
  if (!opts.useAi) return null;
  try {
    return resolveProvider(opts);
  } catch {
    return null;
  }
}

/**
 * Assess many packages with far fewer round-trips: cache hits are served
 * first, the misses are grouped into batches of `batchSize` and sent to the
 * provider's assessBatch in one prompt each. Every result is clamped against
 * its OWN signals (the deterministic floor is per-package, unaffected by
 * batching) and the raw model output is cached exactly as the single path
 * does. Any package the batch doesn't return — a short/misaligned response or
 * a whole-batch failure — falls back to an isolated assessWithCache, so a
 * verdict is never dropped. Returns assessments aligned to signalsList.
 */
export async function assessManyWithCache(
  provider: AiProvider,
  signalsList: Signals[],
  opts: Pick<AssessOptions, "cache" | "cwd" | "reasoning">,
  batchSize = 8,
  concurrency: number = DEFAULT_CONCURRENCY,
  onProgress?: (done: number, total: number) => void,
): Promise<RiskAssessment[]> {
  const results = new Array<RiskAssessment | undefined>(signalsList.length);
  let completed = 0;
  const bump = (): void => onProgress?.(++completed, signalsList.length);
  const keyFor = (signals: Signals) =>
    cacheKey({
      provider: provider.name,
      model: provider.model,
      reasoning: opts.reasoning ?? false,
      signals,
      namespace: provider.cacheNamespace,
    });

  // 1. Serve cache hits; collect the misses.
  const misses: { index: number; signals: Signals }[] = [];
  const cached = opts.cache
    ? await readCachedAssessments(
        signalsList.map((signals) => ({ key: keyFor(signals), packageName: signals.package })),
        opts.cache,
        opts.cwd,
      )
    : new Map<string, CachedAssessment>();
  signalsList.forEach((signals, index) => {
    const hit = cached.get(keyFor(signals));
    if (hit) {
      results[index] = shapeCacheHit(provider, hit, signals);
      bump();
    } else {
      misses.push({ index, signals });
    }
  });

  // 2. Batch the misses; concurrency bounds how many batches are in flight.
  const batches: { index: number; signals: Signals }[][] = [];
  for (let i = 0; i < misses.length; i += batchSize) batches.push(misses.slice(i, i + batchSize));

  const cacheWrites: AssessmentCacheWrite[] = [];
  await mapLimit(batches, concurrency, async (batch) => {
    let byId = new Map<string, RiskAssessment>();
    try {
      const batchResults = await provider.assessBatch(batch.map((m) => m.signals));
      byId = new Map(batchResults.map((r) => [r.package, r.assessment]));
    } catch {
      byId = new Map(); // whole-batch failure -> every item falls back below
    }
    await Promise.all(
      batch.map(async ({ index, signals }) => {
        // Look up by the SAME (sanitized) id the prompt tagged the block with;
        // the model echoes that id, so a raw name@version could miss.
        const raw = byId.get(batchAssessmentId(signals));
        if (raw) {
          if (opts.cache) {
            cacheWrites.push({ key: keyFor(signals), assessment: raw, packageName: signals.package });
          }
          results[index] = clampDecision(raw, signals);
        } else {
          // Missing/misaligned item -> isolated call (clamps + caches inside).
          // A provider outage must degrade THIS package to deterministic rules
          // (like assessRisk), never reject and abort the whole tree review.
          try {
            results[index] = await assessWithCache(provider, signals, opts);
          } catch (err) {
            const fallback = evaluateRules(signals);
            fallback.reasons.push(
              `(AI reasoning unavailable via ${provider.name} — used deterministic rules: ${err instanceof Error ? err.message.split("\n")[0] : String(err)})`,
            );
            results[index] = fallback;
          }
        }
        bump();
      }),
    );
  });

  if (opts.cache && cacheWrites.length > 0) {
    await writeCachedAssessments(cacheWrites, opts.cache, opts.cwd);
  }

  return results as RiskAssessment[];
}

/**
 * Ask an AI provider to reason over the signals. Falls back to the
 * deterministic rules engine when AI is disabled, no provider can be
 * resolved (no credentials configured anywhere), or the call fails. The AI
 * can never be more permissive than the hard policy (see clampDecision).
 */
export async function assessRisk(
  signals: Signals,
  opts: AssessOptions,
): Promise<RiskAssessment> {
  if (!opts.useAi) return evaluateRules(signals);

  let provider;
  try {
    provider = resolveProvider(opts);
  } catch (err) {
    const fallback = evaluateRules(signals);
    fallback.reasons.push(
      `(AI provider misconfigured — used deterministic rules: ${err instanceof Error ? err.message : String(err)})`,
    );
    return fallback;
  }

  if (!provider) return evaluateRules(signals);

  try {
    return await assessWithCache(provider, signals, opts);
  } catch (err) {
    const fallback = evaluateRules(signals);
    fallback.reasons.push(
      `(AI reasoning unavailable via ${provider.name} — used deterministic rules: ${err instanceof Error ? err.message.split("\n")[0] : String(err)})`,
    );
    return fallback;
  }
}
