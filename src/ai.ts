import {
  cacheKey,
  readCachedAssessment,
  writeCachedAssessment,
  type AiCacheSettings,
} from "./ai-cache.js";
import { resolveProvider, type ProviderSelection } from "./providers/index.js";
import type { AiProvider } from "./providers/types.js";
import { clampDecision, evaluateRules } from "./rules.js";
import type { RiskAssessment, Signals } from "./types.js";

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
      })
    : null;

  if (key && opts.cache) {
    const hit = await readCachedAssessment(key, opts.cache, signals.package, opts.cwd);
    if (hit) {
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
  }

  const assessment = await provider.assess(signals);
  if (key && opts.cache) {
    await writeCachedAssessment(key, assessment, opts.cache, signals.package, opts.cwd);
  }
  return clampDecision(assessment, signals);
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
