import { resolveProvider, type ProviderSelection } from "./providers/index.js";
import { clampDecision, evaluateRules } from "./rules.js";
import type { RiskAssessment, Signals } from "./types.js";

export interface AssessOptions extends ProviderSelection {
  /** When false, skip AI entirely and use the deterministic rules engine. */
  useAi: boolean;
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
    const assessment = await provider.assess(signals);
    return clampDecision(assessment, signals);
  } catch (err) {
    const fallback = evaluateRules(signals);
    fallback.reasons.push(
      `(AI reasoning unavailable via ${provider.name} — used deterministic rules: ${err instanceof Error ? err.message.split("\n")[0] : String(err)})`,
    );
    return fallback;
  }
}
