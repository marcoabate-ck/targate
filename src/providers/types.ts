import type { RiskAssessment, Signals } from "../types.js";

/** A pluggable AI backend that reasons over deterministic signals. */
export interface AiProvider {
  /** Short label used in reports and error messages (e.g. "anthropic", "ollama"). */
  readonly name: string;
  /** Model identifier — part of the AI-cache key, so answers never leak across models. */
  readonly model: string;
  assess(signals: Signals): Promise<RiskAssessment>;
}

export type ProviderName = "anthropic" | "deepseek" | "openai" | "ollama" | "custom";
