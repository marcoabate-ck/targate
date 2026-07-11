import type { RiskAssessment, Signals } from "../types.js";
import type { BatchAssessment } from "./validate.js";

export type { BatchAssessment } from "./validate.js";

/** A pluggable AI backend that reasons over deterministic signals. */
export interface AiProvider {
  /** Short label used in reports and error messages (e.g. "anthropic", "ollama"). */
  readonly name: string;
  /** Model identifier — part of the AI-cache key, so answers never leak across models. */
  readonly model: string;
  assess(signals: Signals): Promise<RiskAssessment>;
  /**
   * Assess several packages in one request. Returns one entry per verdict the
   * model produced, tagged with the package id; the caller maps them back and
   * falls back to `assess` for any package left without a verdict.
   */
  assessBatch(signalsList: Signals[]): Promise<BatchAssessment[]>;
  /**
   * Propose up to `count` npm package names for a free-text need (used by
   * `targate recommend`). Optional: a provider without it simply contributes
   * no AI candidates. Suggestions are names ONLY — every one is resolved on
   * the registry and analyzed deterministically before it can be recommended.
   */
  suggestPackages?(need: string, count: number): Promise<string[]>;
}

export type ProviderName = "anthropic" | "deepseek" | "openai" | "ollama" | "custom";
