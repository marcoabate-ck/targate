import type { RiskAssessment, Signals, SourceAuditFinding } from "../types.js";
import type { BatchAssessment } from "./validate.js";

export type { BatchAssessment } from "./validate.js";

/** One selected source file (or slice) handed to the AI code audit. */
export interface SourceAuditFile {
  /** POSIX package-relative path. */
  relPath: string;
  /** The file text (possibly a head+tail slice). */
  content: string;
  /** True when only a slice of a larger file is included. */
  truncated: boolean;
}

/** Input to `analyzeSource`: which package + the bounded risky file subset. */
export interface SourceAuditInput {
  package: string;
  version: string;
  files: SourceAuditFile[];
}

/** A pluggable AI backend that reasons over deterministic signals. */
export interface AiProvider {
  /** Short label used in reports and error messages (e.g. "anthropic", "ollama"). */
  readonly name: string;
  /** Model identifier — part of the AI-cache key, so answers never leak across models. */
  readonly model: string;
  /**
   * Endpoint identity folded into the AI-cache key. `name` alone is "custom"
   * for every OpenAI-compatible custom endpoint, so without this two different
   * `--base-url` targets on the same model would share cached verdicts.
   */
  readonly cacheNamespace?: string;
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
  /**
   * Read a bounded subset of a package's actual source and report security
   * findings (the opt-in `--audit-code` pass). Optional: a provider without it
   * simply contributes no source-audit findings. The file contents are
   * attacker-controlled and must be treated as untrusted DATA by the prompt;
   * findings only ever ESCALATE the verdict through the deterministic clamp.
   */
  analyzeSource?(input: SourceAuditInput): Promise<SourceAuditFinding[]>;
}

export type ProviderName = "anthropic" | "deepseek" | "openai" | "ollama" | "custom";
