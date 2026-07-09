import type { Decision, RiskAssessment, RiskLevel } from "../types.js";

const RISK_LEVELS: RiskLevel[] = ["low", "medium", "high"];
const DECISIONS: Decision[] = [
  "allow",
  "allow_with_warnings",
  "require_approval",
  "block",
];

/**
 * Validate a parsed model response against the assessment shape. Anthropic's
 * structured outputs guarantee this server-side, but OpenAI-compatible
 * providers (DeepSeek, Ollama, self-hosted) only get a best-effort JSON mode,
 * so untrusted output must be checked before it drives an install decision.
 */
export function validateAssessment(raw: unknown): Omit<RiskAssessment, "source"> {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("model response is not a JSON object");
  }
  const obj = raw as Record<string, unknown>;

  if (!RISK_LEVELS.includes(obj.risk as RiskLevel)) {
    throw new Error(`invalid or missing "risk" field: ${JSON.stringify(obj.risk)}`);
  }
  if (!DECISIONS.includes(obj.decision as Decision)) {
    throw new Error(`invalid or missing "decision" field: ${JSON.stringify(obj.decision)}`);
  }
  if (typeof obj.summary !== "string" || obj.summary.length === 0) {
    throw new Error('missing or empty "summary" field');
  }
  if (!Array.isArray(obj.reasons)) {
    throw new Error('missing "reasons" field');
  }
  if (typeof obj.recommendedAction !== "string" || obj.recommendedAction.length === 0) {
    throw new Error('missing or empty "recommendedAction" field');
  }

  return {
    risk: obj.risk as RiskLevel,
    decision: obj.decision as Decision,
    summary: obj.summary,
    reasons: obj.reasons.map(String),
    recommendedAction: obj.recommendedAction,
    suggestedAlternatives: Array.isArray(obj.suggestedAlternatives)
      ? obj.suggestedAlternatives.map(String)
      : undefined,
  };
}

/** One entry of a batched response: which package it is for + its verdict. */
export interface BatchAssessment {
  package: string;
  assessment: RiskAssessment;
}

/**
 * Validate a parsed batch response `{ results: [...] }`. Each item is checked
 * with validateAssessment plus a non-empty `package` id (used to map the
 * verdict back to its input). Items that fail validation are dropped, not
 * fatal — the caller falls back to an isolated call for any package left
 * without a verdict, so one bad item never poisons the batch.
 */
export function validateBatchAssessment(raw: unknown): BatchAssessment[] {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("batch response is not a JSON object");
  }
  const results = (raw as { results?: unknown }).results;
  if (!Array.isArray(results)) {
    throw new Error('batch response missing "results" array');
  }
  const out: BatchAssessment[] = [];
  for (const item of results) {
    if (typeof item !== "object" || item === null) continue;
    const pkg = (item as { package?: unknown }).package;
    if (typeof pkg !== "string" || pkg.length === 0) continue;
    try {
      out.push({ package: pkg, assessment: { ...validateAssessment(item), source: "ai" } });
    } catch {
      /* skip malformed item — caller falls back for its package */
    }
  }
  return out;
}

/** Strip ```json ... ``` fences some local models wrap output in despite instructions. */
export function stripJsonFences(text: string): string {
  const trimmed = text.trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  return fenced ? fenced[1] : trimmed;
}

/**
 * Local reasoning models (deepseek-r1, qwq, etc.) emit their chain of
 * thought inline as <think>...</think> before the actual answer. Remove it
 * so the JSON that follows can be parsed.
 */
export function stripThinkBlocks(text: string): string {
  return text.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
}
