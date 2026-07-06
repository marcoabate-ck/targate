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
