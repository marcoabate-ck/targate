import type {
  Decision,
  RiskAssessment,
  RiskLevel,
  SourceAuditFinding,
  SourceAuditSeverity,
} from "../types.js";

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

const AUDIT_SEVERITIES: SourceAuditSeverity[] = ["info", "low", "medium", "high"];

/**
 * Validate a parsed source-audit response `{ findings: [...] }`. Malformed
 * findings are dropped, not fatal — a garbled item must never crash the audit
 * (which is advisory), but the surviving findings must be well-typed before
 * they feed the verdict. A response missing `findings` entirely throws.
 */
export function validateSourceAudit(raw: unknown): SourceAuditFinding[] {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("source-audit response is not a JSON object");
  }
  const findings = (raw as { findings?: unknown }).findings;
  if (!Array.isArray(findings)) {
    throw new Error('source-audit response missing "findings" array');
  }
  const out: SourceAuditFinding[] = [];
  for (const item of findings) {
    if (typeof item !== "object" || item === null) continue;
    const obj = item as Record<string, unknown>;
    if (!AUDIT_SEVERITIES.includes(obj.severity as SourceAuditSeverity)) continue;
    if (typeof obj.file !== "string" || obj.file.length === 0) continue;
    if (typeof obj.summary !== "string" || obj.summary.length === 0) continue;
    out.push({
      severity: obj.severity as SourceAuditSeverity,
      file: obj.file,
      summary: obj.summary,
      ...(typeof obj.line === "number" && Number.isFinite(obj.line)
        ? { line: obj.line }
        : {}),
    });
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

/** npm package-name shape (scoped or bare) — the hallucination first pass. */
const NPM_NAME_RE = /^(@[a-z0-9][a-z0-9-_.]*\/)?[a-z0-9][a-z0-9-_.]*$/;

/**
 * Validate an AI suggestions payload: `{suggestions: string[]}`. Names are
 * lowercased, shape-checked, and deduped; anything that cannot be an npm name
 * is dropped here (real existence is checked later by the registry fetch).
 */
export function validateSuggestions(raw: unknown, max: number): string[] {
  if (typeof raw !== "object" || raw === null || !Array.isArray((raw as { suggestions?: unknown }).suggestions)) {
    throw new Error('AI suggestions response must be {"suggestions": string[]}');
  }
  const seen = new Set<string>();
  const names: string[] = [];
  for (const entry of (raw as { suggestions: unknown[] }).suggestions) {
    if (typeof entry !== "string") continue;
    const name = entry.trim().toLowerCase();
    if (!NPM_NAME_RE.test(name) || seen.has(name)) continue;
    seen.add(name);
    names.push(name);
    if (names.length >= max) break;
  }
  return names;
}
