import Anthropic from "@anthropic-ai/sdk";
import type { RiskAssessment, Signals, SourceAuditFinding } from "../types.js";
import {
  ASSESSMENT_JSON_SCHEMA,
  BATCH_ASSESSMENT_JSON_SCHEMA,
  SOURCE_AUDIT_JSON_SCHEMA,
  SOURCE_AUDIT_SYSTEM_PROMPT,
  SUGGESTIONS_JSON_SCHEMA,
  SYSTEM_PROMPT,
  buildBatchUserPrompt,
  buildSourceAuditPrompt,
  buildSuggestPrompt,
  buildUserPrompt,
} from "./prompt.js";
import type { AiProvider, BatchAssessment, SourceAuditInput } from "./types.js";
import {
  validateAssessment,
  validateBatchAssessment,
  validateSourceAudit,
  validateSuggestions,
} from "./validate.js";

const DEFAULT_MODEL = "claude-opus-4-8";
/** Bound each model call so a hung API can't stall the pre-install gate for
 *  the SDK's ~10-minute default. */
const REQUEST_TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;

/** Wrap a stable system prompt for ephemeral prompt caching (paid once per run). */
const cachedSystem = (text: string) => [
  { type: "text" as const, text, cache_control: { type: "ephemeral" as const } },
];

// Cache the (stable, ~1.5KB) system prompt so repeated calls in a run only pay
// for the per-package data + output, not the instructions every time.
const CACHED_SYSTEM = cachedSystem(SYSTEM_PROMPT);
const CACHED_AUDIT_SYSTEM = cachedSystem(SOURCE_AUDIT_SYSTEM_PROMPT);

export interface AnthropicProviderOptions {
  /** Falls back to ANTHROPIC_API_KEY or an `ant auth login` profile when omitted. */
  apiKey?: string;
  model?: string;
}

export class AnthropicProvider implements AiProvider {
  readonly name = "anthropic";
  readonly model: string;
  private readonly client: Anthropic;

  constructor(opts: AnthropicProviderOptions = {}) {
    this.client = new Anthropic({
      ...(opts.apiKey ? { apiKey: opts.apiKey } : {}),
      timeout: REQUEST_TIMEOUT_MS,
      maxRetries: MAX_RETRIES,
    });
    this.model = opts.model ?? DEFAULT_MODEL;
  }

  async assess(signals: Signals): Promise<RiskAssessment> {
    const text = await this.complete(buildUserPrompt(signals), ASSESSMENT_JSON_SCHEMA, 4096);
    return { ...validateAssessment(JSON.parse(text)), source: "ai" };
  }

  async assessBatch(signalsList: Signals[]): Promise<BatchAssessment[]> {
    // Scale the token budget with the batch; each verdict is small.
    const maxTokens = Math.min(16_384, 1024 + signalsList.length * 512);
    const text = await this.complete(
      buildBatchUserPrompt(signalsList),
      BATCH_ASSESSMENT_JSON_SCHEMA,
      maxTokens,
    );
    return validateBatchAssessment(JSON.parse(text));
  }

  async suggestPackages(need: string, count: number): Promise<string[]> {
    const text = await this.complete(buildSuggestPrompt(need, count), SUGGESTIONS_JSON_SCHEMA, 2048);
    return validateSuggestions(JSON.parse(text), count);
  }

  async analyzeSource(input: SourceAuditInput): Promise<SourceAuditFinding[]> {
    // Scale tokens with the number of files; findings are compact.
    const maxTokens = Math.min(8192, 1024 + input.files.length * 256);
    const text = await this.complete(
      buildSourceAuditPrompt(input),
      SOURCE_AUDIT_JSON_SCHEMA,
      maxTokens,
      CACHED_AUDIT_SYSTEM,
    );
    return validateSourceAudit(JSON.parse(text));
  }

  private async complete(
    userContent: string,
    schema: Record<string, unknown>,
    maxTokens: number,
    system: typeof CACHED_SYSTEM = CACHED_SYSTEM,
  ): Promise<string> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      // Opus 4.8 runs WITHOUT thinking when the field is omitted — enable
      // adaptive reasoning explicitly so the model can weigh weak signals.
      thinking: { type: "adaptive" },
      system,
      output_config: { format: { type: "json_schema", schema } },
      messages: [{ role: "user", content: userContent }],
    });

    if (response.stop_reason === "refusal") {
      throw new Error("model refused to assess this package");
    }
    const text = response.content.find((b) => b.type === "text")?.text;
    if (!text) throw new Error("response contained no text block");
    return text;
  }
}
