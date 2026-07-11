import Anthropic from "@anthropic-ai/sdk";
import type { RiskAssessment, Signals } from "../types.js";
import {
  ASSESSMENT_JSON_SCHEMA,
  BATCH_ASSESSMENT_JSON_SCHEMA,
  SUGGESTIONS_JSON_SCHEMA,
  SYSTEM_PROMPT,
  buildBatchUserPrompt,
  buildSuggestPrompt,
  buildUserPrompt,
} from "./prompt.js";
import type { AiProvider, BatchAssessment } from "./types.js";
import { validateAssessment, validateBatchAssessment, validateSuggestions } from "./validate.js";

const DEFAULT_MODEL = "claude-opus-4-8";

// Cache the (stable, ~1.5KB) system prompt so repeated calls in a run only pay
// for the per-package data + output, not the instructions every time.
const CACHED_SYSTEM = [
  { type: "text" as const, text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" as const } },
];

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
    this.client = opts.apiKey ? new Anthropic({ apiKey: opts.apiKey }) : new Anthropic();
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

  private async complete(
    userContent: string,
    schema: Record<string, unknown>,
    maxTokens: number,
  ): Promise<string> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      // Opus 4.8 runs WITHOUT thinking when the field is omitted — enable
      // adaptive reasoning explicitly so the model can weigh weak signals.
      thinking: { type: "adaptive" },
      system: CACHED_SYSTEM,
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
