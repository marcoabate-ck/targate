import OpenAI from "openai";
import type { RiskAssessment, Signals } from "../types.js";
import {
  SYSTEM_PROMPT,
  batchJsonModeInstruction,
  buildBatchUserPrompt,
  buildSuggestPrompt,
  buildUserPrompt,
  jsonModeInstruction,
  suggestJsonModeInstruction,
} from "./prompt.js";
import type { AiProvider, BatchAssessment } from "./types.js";
import {
  stripJsonFences,
  stripThinkBlocks,
  validateAssessment,
  validateBatchAssessment,
  validateSuggestions,
} from "./validate.js";

export interface OpenAiCompatibleOptions {
  baseURL: string;
  /** Some local servers (e.g. Ollama) don't require a key. */
  apiKey?: string;
  model: string;
  /** Label used in reports/errors — "deepseek" | "openai" | "ollama" | "custom". */
  label: string;
  /**
   * Opt-in reasoning. There is no standard knob across OpenAI-compatible
   * backends, so this maps differently per provider (see resolveProvider):
   * - openai: sends `reasoning_effort`
   * - deepseek: the caller switches the model to deepseek-reasoner, which
   *   does not support response_format — so JSON mode is dropped and the
   *   schema in the prompt + client-side validation carry the weight
   * - ollama/custom: no request change; reasoning models (deepseek-r1, qwq)
   *   think on their own and their <think> blocks are stripped on parse
   */
  reasoning?: boolean;
  /** Drop response_format for servers/models that reject it. */
  disableJsonMode?: boolean;
}

/**
 * Generic client for any OpenAI-compatible chat completions endpoint:
 * DeepSeek, OpenAI, Ollama (local), LM Studio, vLLM, self-hosted gateways.
 * JSON output is requested via response_format + an embedded schema in the
 * prompt, then validated client-side since enforcement varies by backend.
 */
export class OpenAiCompatibleProvider implements AiProvider {
  readonly name: string;
  private readonly client: OpenAI;
  private readonly opts: OpenAiCompatibleOptions;

  get model(): string {
    return this.opts.model;
  }

  constructor(opts: OpenAiCompatibleOptions) {
    this.name = opts.label;
    this.opts = opts;
    this.client = new OpenAI({
      baseURL: opts.baseURL,
      // The OpenAI SDK requires a non-empty string even when the server
      // (e.g. local Ollama) doesn't check it.
      apiKey: opts.apiKey && opts.apiKey.length > 0 ? opts.apiKey : "not-needed",
    });
  }

  async assess(signals: Signals): Promise<RiskAssessment> {
    const parsed = await this.complete(
      `${SYSTEM_PROMPT}${jsonModeInstruction()}`,
      buildUserPrompt(signals),
    );
    return { ...validateAssessment(parsed), source: "ai" };
  }

  async assessBatch(signalsList: Signals[]): Promise<BatchAssessment[]> {
    const parsed = await this.complete(
      `${SYSTEM_PROMPT}${batchJsonModeInstruction()}`,
      buildBatchUserPrompt(signalsList),
    );
    return validateBatchAssessment(parsed);
  }

  async suggestPackages(need: string, count: number): Promise<string[]> {
    const parsed = await this.complete(
      `${SYSTEM_PROMPT}${suggestJsonModeInstruction()}`,
      buildSuggestPrompt(need, count),
    );
    return validateSuggestions(parsed, count);
  }

  private async complete(systemContent: string, userContent: string): Promise<unknown> {
    const request: OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming = {
      model: this.opts.model,
      messages: [
        { role: "system", content: systemContent },
        { role: "user", content: userContent },
      ],
    };
    if (!this.opts.disableJsonMode) {
      request.response_format = { type: "json_object" };
    }
    if (this.opts.reasoning && this.opts.label === "openai") {
      request.reasoning_effort = "medium";
    }

    const completion = await this.client.chat.completions.create(request);

    const text = completion.choices[0]?.message?.content;
    if (!text) throw new Error(`${this.name} returned an empty response`);

    try {
      return JSON.parse(stripJsonFences(stripThinkBlocks(text)));
    } catch {
      throw new Error(
        `${this.name} did not return valid JSON: ${text.slice(0, 200)}${text.length > 200 ? "…" : ""}`,
      );
    }
  }
}
