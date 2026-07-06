import Anthropic from "@anthropic-ai/sdk";
import type { RiskAssessment, Signals } from "../types.js";
import { ASSESSMENT_JSON_SCHEMA, SYSTEM_PROMPT, buildUserPrompt } from "./prompt.js";
import type { AiProvider } from "./types.js";
import { validateAssessment } from "./validate.js";

const DEFAULT_MODEL = "claude-opus-4-8";

export interface AnthropicProviderOptions {
  /** Falls back to ANTHROPIC_API_KEY or an `ant auth login` profile when omitted. */
  apiKey?: string;
  model?: string;
}

export class AnthropicProvider implements AiProvider {
  readonly name = "anthropic";
  private readonly client: Anthropic;
  private readonly model: string;

  constructor(opts: AnthropicProviderOptions = {}) {
    this.client = opts.apiKey ? new Anthropic({ apiKey: opts.apiKey }) : new Anthropic();
    this.model = opts.model ?? DEFAULT_MODEL;
  }

  async assess(signals: Signals): Promise<RiskAssessment> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 4096,
      // Opus 4.8 runs WITHOUT thinking when the field is omitted — enable
      // adaptive reasoning explicitly so the model can weigh weak signals.
      thinking: { type: "adaptive" },
      system: SYSTEM_PROMPT,
      output_config: {
        format: { type: "json_schema", schema: ASSESSMENT_JSON_SCHEMA },
      },
      messages: [{ role: "user", content: buildUserPrompt(signals) }],
    });

    if (response.stop_reason === "refusal") {
      throw new Error("model refused to assess this package");
    }

    const text = response.content.find((b) => b.type === "text")?.text;
    if (!text) throw new Error("response contained no text block");

    return { ...validateAssessment(JSON.parse(text)), source: "ai" };
  }
}
