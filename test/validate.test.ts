import { describe, expect, it } from "vitest";
import { validateAssessment, validateBatchAssessment } from "../src/providers/validate.js";

// Regression (review A1.2): validateAssessment / validateBatchAssessment are the
// FIRST line that rejects malformed or jailbroken model output before it reaches
// the deterministic clamp. Anthropic enforces the shape server-side, but
// OpenAI-compatible providers (DeepSeek, Ollama, self-hosted) only get best-effort
// JSON, so a hostile/garbled response must be caught here. The clamp is the
// backstop; this proves the parse layer itself does not pass garbage through.

const VALID = {
  risk: "medium",
  decision: "require_approval",
  summary: "needs review",
  reasons: ["a", "b"],
  recommendedAction: "review it",
};

describe("validateAssessment", () => {
  it("accepts a well-formed assessment and normalizes reasons to strings", () => {
    const out = validateAssessment({ ...VALID, reasons: ["ok", 42, true] });
    expect(out.decision).toBe("require_approval");
    expect(out.risk).toBe("medium");
    expect(out.reasons).toEqual(["ok", "42", "true"]);
    expect(out.suggestedAlternatives).toBeUndefined();
  });

  it("keeps suggestedAlternatives when present, coerced to strings", () => {
    expect(validateAssessment({ ...VALID, suggestedAlternatives: ["x", 1] }).suggestedAlternatives).toEqual([
      "x",
      "1",
    ]);
  });

  it.each([
    [null, /not a JSON object/],
    ["a string", /not a JSON object/],
    [{ ...VALID, risk: "critical" }, /"risk"/],
    [{ ...VALID, risk: undefined }, /"risk"/],
    [{ ...VALID, decision: "allow_maybe" }, /"decision"/],
    // A jailbroken "downgrade to allow" with a bogus risk is still rejected here.
    [{ ...VALID, decision: "allow", risk: "none" }, /"risk"/],
    [{ ...VALID, summary: "" }, /summary/],
    [{ ...VALID, summary: 123 }, /summary/],
    [{ ...VALID, reasons: "not-an-array" }, /reasons/],
    [{ ...VALID, recommendedAction: "" }, /recommendedAction/],
  ])("rejects malformed input %#", (raw, pattern) => {
    expect(() => validateAssessment(raw)).toThrow(pattern as RegExp);
  });
});

describe("validateBatchAssessment", () => {
  it("keeps valid items and maps each to its package id", () => {
    const out = validateBatchAssessment({
      results: [
        { package: "left-pad@1.3.0", ...VALID },
        { package: "lodash@4.17.21", ...VALID, decision: "allow", risk: "low" },
      ],
    });
    expect(out.map((r) => r.package)).toEqual(["left-pad@1.3.0", "lodash@4.17.21"]);
    expect(out[1].assessment.decision).toBe("allow");
    expect(out[1].assessment.source).toBe("ai");
  });

  it("drops malformed items instead of failing the whole batch", () => {
    const out = validateBatchAssessment({
      results: [
        { package: "good@1.0.0", ...VALID },
        { package: "bad@1.0.0", ...VALID, decision: "nonsense" }, // invalid assessment
        { ...VALID }, // no package id
        "garbage",
        null,
      ],
    });
    expect(out.map((r) => r.package)).toEqual(["good@1.0.0"]);
  });

  it.each([
    [null, /not a JSON object/],
    [{ notResults: [] }, /"results"/],
    [{ results: "nope" }, /"results"/],
  ])("throws on a structurally invalid batch %#", (raw, pattern) => {
    expect(() => validateBatchAssessment(raw)).toThrow(pattern as RegExp);
  });
});
