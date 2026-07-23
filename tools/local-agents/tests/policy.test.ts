import { describe, expect, it } from "vitest";
import { decide, planChanged, planHash } from "../src/policy.js";

describe("decide — mandatory approval triggers", () => {
  const triggers = [
    { key: "securitySensitive", label: "security" },
    { key: "changesExecutionOrCredentials", label: "execution/credentials" },
    { key: "destructive", label: "destructive" },
    { key: "dependencyChange", label: "dependency" },
    { key: "publicApiBreaking", label: "api break" },
    { key: "affectsCiOrRelease", label: "ci" },
    { key: "architectural", label: "architectural" },
  ] as const;
  for (const t of triggers) {
    it(`forces approval for ${t.label} even in adaptive mode`, () => {
      const d = decide({ [t.key]: true } as never, "adaptive");
      expect(d.approvalRequired).toBe(true);
      expect(d.approvalReason).toBeTruthy();
    });
  }
});

describe("decide — tiers", () => {
  it("classifies a one-file change as small with no approval", () => {
    const d = decide({ likelyFiles: 1 }, "adaptive");
    expect(d.riskTier).toBe("small");
    expect(d.approvalRequired).toBe(false);
    expect(d.suggestedFlow).toContain("implementer");
  });
  it("classifies explanatory tasks as trivial (no workers)", () => {
    const d = decide({ explanatoryOnly: true }, "adaptive");
    expect(d.riskTier).toBe("trivial");
    expect(d.useWorkers).toBe(false);
    expect(d.suggestedFlow).toEqual([]);
  });
  it("classifies many files as large and requires approval", () => {
    const d = decide({ likelyFiles: 20 }, "adaptive");
    expect(d.riskTier).toBe("large");
    expect(d.approvalRequired).toBe(true);
  });
});

describe("decide — modes", () => {
  it("always mode forces approval on a trivial task", () => {
    expect(decide({ likelyFiles: 1 }, "always").approvalRequired).toBe(true);
  });
  it("never mode overrides even a mandatory trigger but records the note", () => {
    const d = decide({ securitySensitive: true }, "never");
    expect(d.approvalRequired).toBe(false);
    expect(d.notes.join(" ")).toMatch(/mandatory trigger/);
  });
});

describe("plan hash", () => {
  it("is stable and detects drift", () => {
    const h = planHash("do X then Y");
    expect(h).toBe(planHash("do X then Y"));
    expect(planChanged("do X then Y", h)).toBe(false);
    expect(planChanged("do X then Z", h)).toBe(true);
  });
});
