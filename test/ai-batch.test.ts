import { describe, expect, it, vi } from "vitest";
import { assessManyWithCache } from "../src/ai.js";
import type { AiProvider, BatchAssessment } from "../src/providers/types.js";
import type { RiskAssessment, Signals } from "../src/types.js";
import { makeSignals } from "./helpers.js";

function verdict(decision: RiskAssessment["decision"] = "allow"): RiskAssessment {
  return {
    risk: "low",
    decision,
    summary: "ok",
    reasons: ["r"],
    recommendedAction: "install",
    source: "ai",
  };
}

/** Provider whose batch returns exactly the entries we dictate (by index). */
function provider(
  batch: (signalsList: Signals[]) => BatchAssessment[],
  single: RiskAssessment = verdict(),
): { p: AiProvider; assess: ReturnType<typeof vi.fn>; assessBatch: ReturnType<typeof vi.fn> } {
  const assess = vi.fn(async () => single);
  const assessBatch = vi.fn(async (s: Signals[]) => batch(s));
  return { p: { name: "fake", model: "m", assess, assessBatch }, assess, assessBatch };
}

const opts = { cache: undefined, cwd: undefined, reasoning: false };

describe("assessManyWithCache", () => {
  it("assesses every package in one batch (no cache) and keeps order", async () => {
    const list = [makeSignals({ package: "a" }), makeSignals({ package: "b" })];
    const { p, assess, assessBatch } = provider((s) =>
      s.map((sig) => ({ package: `${sig.package}@${sig.version}`, assessment: verdict("allow_with_warnings") })),
    );
    const out = await assessManyWithCache(p, list, opts);
    expect(assessBatch).toHaveBeenCalledTimes(1);
    expect(assess).not.toHaveBeenCalled();
    expect(out.map((r) => r.decision)).toEqual(["allow_with_warnings", "allow_with_warnings"]);
  });

  it("falls back to an isolated assess for a package the batch omits", async () => {
    const list = [makeSignals({ package: "a" }), makeSignals({ package: "b" })];
    // Batch returns only package a; b is missing -> isolated assess.
    const { p, assess } = provider((s) => [
      { package: `${s[0].package}@${s[0].version}`, assessment: verdict() },
    ]);
    const out = await assessManyWithCache(p, list, opts);
    expect(assess).toHaveBeenCalledTimes(1);
    expect(out).toHaveLength(2);
    expect(out[1].decision).toBe("allow");
  });

  // Regression (v3 P3): a whole-batch outage degrades every item to
  // deterministic rules DIRECTLY — it must NOT fan out into N isolated
  // provider.assess calls (each with its own retry/timeout budget).
  it("degrades the whole batch to rules without re-hitting the provider", async () => {
    const list = [makeSignals({ package: "a" }), makeSignals({ package: "b" })];
    const assess = vi.fn(async () => verdict());
    const assessBatch = vi.fn(async () => {
      throw new Error("batch API down");
    });
    const p: AiProvider = { name: "fake", model: "m", assess, assessBatch };
    const out = await assessManyWithCache(p, list, opts);
    expect(assess).not.toHaveBeenCalled(); // no per-item fan-out
    expect(out).toHaveLength(2);
    expect(out.every((r) => r.source === "rules")).toBe(true);
  });

  it("reports per-package progress across cache hits, batch items and fallbacks", async () => {
    const list = [makeSignals({ package: "a" }), makeSignals({ package: "b" }), makeSignals({ package: "c" })];
    // Batch returns only a and b; c falls back to an isolated call.
    const { p } = provider((s) =>
      s
        .filter((sig) => sig.package !== "c")
        .map((sig) => ({ package: `${sig.package}@${sig.version}`, assessment: verdict() })),
    );
    const seen: Array<[number, number]> = [];
    await assessManyWithCache(p, list, opts, 8, 16, (done, total) => seen.push([done, total]));
    expect(seen).toHaveLength(3); // one event per package, whatever its path
    expect(seen.at(-1)).toEqual([3, 3]);
  });

  it("clamps each result on its OWN signals — a batched allow can't clear a hard block", async () => {
    const list = [
      makeSignals({ package: "clean" }),
      makeSignals({ package: "evil", knownMalicious: true, maliciousRecords: [{ id: "MAL-1" }] }),
    ];
    // Model (or an injection) returns allow for the malicious package.
    const { p } = provider((s) =>
      s.map((sig) => ({ package: `${sig.package}@${sig.version}`, assessment: verdict("allow") })),
    );
    const out = await assessManyWithCache(p, list, opts);
    expect(out[0].decision).toBe("allow");
    expect(out[1].decision).toBe("block"); // clamp overrides the batched allow
  });
});
