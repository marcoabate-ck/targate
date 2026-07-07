import { describe, expect, it, vi } from "vitest";
import type { PackageAnalysis } from "../src/pipeline.js";
import {
  aggregateWithTransitive,
  analyzeTransitiveDeps,
  parseResolvedTree,
  type TransitiveResult,
} from "../src/transitive.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

function assessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    risk: "low",
    decision: "allow",
    summary: "fine",
    reasons: ["clean"],
    recommendedAction: "install",
    source: "rules",
    ...overrides,
  };
}

function result(
  name: string,
  decision: RiskAssessment["decision"],
  version = "1.0.0",
): TransitiveResult {
  return { name, version, assessment: assessment({ decision }) };
}

describe("parseResolvedTree", () => {
  const lock = JSON.stringify({
    packages: {
      "": { name: "bye-deep-resolution" },
      "node_modules/root-pkg": { version: "2.0.0" },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/@scope/util": { version: "0.5.0" },
      "node_modules/left-pad/node_modules/nested": { version: "3.1.4" },
    },
  });

  it("lists every unique package excluding the analyzed root", () => {
    const tree = parseResolvedTree(lock, "root-pkg", "2.0.0");
    expect(tree).toEqual([
      { name: "@scope/util", version: "0.5.0" },
      { name: "left-pad", version: "1.3.0" },
      { name: "nested", version: "3.1.4" },
    ]);
  });

  it("keeps the root package when another VERSION of it appears in the tree", () => {
    const withDupe = JSON.stringify({
      packages: {
        "node_modules/root-pkg": { version: "2.0.0" },
        "node_modules/dep/node_modules/root-pkg": { version: "1.0.0" },
      },
    });
    const tree = parseResolvedTree(withDupe, "root-pkg", "2.0.0");
    expect(tree).toEqual([{ name: "root-pkg", version: "1.0.0" }]);
  });
});

describe("analyzeTransitiveDeps", () => {
  const packages = [
    { name: "a", version: "1.0.0" },
    { name: "b", version: "2.0.0" },
    { name: "c", version: "3.0.0" },
  ];

  it("runs the injected pipeline on every package and keeps input order", async () => {
    const analyze = vi.fn(
      async (name: string, version: string | undefined): Promise<PackageAnalysis> => ({
        metadata: {} as PackageAnalysis["metadata"],
        signals: makeSignals({ package: name, version }),
        assessment: assessment({ decision: name === "b" ? "require_approval" : "allow" }),
      }),
    );

    const results = await analyzeTransitiveDeps(packages, {
      assess: { useAi: false },
      analyze,
      concurrency: 2,
    });

    expect(analyze).toHaveBeenCalledTimes(3);
    expect(results.map((r) => r.name)).toEqual(["a", "b", "c"]);
    expect(results[1].assessment.decision).toBe("require_approval");
  });

  it("maps an analysis failure to require_approval — unknown is not clean", async () => {
    const analyze = vi.fn(async (name: string) => {
      if (name === "b") throw new Error("registry exploded");
      return {
        metadata: {} as PackageAnalysis["metadata"],
        signals: makeSignals(),
        assessment: assessment(),
      };
    });

    const results = await analyzeTransitiveDeps(packages, {
      assess: { useAi: false },
      analyze,
    });
    const failed = results[1];
    expect(failed.error).toContain("registry exploded");
    expect(failed.assessment.decision).toBe("require_approval");
  });

  it("reports progress through onResult", async () => {
    const seen: string[] = [];
    await analyzeTransitiveDeps(packages, {
      assess: { useAi: false },
      analyze: async (name) => ({
        metadata: {} as PackageAnalysis["metadata"],
        signals: makeSignals(),
        assessment: assessment(),
      }),
      onResult: (r) => seen.push(r.name),
    });
    expect(seen.sort()).toEqual(["a", "b", "c"]);
  });
});

describe("aggregateWithTransitive", () => {
  it("keeps the root verdict and notes a fully clean tree", () => {
    const out = aggregateWithTransitive(assessment(), [result("a", "allow"), result("b", "allow")]);
    expect(out.decision).toBe("allow");
    expect(out.reasons.join(" ")).toContain("all 2 transitive dependencies analyzed");
  });

  it("a blocked transitive dependency blocks the whole install", () => {
    const out = aggregateWithTransitive(assessment(), [
      result("a", "allow"),
      result("evil-dep", "block"),
    ]);
    expect(out.decision).toBe("block");
    expect(out.risk).toBe("high");
    expect(out.reasons.join(" ")).toContain("[deep] evil-dep@1.0.0: block");
  });

  it("a require_approval child escalates an allow root", () => {
    const out = aggregateWithTransitive(assessment(), [result("needs-review", "require_approval")]);
    expect(out.decision).toBe("require_approval");
  });

  it("never downgrades a stricter root", () => {
    const out = aggregateWithTransitive(
      assessment({ decision: "block", risk: "high" }),
      [result("a", "allow_with_warnings")],
    );
    expect(out.decision).toBe("block");
  });

  it("lists at most 10 flagged packages and says how many were omitted", () => {
    const flagged = Array.from({ length: 13 }, (_, i) =>
      result(`pkg-${String(i).padStart(2, "0")}`, "require_approval"),
    );
    const out = aggregateWithTransitive(assessment(), flagged);
    const deepReasons = out.reasons.filter((r) => r.includes(": require_approval"));
    expect(deepReasons).toHaveLength(10);
    expect(out.reasons.join(" ")).toContain("and 3 more flagged transitive dependencies");
  });
});
