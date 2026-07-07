import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  aggregateInstallDecision,
  treeFromLockfile,
  vetInstall,
  type InstallVetResult,
} from "../src/full-install.js";
import type { PackageAnalysis } from "../src/pipeline.js";
import type { TransitiveResult } from "../src/transitive.js";
import type { Decision, RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

function assessment(decision: Decision): RiskAssessment {
  return {
    risk: decision === "block" ? "high" : "low",
    decision,
    summary: `${decision} summary`,
    reasons: [`${decision} reason`],
    recommendedAction: "x",
    source: "rules",
  };
}

function vet(name: string, decision: Decision, approved = false): InstallVetResult {
  return { name, version: "1.0.0", assessment: assessment(decision), approved };
}

describe("treeFromLockfile", () => {
  it("enumerates the whole npm lockfile, de-duped and sorted", () => {
    const lock = JSON.stringify({
      packages: {
        "": { name: "root" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/@scope/util": { version: "2.0.0" },
        "node_modules/dep/node_modules/left-pad": { version: "1.3.0" }, // dup of above
      },
    });
    expect(treeFromLockfile("npm", lock)).toEqual([
      { name: "@scope/util", version: "2.0.0" },
      { name: "left-pad", version: "1.3.0" },
    ]);
  });

  it("parses pnpm lockfile packages", () => {
    const lock = ["packages:", "", "  left-pad@1.3.0:", "    resolution: {integrity: sha512-x}"].join("\n");
    expect(treeFromLockfile("pnpm", lock)).toEqual([{ name: "left-pad", version: "1.3.0" }]);
  });
});

describe("aggregateInstallDecision", () => {
  it("returns allow / exit 0 for a fully clean tree", () => {
    expect(aggregateInstallDecision([vet("a", "allow"), vet("b", "allow")])).toEqual({
      decision: "allow",
      exitCode: 0,
    });
  });

  it("takes the strictest decision and exits 2 on a block", () => {
    const out = aggregateInstallDecision([vet("a", "allow"), vet("evil", "block")]);
    expect(out.decision).toBe("block");
    expect(out.exitCode).toBe(2);
  });

  it("exits 2 for an unapproved require_approval but 0 when it is approved", () => {
    expect(aggregateInstallDecision([vet("a", "require_approval", false)]).exitCode).toBe(2);
    const approved = aggregateInstallDecision([vet("a", "require_approval", true)]);
    expect(approved.exitCode).toBe(0);
    expect(approved.decision).toBe("require_approval"); // still the strictest label…
  });

  it("allow_with_warnings never fails the build", () => {
    expect(aggregateInstallDecision([vet("a", "allow_with_warnings")])).toEqual({
      decision: "allow_with_warnings",
      exitCode: 0,
    });
  });
});

describe("vetInstall (over a fixture lockfile, injected analyzer)", () => {
  async function fixture(lock: string): Promise<string> {
    dir = await mkdtemp(path.join(tmpdir(), "bye-vet-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "app" }));
    await writeFile(path.join(dir, "package-lock.json"), lock);
    return dir;
  }

  const lock = JSON.stringify({
    packages: {
      "node_modules/good": { version: "1.0.0" },
      "node_modules/evil": { version: "6.6.6" },
    },
  });

  // Analyzer stub: "evil" blocks, everything else allows. No network.
  const analyzeAll: typeof import("../src/transitive.js").analyzeTransitiveDeps = async (
    packages,
    o,
  ) => {
    return packages.map((p, i) => {
      const decision: Decision = p.name === "evil" ? "block" : "allow";
      const r: TransitiveResult = { name: p.name, version: p.version, assessment: assessment(decision) };
      o.onResult?.(r, i, packages.length);
      return r;
    });
  };

  it("reads the lockfile, vets every package, and blocks the tree", async () => {
    const cwd = await fixture(lock);
    const report = await vetInstall({
      packageManager: "npm",
      cwd,
      assess: { useAi: false },
      approvals: {},
      analyzeAll,
    });
    expect(report.source).toBe("lockfile");
    expect(report.total).toBe(2);
    expect(report.decision).toBe("block");
    expect(report.exitCode).toBe(2);
    expect(report.results.find((r) => r.name === "evil")?.assessment.decision).toBe("block");
  });

  it("passes (exit 0) when a flagged package is pre-approved", async () => {
    const raLock = JSON.stringify({ packages: { "node_modules/needs": { version: "2.0.0" } } });
    const cwd = await fixture(raLock);
    const raAnalyzer: typeof analyzeAll = async (packages, o) =>
      packages.map((p, i) => {
        const r: TransitiveResult = { name: p.name, version: p.version, assessment: assessment("require_approval") };
        o.onResult?.(r, i, packages.length);
        return r;
      });

    const blocked = await vetInstall({
      packageManager: "npm",
      cwd,
      assess: { useAi: false },
      approvals: {},
      analyzeAll: raAnalyzer,
    });
    expect(blocked.exitCode).toBe(2);

    const approved = await vetInstall({
      packageManager: "npm",
      cwd,
      assess: { useAi: false },
      approvals: { "needs@2.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } },
      analyzeAll: raAnalyzer,
    });
    expect(approved.exitCode).toBe(0);
    expect(approved.results[0].approved).toBe(true);
  });
});
