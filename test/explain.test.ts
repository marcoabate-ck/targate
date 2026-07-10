import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { explainCommand } from "../src/commands/explain.js";
import { writeLastRun, type LastRunPackage } from "../src/last-run.js";
import { renderExplanation, residualRisks } from "../src/report.js";
import { computeSecurityScore } from "../src/score.js";
import { makeSignals } from "./helpers.js";

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

async function buildTarball(): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({ name: "left-pad", version: "1.3.0" }),
    );
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

function stubNetwork(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) {
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      }
      if (url.includes("api.npmjs.org/downloads")) {
        return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      }
      if (url.includes("api.github.com")) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({ archived: false }) };
      }
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => new Uint8Array(tarballBytes).buffer };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: "1.3.0" },
          versions: {
            "1.3.0": {
              name: "left-pad",
              repository: { url: "https://github.com/x/left-pad" },
              maintainers: [{ name: "x" }],
              dist: { tarball: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" },
              scripts: {},
              dependencies: {},
            },
          },
          time: { created: "2016-01-01T00:00:00Z", "1.3.0": "2018-01-01T00:00:00Z" },
        }),
      };
    }),
  );
}

function makeLastRunPackage(): LastRunPackage {
  const signals = makeSignals({ package: "left-pad", version: "1.3.0" });
  return {
    metadata: {
      name: "left-pad",
      version: "1.3.0",
      maintainers: ["x"],
      tarballUrl: "https://reg/x.tgz",
      scripts: {},
      dependencyCount: 0,
      directDependencies: [],
      registryReputation: { hasProvenance: false },
    },
    signals,
    assessment: {
      risk: "low",
      decision: "allow",
      summary: "clean",
      reasons: ["No lifecycle scripts."],
      recommendedAction: "Safe to install normally.",
      source: "rules",
    },
    score: computeSecurityScore(signals),
  };
}

beforeAll(async () => {
  tarballBytes = await buildTarball();
});

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-explain-"));
  process.chdir(dir);
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("explain <spec> (fresh analysis)", () => {
  it("emits a single JSON envelope and exits 0", async () => {
    stubNetwork();
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.join(" "));
    });
    const code = await explainCommand({
      spec: "left-pad@1.3.0",
      last: false,
      json: true,
      assess: { useAi: false },
    });
    spy.mockRestore();

    expect(code).toBe(0);
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.command).toBe("explain");
    expect(parsed.source).toBe("fresh");
    expect(parsed.packages).toHaveLength(1);
    expect(parsed.packages[0].assessment.decision).toBe("allow");
    expect(parsed.packages[0].score.total).toBeGreaterThan(0);
  });

  it("does not write the last-run record (explain is a lens, not a run)", async () => {
    stubNetwork();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    await explainCommand({ spec: "left-pad@1.3.0", last: false, json: true, assess: { useAi: false } });
    spy.mockRestore();
    await expect(readFile(path.join(dir, ".targate", "last-run.json"))).rejects.toThrow();
  });
});

describe("explain --last", () => {
  it("reads the recorded run without any network access", async () => {
    await writeLastRun("add", [makeLastRunPackage()], dir);
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("explain --last must not hit the network");
    }));

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.join(" "));
    });
    const code = await explainCommand({ last: true, json: true, assess: { useAi: false } });
    spy.mockRestore();

    expect(code).toBe(0);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.source).toBe("last-run");
    expect(parsed.originCommand).toBe("add");
    expect(parsed.packages[0].metadata.name).toBe("left-pad");
  });

  it("exits 1 with an actionable message when no run is recorded", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...args) => {
      errors.push(args.join(" "));
    });
    const code = await explainCommand({ last: true, json: false, assess: { useAi: false } });
    spy.mockRestore();

    expect(code).toBe(1);
    expect(errors.join("\n")).toContain("no recorded run found");
  });
});

describe("residualRisks", () => {
  it("is empty for a fully clean package", () => {
    expect(residualRisks(makeSignals())).toEqual([]);
  });

  it("names the honest caveats", () => {
    const risks = residualRisks(
      makeSignals({
        hasNativeCode: true,
        hasLifecycleScripts: true,
        osvUnavailable: true,
        content: {
          hasProcessEnvAccess: true,
          hasChildProcessUsage: false,
          hasNetworkCalls: true,
          hasEvalUsage: false,
          hasMinifiedCode: true,
          suspiciousFiles: [],
          installTimeFindings: [],
        },
      }),
    );
    expect(risks.join("\n")).toContain("native/compiled code");
    expect(risks.join("\n")).toContain("lifecycle scripts");
    expect(risks.join("\n")).toContain("UNKNOWN");
    expect(risks.join("\n")).toContain("exfiltration");
    expect(risks.join("\n")).toContain("minified");
  });
});

describe("renderExplanation", () => {
  const pkg = makeLastRunPackage();

  it("partitions engine reasons from team/policy adjustments", () => {
    const out = renderExplanation(
      pkg.metadata,
      pkg.signals,
      {
        ...pkg.assessment,
        reasons: ["Rules engine finding.", "[policy] Team policy requires approval.", "[team] already approved."],
      },
      pkg.score,
    );
    expect(out).toContain("Main reasons");
    expect(out).toContain("1. Rules engine finding.");
    expect(out).toContain("Team & policy adjustments");
    expect(out).toContain("[policy] Team policy requires approval.");
    // Adjustments must not appear in the numbered list.
    expect(out).not.toContain("2. [policy]");
  });

  it("labels engine reasons as AI reasoning when the source is ai", () => {
    const out = renderExplanation(pkg.metadata, pkg.signals, { ...pkg.assessment, source: "ai" }, pkg.score);
    expect(out).toContain("AI reasoning");
    expect(out).not.toContain("Main reasons");
  });

  it("shows the deterministic verdict block before the AI reasoning", () => {
    const out = renderExplanation(
      pkg.metadata,
      pkg.signals,
      {
        ...pkg.assessment,
        source: "ai",
        deterministic: {
          decision: "require_approval",
          risk: "medium",
          reasons: ["Package has lifecycle scripts."],
        },
      },
      pkg.score,
    );
    expect(out).toContain("Deterministic verdict (rules engine)");
    expect(out).toContain("REQUIRE MANUAL APPROVAL");
    expect(out).toContain("Package has lifecycle scripts.");
    expect(out.indexOf("Deterministic verdict")).toBeLessThan(out.indexOf("AI reasoning"));
  });

  it("includes the deterministic findings, score, and last-run banner", () => {
    const out = renderExplanation(pkg.metadata, pkg.signals, pkg.assessment, pkg.score, {
      fromLastRun: { command: "add", timestamp: "2026-07-10T09:00:00Z" },
    });
    expect(out).toContain("Deterministic findings");
    expect(out).toContain("Security score:");
    expect(out).toContain("from last add run");
  });

  it("mentions a committed approval when provided", () => {
    const out = renderExplanation(pkg.metadata, pkg.signals, pkg.assessment, pkg.score, {
      approval: { mode: "no-scripts", approvedAt: "2026-07-01T00:00:00Z", approvedBy: "marco" },
    });
    expect(out).toContain("committed team approval");
    expect(out).toContain("no-scripts");
  });
});
