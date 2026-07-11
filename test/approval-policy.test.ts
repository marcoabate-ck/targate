import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InstallReport } from "../src/full-install.js";
import type { RiskAssessment } from "../src/types.js";
import { makeMetadata, makeSignals } from "./helpers.js";

/**
 * Command-level acceptance specs for approval and script-policy semantics.
 * These are release-blocker acceptance tests: none may regress to expected failure.
 */

let originalCwd: string;
const tempDirs: string[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function assessment(decision: RiskAssessment["decision"]): RiskAssessment {
  return {
    risk: decision === "block" ? "high" : decision === "allow" ? "low" : "medium",
    decision,
    summary: `${decision} summary`,
    reasons: [`${decision} reason`],
    recommendedAction: "Review the package.",
    source: "rules",
  };
}

beforeEach(() => {
  originalCwd = process.cwd();
  vi.resetModules();
});

afterEach(async () => {
  process.chdir(originalCwd);
  vi.restoreAllMocks();
  vi.doUnmock("../src/pipeline.js");
  vi.doUnmock("../src/transitive.js");
  vi.doUnmock("../src/full-install.js");
  vi.resetModules();
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("approval script policy", () => {
  it("a transitive no-scripts approval forces the final add command to disable scripts", async () => {
    const dir = await tempDir("targate-deep-no-scripts-");
    process.chdir(dir);
    await mkdir(path.join(dir, ".targate"));
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({
        "transitive-build@2.0.0": {
          mode: "no-scripts",
          approvedAt: "2026-01-01T00:00:00.000Z",
        },
      }),
    );

    const metadata = makeMetadata({ name: "root-package", version: "1.0.0" });
    const signals = makeSignals({ package: "root-package", version: "1.0.0" });

    vi.doMock("../src/pipeline.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/pipeline.js")>();
      return {
        ...actual,
        analyzePackage: vi.fn(async () => ({
          metadata,
          signals,
          assessment: assessment("allow"),
          score: {
            total: 100,
            categories: [{ name: "fixture", label: "Fixture", score: 100, max: 100 }],
          },
        })),
      };
    });
    vi.doMock("../src/transitive.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/transitive.js")>();
      return {
        ...actual,
        resolveTransitiveTree: vi.fn(async () => [
          { name: "transitive-build", version: "2.0.0" },
        ]),
        analyzeTransitiveDeps: vi.fn(async () => [
          {
            name: "transitive-build",
            version: "2.0.0",
            hardBlock: false,
            assessment: assessment("require_approval"),
          },
        ]),
      };
    });

    const { checkCommand } = await import("../src/commands/check.js");
    const output: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => output.push(args.join(" ")));

    const code = await checkCommand({
      spec: "root-package@1.0.0",
      packageManager: "npm",
      json: false,
      dryRun: true,
      assumeYes: true,
      deep: true,
      assess: { useAi: false },
    });

    expect(code).toBe(0);
    expect(output.join("\n")).toContain("npm install root-package@1.0.0 --ignore-scripts");
  });

  it("full install cannot override a no-scripts approval with --allow-scripts", async () => {
    const dir = await tempDir("targate-install-no-scripts-");
    process.chdir(dir);

    const report: InstallReport = {
      packageManager: "npm",
      source: "lockfile",
      total: 1,
      results: [
        {
          name: "transitive-build",
          version: "2.0.0",
          hardBlock: false,
          approved: true,
          approvalMode: "no-scripts",
          assessment: assessment("require_approval"),
        } as InstallReport["results"][number],
      ],
      decision: "require_approval",
      exitCode: 0,
    };

    vi.doMock("../src/full-install.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/full-install.js")>();
      return { ...actual, vetInstall: vi.fn(async () => report) };
    });

    const { installCommand } = await import("../src/commands/install.js");
    const output: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => output.push(args.join(" ")));

    const code = await installCommand({
      packageManager: "npm",
      json: false,
      dryRun: true,
      assumeYes: true,
      allowScripts: true,
      assess: { useAi: false },
    });

    expect(code).toBe(0);
    expect(output.join("\n")).toContain("npm install --ignore-scripts");
  });

  it("an approved soft block is not listed as unresolved again", async () => {
    const dir = await tempDir("targate-install-unresolved-");
    process.chdir(dir);

    const report: InstallReport = {
      packageManager: "npm",
      source: "lockfile",
      total: 2,
      results: [
        {
          name: "approved-soft",
          version: "1.0.0",
          hardBlock: false,
          approved: true,
          assessment: assessment("block"),
        },
        {
          name: "still-needs-review",
          version: "1.0.0",
          hardBlock: false,
          approved: false,
          assessment: assessment("require_approval"),
        },
      ],
      decision: "block",
      exitCode: 2,
    };

    vi.doMock("../src/full-install.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/full-install.js")>();
      return { ...actual, vetInstall: vi.fn(async () => report) };
    });

    const { installCommand } = await import("../src/commands/install.js");
    const output: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => output.push(args.join(" ")));

    const code = await installCommand({
      packageManager: "npm",
      json: false,
      dryRun: true,
      assumeYes: true,
      assess: { useAi: false },
    });

    expect(code).toBe(2);
    expect(output.join("\n")).not.toContain("approved-soft");
  });
});
