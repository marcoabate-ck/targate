import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadApprovals } from "../src/approvals.js";
import { vetInstall } from "../src/full-install.js";
import { gateInstall } from "../src/installer.js";
import { clampDecision, evaluateRules } from "../src/rules.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

/**
 * Release-blocking trust invariants captured before their production fixes.
 * `it.fails` means the desired assertion exposes a known bug today; remove
 * `.fails` when the corresponding invariant is implemented.
 */

const tempDirs: string[] = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function aiAllow(): RiskAssessment {
  return {
    risk: "low",
    decision: "allow",
    summary: "AI considers the package safe",
    reasons: ["AI found no contextual concern"],
    recommendedAction: "Install normally.",
    source: "ai",
  };
}

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("trust invariants", () => {
  it("the AI cannot lower deterministic require_approval to allow", () => {
    const signals = makeSignals({
      hasLifecycleScripts: true,
      lifecycleScripts: { postinstall: "node setup.js" },
    });

    expect(evaluateRules(signals).decision).toBe("require_approval");
    expect(clampDecision(aiAllow(), signals).decision).toBe("require_approval");
  });

  it("a non-zero package-manager exit is an install failure", async () => {
    // Spawn `node <script>` rather than a PATH-resolved shebang binary: an
    // extensionless shell script is not executable on Windows. Overriding the
    // command keeps this exit-code contract test OS-independent.
    const binDir = await tempDir("targate-fake-pm-");
    const script = path.join(binDir, "fake-pm.mjs");
    await writeFile(script, "process.exit(7);\n");
    const command = [process.execPath, script, "install"];

    const result = await gateInstall("allow", "pnpm", "example-package@1.0.0", {
      assumeYes: true,
      commands: { normal: command, noScripts: command },
    });

    expect(result).toMatchObject({
      status: "failed",
      installed: false,
      exitCode: 7,
    });
  });

  it("malformed approval records are ignored fail-safe", async () => {
    const dir = await tempDir("targate-invalid-approval-");
    await mkdir(path.join(dir, ".targate"));
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({
        "example-package@1.0.0": {
          mode: "unknown-mode",
          approvedAt: 42,
        },
      }),
    );

    expect(await loadApprovals(dir)).toEqual({});
  });

  it("full-tree review retains the no-scripts approval mode", async () => {
    const dir = await tempDir("targate-approval-mode-");
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    await writeFile(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        packages: {
          "node_modules/needs-review": { version: "1.0.0" },
        },
      }),
    );

    const report = await vetInstall({
      packageManager: "npm",
      cwd: dir,
      assess: { useAi: false },
      approvals: {
        "needs-review@1.0.0": {
          mode: "no-scripts",
          approvedAt: "2026-01-01T00:00:00.000Z",
        },
      },
      analyzeAll: async (packages) =>
        packages.map((pkg) => ({
          ...pkg,
          hardBlock: false,
          assessment: {
            risk: "medium",
            decision: "require_approval",
            summary: "Human review required",
            reasons: ["lifecycle scripts present"],
            recommendedAction: "Approve without scripts.",
            source: "rules",
          },
        })),
    });

    expect(report.results[0]).toMatchObject({
      approved: true,
      approvalMode: "no-scripts",
    });
  });
});
