import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadApprovals, recordApproval } from "../src/approvals.js";
import { initPolicy, loadPolicy, PolicyError } from "../src/policy.js";

let dir: string;

beforeEach(() => {
  // Executable formats are migration-only and require explicit consent.
  vi.stubEnv("TARGATE_ALLOW_EXEC_CONFIG", "1");
  vi.spyOn(console, "error").mockImplementation(() => {});
});

async function scratch(): Promise<string> {
  dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
  return dir;
}

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("policy formats", () => {
  it("loads targate.policy.yaml", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.yaml"),
      "dependencyPolicy:\n  minPackageAgeDays: 14\n",
    );
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(14);
    expect(path.basename(loaded!.file)).toBe("targate.policy.yaml");
  });

  it("loads targate.policy.json", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.json"),
      JSON.stringify({ dependencyPolicy: { blockPackages: ["evil"] } }),
    );
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.blockPackages).toEqual(["evil"]);
  });

  it("loads targate.policy.js (default export)", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.js"),
      `export default { dependencyPolicy: { requireApprovalForNativeCode: true } };\n`,
    );
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.requireApprovalForNativeCode).toBe(true);
  });

  it("loads targate.policy.ts with type annotations", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.ts"),
      [
        `interface P { dependencyPolicy: { minPackageAgeDays?: number; allowKnownPackages?: string[] } }`,
        `const policy: P = { dependencyPolicy: { minPackageAgeDays: 30, allowKnownPackages: ["react"] } };`,
        `export default policy;`,
      ].join("\n"),
    );
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(30);
    expect(loaded?.policy.dependencyPolicy.allowKnownPackages).toEqual(["react"]);
  });

  it("prefers ts over yaml over json when multiple exist", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.json"),
      JSON.stringify({ dependencyPolicy: { minPackageAgeDays: 1 } }),
    );
    await writeFile(path.join(cwd, "targate.policy.yaml"), "dependencyPolicy:\n  minPackageAgeDays: 2\n");
    await writeFile(
      path.join(cwd, "targate.policy.ts"),
      `export default { dependencyPolicy: { minPackageAgeDays: 3 } };\n`,
    );
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(3);
  });

  it("validates js/ts policies like any other format", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.js"),
      `export default { dependencyPolicy: { minPackageAgeDays: "banana" } };\n`,
    );
    await expect(loadPolicy(cwd)).rejects.toThrow(PolicyError);
  });

  it("returns null when no policy file exists", async () => {
    const cwd = await scratch();
    expect(await loadPolicy(cwd)).toBeNull();
  });
});

describe("policy init formats", () => {
  it.each(["yaml", "json", "js", "ts"] as const)("scaffolds a loadable %s policy", async (format) => {
    const cwd = await scratch();
    const file = await initPolicy(cwd, format);
    expect(file).toBe(path.join(cwd, `targate.policy.${format}`));
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(7);
  });

  it("refuses to scaffold when a policy in another format exists", async () => {
    const cwd = await scratch();
    await initPolicy(cwd, "json");
    expect(await initPolicy(cwd, "ts")).toBeNull();
  });

  it("ts template uses a type-only import (loads without targate installed)", async () => {
    const cwd = await scratch();
    const file = await initPolicy(cwd, "ts");
    const content = await readFile(file!, "utf8");
    expect(content).toContain('import type { PolicyFile } from "targate"');
    // Already proven loadable by the it.each above, but make the intent explicit:
    expect((await loadPolicy(cwd))?.policy).toBeTruthy();
  });
});

describe("approvals formats", () => {
  it("reads yaml approvals", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.yaml"),
      `"core-js@3.49.0":\n  mode: no-scripts\n  approvedAt: 2026-07-07T00:00:00Z\n`,
    );
    const approvals = await loadApprovals(cwd);
    expect(approvals["core-js@3.49.0"]?.mode).toBe("no-scripts");
  });

  it("reads ts approvals", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.ts"),
      `export default { "left-pad@1.3.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } };\n`,
    );
    const approvals = await loadApprovals(cwd);
    expect(approvals["left-pad@1.3.0"]?.mode).toBe("normal");
  });

  it("merges all sources with tool-written json taking precedence", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.ts"),
      `export default {
        "a@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" },
        "b@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" },
      };\n`,
    );
    await recordApproval("b", "1.0.0", "no-scripts", cwd); // writes approvals.json
    const approvals = await loadApprovals(cwd);
    expect(approvals["a@1.0.0"]?.mode).toBe("normal"); // from ts
    expect(approvals["b@1.0.0"]?.mode).toBe("no-scripts"); // json wins
  });

  it("recording never touches hand-curated sources", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    const tsSource = `export default { "a@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } };\n`;
    await writeFile(path.join(cwd, ".targate", "approvals.ts"), tsSource);
    await recordApproval("c", "2.0.0", "normal", cwd);
    expect(await readFile(path.join(cwd, ".targate", "approvals.ts"), "utf8")).toBe(tsSource);
    const json = JSON.parse(await readFile(path.join(cwd, ".targate", "approvals.json"), "utf8"));
    expect(Object.keys(json)).toEqual(["c@2.0.0"]);
  });

  it("ignores a broken source instead of crashing", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(path.join(cwd, ".targate", "approvals.js"), "export default {{{ nope\n");
    await writeFile(
      path.join(cwd, ".targate", "approvals.json"),
      JSON.stringify({ "x@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    const approvals = await loadApprovals(cwd);
    expect(approvals["x@1.0.0"]?.mode).toBe("normal");
  });
});
