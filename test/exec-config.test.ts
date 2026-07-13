import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadApprovals } from "../src/approvals.js";
import { execConfigDisabled, loadConfigFile } from "../src/config-loader.js";
import { findPolicyFile } from "../src/policy.js";

/**
 * Executable policy/approval files are disabled by default. They run only
 * after the operator explicitly sets TARGATE_ALLOW_EXEC_CONFIG=1.
 */

let dir: string;

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("execConfigDisabled", () => {
  it("is on by default and requires an exact opt-in", () => {
    expect(execConfigDisabled({})).toBe(true);
    expect(execConfigDisabled({ TARGATE_ALLOW_EXEC_CONFIG: "true" })).toBe(true);
    expect(execConfigDisabled({ TARGATE_ALLOW_EXEC_CONFIG: "1" })).toBe(false);
    expect(execConfigDisabled({ TARGATE_ALLOW_EXEC_CONFIG: "1", TARGATE_NO_EXEC_CONFIG: "1" })).toBe(true);
    expect(execConfigDisabled({ TARGATE_NO_EXEC_CONFIG: "1" })).toBe(true);
  });
});

describe("TARGATE_ALLOW_EXEC_CONFIG", () => {
  it("loadConfigFile refuses to execute a .js config by default", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-execcfg-"));
    const file = path.join(dir, "targate.policy.js");
    await writeFile(file, "module.exports = { dependencyPolicy: {} };\n");
    await expect(loadConfigFile(file)).rejects.toThrow(/TARGATE_ALLOW_EXEC_CONFIG=1/);
  });

  it("findPolicyFile skips an executable policy and falls through to yaml", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-execcfg-"));
    await writeFile(path.join(dir, "targate.policy.js"), "throw new Error('must not run');\n");
    await writeFile(path.join(dir, "targate.policy.yaml"), "dependencyPolicy: {}\n");
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(findPolicyFile(dir)).toBe(path.join(dir, "targate.policy.yaml"));
    // The skip is visible on stderr, never silent.
    expect(warn.mock.calls.some((c) => String(c[0]).includes("targate.policy.js"))).toBe(true);

    // Explicit opt-in restores executable config during migration.
    vi.stubEnv("TARGATE_ALLOW_EXEC_CONFIG", "1");
    expect(findPolicyFile(dir)).toBe(path.join(dir, "targate.policy.js"));
  });

  it("loadApprovals ignores executable sources but still merges json", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-execcfg-"));
    await mkdir(path.join(dir, ".targate"));
    await writeFile(
      path.join(dir, ".targate", "approvals.js"),
      "module.exports = { 'evil@1.0.0': { mode: 'normal', approvedAt: '2026-01-01T00:00:00Z' } };\n",
    );
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({ "left-pad@1.3.0": { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    vi.spyOn(console, "error").mockImplementation(() => {});

    const approvals = await loadApprovals(dir);
    // The js-sourced approval is gone (safe direction: the package asks again);
    // the declarative json still loads.
    expect(approvals["evil@1.0.0"]).toBeUndefined();
    expect(approvals["left-pad@1.3.0"]?.mode).toBe("no-scripts");
  });

  it("executes only after opt-in and emits a strong warning", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-execcfg-"));
    const file = path.join(dir, "targate.policy.js");
    await writeFile(file, "module.exports = { dependencyPolicy: {} };\n");
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubEnv("TARGATE_ALLOW_EXEC_CONFIG", "1");
    await expect(loadConfigFile(file)).resolves.toMatchObject({ dependencyPolicy: {} });
    expect(warn.mock.calls.some((call) => String(call[0]).includes("WARNING"))).toBe(true);
  });
});
