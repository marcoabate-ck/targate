import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadApprovals, recordApproval } from "../src/approvals.js";
import { initPolicy, loadPolicy, PolicyError } from "../src/policy.js";

let dir: string;

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
});

async function scratch(): Promise<string> {
  dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
  return dir;
}

afterEach(async () => {
  vi.restoreAllMocks();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("policy formats (declarative only)", () => {
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

  it("prefers yaml over json when both exist", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.json"),
      JSON.stringify({ dependencyPolicy: { minPackageAgeDays: 1 } }),
    );
    await writeFile(path.join(cwd, "targate.policy.yaml"), "dependencyPolicy:\n  minPackageAgeDays: 2\n");
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(2);
  });

  it("validates a declarative policy", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.yaml"),
      "dependencyPolicy:\n  minPackageAgeDays: banana\n",
    );
    await expect(loadPolicy(cwd)).rejects.toThrow(PolicyError);
  });

  it("returns null when no policy file exists", async () => {
    const cwd = await scratch();
    expect(await loadPolicy(cwd)).toBeNull();
  });

  // Regression: executable config was removed. A legacy targate.policy.ts must
  // be IGNORED (not loaded, not executed), so loadPolicy sees no policy.
  it("ignores a legacy executable targate.policy.ts", async () => {
    const cwd = await scratch();
    await writeFile(
      path.join(cwd, "targate.policy.ts"),
      `export default { dependencyPolicy: { minPackageAgeDays: 99 } };\n`,
    );
    expect(await loadPolicy(cwd)).toBeNull();
  });
});

describe("policy init formats (declarative only)", () => {
  it.each(["yaml", "json"] as const)("scaffolds a loadable %s policy", async (format) => {
    const cwd = await scratch();
    const file = await initPolicy(cwd, format);
    expect(file).toBe(path.join(cwd, `targate.policy.${format}`));
    const loaded = await loadPolicy(cwd);
    expect(loaded?.policy.dependencyPolicy.minPackageAgeDays).toBe(7);
  });

  it("refuses to scaffold when a policy in another format exists", async () => {
    const cwd = await scratch();
    await initPolicy(cwd, "json");
    expect(await initPolicy(cwd, "yaml")).toBeNull();
  });
});

describe("approvals formats (declarative only)", () => {
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

  // Regression (v4 LOW): a `__proto__` key in a committed approvals.json must
  // not pollute a prototype, and normal keys must still load.
  it("ignores a __proto__ key in approvals.json without polluting Object.prototype", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.json"),
      JSON.stringify({
        "__proto__": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z", polluted: true },
        "safe@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" },
      }),
    );
    const approvals = await loadApprovals(cwd);
    expect(approvals["safe@1.0.0"]?.mode).toBe("normal");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("merges yaml and json, with tool-written json taking precedence", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.yaml"),
      `"a@1.0.0":\n  mode: normal\n  approvedAt: 2026-01-01T00:00:00Z\n"b@1.0.0":\n  mode: normal\n  approvedAt: 2026-01-01T00:00:00Z\n`,
    );
    await recordApproval("b", "1.0.0", "no-scripts", cwd); // writes approvals.json
    const approvals = await loadApprovals(cwd);
    expect(approvals["a@1.0.0"]?.mode).toBe("normal"); // from yaml
    expect(approvals["b@1.0.0"]?.mode).toBe("no-scripts"); // json wins
  });

  it("recording never touches hand-curated sources", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    const yamlSource = `"a@1.0.0":\n  mode: normal\n  approvedAt: 2026-01-01T00:00:00Z\n`;
    await writeFile(path.join(cwd, ".targate", "approvals.yaml"), yamlSource);
    await recordApproval("c", "2.0.0", "normal", cwd);
    expect(await readFile(path.join(cwd, ".targate", "approvals.yaml"), "utf8")).toBe(yamlSource);
    const json = JSON.parse(await readFile(path.join(cwd, ".targate", "approvals.json"), "utf8"));
    expect(Object.keys(json)).toEqual(["c@2.0.0"]);
  });

  it("ignores a broken source instead of crashing", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(path.join(cwd, ".targate", "approvals.yaml"), '"x@1.0.0": [unclosed\n');
    await writeFile(
      path.join(cwd, ".targate", "approvals.json"),
      JSON.stringify({ "x@1.0.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    const approvals = await loadApprovals(cwd);
    expect(approvals["x@1.0.0"]?.mode).toBe("normal");
  });

  // Regression: a legacy .targate/approvals.ts is IGNORED, not executed.
  it("ignores a legacy executable approvals.ts", async () => {
    const cwd = await scratch();
    await mkdir(path.join(cwd, ".targate"));
    await writeFile(
      path.join(cwd, ".targate", "approvals.ts"),
      `export default { "left-pad@1.3.0": { mode: "normal", approvedAt: "2026-01-01T00:00:00Z" } };\n`,
    );
    expect(Object.keys(await loadApprovals(cwd))).toEqual([]);
  });
});
