import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { diffDependencies, initCiWorkflow } from "../src/ci.js";

describe("diffDependencies", () => {
  it("detects added dependencies", () => {
    const changes = diffDependencies(
      { dependencies: { react: "^18.0.0" } },
      { dependencies: { react: "^18.0.0", "left-pad": "^1.3.0" } },
    );
    expect(changes).toEqual([
      { name: "left-pad", range: "^1.3.0", kind: "added", section: "dependencies" },
    ]);
  });

  it("detects updated ranges", () => {
    const changes = diffDependencies(
      { dependencies: { axios: "^1.0.0" } },
      { dependencies: { axios: "^1.7.0" } },
    );
    expect(changes[0]).toMatchObject({
      name: "axios",
      kind: "updated",
      previousRange: "^1.0.0",
      range: "^1.7.0",
    });
  });

  it("covers devDependencies too", () => {
    const changes = diffDependencies(
      {},
      { devDependencies: { vitest: "^4.0.0" } },
    );
    expect(changes[0]).toMatchObject({ name: "vitest", section: "devDependencies" });
  });

  it("ignores removals and unchanged deps", () => {
    const changes = diffDependencies(
      { dependencies: { a: "1.0.0", b: "2.0.0" } },
      { dependencies: { a: "1.0.0" } },
    );
    expect(changes).toEqual([]);
  });

  it("treats an empty base as all-added", () => {
    const changes = diffDependencies({}, { dependencies: { a: "1.0.0" } });
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("added");
  });
});

describe("initCiWorkflow", () => {
  it("scaffolds a valid workflow that keeps GitHub context out of the run line", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "bye-workflow-"));
    try {
      const file = await initCiWorkflow(dir);
      expect(file).toBe(path.join(dir, ".github", "workflows", "bye.yml"));
      const content = await readFile(file!, "utf8");

      // Parseable YAML with the expected job step.
      const doc = parseYaml(content) as {
        jobs?: { bye?: { steps?: Array<{ run?: string; env?: Record<string, string> }> } };
      };
      const steps = doc.jobs?.bye?.steps ?? [];
      const analyze = steps.find((s) => s.run?.includes("bye ci"));
      expect(analyze).toBeDefined();

      // Script-injection defense: `${{ … }}` only in env values, never in run.
      expect(analyze!.run).not.toContain("${{");
      expect(analyze!.run).toContain('"origin/$BASE_REF"');
      expect(analyze!.run).toContain("--fail-on-osv-error");
      expect(analyze!.env?.BASE_REF).toBe("${{ github.base_ref }}");

      // Second call is a no-op.
      expect(await initCiWorkflow(dir)).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
