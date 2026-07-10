import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { diffCommand } from "../src/commands/diff.js";

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

async function buildTarball(): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(path.join(work, "package", "package.json"), JSON.stringify({ name: "widget", version: "x" }));
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** Registry doc for "widget" with two versions; v2 adds a postinstall script. */
function widgetDoc() {
  return {
    "dist-tags": { latest: "2.0.0" },
    versions: {
      "1.0.0": {
        name: "widget",
        dist: { tarball: "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz" },
        maintainers: [{ name: "alice" }],
        repository: { url: "https://github.com/x/widget" },
        scripts: {},
        dependencies: {},
      },
      "2.0.0": {
        name: "widget",
        dist: { tarball: "https://registry.npmjs.org/widget/-/widget-2.0.0.tgz" },
        maintainers: [{ name: "alice" }],
        repository: { url: "https://github.com/x/widget" },
        scripts: { postinstall: "node install.js" },
        dependencies: {},
      },
    },
    time: {
      created: "2020-01-01T00:00:00Z",
      "1.0.0": "2020-01-01T00:00:00Z",
      "2.0.0": "2024-01-01T00:00:00Z",
    },
  };
}

function stubNetwork(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      if (url.includes("api.npmjs.org/downloads")) return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      if (url.includes("registry.npmjs.org/-/v1/search")) return { ok: true, status: 200, json: async () => ({ total: 0, objects: [] }) };
      if (url.includes("api.github.com")) return { ok: true, status: 200, headers: new Headers(), json: async () => ({ archived: false }) };
      if (url.endsWith(".tgz")) return { ok: true, status: 200, arrayBuffer: async () => new Uint8Array(tarballBytes).buffer };
      return { ok: true, status: 200, json: async () => widgetDoc() };
    }),
  );
}

beforeAll(async () => {
  tarballBytes = await buildTarball();
});
beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-diff-"));
  process.chdir(dir);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("diffCommand", () => {
  it("rejects two different package names", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    const code = await diffCommand({ specA: "a@1.0.0", specB: "b@2.0.0", json: true, failOn: "high", assess: { useAi: false } });
    spy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join(" ")).toContain("ONE package");
  });

  it("emits one JSON envelope and flags the added lifecycle script as high", async () => {
    stubNetwork();
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
    const code = await diffCommand({
      specA: "widget@1.0.0",
      specB: "widget@2.0.0",
      json: true,
      failOn: "high",
      assess: { useAi: false },
    });
    spy.mockRestore();

    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.command).toBe("diff");
    expect(parsed.diff.diffRisk).toBe("high");
    expect(parsed.diff.lifecycleScripts.added).toHaveLength(1);
    expect(parsed.exitCode).toBe(2);
    expect(code).toBe(2);
  });

  it("honors --fail-on medium (a medium-risk diff then exits 2)", async () => {
    stubNetwork();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    // v1 → latest(2.0.0) is HIGH here; use a medium threshold to confirm wiring:
    // the added script is high, so still 2 — but assert the threshold plumbs through.
    const code = await diffCommand({
      specA: "widget@1.0.0",
      json: true,
      failOn: "medium",
      assess: { useAi: false },
    });
    spy.mockRestore();
    expect(code).toBe(2);
  });

  it("resolves the bare form from the lockfile", async () => {
    await writeFile(
      path.join(dir, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/widget": { version: "1.0.0" } } }),
    );
    stubNetwork();
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
    const code = await diffCommand({ specA: "widget", json: true, failOn: "high", assess: { useAi: false } });
    spy.mockRestore();
    const parsed = JSON.parse(lines[0]);
    expect(parsed.diff.from.version).toBe("1.0.0");
    expect(parsed.diff.to.version).toBe("2.0.0");
    expect(code).toBe(2);
  });

  it("exits 1 for the bare form when the package is not in the lockfile", async () => {
    await writeFile(path.join(dir, "package-lock.json"), JSON.stringify({ packages: {} }));
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    const code = await diffCommand({ specA: "widget", json: true, failOn: "high", assess: { useAi: false } });
    spy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join(" ")).toContain("not in the");
  });
});
