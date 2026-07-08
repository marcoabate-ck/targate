import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { checkCommand } from "../src/commands/check.js";

/**
 * The agent skill tells agents to run `targate add <pkg> --json` and parse stdout
 * as JSON. That only works if stdout is EXACTLY the JSON document — no
 * progress narration, no post-install lines. This guards that contract.
 */

let dir: string;
let tarballBytes: Buffer;
let cwd: string;

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

beforeAll(async () => {
  tarballBytes = await buildTarball();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (cwd) process.chdir(cwd);
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("targate add --json emits only JSON on stdout (agent contract)", () => {
  it("stdout parses as a single JSON document with the documented keys", async () => {
    cwd = process.cwd();
    dir = await mkdtemp(path.join(tmpdir(), "targate-json-"));
    process.chdir(dir); // isolate cache/policy/approvals/lockfile lookups
    stubNetwork();

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.join(" "));
    });

    const code = await checkCommand({
      spec: "left-pad@1.3.0",
      json: true,
      dryRun: true,
      assumeYes: true,
      assess: { useAi: false },
    });
    spy.mockRestore();

    expect(code).toBe(0);
    // Exactly one console.log call, and it is valid JSON with the right shape.
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(Object.keys(parsed).sort()).toEqual(["assessment", "deep", "metadata", "signals"]);
    expect(parsed.assessment.decision).toBe("allow");
    expect(parsed.deep).toBeNull();
  });
});
