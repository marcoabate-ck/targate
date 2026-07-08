import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { approveCommand, approveOutcome } from "../src/commands/approve.js";

describe("approveOutcome", () => {
  it("refuses a HARD block — never approvable", () => {
    expect(approveOutcome("block", true)).toBe("hard-blocked");
  });

  it("treats a SOFT block as approvable", () => {
    expect(approveOutcome("block", false)).toBe("approvable");
  });

  it("treats require_approval as approvable", () => {
    expect(approveOutcome("require_approval", false)).toBe("approvable");
  });

  it("needs no approval for allow / allow_with_warnings", () => {
    expect(approveOutcome("allow", false)).toBe("already-allowed");
    expect(approveOutcome("allow_with_warnings", false)).toBe("already-allowed");
  });
});

/**
 * Integration tests for the non-interactive hardening (security analysis
 * finding 7): recording an approval requires explicit human intent (--yes or
 * an interactive confirmation), --json alone never records, and approve is
 * refused outright in CI.
 */

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

// A package WITH a lifecycle script → rules engine says require_approval.
async function buildTarball(): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({
        name: "scripted-pkg",
        version: "1.0.0",
        scripts: { postinstall: "node setup.js" },
      }),
    );
    await writeFile(path.join(work, "package", "setup.js"), "console.log('build')\n");
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
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "scripted-pkg",
              repository: { url: "https://github.com/x/scripted-pkg" },
              maintainers: [{ name: "x" }],
              dist: { tarball: "https://registry.npmjs.org/scripted-pkg/-/scripted-pkg-1.0.0.tgz" },
              scripts: { postinstall: "node setup.js" },
              dependencies: {},
            },
          },
          time: { created: "2016-01-01T00:00:00Z", "1.0.0": "2018-01-01T00:00:00Z" },
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
  vi.unstubAllEnvs();
  if (cwd) process.chdir(cwd);
  if (dir) await rm(dir, { recursive: true, force: true });
});

async function setup(): Promise<void> {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-approve-"));
  process.chdir(dir);
  vi.stubEnv("CI", ""); // tests may themselves run in CI — neutralize
  stubNetwork();
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
}

const approvalsFile = () => path.join(dir, ".targate", "approvals.json");

describe("approve non-interactive hardening", () => {
  it("refuses to run in CI (exit 1, nothing analyzed or recorded)", async () => {
    await setup();
    vi.stubEnv("CI", "true");
    const code = await approveCommand({
      spec: "scripted-pkg@1.0.0",
      json: false,
      assumeYes: true,
      assess: { useAi: false },
    });
    expect(code).toBe(1);
    expect(existsSync(approvalsFile())).toBe(false);
  });

  it("--json WITHOUT --yes analyzes but records nothing", async () => {
    await setup();
    const code = await approveCommand({
      spec: "scripted-pkg@1.0.0",
      json: true,
      assumeYes: false,
      assess: { useAi: false },
    });
    expect(code).toBe(0);
    expect(existsSync(approvalsFile())).toBe(false);
  });

  it("--yes records the approval (explicit human intent)", async () => {
    await setup();
    const code = await approveCommand({
      spec: "scripted-pkg@1.0.0",
      json: true,
      assumeYes: true,
      assess: { useAi: false },
    });
    expect(code).toBe(0);
    const recorded = JSON.parse(await readFile(approvalsFile(), "utf8"));
    expect(recorded["scripted-pkg@1.0.0"].mode).toBe("no-scripts");
  });

  it("--yes --allow-scripts records mode normal", async () => {
    await setup();
    await approveCommand({
      spec: "scripted-pkg@1.0.0",
      json: true,
      assumeYes: true,
      allowScripts: true,
      assess: { useAi: false },
    });
    const recorded = JSON.parse(await readFile(approvalsFile(), "utf8"));
    expect(recorded["scripted-pkg@1.0.0"].mode).toBe("normal");
  });
});
