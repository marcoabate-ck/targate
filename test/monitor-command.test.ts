import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { monitorCommand } from "../src/commands/monitor.js";

let dir: string;
let cwd: string;

/** widget has a malicious record; happy has none. */
function stubNetwork(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) {
        // querybatch: echo a MAL record for widget only.
        const body = init?.body ? JSON.parse(String(init.body)) : {};
        if (Array.isArray(body.queries)) {
          const results = body.queries.map((q: { package: { name: string } }) =>
            q.package.name === "widget" ? { vulns: [{ id: "MAL-2026-1" }] } : {},
          );
          return { ok: true, status: 200, json: async () => ({ results }) };
        }
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      }
      if (url.includes("api.npmjs.org/downloads")) return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      if (url.includes("api.github.com")) return { ok: true, status: 200, headers: new Headers(), json: async () => ({ archived: false }) };
      // registry packument for whichever package
      const name = decodeURIComponent(url.split("/").pop() || "");
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: "1.0.0" },
          versions: { "1.0.0": { name, dist: { tarball: `https://reg/${name}.tgz` }, maintainers: [{ name: "alice" }] } },
          time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
        }),
      };
    }),
  );
}

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-monitor-cmd-"));
  process.chdir(dir);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("monitorCommand", () => {
  it("errors when there is nothing to monitor", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    const code = await monitorCommand({ json: true, assess: { useAi: false } });
    spy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join(" ")).toContain("Nothing to monitor");
  });

  it("creates a baseline on the first run and fails on an always-on malicious finding", async () => {
    // Approve a package so it becomes a monitor target.
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({ "widget@1.0.0": { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    stubNetwork();

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
    const code = await monitorCommand({ json: true, assess: { useAi: false } });
    spy.mockRestore();

    const parsed = JSON.parse(lines[0]);
    expect(parsed.command).toBe("monitor");
    expect(parsed.baseline.created).toBe(true);
    expect(parsed.events.some((e: { kind: string }) => e.kind === "known-malicious")).toBe(true);
    expect(parsed.exitCode).toBe(2);
    expect(code).toBe(2);

    // Baseline was written.
    const baseline = JSON.parse(await readFile(path.join(dir, ".targate", "monitor-baseline.json"), "utf8"));
    expect(baseline.snapshots["widget@1.0.0"]).toBeDefined();
  });

  it("--no-update leaves no baseline behind", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({ "happy@1.0.0": { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    stubNetwork();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const code = await monitorCommand({ json: true, noUpdate: true, assess: { useAi: false } });
    spy.mockRestore();
    expect(code).toBe(0); // happy has no findings
    await expect(readFile(path.join(dir, ".targate", "monitor-baseline.json"))).rejects.toThrow();
  });
});
