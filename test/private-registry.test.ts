import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { resetNpmrcCacheForTests } from "../src/npmrc.js";
import { buildPackageSignals } from "../src/pipeline.js";
import { fetchPackageMetadata } from "../src/registry.js";
import { resetReputationCacheForTests } from "../src/reputation.js";
import type { LoadedPolicy } from "../src/policy.js";

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

async function buildTarball(): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({ name: "@acme/lib", version: "1.0.0" }),
    );
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

function packumentFor(name: string, tarball: string) {
  return {
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": {
        name,
        dist: { tarball },
        maintainers: [{ name: "alice" }],
        repository: { url: "https://github.com/acme/lib" },
        scripts: {},
        dependencies: {},
      },
    },
    time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
  };
}

/** Every request is recorded; packument + tarball served from the fake registry. */
function stubNetwork(requests: { url: string; headers: Record<string, string> }[]): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, headers: (init?.headers as Record<string, string>) ?? {} });
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => tarballBytes };
      }
      if (url.includes("npm.acme.com")) {
        return {
          ok: true,
          status: 200,
          json: async () =>
            packumentFor("@acme/lib", "https://npm.acme.com/@acme/lib/-/lib-1.0.0.tgz"),
        };
      }
      if (url.includes("api.osv.dev")) {
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      }
      if (url.includes("api.npmjs.org")) {
        return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      }
      if (url.includes("api.github.com")) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({ archived: false }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    }),
  );
}

beforeAll(async () => {
  tarballBytes = await buildTarball();
});

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-privreg-"));
  await writeFile(
    path.join(dir, ".npmrc"),
    ["@acme:registry=https://npm.acme.com/", "//npm.acme.com/:_authToken=tok-abc"].join("\n"),
  );
  process.chdir(dir);
  resetNpmrcCacheForTests();
  resetReputationCacheForTests();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  resetNpmrcCacheForTests();
  await rm(dir, { recursive: true, force: true });
});

function internalPolicy(scopes: string[]): LoadedPolicy {
  return {
    policy: { dependencyPolicy: { internalScopes: scopes } },
    file: path.join(dir, "targate.policy.yaml"),
  };
}

describe("private-registry metadata + tarball", () => {
  it("fetches a scope-mapped package from its registry with the nerf-darted token", async () => {
    const requests: { url: string; headers: Record<string, string> }[] = [];
    stubNetwork(requests);

    const metadata = await fetchPackageMetadata("@acme/lib");
    expect(metadata.registryUrl).toBe("https://npm.acme.com");
    expect(metadata.registrySource).toBe("scope");

    const packument = requests.find((r) => r.url === "https://npm.acme.com/@acme%2Flib");
    expect(packument).toBeDefined();
    expect(packument!.headers.authorization).toBe("Bearer tok-abc");
  });

  it("passes the registry credential to the tarball download too", async () => {
    const requests: { url: string; headers: Record<string, string> }[] = [];
    stubNetwork(requests);

    await buildPackageSignals("@acme/lib", undefined, { noReputation: true });
    const tarball = requests.find((r) => r.url.endsWith(".tgz"));
    expect(tarball).toBeDefined();
    expect(tarball!.headers.authorization).toBe("Bearer tok-abc");
  });

  it("skips npmjs-only lookups (downloads) for scope-mapped packages but keeps OSV + GitHub", async () => {
    const requests: { url: string; headers: Record<string, string> }[] = [];
    stubNetwork(requests);

    const { signals } = await buildPackageSignals("@acme/lib", undefined, {
      maintainerIntel: true,
    });
    expect(requests.some((r) => r.url.includes("api.npmjs.org"))).toBe(false); // downloads skipped
    expect(requests.some((r) => r.url.includes("/-/v1/search"))).toBe(false); // maintainer search skipped
    expect(requests.some((r) => r.url.includes("api.osv.dev"))).toBe(true); // OSV still checked
    expect(requests.some((r) => r.url.includes("api.github.com"))).toBe(true); // repo status still checked
    expect(signals.reputation.downloads.status).toBe("skipped");
    expect(signals.internalScope).toBeUndefined();
  });
});

describe("policy internalScopes", () => {
  it("never sends the package name to OSV/downloads/GitHub and skips typosquat", async () => {
    const requests: { url: string; headers: Record<string, string> }[] = [];
    stubNetwork(requests);

    const { signals } = await buildPackageSignals("@acme/lib", undefined, {
      policy: internalPolicy(["@acme"]),
      maintainerIntel: true,
    });

    const external = requests.filter(
      (r) =>
        r.url.includes("api.osv.dev") ||
        r.url.includes("api.npmjs.org") ||
        r.url.includes("api.github.com") ||
        r.url.includes("/-/v1/search"),
    );
    expect(external).toEqual([]); // the name never left the private registry

    expect(signals.internalScope).toBe(true);
    expect(signals.osvUnavailable).toBe(false); // a choice, not a failure
    expect(signals.knownMalicious).toBe(false);
    expect(signals.nameSimilarity).toBeNull();
    expect(signals.reputation.downloads.status).toBe("skipped");
  });

  it("emits the internal-scope stage so command output explains the skips", async () => {
    stubNetwork([]);
    const stages: string[] = [];
    await buildPackageSignals("@acme/lib", undefined, {
      policy: internalPolicy(["@acme"]),
      onStage: (stage) => stages.push(stage),
    });
    expect(stages).toContain("internal-scope");
    expect(stages).not.toContain("osv");
    expect(stages).not.toContain("osv-failed");
  });

  it("a non-listed scope is unaffected", async () => {
    const requests: { url: string; headers: Record<string, string> }[] = [];
    stubNetwork(requests);
    const { signals } = await buildPackageSignals("@acme/lib", undefined, {
      policy: internalPolicy(["@other"]),
    });
    expect(signals.internalScope).toBeUndefined();
    expect(requests.some((r) => r.url.includes("api.osv.dev"))).toBe(true);
  });
});
