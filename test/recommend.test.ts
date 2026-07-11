import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { recommendCommand } from "../src/commands/recommend.js";
import {
  DEFAULT_RECOMMEND_LIMIT,
  MAX_RECOMMEND_LIMIT,
  mergeCandidates,
  rankRecommendations,
  recommendPackages,
  searchCandidates,
  RecommendSearchError,
  type Recommendation,
} from "../src/recommend.js";
import { resetNpmrcCacheForTests } from "../src/npmrc.js";
import { resetReputationCacheForTests } from "../src/reputation.js";

let dir: string;
let cwd: string;
let tarballBytes: Buffer;

async function buildTarball(): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({ name: "candidate", version: "1.0.0" }),
    );
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

interface FakeCandidate {
  name: string;
  weekly?: number;
  deprecated?: string;
  malicious?: boolean;
  scripts?: Record<string, string>;
}

function packument(c: FakeCandidate) {
  return {
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": {
        name: c.name,
        dist: { tarball: `https://registry.npmjs.org/${c.name}/-/${c.name}-1.0.0.tgz` },
        maintainers: [{ name: "alice" }, { name: "bob" }],
        repository: { url: `https://github.com/x/${c.name}` },
        scripts: c.scripts ?? {},
        dependencies: {},
        ...(c.deprecated ? { deprecated: c.deprecated } : {}),
      },
    },
    time: { created: "2019-01-01T00:00:00Z", "1.0.0": "2019-01-01T00:00:00Z" },
  };
}

function stubNetwork(candidates: FakeCandidate[]): void {
  const byName = new Map(candidates.map((c) => [c.name, c]));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/-/v1/search")) {
        // maintainer-intel portfolio lookups also hit search — give a benign portfolio.
        if (url.includes("maintainer%3A") || url.includes("maintainer:")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              total: 12,
              objects: [{ package: { name: "popular" }, downloads: { weekly: 50_000 } }],
            }),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            objects: candidates.map((c) => ({
              package: { name: c.name, version: "1.0.0", description: `${c.name} does things` },
              downloads: { weekly: c.weekly },
            })),
          }),
        };
      }
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => tarballBytes };
      }
      if (url.includes("api.osv.dev")) {
        const body = init?.body ? JSON.parse(String(init.body)) : {};
        const name: string | undefined = body?.package?.name;
        const vulns =
          name && byName.get(name)?.malicious
            ? [{ id: "MAL-2026-99", summary: "malware" }]
            : [];
        return { ok: true, status: 200, json: async () => ({ vulns }) };
      }
      if (url.includes("api.npmjs.org")) {
        return { ok: true, status: 200, json: async () => ({ downloads: [] }) };
      }
      if (url.includes("api.github.com")) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({ archived: false }) };
      }
      // packument
      const name = decodeURIComponent(url.split("/").pop() ?? "");
      const c = byName.get(name);
      if (!c) return { ok: false, status: 404, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => packument(c) };
    }),
  );
}

beforeAll(async () => {
  tarballBytes = await buildTarball();
});

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-recommend-"));
  process.chdir(dir);
  resetNpmrcCacheForTests();
  resetReputationCacheForTests();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("rankRecommendations", () => {
  function rec(name: string, score: number, weekly?: number): Recommendation {
    return {
      name,
      version: "1.0.0",
      weeklyDownloads: weekly,
      source: "npm-search",
      score: { total: score, categories: [] },
      assessment: {
        risk: "low",
        decision: "allow",
        summary: "",
        reasons: [],
        recommendedAction: "",
        source: "rules",
      },
      signals: {} as Recommendation["signals"],
    };
  }

  it("sorts by score desc, then adoption desc, then name", () => {
    const ranked = rankRecommendations([
      rec("low-score", 60, 1_000_000),
      rec("b-popular", 90, 500_000),
      rec("a-popular", 90, 500_000),
      rec("winner", 90, 900_000),
    ]);
    expect(ranked.map((r) => r.name)).toEqual(["winner", "a-popular", "b-popular", "low-score"]);
  });
});

describe("searchCandidates", () => {
  it("parses the validated npm search shape", async () => {
    stubNetwork([{ name: "alpha", weekly: 100 }]);
    const found = await searchCandidates("alpha things", 5);
    expect(found).toEqual([
      {
        name: "alpha",
        version: "1.0.0",
        description: "alpha does things",
        weeklyDownloads: 100,
        source: "npm-search",
      },
    ]);
  });

  it("throws RecommendSearchError on HTTP failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500 })));
    await expect(searchCandidates("x", 5)).rejects.toThrow(RecommendSearchError);
  });
});

describe("recommendPackages", () => {
  it("analyzes candidates, excludes malicious and deprecated ones, ranks the rest", async () => {
    stubNetwork([
      { name: "good-popular", weekly: 1_000_000 },
      { name: "good-small", weekly: 200 },
      { name: "evil", weekly: 5_000, malicious: true },
      { name: "old", weekly: 9_000, deprecated: "use something else" },
    ]);
    const report = await recommendPackages("padding", { limit: 4 });

    expect(report.analyzed).toBe(4);
    expect(report.recommendations.map((r) => r.name)).toEqual(["good-popular", "good-small"]);
    expect(report.recommendations[0].score.total).toBeGreaterThan(0);
    expect(report.recommendations[0].assessment.source).toBe("rules");

    const reasons = Object.fromEntries(report.rejected.map((r) => [r.name, r.reason]));
    expect(reasons.evil).toContain("MAL-2026-99");
    expect(reasons.old).toContain("deprecated");
  });

  it("respects the team policy block list without analyzing forbidden winners into the list", async () => {
    stubNetwork([{ name: "banned", weekly: 1_000_000 }, { name: "fine", weekly: 10 }]);
    const report = await recommendPackages("padding", {
      limit: 2,
      policy: {
        policy: { dependencyPolicy: { blockPackages: ["banned"] } },
        file: path.join(dir, "targate.policy.yaml"),
      },
    });
    expect(report.recommendations.map((r) => r.name)).toEqual(["fine"]);
    expect(report.rejected[0].name).toBe("banned");
    expect(report.rejected[0].reason).toContain("[policy]");
  });

  it("a failed candidate analysis is reported, not fatal", async () => {
    stubNetwork([{ name: "good-popular", weekly: 100 }]);
    const report = await recommendPackages("padding", {
      limit: 2,
      search: async () => [
        { name: "good-popular", weeklyDownloads: 100 },
        { name: "ghost" }, // no packument → 404 → analysis error
      ],
    });
    expect(report.recommendations.map((r) => r.name)).toEqual(["good-popular"]);
    expect(report.rejected[0].name).toBe("ghost");
    expect(report.rejected[0].reason).toContain("analysis failed");
  });

  it("clamps the limit to the hard cap", async () => {
    const seen: number[] = [];
    stubNetwork([]);
    await recommendPackages("x", {
      limit: 999,
      search: async (_q, size) => {
        seen.push(size);
        return [];
      },
    });
    expect(seen).toEqual([MAX_RECOMMEND_LIMIT]);
    expect(DEFAULT_RECOMMEND_LIMIT).toBeLessThanOrEqual(MAX_RECOMMEND_LIMIT);
  });
});

describe("mergeCandidates", () => {
  it("dedupes by name and tags overlap as 'both'", () => {
    const merged = mergeCandidates(
      [
        { name: "alpha", weeklyDownloads: 10, source: "npm-search" },
        { name: "beta", source: "npm-search" },
      ],
      ["beta", "gamma"],
    );
    expect(merged).toEqual([
      { name: "alpha", weeklyDownloads: 10, source: "npm-search" },
      { name: "beta", source: "both" },
      { name: "gamma", source: "ai" },
    ]);
  });
});

describe("AI-suggested candidates", () => {
  it("analyzes AI suggestions with the same pipeline and tags sources", async () => {
    stubNetwork([
      { name: "good-popular", weekly: 1_000 },
      { name: "ai-pick", weekly: 50 }, // packument exists; NOT in search results
    ]);
    const report = await recommendPackages("padding", {
      limit: 3,
      search: async () => [
        { name: "good-popular", weeklyDownloads: 1_000, source: "npm-search" },
      ],
      suggest: async () => ["ai-pick", "good-popular"],
    });
    expect(report.aiSuggestions.status).toBe("ok");
    expect(report.analyzed).toBe(2);
    const byName = Object.fromEntries(report.recommendations.map((r) => [r.name, r]));
    expect(byName["good-popular"].source).toBe("both");
    expect(byName["ai-pick"].source).toBe("ai");
    // AI-suggested candidates get real scores from the same pipeline.
    expect(byName["ai-pick"].score.total).toBeGreaterThan(0);
    expect(byName["ai-pick"].assessment.source).toBe("rules");
  });

  it("rejects hallucinated AI names via the registry lookup, with a distinct reason", async () => {
    stubNetwork([{ name: "good-popular", weekly: 1_000 }]);
    const report = await recommendPackages("padding", {
      limit: 2,
      suggest: async () => ["totally-made-up-pkg-xyz"],
    });
    const ghost = report.rejected.find((r) => r.name === "totally-made-up-pkg-xyz");
    expect(ghost?.reason).toContain("does not exist on the npm registry");
    expect(ghost?.source).toBe("ai");
    expect(report.recommendations.map((r) => r.name)).toEqual(["good-popular"]);
  });

  it("an AI failure degrades to search-only, never fatal", async () => {
    stubNetwork([{ name: "good-popular", weekly: 1_000 }]);
    const report = await recommendPackages("padding", {
      limit: 2,
      suggest: async () => {
        throw new Error("model exploded");
      },
    });
    expect(report.aiSuggestions.status).toBe("unavailable");
    expect(report.aiSuggestions.detail).toContain("model exploded");
    expect(report.recommendations.map((r) => r.name)).toEqual(["good-popular"]);
  });

  it("skips AI discovery with --no-ai / no provider, stating why", async () => {
    stubNetwork([{ name: "good-popular", weekly: 1_000 }]);
    const noAi = await recommendPackages("padding", { limit: 1, assess: { useAi: false } });
    expect(noAi.aiSuggestions.status).toBe("skipped");
    expect(noAi.aiSuggestions.detail).toContain("--no-ai");

    const noProvider = await recommendPackages("padding", { limit: 1 });
    expect(noProvider.aiSuggestions.status).toBe("skipped");
  });
});

describe("recommendCommand", () => {
  it("--json prints a single enveloped document", async () => {
    stubNetwork([{ name: "good-popular", weekly: 500 }]);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const code = await recommendCommand({ query: "padding", limit: 1, json: true });
    expect(code).toBe(0);
    const doc = JSON.parse(logs.join("\n"));
    expect(doc.schemaVersion).toBe(1);
    expect(doc.command).toBe("recommend");
    expect(doc.query).toBe("padding");
    expect(doc.recommendations[0].name).toBe("good-popular");
    expect(doc.aiSuggestions.status).toBe("skipped"); // no provider in tests
    expect(doc.exitCode).toBe(0);
  });

  it("exits 1 when the search itself fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503 })));
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    vi.spyOn(console, "log").mockImplementation(() => {});
    const code = await recommendCommand({ query: "padding", json: false });
    expect(code).toBe(1);
    expect(errors.join("\n")).toContain("npm search");
  });
});
