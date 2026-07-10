import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  classifyDownloadTrend,
  deriveReputation,
  fetchReputation,
  parseGitHubRepo,
  resetReputationCacheForTests,
} from "../src/reputation.js";
import type { PackageMetadata } from "../src/types.js";

const DAY = 86_400_000;

function makeMetadata(overrides: Partial<PackageMetadata> = {}): PackageMetadata {
  return {
    name: "example",
    version: "2.0.0",
    repositoryUrl: "git+https://github.com/owner/example.git",
    maintainers: ["alice", "bob"],
    publishDate: new Date(Date.now() - 10 * DAY).toISOString(),
    ageInDays: 1000,
    tarballUrl: "https://registry.npmjs.org/example/-/example-2.0.0.tgz",
    scripts: {},
    dependencyCount: 0,
    directDependencies: [],
    registryReputation: {
      previousVersion: "1.9.0",
      previousVersionPublishDate: new Date(Date.now() - 40 * DAY).toISOString(),
      hasProvenance: false,
      versionMaintainers: ["alice", "bob"],
      previousVersionMaintainers: ["alice", "bob"],
      publisher: "alice",
      latestRepositoryUrl: "git+https://github.com/owner/example.git",
    },
    ...overrides,
  };
}

function days(counts: number[]): { day: string; downloads: number }[] {
  return counts.map((downloads, i) => ({ day: `2026-06-${String(i + 1).padStart(2, "0")}`, downloads }));
}

beforeEach(() => resetReputationCacheForTests());
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("classifyDownloadTrend", () => {
  it("classifies steady traffic as stable", () => {
    const r = classifyDownloadTrend(days(Array(30).fill(1000)));
    expect(r.trend).toBe("stable");
    expect(r.weeklyDownloads).toBe(7000);
  });

  it("detects a spike (≥5x with the absolute floor met)", () => {
    const r = classifyDownloadTrend(days([...Array(23).fill(100), ...Array(7).fill(600)]));
    expect(r.trend).toBe("spike");
    expect(r.trendDetail).toContain("x)");
  });

  it("suppresses spikes on tiny packages below the weekly floor", () => {
    // 3/day -> 20/day is >5x but only 140/week — noise, not a spike.
    const r = classifyDownloadTrend(days([...Array(23).fill(3), ...Array(7).fill(20)]));
    expect(r.trend).toBe("stable");
  });

  it("detects a drop (≤0.2x when there was real traffic)", () => {
    const r = classifyDownloadTrend(days([...Array(23).fill(1000), ...Array(7).fill(100)]));
    expect(r.trend).toBe("drop");
  });

  it("ignores drops from a negligible baseline", () => {
    const r = classifyDownloadTrend(days([...Array(23).fill(50), ...Array(7).fill(5)]));
    expect(r.trend).toBe("stable");
  });

  it("returns no trend with fewer than 28 days of data", () => {
    const r = classifyDownloadTrend(days(Array(10).fill(500)));
    expect(r.trend).toBeUndefined();
    expect(r.weeklyDownloads).toBe(3500);
  });
});

describe("parseGitHubRepo", () => {
  it.each([
    ["git+https://github.com/o/r.git", { owner: "o", repo: "r" }],
    ["https://github.com/o/r", { owner: "o", repo: "r" }],
    ["git://github.com/o/r.git", { owner: "o", repo: "r" }],
    ["ssh://git@github.com/o/r.git", { owner: "o", repo: "r" }],
    ["git@github.com:o/r.git", { owner: "o", repo: "r" }],
    ["github:o/r", { owner: "o", repo: "r" }],
  ])("parses %s", (url, expected) => {
    expect(parseGitHubRepo(url)).toEqual(expected);
  });

  it("returns null for non-GitHub hosts", () => {
    expect(parseGitHubRepo("https://gitlab.com/o/r")).toBeNull();
    expect(parseGitHubRepo("https://bitbucket.org/o/r.git")).toBeNull();
  });
});

describe("fetchReputation", () => {
  const ghUrl = "git+https://github.com/owner/repo.git";

  function stubFetch(handler: (url: string, init?: RequestInit) => Partial<Response>) {
    const mock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      return { ok: true, status: 200, headers: new Headers(), json: async () => ({}), ...handler(url, init) } as Response;
    });
    vi.stubGlobal("fetch", mock);
    return mock;
  }

  it("returns ok statuses on healthy responses", async () => {
    stubFetch((url) => {
      if (url.includes("api.npmjs.org")) {
        return { json: async () => ({ downloads: days(Array(30).fill(500)) }) } as Partial<Response>;
      }
      return { json: async () => ({ archived: false }) } as Partial<Response>;
    });
    const r = await fetchReputation("example", ghUrl);
    expect(r.downloads.status).toBe("ok");
    expect(r.downloads.weeklyDownloads).toBe(3500);
    expect(r.repo).toEqual({ status: "ok", archived: false });
  });

  it("reports archived repositories", async () => {
    stubFetch((url) =>
      url.includes("api.github.com")
        ? ({ json: async () => ({ archived: true }) } as Partial<Response>)
        : ({ json: async () => ({ downloads: days(Array(30).fill(1)) }) } as Partial<Response>),
    );
    const r = await fetchReputation("example", ghUrl);
    expect(r.repo).toEqual({ status: "ok", archived: true });
  });

  it("maps downloads 404 to unavailable, never zero", async () => {
    stubFetch((url) =>
      url.includes("api.npmjs.org")
        ? ({ ok: false, status: 404 } as Partial<Response>)
        : ({ json: async () => ({ archived: false }) } as Partial<Response>),
    );
    const r = await fetchReputation("example", ghUrl);
    expect(r.downloads).toEqual({ status: "unavailable" });
  });

  it("maps GitHub 404 to not-found", async () => {
    stubFetch((url) =>
      url.includes("api.github.com")
        ? ({ ok: false, status: 404 } as Partial<Response>)
        : ({ json: async () => ({ downloads: days(Array(30).fill(1)) }) } as Partial<Response>),
    );
    const r = await fetchReputation("example", ghUrl);
    expect(r.repo.status).toBe("not-found");
  });

  it("trips the circuit breaker on an exhausted GitHub quota", async () => {
    const mock = stubFetch((url) =>
      url.includes("api.github.com")
        ? ({
            ok: false,
            status: 403,
            headers: new Headers({ "x-ratelimit-remaining": "0" }),
          } as Partial<Response>)
        : ({ json: async () => ({ downloads: [] }) } as Partial<Response>),
    );
    const first = await fetchReputation("a", "https://github.com/o/one");
    expect(first.repo.status).toBe("rate-limited");
    const githubCallsAfterFirst = mock.mock.calls.filter((c) => String(c[0]).includes("github")).length;

    // A DIFFERENT repo: the breaker must short-circuit without a request.
    const second = await fetchReputation("b", "https://github.com/o/two");
    expect(second.repo.status).toBe("rate-limited");
    const githubCallsAfterSecond = mock.mock.calls.filter((c) => String(c[0]).includes("github")).length;
    expect(githubCallsAfterSecond).toBe(githubCallsAfterFirst);
  });

  it("memoizes GitHub lookups per owner/repo", async () => {
    const mock = stubFetch(() => ({ json: async () => ({ archived: false, downloads: [] }) }) as Partial<Response>);
    await fetchReputation("a", ghUrl);
    await fetchReputation("b", ghUrl); // same repo, different package
    const githubCalls = mock.mock.calls.filter((c) => String(c[0]).includes("github")).length;
    expect(githubCalls).toBe(1);
  });

  it("sends the GITHUB_TOKEN as a bearer header when set", async () => {
    vi.stubEnv("GITHUB_TOKEN", "gh-test-token");
    const mock = stubFetch(() => ({ json: async () => ({ archived: false, downloads: [] }) }) as Partial<Response>);
    await fetchReputation("example", ghUrl);
    const ghCall = mock.mock.calls.find((c) => String(c[0]).includes("github"));
    expect((ghCall?.[1]?.headers as Record<string, string>).authorization).toBe("Bearer gh-test-token");
  });

  it("degrades to unavailable when the network throws", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("network down");
    }));
    const r = await fetchReputation("example", ghUrl);
    expect(r.downloads.status).toBe("unavailable");
    expect(r.repo.status).toBe("unavailable");
  });

  it("skips GitHub without a repository URL and marks non-GitHub hosts", async () => {
    stubFetch(() => ({ json: async () => ({ downloads: [] }) }) as Partial<Response>);
    expect((await fetchReputation("x", undefined)).repo.status).toBe("skipped");
    expect((await fetchReputation("y", "https://gitlab.com/o/r")).repo.status).toBe("not-github");
  });
});

describe("deriveReputation", () => {
  const lookup = { downloads: { status: "skipped" as const }, repo: { status: "skipped" as const } };
  const now = Date.now();

  it("computes version age and release gap", () => {
    const meta = makeMetadata({ publishDate: new Date(now - 10 * DAY).toISOString() });
    meta.registryReputation.previousVersionPublishDate = new Date(now - 40 * DAY).toISOString();
    const r = deriveReputation(meta, lookup, now);
    expect(r.versionAgeDays).toBe(10);
    expect(r.releaseAfterInactivityDays).toBe(30);
    expect(r.releaseGapAnomaly).toBe(false);
  });

  it("flags a fresh release after ≥365 days of inactivity", () => {
    const meta = makeMetadata({
      publishDate: new Date(now - 5 * DAY).toISOString(),
    });
    meta.registryReputation.previousVersionPublishDate = new Date(now - 400 * DAY).toISOString();
    const r = deriveReputation(meta, lookup, now);
    expect(r.releaseAfterInactivityDays).toBe(395);
    expect(r.releaseGapAnomaly).toBe(true);
  });

  it("does not flag an old version even after a long gap", () => {
    const meta = makeMetadata({ publishDate: new Date(now - 200 * DAY).toISOString() });
    meta.registryReputation.previousVersionPublishDate = new Date(now - 700 * DAY).toISOString();
    expect(deriveReputation(meta, lookup, now).releaseGapAnomaly).toBe(false);
  });

  it("detects a foreign publisher as a maintainer change", () => {
    const meta = makeMetadata();
    meta.registryReputation.publisher = "mallory";
    const r = deriveReputation(meta, lookup, now);
    expect(r.maintainerChange).toEqual({
      changed: true,
      detail: 'publisher "mallory" was not a maintainer of 1.9.0',
    });
  });

  it("detects added/removed maintainers between releases", () => {
    const meta = makeMetadata();
    meta.registryReputation.versionMaintainers = ["alice", "carol"];
    const r = deriveReputation(meta, lookup, now);
    expect(r.maintainerChange?.changed).toBe(true);
    expect(r.maintainerChange?.detail).toContain("added: carol");
    expect(r.maintainerChange?.detail).toContain("removed: bob");
  });

  it("returns null maintainer change when per-version data is absent", () => {
    const meta = makeMetadata();
    meta.registryReputation.versionMaintainers = undefined;
    expect(deriveReputation(meta, lookup, now).maintainerChange).toBeNull();
  });

  it("flags a repository mismatch vs the latest version", () => {
    const meta = makeMetadata();
    meta.registryReputation.latestRepositoryUrl = "git+https://github.com/other/place.git";
    const r = deriveReputation(meta, lookup, now);
    expect(r.repositoryMismatch).toBe(true);
    expect(r.repositoryMismatchDetail).toContain("github.com/other/place");
  });

  it("normalizes equivalent URL forms as a match", () => {
    const meta = makeMetadata({ repositoryUrl: "git@github.com:owner/example.git" });
    meta.registryReputation.latestRepositoryUrl = "https://github.com/Owner/example";
    expect(deriveReputation(meta, lookup, now).repositoryMismatch).toBe(false);
  });

  it("normalizes deprecated:true to a generic message", () => {
    const meta = makeMetadata();
    meta.registryReputation.deprecated = true;
    expect(deriveReputation(meta, lookup, now).deprecated).toBe("deprecated (no message)");
  });
});
