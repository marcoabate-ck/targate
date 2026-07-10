import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchMaintainerIntel,
  fetchMaintainerPortfolio,
  resetMaintainerIntelCacheForTests,
} from "../src/maintainer-intel.js";
import { makeMetadata } from "./helpers.js";

/** Build a search-API response body in the validated shape. */
function searchBody(pkgs: { name: string; weekly: number }[], total = pkgs.length) {
  return {
    total,
    objects: pkgs.map((p) => ({
      package: { name: p.name, maintainers: [{ username: "x" }] },
      downloads: { weekly: p.weekly, monthly: p.weekly * 4 },
      score: { final: 50, detail: { popularity: 1, quality: 1, maintenance: 1 } },
    })),
  };
}

function stubSearch(handler: (name: string) => unknown) {
  const mock = vi.fn(async (input: string | URL) => {
    const url = String(input);
    const m = /maintainer:([^&]+)/.exec(url);
    const name = m ? decodeURIComponent(m[1]) : "";
    return { ok: true, status: 200, json: async () => handler(name) } as Response;
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

beforeEach(() => resetMaintainerIntelCacheForTests());
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("fetchMaintainerPortfolio", () => {
  it("parses the validated search shape and ranks by weekly downloads", async () => {
    stubSearch(() =>
      searchBody(
        [
          { name: "chalk", weekly: 500_000 },
          { name: "tiny", weekly: 5 },
          { name: "ansi-styles", weekly: 900_000 },
        ],
        1066,
      ),
    );
    const p = await fetchMaintainerPortfolio("sindresorhus");
    expect(p.status).toBe("ok");
    expect(p.packageCount).toBe(1066);
    expect(p.topPackages?.map((t) => t.name)).toEqual(["ansi-styles", "chalk"]);
    expect(p.hasEstablishedPackage).toBe(true);
  });

  it("handles an empty portfolio without error", async () => {
    stubSearch(() => ({ total: 0, objects: [] }));
    const p = await fetchMaintainerPortfolio("nobody-xyz");
    expect(p.status).toBe("ok");
    expect(p.packageCount).toBe(0);
    expect(p.hasEstablishedPackage).toBe(false);
  });

  it("fails open to unavailable on a non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500 }) as Response));
    expect((await fetchMaintainerPortfolio("x")).status).toBe("unavailable");
  });

  it("fails open when the network throws", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("offline");
    }));
    expect((await fetchMaintainerPortfolio("x")).status).toBe("unavailable");
  });

  it("memoizes per maintainer name", async () => {
    const mock = stubSearch(() => searchBody([{ name: "a", weekly: 1 }]));
    await fetchMaintainerPortfolio("dup");
    await fetchMaintainerPortfolio("DUP"); // case-insensitive key
    expect(mock).toHaveBeenCalledTimes(1);
  });
});

describe("fetchMaintainerIntel", () => {
  it("flags a newly-added maintainer with no track record", async () => {
    stubSearch((name) =>
      name === "mallory"
        ? searchBody([{ name: "only-pkg", weekly: 3 }], 1)
        : searchBody([{ name: "chalk", weekly: 900_000 }], 500),
    );
    const meta = makeMetadata({ maintainers: ["alice", "mallory"] });
    meta.registryReputation.versionMaintainers = ["alice", "mallory"];
    meta.registryReputation.previousVersionMaintainers = ["alice"];
    const intel = await fetchMaintainerIntel(meta);
    expect(intel.status).toBe("ok");
    expect(intel.newMaintainerNoTrackRecord).toEqual(["mallory"]);
  });

  it("does not flag an added maintainer who has a real portfolio", async () => {
    stubSearch(() => searchBody([{ name: "big", weekly: 900_000 }], 50));
    const meta = makeMetadata({ maintainers: ["alice", "bob"] });
    meta.registryReputation.versionMaintainers = ["alice", "bob"];
    meta.registryReputation.previousVersionMaintainers = ["alice"];
    expect((await fetchMaintainerIntel(meta)).newMaintainerNoTrackRecord).toEqual([]);
  });

  it("makes no no-track-record claim when history is not derivable", async () => {
    stubSearch(() => searchBody([{ name: "x", weekly: 1 }], 1));
    const meta = makeMetadata({ maintainers: ["alice"] });
    // versionMaintainers/previousVersionMaintainers absent
    expect((await fetchMaintainerIntel(meta)).newMaintainerNoTrackRecord).toEqual([]);
  });

  it("truncates to the first 5 maintainers", async () => {
    const mock = stubSearch(() => searchBody([{ name: "x", weekly: 1 }]));
    const meta = makeMetadata({ maintainers: ["a", "b", "c", "d", "e", "f", "g"] });
    const intel = await fetchMaintainerIntel(meta);
    expect(intel.truncated).toBe(true);
    expect(intel.maintainers).toHaveLength(5);
    expect(mock).toHaveBeenCalledTimes(5);
  });

  it("reports unavailable when any consulted maintainer lookup failed", async () => {
    let n = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      n += 1;
      if (n === 1) return { ok: true, status: 200, json: async () => searchBody([{ name: "x", weekly: 1 }]) } as Response;
      return { ok: false, status: 503 } as Response;
    }));
    const intel = await fetchMaintainerIntel(makeMetadata({ maintainers: ["a", "b"] }));
    expect(intel.status).toBe("unavailable");
  });
});
