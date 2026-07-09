import { afterEach, describe, expect, it, vi } from "vitest";
import { isMaliciousRecord, queryOsvBatch } from "../src/osv.js";

describe("isMaliciousRecord", () => {
  it("flags OpenSSF MAL- records", () => {
    expect(isMaliciousRecord({ id: "MAL-2024-1234" })).toBe(true);
  });

  it("flags GHSA advisories that describe malware", () => {
    expect(
      isMaliciousRecord({
        id: "GHSA-hm6q-r2jc-cpqh",
        summary: "lodahs is malware",
        details: "All versions of this package contained malware.",
      }),
    ).toBe(true);
  });

  it("does not flag ordinary vulnerability advisories", () => {
    expect(
      isMaliciousRecord({
        id: "GHSA-jf85-cpcp-j695",
        summary: "Prototype Pollution in lodash",
        details: "Versions of lodash before 4.17.5 are vulnerable to prototype pollution.",
      }),
    ).toBe(false);
  });
});

describe("queryOsvBatch", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  /** Fake fetch: one /querybatch response (by index) + per-id /vulns lookups. */
  function stub(
    batchVulns: Array<Array<{ id: string }>>,
    vulnDetails: Record<string, { summary?: string; details?: string }> = {},
  ) {
    const detailCalls: string[] = [];
    const batchCalls: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: { body?: string }) => {
        const url = String(input);
        if (url.endsWith("/querybatch")) {
          batchCalls.push(JSON.parse(String(init?.body)));
          return { ok: true, status: 200, json: async () => ({ results: batchVulns.map((v) => ({ vulns: v })) }) };
        }
        if (url.includes("/vulns/")) {
          const id = decodeURIComponent(url.split("/vulns/")[1]);
          detailCalls.push(id);
          return { ok: true, status: 200, json: async () => ({ id, ...vulnDetails[id] }) };
        }
        throw new Error(`unexpected fetch: ${url}`);
      }),
    );
    return { detailCalls, batchCalls };
  }

  it("flags a MAL- id as malicious WITHOUT a detail fetch", async () => {
    const { detailCalls } = stub([[{ id: "MAL-2024-1" }]]);
    const map = await queryOsvBatch([{ name: "evil", version: "1.0.0" }]);
    expect(map.get("evil@1.0.0")?.knownMalicious).toBe(true);
    expect(detailCalls).toHaveLength(0);
  });

  it("classifies a GHSA-malware id as malicious after a detail fetch", async () => {
    const { detailCalls } = stub([[{ id: "GHSA-mal" }]], {
      "GHSA-mal": { summary: "package is malware" },
    });
    const map = await queryOsvBatch([{ name: "bad", version: "2.0.0" }]);
    expect(map.get("bad@2.0.0")?.knownMalicious).toBe(true);
    expect(detailCalls).toEqual(["GHSA-mal"]);
  });

  it("keeps an ordinary advisory as advisory, not malicious", async () => {
    stub([[{ id: "GHSA-vuln" }]], { "GHSA-vuln": { summary: "Prototype pollution" } });
    const map = await queryOsvBatch([{ name: "lib", version: "3.0.0" }]);
    const r = map.get("lib@3.0.0")!;
    expect(r.knownMalicious).toBe(false);
    expect(r.advisories.map((a) => a.id)).toEqual(["GHSA-vuln"]);
  });

  it("returns a clean result with zero detail calls for a package with no vulns", async () => {
    const { detailCalls } = stub([[]]);
    const map = await queryOsvBatch([{ name: "clean", version: "1.0.0" }]);
    expect(map.get("clean@1.0.0")).toEqual({
      knownMalicious: false,
      maliciousRecords: [],
      advisories: [],
      unavailable: false,
    });
    expect(detailCalls).toHaveLength(0);
  });

  it("marks a package unavailable when a detail fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL) => {
        const url = String(input);
        if (url.endsWith("/querybatch")) {
          return { ok: true, status: 200, json: async () => ({ results: [{ vulns: [{ id: "GHSA-x" }] }] }) };
        }
        return { ok: false, status: 500 }; // detail fetch fails
      }),
    );
    const map = await queryOsvBatch([{ name: "p", version: "1.0.0" }]);
    expect(map.get("p@1.0.0")?.unavailable).toBe(true);
    expect(map.get("p@1.0.0")?.knownMalicious).toBe(false);
  });

  it("chunks requests at 1000 queries", async () => {
    const packages = Array.from({ length: 1500 }, (_, i) => ({ name: `p${i}`, version: "1.0.0" }));
    const { batchCalls } = stub(packages.map(() => []));
    await queryOsvBatch(packages);
    expect(batchCalls).toHaveLength(2); // 1000 + 500
    expect((batchCalls[0] as { queries: unknown[] }).queries).toHaveLength(1000);
    expect((batchCalls[1] as { queries: unknown[] }).queries).toHaveLength(500);
  });

  it("throws on a failed batch request so the caller can fall back", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 503 })));
    await expect(queryOsvBatch([{ name: "p", version: "1.0.0" }])).rejects.toThrow(/OSV batch/);
  });
});
