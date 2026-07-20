import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AiCacheSettings } from "../src/ai-cache.js";
import {
  readCachedSourceAudit,
  sourceAuditCacheKey,
  writeCachedSourceAudit,
  SOURCE_AUDIT_TTL_HOURS,
} from "../src/source-audit-cache.js";
import { auditSourceWithCache } from "../src/ai.js";
import type { AiProvider, SourceAuditInput } from "../src/providers/types.js";
import type { SourceAuditFinding } from "../src/types.js";

let dir = "";
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "targate-audit-cache-"));
});
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
});

const settings = (over: Partial<AiCacheSettings> = {}): AiCacheSettings => ({
  enabled: true,
  scope: "project",
  ttlHours: 24,
  exclude: [],
  refresh: false,
  ...over,
});

const finding = (file: string): SourceAuditFinding => ({
  severity: "high",
  file,
  summary: "exfiltrates env",
});

const KEY = {
  provider: "anthropic",
  model: "claude-opus-4-8",
  digest: "sha512-AAAA",
  promptVersion: "1",
  selectionVersion: "1",
};

describe("sourceAuditCacheKey", () => {
  it("is deterministic and varies by every component", () => {
    const base = sourceAuditCacheKey(KEY);
    expect(sourceAuditCacheKey(KEY)).toBe(base);
    expect(sourceAuditCacheKey({ ...KEY, digest: "sha512-BBBB" })).not.toBe(base);
    expect(sourceAuditCacheKey({ ...KEY, model: "other" })).not.toBe(base);
    expect(sourceAuditCacheKey({ ...KEY, promptVersion: "2" })).not.toBe(base);
    expect(sourceAuditCacheKey({ ...KEY, selectionVersion: "2" })).not.toBe(base);
    expect(base.startsWith("code-audit/anthropic/claude-opus-4-8/")).toBe(true);
  });
});

describe("read/write source-audit cache", () => {
  it("round-trips findings by key", async () => {
    const key = sourceAuditCacheKey(KEY);
    await writeCachedSourceAudit(key, [finding("a.js")], settings(), "pkg", dir);
    const hit = await readCachedSourceAudit(key, settings(), "pkg", dir);
    expect(hit).toEqual([finding("a.js")]);
  });

  it("caches a clean (empty) audit and returns it as a hit", async () => {
    const key = sourceAuditCacheKey(KEY);
    await writeCachedSourceAudit(key, [], settings(), "pkg", dir);
    const hit = await readCachedSourceAudit(key, settings(), "pkg", dir);
    expect(hit).toEqual([]); // empty array, not null → no re-audit
  });

  it("misses for a different digest", async () => {
    await writeCachedSourceAudit(sourceAuditCacheKey(KEY), [finding("a.js")], settings(), "pkg", dir);
    const other = sourceAuditCacheKey({ ...KEY, digest: "sha512-ZZZZ" });
    expect(await readCachedSourceAudit(other, settings(), "pkg", dir)).toBeNull();
  });

  it("refresh forces a miss; exclude and disabled skip", async () => {
    const key = sourceAuditCacheKey(KEY);
    await writeCachedSourceAudit(key, [finding("a.js")], settings(), "pkg", dir);
    expect(await readCachedSourceAudit(key, settings({ refresh: true }), "pkg", dir)).toBeNull();
    expect(await readCachedSourceAudit(key, settings({ exclude: ["pkg"] }), "pkg", dir)).toBeNull();
    expect(await readCachedSourceAudit(key, settings({ enabled: false }), "pkg", dir)).toBeNull();
  });

  it("ignores an entry past the TTL", async () => {
    const key = sourceAuditCacheKey(KEY);
    const stale = new Date(Date.now() - (SOURCE_AUDIT_TTL_HOURS + 1) * 3_600_000).toISOString();
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "source-audit-cache.json"),
      JSON.stringify({ entries: { [key]: { findings: [finding("a.js")], cachedAt: stale } } }),
    );
    expect(await readCachedSourceAudit(key, settings(), "pkg", dir)).toBeNull();
  });
});

function fakeProvider(findings: SourceAuditFinding[], counter: { n: number }): AiProvider {
  return {
    name: "fake",
    model: "m1",
    assess: async () => {
      throw new Error("unused");
    },
    assessBatch: async () => [],
    analyzeSource: async () => {
      counter.n++;
      return findings;
    },
  };
}

const input = (pkg: string): SourceAuditInput => ({
  package: pkg,
  version: "1.0.0",
  files: [{ relPath: "a.js", content: "process.env.TOKEN", truncated: false }],
});

describe("auditSourceWithCache", () => {
  it("calls the model once per digest, then serves the cache", async () => {
    const counter = { n: 0 };
    const provider = fakeProvider([finding("a.js")], counter);
    const opts = { cache: settings(), cwd: dir };
    const first = await auditSourceWithCache(provider, input("pkg"), "sha512-D1", opts);
    const second = await auditSourceWithCache(provider, input("pkg"), "sha512-D1", opts);
    expect(first).toEqual([finding("a.js")]);
    expect(second).toEqual([finding("a.js")]);
    expect(counter.n).toBe(1); // second served from cache
  });

  it("shares a cache hit across packages with identical bytes", async () => {
    const counter = { n: 0 };
    const provider = fakeProvider([finding("a.js")], counter);
    const opts = { cache: settings(), cwd: dir };
    await auditSourceWithCache(provider, input("pkg-a"), "sha512-SAME", opts);
    await auditSourceWithCache(provider, input("pkg-b"), "sha512-SAME", opts);
    expect(counter.n).toBe(1); // same digest → one model call for both packages
  });

  it("does not cache when no cache settings are passed", async () => {
    const counter = { n: 0 };
    const provider = fakeProvider([], counter);
    await auditSourceWithCache(provider, input("pkg"), "sha512-D2", { cwd: dir });
    await auditSourceWithCache(provider, input("pkg"), "sha512-D2", { cwd: dir });
    expect(counter.n).toBe(2);
  });

  it("returns [] and never calls a provider without analyzeSource", async () => {
    const provider: AiProvider = {
      name: "no-audit",
      model: "m",
      assess: async () => {
        throw new Error("unused");
      },
      assessBatch: async () => [],
    };
    expect(await auditSourceWithCache(provider, input("pkg"), "sha512-D3", { cache: settings(), cwd: dir })).toEqual([]);
  });

  it("returns [] for an empty file selection without a model call", async () => {
    const counter = { n: 0 };
    const provider = fakeProvider([finding("a.js")], counter);
    const empty: SourceAuditInput = { package: "pkg", version: "1.0.0", files: [] };
    expect(await auditSourceWithCache(provider, empty, "sha512-D4", { cache: settings(), cwd: dir })).toEqual([]);
    expect(counter.n).toBe(0);
  });
});
