import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cacheFilePath,
  cacheKey,
  readCachedAssessment,
  resolveCacheSettings,
  writeCachedAssessment,
  type AiCacheSettings,
} from "../src/ai-cache.js";
import { assessWithCache } from "../src/ai.js";
import type { AiProvider } from "../src/providers/types.js";
import type { RiskAssessment } from "../src/types.js";
import { makeSignals } from "./helpers.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

function projectSettings(overrides: Partial<AiCacheSettings> = {}): AiCacheSettings {
  return { enabled: true, scope: "project", ttlHours: 24, exclude: [], ...overrides };
}

function assessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    risk: "low",
    decision: "allow",
    summary: "fine",
    reasons: ["looks good"],
    recommendedAction: "install",
    source: "ai",
    ...overrides,
  };
}

describe("resolveCacheSettings", () => {
  it("defaults to enabled, user scope, 24h TTL", () => {
    expect(resolveCacheSettings()).toEqual({
      enabled: true,
      scope: "user",
      ttlHours: 24,
      exclude: [],
    });
  });

  it("applies policy overrides", () => {
    expect(
      resolveCacheSettings({ enabled: false, scope: "project", ttlHours: 1, exclude: ["x"] }),
    ).toEqual({ enabled: false, scope: "project", ttlHours: 1, exclude: ["x"] });
  });
});

describe("cacheFilePath", () => {
  it("uses the home directory for user scope and cwd for project scope", () => {
    expect(cacheFilePath(projectSettings({ scope: "user" }), "/some/repo")).toBe(
      path.join(homedir(), ".bye", "ai-cache.json"),
    );
    expect(cacheFilePath(projectSettings(), "/some/repo")).toBe(
      path.join("/some/repo", ".bye", "ai-cache.json"),
    );
  });
});

describe("cacheKey", () => {
  const base = { provider: "anthropic", model: "claude-opus-4-8", reasoning: false };

  it("differs by provider, model, reasoning, version, and signals", () => {
    const signals = makeSignals({ package: "left-pad", version: "1.3.0" });
    const key = cacheKey({ ...base, signals });

    expect(cacheKey({ ...base, provider: "deepseek", signals })).not.toBe(key);
    expect(cacheKey({ ...base, model: "other-model", signals })).not.toBe(key);
    expect(cacheKey({ ...base, reasoning: true, signals })).not.toBe(key);
    expect(
      cacheKey({ ...base, signals: makeSignals({ package: "left-pad", version: "1.3.1" }) }),
    ).not.toBe(key);
    // Same package/version but different evidence (new OSV record) → different key.
    expect(
      cacheKey({
        ...base,
        signals: makeSignals({ package: "left-pad", version: "1.3.0", osvUnavailable: true }),
      }),
    ).not.toBe(key);
  });

  it("is stable for identical inputs", () => {
    const signals = makeSignals();
    expect(cacheKey({ ...base, signals })).toBe(cacheKey({ ...base, signals }));
  });
});

describe("read/write cached assessments", () => {
  it("round-trips an assessment through the project-scoped cache", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings();
    await writeCachedAssessment("k1", assessment(), settings, "left-pad", dir);

    const hit = await readCachedAssessment("k1", settings, "left-pad", dir);
    expect(hit?.assessment.decision).toBe("allow");
    expect(hit?.cachedAt).toBeTruthy();
  });

  it("misses on an unknown key and when disabled", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings();
    await writeCachedAssessment("k1", assessment(), settings, "left-pad", dir);
    expect(await readCachedAssessment("other", settings, "left-pad", dir)).toBeNull();
    expect(
      await readCachedAssessment("k1", projectSettings({ enabled: false }), "left-pad", dir),
    ).toBeNull();
  });

  it("never reads or writes excluded packages", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings({ exclude: ["secret-lib"] });
    await writeCachedAssessment("k1", assessment(), settings, "secret-lib", dir);
    expect(await readCachedAssessment("k1", settings, "secret-lib", dir)).toBeNull();
    // Nothing was persisted for the excluded package at all.
    await expect(readFile(cacheFilePath(settings, dir), "utf8")).rejects.toThrow();
  });

  it("expires entries past the TTL and prunes them on the next write", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings({ ttlHours: 1 });
    const file = cacheFilePath(settings, dir);
    await mkdir(path.dirname(file), { recursive: true });
    const stale = new Date(Date.now() - 2 * 3_600_000).toISOString();
    await writeFile(
      file,
      JSON.stringify({ entries: { old: { assessment: assessment(), cachedAt: stale } } }),
    );

    expect(await readCachedAssessment("old", settings, "left-pad", dir)).toBeNull();

    await writeCachedAssessment("fresh", assessment(), settings, "left-pad", dir);
    const doc = JSON.parse(await readFile(file, "utf8"));
    expect(Object.keys(doc.entries)).toEqual(["fresh"]);
  });

  it("does not lose entries under concurrent writes (the --deep path)", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings();
    // Mirrors the transitive walker: many assessments finishing at once.
    await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        writeCachedAssessment(`key-${i}`, assessment(), settings, `pkg-${i}`, dir),
      ),
    );
    const doc = JSON.parse(await readFile(cacheFilePath(settings, dir), "utf8"));
    expect(Object.keys(doc.entries).sort()).toEqual(
      Array.from({ length: 12 }, (_, i) => `key-${i}`).sort(),
    );
  });

  it("treats a corrupt cache file as empty instead of crashing", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings();
    const file = cacheFilePath(settings, dir);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, "{{{ not json");
    expect(await readCachedAssessment("k", settings, "left-pad", dir)).toBeNull();
    await writeCachedAssessment("k", assessment(), settings, "left-pad", dir); // rewrites it
    expect((await readCachedAssessment("k", settings, "left-pad", dir))?.assessment.risk).toBe("low");
  });
});

describe("assessWithCache", () => {
  function stubProvider(result: RiskAssessment): AiProvider & { assess: ReturnType<typeof vi.fn> } {
    return {
      name: "stub",
      model: "stub-model",
      assess: vi.fn(async () => result),
    };
  }

  it("caches the first answer and serves the second run without calling the provider", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const provider = stubProvider(assessment());
    const signals = makeSignals();
    const opts = { cache: projectSettings(), cwd: dir, reasoning: false };

    const first = await assessWithCache(provider, signals, opts);
    expect(first.decision).toBe("allow");
    expect(provider.assess).toHaveBeenCalledTimes(1);

    const second = await assessWithCache(provider, signals, opts);
    expect(provider.assess).toHaveBeenCalledTimes(1); // served from cache
    expect(second.decision).toBe("allow");
    expect(second.reasons.join(" ")).toContain("[cache] reused stub/stub-model assessment");
  });

  it("does not reuse an answer cached by a different provider or model", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const signals = makeSignals();
    const opts = { cache: projectSettings(), cwd: dir, reasoning: false };

    const first = stubProvider(assessment());
    await assessWithCache(first, signals, opts);

    const other = stubProvider(assessment({ decision: "allow_with_warnings", risk: "medium" }));
    other.name = "other-provider" as never;
    const result = await assessWithCache(other, signals, opts);
    expect(other.assess).toHaveBeenCalledTimes(1); // cache miss → real call
    expect(result.decision).toBe("allow_with_warnings");
  });

  it("clamps a cached answer against the deterministic floor at read time", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const settings = projectSettings();
    // A poisoned/hand-edited cache entry claiming "allow" for a package the
    // rules engine blocks must not bypass the floor.
    const blockedSignals = makeSignals({
      recentPublish: true,
      ageInDays: 2,
      nameSimilarity: { similarTo: "react-native-mmkv", distance: 1 },
    });
    const key = cacheKey({
      provider: "stub",
      model: "stub-model",
      reasoning: false,
      signals: blockedSignals,
    });
    await writeCachedAssessment(key, assessment(), settings, blockedSignals.package, dir);

    const provider = stubProvider(assessment());
    const result = await assessWithCache(provider, blockedSignals, {
      cache: settings,
      cwd: dir,
      reasoning: false,
    });
    expect(provider.assess).not.toHaveBeenCalled(); // it WAS a cache hit…
    expect(result.decision).toBe("block"); // …but the floor still wins
  });

  it("skips the cache entirely when no settings are passed (the CI path)", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-cache-"));
    const provider = stubProvider(assessment());
    const signals = makeSignals();

    await assessWithCache(provider, signals, { cwd: dir });
    await assessWithCache(provider, signals, { cwd: dir });
    expect(provider.assess).toHaveBeenCalledTimes(2); // fresh every time
    await expect(
      readFile(path.join(dir, ".bye", "ai-cache.json"), "utf8"),
    ).rejects.toThrow(); // nothing persisted
  });
});
