import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadApprovals } from "../src/approvals.js";
import { cacheFilePath, readCachedAssessment, type AiCacheSettings } from "../src/ai-cache.js";
import { buildDegradedSignals } from "../src/analyze/index.js";
import { lastRunPath, readLastRun, writeLastRun, type LastRunPackage } from "../src/last-run.js";
import { baselinePath, readBaseline } from "../src/monitor.js";
import { fetchWithTimeout, readResponseBuffer } from "../src/network.js";
import { quarantineTarball } from "../src/quarantine.js";
import { ResourceLimitError } from "../src/resource-limits.js";
import { evaluateRules } from "../src/rules.js";
import { computeSecurityScore } from "../src/score.js";
import { makeMetadata, makeSignals } from "./helpers.js";

let dir: string;
const settings: AiCacheSettings = {
  enabled: true,
  scope: "project",
  ttlHours: 24,
  exclude: [],
  refresh: false,
};

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "targate-m3-"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await rm(dir, { recursive: true, force: true });
});

describe("persisted trust validation", () => {
  it("ignores invalid approval records visibly and never defaults an unknown mode", async () => {
    await mkdir(path.join(dir, ".targate"));
    await writeFile(path.join(dir, ".targate", "approvals.json"), JSON.stringify({
      "safe@1.0.0": { mode: "no-scripts", approvedAt: "2026-07-13T10:00:00.000Z" },
      "evil@1.0.0": { mode: "run-everything", approvedAt: "yesterday" },
    }));
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    const approvals = await loadApprovals(dir);
    expect(Object.keys(approvals)).toEqual(["safe@1.0.0"]);
    expect(warn.mock.calls.flat().join(" ")).toContain("approvals.json#evil@1.0.0");
  });

  it("ignores a poisoned AI cache entry instead of trusting its allow", async () => {
    const file = cacheFilePath(settings, dir);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ entries: {
      poisoned: { cachedAt: new Date().toISOString(), assessment: { decision: "allow" } },
    } }));
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await readCachedAssessment("poisoned", settings, "pkg", dir)).toBeNull();
    expect(warn.mock.calls.flat().join(" ")).toContain(`${file}#poisoned`);
  });

  it("drops malformed monitor snapshots with a file-and-key warning", async () => {
    await mkdir(path.join(dir, ".targate"));
    const file = baselinePath(dir);
    await writeFile(file, JSON.stringify({
      schemaVersion: 1,
      updatedAt: "2026-07-13T10:00:00.000Z",
      snapshots: { "pkg@1.0.0": { name: "pkg", version: "1.0.0", knownMalicious: "no" } },
    }));
    const warn = vi.fn();
    const baseline = await readBaseline(dir, warn);
    expect(baseline?.snapshots).toEqual({});
    expect(warn.mock.calls.flat().join(" ")).toContain(`${file}#pkg@1.0.0`);
  });

  it("rejects a structurally malformed last-run record before rendering", async () => {
    const signals = makeSignals();
    const pkg: LastRunPackage = {
      metadata: makeMetadata(),
      signals,
      assessment: evaluateRules(signals),
      score: computeSecurityScore(signals),
    };
    await writeLastRun("add", [pkg], dir);
    const file = lastRunPath(dir);
    const doc = JSON.parse(await readFile(file, "utf8"));
    doc.packages[0].signals.nativeSurface = null;
    await writeFile(file, JSON.stringify(doc));
    await expect(readLastRun(dir)).rejects.toThrow(/different targate version/);
  });
});

describe("network and quarantine budgets", () => {
  it("enforces response size while streaming", async () => {
    const response = new Response(new Uint8Array(32));
    await expect(readResponseBuffer(response, 8, "fixture")).rejects.toMatchObject({
      kind: "response-size",
    });
  });

  it("terminates a slow fetch even when the fetch implementation ignores AbortSignal", async () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})));
    await expect(fetchWithTimeout("https://example.test", {}, {
      timeoutMs: 10,
      maxResponseBytes: 100,
    })).rejects.toMatchObject({ kind: "network-timeout" });
  });

  it("turns a tarball size limit into an explicit resource error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new Uint8Array(64), { status: 200 })));
    await expect(quarantineTarball("https://registry.test/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://registry.test",
      registry: {},
      resourceLimits: { maxTarballBytes: 8 },
    })).rejects.toMatchObject({ kind: "tarball-size" });
  });

  // Regression (v3 P1.1): a redirect to a private/metadata host must be refused,
  // not followed. Node's default redirect:"follow" would otherwise turn a
  // valid-looking public tarball URL into an SSRF via a 302.
  it("refuses a tarball redirect to a private/metadata host (SSRF)", async () => {
    const fetchMock = vi.fn(async (url: string) =>
      url.includes("169.254.169.254")
        ? new Response("secret", { status: 200 })
        : new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      quarantineTarball("https://registry.test/pkg.tgz", {
        packageName: "pkg",
        version: "1.0.0",
        registryUrl: "https://registry.test",
        registry: {},
      }),
    ).rejects.toThrow(/private\/loopback|https/);
    // The internal host was never actually fetched.
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("169.254.169.254"))).toBe(false);
  });

  it("ignores archive symlinks and keeps extracted real paths inside quarantine", async () => {
    const work = path.join(dir, "source");
    await mkdir(path.join(work, "package"), { recursive: true });
    await writeFile(path.join(work, "package", "package.json"), JSON.stringify({ name: "pkg", version: "1.0.0" }));
    await symlink("/etc/passwd", path.join(work, "package", "escape"));
    const archive = path.join(dir, "package.tgz");
    await tar.c({ cwd: work, file: archive, gzip: true }, ["package"]);
    const bytes = await readFile(archive);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(bytes, { status: 200 })));
    const quarantine = await quarantineTarball("https://registry.test/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://registry.test",
      registry: {},
    });
    await expect(access(path.join(quarantine.packageDir, "escape"))).rejects.toThrow();
    await quarantine.cleanup();
  });

  // Regression (v2 P0.1): these archive-limit breaches used to be thrown from
  // the node-tar filter, which escaped as an uncaughtException and CRASHED the
  // process instead of rejecting. They must reject cleanly with the right kind.
  async function tarballWith(files: Record<string, string>): Promise<Buffer> {
    const work = path.join(dir, `src-${Object.keys(files).length}-${Object.values(files).join("").length}`);
    await mkdir(path.join(work, "package"), { recursive: true });
    for (const [name, content] of Object.entries(files)) {
      await writeFile(path.join(work, "package", name), content);
    }
    const archive = path.join(work, "package.tgz");
    await tar.c({ cwd: work, file: archive, gzip: true }, ["package"]);
    return readFile(archive);
  }

  async function quarantineWithLimits(bytes: Buffer, resourceLimits: object) {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(bytes, { status: 200 })));
    return quarantineTarball("https://registry.test/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://registry.test",
      registry: {},
      resourceLimits,
    } as never);
  }

  it("rejects (not crashes) when the archive exceeds the file-count limit", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 12; i++) files[`f${i}.js`] = `x=${i}`;
    const bytes = await tarballWith(files);
    await expect(quarantineWithLimits(bytes, { maxFiles: 3 })).rejects.toMatchObject({
      kind: "file-count",
    });
  });

  it("rejects when a single entry exceeds the per-file byte limit", async () => {
    const bytes = await tarballWith({ "big.js": "a".repeat(5000) });
    await expect(quarantineWithLimits(bytes, { maxFileBytes: 100 })).rejects.toMatchObject({
      kind: "file-size",
    });
  });

  it("rejects when the total extracted size exceeds the limit", async () => {
    const bytes = await tarballWith({ "a.js": "a".repeat(400), "b.js": "b".repeat(400) });
    await expect(
      quarantineWithLimits(bytes, { maxFileBytes: 1000, maxExtractedBytes: 500 }),
    ).rejects.toMatchObject({ kind: "extracted-size" });
  });

  // Regression (v3 P2.1): a highly-compressible payload that inflates past the
  // extracted-size cap must be rejected by the decompression-bomb pre-check
  // (before node-tar burns CPU inflating it), not hang.
  it("rejects a decompression bomb via the pre-extraction gunzip cap", async () => {
    const bytes = await tarballWith({ "big.js": "a".repeat(2_000_000) }); // compresses tiny
    await expect(
      quarantineWithLimits(bytes, { maxExtractedBytes: 1000, maxFileBytes: 50_000_000, maxFiles: 100 }),
    ).rejects.toMatchObject({ kind: "extracted-size" });
  });

  it("makes an exceeded analysis budget UNKNOWN and approval-required", () => {
    const signals = buildDegradedSignals(
      makeMetadata(),
      { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      "file-count: archive exceeds 20000 entries",
    );
    const result = evaluateRules(signals);
    expect(result.decision).toBe("require_approval");
    expect(result.reasons.join(" ")).toContain("[unknown]");
    expect(signals.artifact.digest).toBe("unavailable");
  });
});
