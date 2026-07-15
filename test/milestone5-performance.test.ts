import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { assessManyWithCache } from "../src/ai.js";
import type { AiCacheSettings } from "../src/ai-cache.js";
import {
  assertCompleteFileIndex,
  buildPackageFileIndex,
} from "../src/analyze/file-index.js";
import { buildPackageSignals } from "../src/pipeline.js";
import type { AiProvider } from "../src/providers/types.js";
import type { RiskAssessment } from "../src/types.js";
import { makeMetadata, makeSignals } from "./helpers.js";

let directory: string;

beforeEach(async () => {
  directory = await mkdtemp(path.join(tmpdir(), "targate-m5-"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await rm(directory, { recursive: true, force: true });
});

describe("shared package file index", () => {
  it("indexes nested files once with basename and byte metrics", async () => {
    const root = path.join(directory, "package");
    await mkdir(path.join(root, "ios"), { recursive: true });
    await writeFile(path.join(root, "index.js"), "export default 1;\n");
    await writeFile(path.join(root, "ios", "module.podspec"), "Pod::Spec.new\n");
    const index = await buildPackageFileIndex(root);
    expect(index.totalFiles).toBe(2);
    expect(index.totalBytes).toBe(Buffer.byteLength("export default 1;\nPod::Spec.new\n"));
    expect(index.byBasename.get("module.podspec")?.[0].relPath).toBe(
      path.join("ios", "module.podspec"),
    );
    expect(index.truncated).toBe(false);
  });

  it("marks a bounded partial index and refuses to treat it as complete", async () => {
    const root = path.join(directory, "package");
    await mkdir(root);
    await Promise.all([
      writeFile(path.join(root, "a.js"), "a"),
      writeFile(path.join(root, "b.js"), "b"),
    ]);
    const index = await buildPackageFileIndex(root, {
      networkTimeoutMs: 100,
      maxResponseBytes: 100,
      maxTarballBytes: 100,
      maxExtractedBytes: 100,
      maxFiles: 1,
      maxFileBytes: 100,
      maxScanDuration: 100,
    });
    expect(index.truncated).toBe(true);
    expect(() => assertCompleteFileIndex(index)).toThrow(/file-count budget/);
  });
});

describe("parallel package I/O", () => {
  it("starts OSV while the tarball download is still in flight", async () => {
    const source = path.join(directory, "source");
    await mkdir(path.join(source, "package"), { recursive: true });
    await writeFile(
      path.join(source, "package", "package.json"),
      JSON.stringify({ name: "pkg", version: "1.0.0" }),
    );
    const archive = path.join(directory, "package.tgz");
    await tar.c({ cwd: source, file: archive, gzip: true }, ["package"]);
    const bytes = await readFile(archive);

    let releaseTarball!: (response: Response) => void;
    const tarballResponse = new Promise<Response>((resolve) => {
      releaseTarball = resolve;
    });
    const fetchMock = vi.fn((input: string | URL | Request) => {
      const url = String(input);
      if (url.includes("pkg.tgz")) return tarballResponse;
      if (url.includes("api.osv.dev")) {
        return Promise.resolve(new Response(JSON.stringify({ vulns: [] }), { status: 200 }));
      }
      throw new Error(`unexpected URL ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const pending = buildPackageSignals("pkg", "1.0.0", {
      metadata: makeMetadata({
        name: "pkg",
        version: "1.0.0",
        tarballUrl: "https://registry.test/pkg.tgz",
        scripts: {},
        registryUrl: "https://registry.test",
        registrySource: "default",
      }),
      noReputation: true,
      cwd: directory,
    });

    await vi.waitFor(() => {
      const urls = fetchMock.mock.calls.map(([input]) => String(input));
      expect(urls.some((url) => url.includes("pkg.tgz"))).toBe(true);
      expect(urls.some((url) => url.includes("api.osv.dev"))).toBe(true);
    });
    releaseTarball(new Response(bytes, { status: 200 }));
    const result = await pending;
    expect(result.signals.osvUnavailable).toBe(false);
  });
});

describe("batched warm cache", () => {
  it("uses batched cold calls and eliminates provider calls when warm", async () => {
    const settings: AiCacheSettings = {
      enabled: true,
      scope: "project",
      ttlHours: 24,
      exclude: [],
      refresh: false,
    };
    const verdict = (): RiskAssessment => ({
      risk: "low",
      decision: "allow",
      summary: "ok",
      reasons: ["ok"],
      recommendedAction: "install",
      source: "ai",
    });
    const assess = vi.fn(async () => verdict());
    const assessBatch = vi.fn(async (signals: ReturnType<typeof makeSignals>[]) =>
      signals.map((item) => ({
        package: `${item.package}@${item.version}`,
        assessment: verdict(),
      })),
    );
    const provider: AiProvider = { name: "fake", model: "batch", assess, assessBatch };
    const signals = Array.from({ length: 100 }, (_, index) =>
      makeSignals({ package: `package-${index}` }),
    );

    await assessManyWithCache(
      provider,
      signals,
      { cache: settings, cwd: directory, reasoning: false },
      8,
    );
    expect(assessBatch).toHaveBeenCalledTimes(13);
    assessBatch.mockClear();

    const warm = await assessManyWithCache(
      provider,
      signals,
      { cache: settings, cwd: directory, reasoning: false },
      8,
    );
    expect(assessBatch).not.toHaveBeenCalled();
    expect(assess).not.toHaveBeenCalled();
    expect(warm.every((result) => result.reasons.some((reason) => reason.startsWith("[cache]")))).toBe(true);
  });
});

