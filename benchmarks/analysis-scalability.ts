import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import * as tar from "tar";
import { assessManyWithCache } from "../src/ai.js";
import type { AiCacheSettings } from "../src/ai-cache.js";
import { buildPackageFileIndex } from "../src/analyze/file-index.js";
import { buildDegradedSignals } from "../src/analyze/index.js";
import type { AiProvider } from "../src/providers/types.js";
import type { PackageMetadata, RiskAssessment, Signals } from "../src/types.js";

const SIZES = [10, 100, 500, 1000];
const BATCH_SIZE = 8;
const TARGETS = { coldMs1000: 20_000, warmMs1000: 5_000, peakRssBytes: 1024 ** 3 };

interface BenchmarkResult {
  packages: number;
  coldMs: number;
  warmMs: number;
  peakRssBytes: number;
  tarballBytes: number;
  modelCallsCold: number;
  modelCallsWarm: number;
  cacheHitRateWarm: number;
}

const assessment = (): RiskAssessment => ({
  risk: "low",
  decision: "allow",
  summary: "synthetic benchmark",
  reasons: ["synthetic benchmark"],
  recommendedAction: "none",
  source: "ai",
});

function signalsFor(index: number): Signals {
  const name = `benchmark-package-${index}`;
  const metadata: PackageMetadata = {
    name,
    version: "1.0.0",
    maintainers: ["benchmark"],
    tarballUrl: `https://example.invalid/${name}.tgz`,
    scripts: {},
    dependencyCount: 0,
    directDependencies: [],
    registryReputation: { hasProvenance: false },
  };
  return buildDegradedSignals(
    metadata,
    { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
    "synthetic benchmark fixture",
  );
}

async function buildFixture(root: string, count: number): Promise<void> {
  for (let start = 0; start < count; start += 100) {
    const directory = path.join(root, `group-${Math.floor(start / 100)}`);
    await mkdir(directory, { recursive: true });
    const writes: Promise<void>[] = [];
    for (let index = start; index < Math.min(start + 100, count); index++) {
      const source = `export const value${index} = ${index};\n`;
      writes.push(writeFile(path.join(directory, `file-${index}.js`), source));
    }
    await Promise.all(writes);
  }
}

async function runOne(packages: number): Promise<BenchmarkResult> {
  const root = await mkdtemp(path.join(tmpdir(), `targate-benchmark-${packages}-`));
  const packageRoot = path.join(root, "package");
  await mkdir(packageRoot);
  await buildFixture(packageRoot, packages);
  const archive = path.join(root, "package.tgz");
  await tar.c({ cwd: root, file: archive, gzip: true }, ["package"]);
  const tarballBytes = (await stat(archive)).size;
  let peakRssBytes = process.memoryUsage().rss;
  const sampleMemory = () => {
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  };

  try {
    const signals = Array.from({ length: packages }, (_, index) => signalsFor(index));
    const cache: AiCacheSettings = {
      enabled: true,
      scope: "project",
      ttlHours: 24,
      exclude: [],
      refresh: false,
    };
    let modelCalls = 0;
    const provider: AiProvider = {
      name: "benchmark",
      model: "batch-v1",
      async assess() {
        modelCalls++;
        return assessment();
      },
      async assessBatch(items) {
        modelCalls++;
        return items.map((item) => ({
          package: `${item.package}@${item.version}`,
          assessment: assessment(),
        }));
      },
    };

    const coldStarted = performance.now();
    await buildPackageFileIndex(packageRoot);
    await assessManyWithCache(provider, signals, { cache, cwd: root, reasoning: false }, BATCH_SIZE);
    const coldMs = performance.now() - coldStarted;
    const modelCallsCold = modelCalls;
    sampleMemory();

    modelCalls = 0;
    const warmStarted = performance.now();
    await buildPackageFileIndex(packageRoot);
    const warm = await assessManyWithCache(
      provider,
      signals,
      { cache, cwd: root, reasoning: false },
      BATCH_SIZE,
    );
    const warmMs = performance.now() - warmStarted;
    sampleMemory();
    const cacheHits = warm.filter((result) => result.reasons.some((reason) => reason.startsWith("[cache]"))).length;

    return {
      packages,
      coldMs: Math.round(coldMs * 100) / 100,
      warmMs: Math.round(warmMs * 100) / 100,
      peakRssBytes,
      tarballBytes,
      modelCallsCold,
      modelCallsWarm: modelCalls,
      cacheHitRateWarm: cacheHits / packages,
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const results: BenchmarkResult[] = [];
for (const size of SIZES) results.push(await runOne(size));

if (process.argv.includes("--json")) console.log(JSON.stringify({ targets: TARGETS, results }, null, 2));
else {
  console.table(results.map((result) => ({
    packages: result.packages,
    coldMs: result.coldMs,
    warmMs: result.warmMs,
    peakMiB: Math.round(result.peakRssBytes / 1024 / 1024),
    bytes: result.tarballBytes,
    coldModelCalls: result.modelCallsCold,
    warmModelCalls: result.modelCallsWarm,
    warmCacheHit: `${Math.round(result.cacheHitRateWarm * 100)}%`,
  })));
}

const largest = results.at(-1)!;
const failures = [
  largest.coldMs > TARGETS.coldMs1000 ? `1000-package cold run exceeded ${TARGETS.coldMs1000}ms` : null,
  largest.warmMs > TARGETS.warmMs1000 ? `1000-package warm run exceeded ${TARGETS.warmMs1000}ms` : null,
  largest.peakRssBytes > TARGETS.peakRssBytes ? "peak RSS exceeded 1 GiB" : null,
  largest.modelCallsCold > Math.ceil(largest.packages / BATCH_SIZE) ? "batch model-call target regressed" : null,
  largest.modelCallsWarm !== 0 || largest.cacheHitRateWarm !== 1 ? "warm cache did not eliminate model calls" : null,
].filter((failure): failure is string => failure !== null);
if (failures.length > 0) {
  for (const failure of failures) console.error(`Benchmark target failed: ${failure}`);
  process.exitCode = 1;
}
