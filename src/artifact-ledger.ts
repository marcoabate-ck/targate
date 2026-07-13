import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { ArtifactSignal } from "./types.js";

const SCHEMA_VERSION = 1;

export interface ArtifactRecord {
  name: string;
  version: string;
  registryUrl: string;
  digest: string;
  firstObservedAt: string;
  lastObservedAt: string;
}

interface ArtifactLedgerFile {
  schemaVersion: typeof SCHEMA_VERSION;
  artifacts: Record<string, ArtifactRecord>;
}

export interface ArtifactObservation {
  name: string;
  version: string;
  artifact: ArtifactSignal;
}

export function artifactLedgerPath(cwd: string = process.cwd()): string {
  return path.join(cwd, ".targate", "artifacts.json");
}

function normalizeRegistry(url: string): string {
  return url.replace(/\/+$/, "").toLowerCase();
}

export function artifactLedgerKey(registryUrl: string, name: string, version: string): string {
  return `${normalizeRegistry(registryUrl)}|${name}@${version}`;
}

function validIso(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(new Date(value).getTime());
}

function validRecord(value: unknown): value is ArtifactRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.name === "string" &&
    typeof record.version === "string" &&
    typeof record.registryUrl === "string" &&
    typeof record.digest === "string" &&
    /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(record.digest) &&
    validIso(record.firstObservedAt) &&
    validIso(record.lastObservedAt)
  );
}

/** Invalid entries are ignored visibly; malformed state is never trusted. */
export async function loadArtifactLedger(
  cwd: string = process.cwd(),
  warn: (message: string) => void = (message) => console.error(message),
): Promise<Record<string, ArtifactRecord>> {
  const file = artifactLedgerPath(cwd);
  if (!existsSync(file)) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    warn(`[targate] ignoring malformed ${file}: ${err instanceof Error ? err.message : String(err)}`);
    return {};
  }
  if (typeof parsed !== "object" || parsed === null) {
    warn(`[targate] ignoring malformed ${file}: expected an object`);
    return {};
  }
  const doc = parsed as { schemaVersion?: unknown; artifacts?: unknown };
  if (doc.schemaVersion !== SCHEMA_VERSION || typeof doc.artifacts !== "object" || doc.artifacts === null) {
    warn(`[targate] ignoring malformed ${file}: unsupported schema or missing artifacts map`);
    return {};
  }
  const valid: Record<string, ArtifactRecord> = {};
  for (const [key, value] of Object.entries(doc.artifacts)) {
    if (!validRecord(value)) {
      warn(`[targate] ignoring invalid artifact record ${file}#${key}`);
      continue;
    }
    const expectedKey = artifactLedgerKey(value.registryUrl, value.name, value.version);
    if (key !== expectedKey) {
      warn(`[targate] ignoring artifact record with mismatched key ${file}#${key}`);
      continue;
    }
    valid[key] = value;
  }
  return valid;
}

export async function historicalArtifactDigest(
  registryUrl: string,
  name: string,
  version: string,
  cwd: string = process.cwd(),
): Promise<string | undefined> {
  const ledger = await loadArtifactLedger(cwd);
  return ledger[artifactLedgerKey(registryUrl, name, version)]?.digest;
}

/** Record only successful installs; never overwrite evidence of a mutation. */
export async function recordArtifactObservations(
  observations: ArtifactObservation[],
  cwd: string = process.cwd(),
): Promise<void> {
  if (observations.length === 0) return;
  const artifacts = await loadArtifactLedger(cwd);
  const now = new Date().toISOString();
  for (const observation of observations) {
    if (observation.artifact.trust === "mutated") continue;
    const { name, version, artifact } = observation;
    const key = artifactLedgerKey(artifact.registryUrl, name, version);
    const previous = artifacts[key];
    if (previous && previous.digest !== artifact.digest) {
      throw new Error(
        `Refusing to replace historical artifact identity for ${name}@${version}: ${previous.digest} != ${artifact.digest}`,
      );
    }
    artifacts[key] = {
      name,
      version,
      registryUrl: artifact.registryUrl,
      digest: artifact.digest,
      firstObservedAt: previous?.firstObservedAt ?? now,
      lastObservedAt: now,
    };
  }
  const file = artifactLedgerPath(cwd);
  await mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  const doc: ArtifactLedgerFile = { schemaVersion: SCHEMA_VERSION, artifacts };
  await writeFile(temp, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 });
  await rename(temp, file);
}
