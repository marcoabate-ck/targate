import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { compareSemver } from "./semver.js";
import type { PackageManager } from "./types.js";

const LOCKFILES: Record<PackageManager, string> = {
  pnpm: "pnpm-lock.yaml",
  yarn: "yarn.lock",
  npm: "package-lock.json",
};

export function lockfileName(pm: PackageManager): string {
  return LOCKFILES[pm];
}

export interface LockedPackageArtifact {
  name: string;
  version: string;
  resolved?: string;
  /** Raw tarball SRI (Yarn Berry cache checksums are intentionally excluded). */
  integrity?: string;
}

/**
 * A lockfile could not be parsed, or carries conflicting integrity values for
 * the same name@version (the core tampering signal). This MUST fail the review
 * loudly — degrading to an empty artifact list would report a tampered or
 * corrupt tree as "0 packages, all clean" and let the real install proceed
 * unvetted, defeating the whole gate.
 */
export class LockfileParseError extends Error {
  constructor(
    message: string,
    readonly packageManager: PackageManager,
  ) {
    super(message);
    this.name = "LockfileParseError";
  }
}

function artifactKey(artifact: LockedPackageArtifact): string {
  return `${artifact.name}@${artifact.version}`;
}

function mergeArtifact(
  artifacts: Map<string, LockedPackageArtifact>,
  artifact: LockedPackageArtifact,
): void {
  const key = artifactKey(artifact);
  const previous = artifacts.get(key);
  if (previous?.integrity && artifact.integrity && previous.integrity !== artifact.integrity) {
    throw new Error(`Lockfile contains conflicting integrity values for ${key}`);
  }
  const resolved = artifact.resolved ?? previous?.resolved;
  const integrity = artifact.integrity ?? previous?.integrity;
  artifacts.set(key, {
    name: artifact.name,
    version: artifact.version,
    ...(resolved ? { resolved } : {}),
    ...(integrity ? { integrity } : {}),
  });
}

/** A valid lockfile parses to a plain object (or an empty document → nullish).
 *  An array or a scalar (`[]`, `123`, `"x"`) is structurally invalid — fail
 *  loudly rather than degrade to an empty, apparently-clean tree. */
function assertLockfileObject(
  doc: unknown,
  pm: PackageManager,
): asserts doc is Record<string, unknown> | null | undefined {
  if (Array.isArray(doc) || (doc != null && typeof doc !== "object")) {
    throw new LockfileParseError(`Malformed ${pm} lockfile: expected a top-level object`, pm);
  }
}

interface NpmV1Dependency {
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, NpmV1Dependency>;
}

/** npm lockfileVersion 1 (npm 6) has no `packages` map — only a nested
 *  `dependencies` tree. Walk it recursively so a v1 lockfile is vetted instead
 *  of silently yielding zero packages. */
function walkNpmV1Dependencies(
  deps: Record<string, NpmV1Dependency>,
  artifacts: Map<string, LockedPackageArtifact>,
): void {
  for (const [name, meta] of Object.entries(deps)) {
    if (name && meta && typeof meta.version === "string") {
      mergeArtifact(artifacts, {
        name,
        version: meta.version,
        ...(typeof meta.resolved === "string" ? { resolved: meta.resolved } : {}),
        ...(typeof meta.integrity === "string" ? { integrity: meta.integrity } : {}),
      });
    }
    if (meta && typeof meta.dependencies === "object" && meta.dependencies) {
      walkNpmV1Dependencies(meta.dependencies, artifacts);
    }
  }
}

function pnpmIdentity(rawKey: string): { name: string; version: string } | null {
  const key = rawKey.replace(/^\//, "").replace(/\([^\r\n]*\)$/, "");
  const at = key.lastIndexOf("@");
  if (at > 0) return { name: key.slice(0, at), version: key.slice(at + 1) };
  const legacy = key.match(/^(@[^/]+\/[^/]+|[^/]+)\/([^/]+)$/);
  return legacy ? { name: legacy[1], version: legacy[2] } : null;
}

/** Extract exact artifact identities and checksums exposed by each lockfile format. */
export function extractLockfileArtifacts(
  pm: PackageManager,
  content: string,
): LockedPackageArtifact[] {
  const artifacts = new Map<string, LockedPackageArtifact>();
  if (pm === "npm") {
    // Only the parse is wrapped: a genuinely empty-but-valid lockfile yields
    // [] (correct — nothing to vet), while unparsable bytes throw. The
    // conflicting-integrity throw from mergeArtifact deliberately propagates.
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch (err) {
      throw new LockfileParseError(
        `Unparsable npm lockfile: ${err instanceof Error ? err.message : String(err)}`,
        pm,
      );
    }
    assertLockfileObject(parsed, pm);
    const doc = parsed as {
      packages?: Record<string, { version?: string; resolved?: string; integrity?: string }>;
      dependencies?: Record<string, NpmV1Dependency>;
    };
    if (doc?.packages) {
      for (const [key, meta] of Object.entries(doc.packages)) {
        if (!key || !meta.version) continue;
        mergeArtifact(artifacts, {
          name: key.replace(/^.*node_modules\//, ""),
          version: meta.version,
          ...(typeof meta.resolved === "string" ? { resolved: meta.resolved } : {}),
          ...(typeof meta.integrity === "string" ? { integrity: meta.integrity } : {}),
        });
      }
    } else if (doc?.dependencies) {
      // lockfileVersion 1 (npm 6): no `packages` map, only a nested tree.
      walkNpmV1Dependencies(doc.dependencies, artifacts);
    }
    // Neither key present → genuinely empty lockfile → [] (nothing to vet).
  } else if (pm === "pnpm") {
    let parsed: unknown;
    try {
      parsed = parseYaml(content);
    } catch (err) {
      throw new LockfileParseError(
        `Unparsable pnpm lockfile: ${err instanceof Error ? err.message : String(err)}`,
        pm,
      );
    }
    assertLockfileObject(parsed, pm);
    const doc = parsed as {
      packages?: Record<string, { resolution?: { integrity?: string; tarball?: string } | string }>;
    };
    for (const [key, meta] of Object.entries(doc?.packages ?? {})) {
      const identity = pnpmIdentity(key);
      if (!identity) continue;
      const resolution = typeof meta?.resolution === "object" ? meta.resolution : undefined;
      mergeArtifact(artifacts, {
        ...identity,
        ...(typeof resolution?.tarball === "string" ? { resolved: resolution.tarball } : {}),
        ...(typeof resolution?.integrity === "string" ? { integrity: resolution.integrity } : {}),
      });
    }
  } else {
    for (const block of content.split(/\n\n/)) {
      const header = block.match(/^"?((?:@[\w.-]+\/)?[\w.-]+)@[^\n]*?:\s*\n/);
      const version = block.match(/\n\s+version:?\s+["']?([^\s"']+)["']?/);
      if (!header || !version) continue;
      const resolved = block.match(/\n\s+(?:resolved|resolution):?\s+["']?([^\s"']+)["']?/);
      const integrity = block.match(/\n\s+integrity:?\s+([^\s]+)/);
      mergeArtifact(artifacts, {
        name: header[1],
        version: version[1],
        ...(resolved ? { resolved: resolved[1] } : {}),
        ...(integrity ? { integrity: integrity[1] } : {}),
      });
    }
  }
  return [...artifacts.values()].sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
}

/**
 * Extract the set of "name@version" entries from a lockfile, best-effort
 * and parser-free: enough to show WHICH packages an install added, which is
 * the phase-2 "lockfile diff preview".
 */
export function extractLockfileEntries(pm: PackageManager, content: string): Set<string> {
  const entries = new Set<string>();

  if (pm === "npm") {
    try {
      const doc = JSON.parse(content) as {
        packages?: Record<string, { version?: string }>;
      };
      for (const [key, meta] of Object.entries(doc.packages ?? {})) {
        if (!key) continue; // "" is the root project
        const name = key.replace(/^.*node_modules\//, "");
        if (meta.version) entries.add(`${name}@${meta.version}`);
      }
    } catch {
      /* unparsable lockfile — return empty */
    }
    return entries;
  }

  if (pm === "pnpm") {
    // pnpm v6-v10 keys may be slash-prefixed, quoted, and carry peer suffixes.
    for (const match of content.matchAll(
      /^ {2}['"]?\/?((?:@[\w.-]+\/)?[\w.-]+@[^\s:'"(]+)(?:\([^\r\n'"]*\))?['"]?:\s*$/gm,
    )) {
      entries.add(match[1]);
    }
    return entries;
  }

  // yarn.lock (v1): resolution lines "name@^1.0.0:" followed by  version "1.2.3"
  const blocks = content.split(/\n\n/);
  for (const block of blocks) {
    const header = block.match(/^"?((?:@[\w.-]+\/)?[\w.-]+)@[^\n]*?:\s*\n/);
    const version = block.match(/\n\s+version:?\s+["']?([^\s"']+)["']?/);
    if (header && version) entries.add(`${header[1]}@${version[1]}`);
  }
  return entries;
}

export async function snapshotLockfile(
  pm: PackageManager,
  cwd: string = process.cwd(),
): Promise<string | null> {
  const file = path.join(cwd, lockfileName(pm));
  if (!existsSync(file)) return null;
  return readFile(file, "utf8");
}

/**
 * Build a name -> resolved versions index from a lockfile. A package can
 * legitimately appear at several versions (different transitive requirers),
 * so the value is a sorted list, not a single string.
 */
export function lockfileVersionIndex(
  pm: PackageManager,
  content: string,
): Map<string, string[]> {
  const index = new Map<string, Set<string>>();
  for (const entry of extractLockfileEntries(pm, content)) {
    const at = entry.lastIndexOf("@");
    if (at <= 0) continue;
    const name = entry.slice(0, at);
    const version = entry.slice(at + 1);
    (index.get(name) ?? index.set(name, new Set()).get(name)!).add(version);
  }
  // Semver order (ascending) — resolveInstalledVersion takes the LAST entry
  // as "highest", and a lexicographic sort would put 1.9.0 above 1.10.0.
  return new Map([...index].map(([name, versions]) => [name, [...versions].sort(compareSemver)]));
}

export interface ResolvedVersion {
  version: string;
  /** How the version was determined. */
  source: "lockfile" | "range" | "ambiguous-lockfile";
}

/**
 * Resolve the version of a direct dependency that will actually be
 * installed. Prefers the lockfile (the source of truth for what npm/pnpm/
 * yarn will place on disk); falls back to the declared range, flagging when
 * the lockfile lists several versions and the exact one can't be pinned.
 */
export function resolveInstalledVersion(
  name: string,
  declaredRange: string,
  lockIndex: Map<string, string[]> | null,
): ResolvedVersion {
  const rangeVersion = declaredRange.match(/^[\^~]?(\d+\.\d+\.\d+(?:-[\w.]+)?)$/)?.[1];
  const inLock = lockIndex?.get(name);

  if (inLock && inLock.length === 1) {
    return { version: inLock[0], source: "lockfile" };
  }
  if (inLock && inLock.length > 1 && rangeVersion && inLock.includes(rangeVersion)) {
    // Multiple versions in the tree, but one matches the declared pin exactly.
    return { version: rangeVersion, source: "lockfile" };
  }
  if (inLock && inLock.length > 1) {
    // Ambiguous — pick the highest, but tell the caller resolution was fuzzy.
    return { version: inLock[inLock.length - 1], source: "ambiguous-lockfile" };
  }
  if (rangeVersion) return { version: rangeVersion, source: "range" };
  return { version: "", source: "range" };
}

export interface LockfileDiff {
  added: string[];
  removed: string[];
}

export function diffLockfiles(
  pm: PackageManager,
  before: string | null,
  after: string | null,
): LockfileDiff {
  const beforeSet = before ? extractLockfileEntries(pm, before) : new Set<string>();
  const afterSet = after ? extractLockfileEntries(pm, after) : new Set<string>();
  return {
    added: [...afterSet].filter((e) => !beforeSet.has(e)).sort(),
    removed: [...beforeSet].filter((e) => !afterSet.has(e)).sort(),
  };
}
