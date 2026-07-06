import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import type { PackageManager } from "./types.js";

const LOCKFILES: Record<PackageManager, string> = {
  pnpm: "pnpm-lock.yaml",
  yarn: "yarn.lock",
  npm: "package-lock.json",
};

export function lockfileName(pm: PackageManager): string {
  return LOCKFILES[pm];
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
    // pnpm-lock.yaml packages section keys look like:  /name@1.2.3:  or  name@1.2.3:
    for (const match of content.matchAll(/^ {2}\/?((?:@[\w.-]+\/)?[\w.-]+@[^\s:(]+)[^:]*:\s*$/gm)) {
      entries.add(match[1]);
    }
    return entries;
  }

  // yarn.lock (v1): resolution lines "name@^1.0.0:" followed by  version "1.2.3"
  const blocks = content.split(/\n\n/);
  for (const block of blocks) {
    const header = block.match(/^"?((?:@[\w.-]+\/)?[\w.-]+)@[^\n]*?:\s*\n/);
    const version = block.match(/\n\s+version\s+"([^"]+)"/);
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
