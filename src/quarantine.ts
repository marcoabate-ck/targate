import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";

export interface Quarantine {
  /** Root temp dir (contains the tarball and the extracted tree). */
  root: string;
  /** Path of the extracted package contents (the tarball's "package/" dir). */
  packageDir: string;
  cleanup(): Promise<void>;
}

/** Registry-provided checksums to verify the downloaded bytes against. */
export interface TarballChecksums {
  /** SRI string from dist.integrity ("sha512-<base64>", possibly several space-separated). */
  integrity?: string;
  /** Legacy sha1 hex digest from dist.shasum. */
  shasum?: string;
}

const SRI_ALGORITHMS = ["sha512", "sha384", "sha256", "sha1"] as const;

export interface IntegrityResult {
  ok: boolean;
  /** Which check ran: an SRI algorithm, "shasum", or "none" when no checksum was available. */
  algorithm: string;
  expected?: string;
  actual?: string;
}

/**
 * Verify downloaded tarball bytes against the registry checksums — the SRI
 * `dist.integrity` when present (strongest available algorithm wins),
 * otherwise the legacy sha1 `dist.shasum`. The analysis reads these bytes as
 * authoritative evidence, so what we scan must be exactly what the lockfile
 * pins — a mirror/proxy substituting content must fail loudly, not be
 * silently analyzed (security analysis finding 4). Pure, unit-testable.
 */
export function checkTarballIntegrity(bytes: Buffer, checksums: TarballChecksums): IntegrityResult {
  for (const algo of SRI_ALGORITHMS) {
    const entry = (checksums.integrity ?? "")
      .split(/\s+/)
      .find((part) => part.startsWith(`${algo}-`));
    if (!entry) continue;
    const expected = entry.slice(algo.length + 1);
    const actual = createHash(algo).update(bytes).digest("base64");
    return { ok: actual === expected, algorithm: algo, expected, actual };
  }
  if (checksums.shasum) {
    const actual = createHash("sha1").update(bytes).digest("hex");
    return { ok: actual === checksums.shasum, algorithm: "shasum", expected: checksums.shasum, actual };
  }
  return { ok: true, algorithm: "none" };
}

/**
 * Download the package tarball into an isolated temp directory, verify its
 * checksum against the registry manifest, and extract it WITHOUT running any
 * lifecycle scripts. Extraction goes through `tar` with strict path checking,
 * so entries cannot escape the quarantine directory.
 */
export async function quarantineTarball(
  tarballUrl: string,
  checksums: TarballChecksums = {},
): Promise<Quarantine> {
  const root = await mkdtemp(path.join(tmpdir(), "targate-"));
  const tarballPath = path.join(root, "package.tgz");

  const res = await fetch(tarballUrl);
  if (!res.ok) {
    await rm(root, { recursive: true, force: true });
    throw new Error(`Failed to download tarball (${res.status}): ${tarballUrl}`);
  }
  const bytes = Buffer.from(await res.arrayBuffer());

  const integrity = checkTarballIntegrity(bytes, checksums);
  if (!integrity.ok) {
    await rm(root, { recursive: true, force: true });
    throw new Error(
      `Tarball integrity verification FAILED for ${tarballUrl} (${integrity.algorithm}: expected ${integrity.expected}, got ${integrity.actual}). The downloaded bytes do not match the registry manifest — refusing to analyze them.`,
    );
  }

  await writeFile(tarballPath, bytes);

  await tar.x({ file: tarballPath, cwd: root, strict: true }).catch(async (err) => {
    await rm(root, { recursive: true, force: true });
    throw err;
  });

  // npm tarballs contain a top-level "package/" directory
  const packageDir = path.join(root, "package");

  return {
    root,
    packageDir,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}
