import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { authHeaderForUrl, getNpmrc } from "./npmrc.js";
import type { ArtifactSignal, ArtifactTrust } from "./types.js";

export interface Quarantine {
  /** Root temp dir (contains the tarball and the extracted tree). */
  root: string;
  /** Path of the extracted package contents (the tarball's "package/" dir). */
  packageDir: string;
  /** Cryptographic identity and all evidence checked for these exact bytes. */
  artifact: ArtifactSignal;
  cleanup(): Promise<void>;
}

/** Registry-provided checksums to verify the downloaded bytes against. */
export interface TarballChecksums {
  /** SRI string from dist.integrity ("sha512-<base64>", possibly several space-separated). */
  integrity?: string;
  /** Legacy sha1 hex digest from dist.shasum. */
  shasum?: string;
}

export type PublicArtifactEvidence =
  | { status: "available"; registryUrl: string; checksums: TarballChecksums }
  | { status: "not-found"; registryUrl: string }
  | { status: "unavailable"; registryUrl: string; reason: string }
  | { status: "skipped" };

export interface QuarantineOptions {
  packageName: string;
  version: string;
  registryUrl: string;
  registry: TarballChecksums;
  lockfile?: TarballChecksums;
  /** True only for a pre-existing reviewed/committed lockfile, not a fresh resolution. */
  lockfileTrusted?: boolean;
  historicalIntegrity?: string;
  publicArtifact?: PublicArtifactEvidence;
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
 * otherwise the legacy sha1 `dist.shasum`. Higher-level artifact verification
 * applies this primitive independently to registry, lockfile, public-mirror,
 * and historical evidence. Pure and unit-testable.
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

function declaredIntegrity(checksums?: TarballChecksums): string | undefined {
  if (!checksums) return undefined;
  return checksums.integrity ?? (checksums.shasum ? `sha1-${checksums.shasum}` : undefined);
}

function verifyEvidence(
  bytes: Buffer,
  label: string,
  checksums: TarballChecksums | undefined,
  reasons: string[],
): boolean | undefined {
  if (!declaredIntegrity(checksums)) return undefined;
  const result = checkTarballIntegrity(bytes, checksums ?? {});
  if (result.algorithm === "none") {
    reasons.push(`${label} checksum is malformed or uses an unsupported algorithm`);
    return false;
  }
  if (!result.ok) {
    reasons.push(
      `${label} checksum mismatch (${result.algorithm}: expected ${result.expected}, got ${result.actual})`,
    );
    return false;
  }
  return true;
}

/** Build the trust signal without ever treating two claims from one registry as independent. */
export function verifyArtifactIdentity(
  bytes: Buffer,
  tarballUrl: string,
  options: QuarantineOptions,
): ArtifactSignal {
  const digest = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  const reasons: string[] = [];
  const registryOk = verifyEvidence(bytes, "registry", options.registry, reasons);
  const lockfileOk = verifyEvidence(bytes, "lockfile", options.lockfile, reasons);
  const historyOk = options.historicalIntegrity
    ? verifyEvidence(bytes, "historical ledger", { integrity: options.historicalIntegrity }, reasons)
    : undefined;
  const publicOk = options.publicArtifact?.status === "available"
    ? verifyEvidence(bytes, "public registry", options.publicArtifact.checksums, reasons)
    : undefined;

  let trust: ArtifactTrust;
  if ([registryOk, lockfileOk, historyOk, publicOk].includes(false)) {
    trust = "mutated";
  } else if (publicOk) {
    trust = "public-equivalent";
    reasons.push("downloaded bytes match the independent public-registry checksum");
  } else if (lockfileOk && options.lockfileTrusted) {
    trust = "lockfile-verified";
    reasons.push("downloaded bytes match the reviewed lockfile checksum");
  } else if (historyOk) {
    trust = "history-verified";
    reasons.push("downloaded bytes match the previously installed artifact digest");
  } else if (options.publicArtifact?.status === "unavailable") {
    trust = "public-unavailable";
    reasons.push(`public-registry comparison unavailable: ${options.publicArtifact.reason}`);
  } else if (options.publicArtifact?.status === "not-found") {
    trust = declaredIntegrity(options.registry) ? "private-only" : "unverified";
    reasons.push("exact package version is not present on the configured public registry");
  } else if (registryOk) {
    trust = "registry-consistent";
    reasons.push("downloaded bytes match the checksum declared by their source registry");
  } else {
    trust = "unverified";
    reasons.push("no registry, lockfile, public, or historical checksum was available");
  }

  return {
    trust,
    digest,
    registryUrl: options.registryUrl,
    tarballUrl,
    registryIntegrity: declaredIntegrity(options.registry),
    lockfileIntegrity: declaredIntegrity(options.lockfile),
    publicIntegrity:
      options.publicArtifact?.status === "available"
        ? declaredIntegrity(options.publicArtifact.checksums)
        : undefined,
    historicalIntegrity: options.historicalIntegrity,
    publicRegistryUrl:
      options.publicArtifact && options.publicArtifact.status !== "skipped"
        ? options.publicArtifact.registryUrl
        : undefined,
    reasons,
  };
}

/**
 * Download the package tarball into an isolated temp directory, derive and
 * verify its artifact identity, and extract it WITHOUT running lifecycle
 * scripts. A mismatch remains inspectable but is carried as `mutated`, which
 * the deterministic rules engine hard-blocks. Extraction uses strict paths.
 */
export async function quarantineTarball(
  tarballUrl: string,
  options: QuarantineOptions,
): Promise<Quarantine> {
  const root = await mkdtemp(path.join(tmpdir(), "targate-"));
  const tarballPath = path.join(root, "package.tgz");

  // Private registries: reuse the registry's nerf-darted .npmrc credentials
  // when the tarball URL matches one (npm does the same). Public tarballs
  // resolve no header and the request stays anonymous.
  const auth = authHeaderForUrl(tarballUrl, getNpmrc());
  const res = await fetch(tarballUrl, auth ? { headers: { authorization: auth } } : undefined);
  if (!res.ok) {
    await rm(root, { recursive: true, force: true });
    throw new Error(
      `Failed to download tarball (${res.status}): ${tarballUrl}` +
        (res.status === 401 || res.status === 403
          ? " — check the .npmrc credentials for this registry"
          : ""),
    );
  }
  const bytes = Buffer.from(await res.arrayBuffer());

  const artifact = verifyArtifactIdentity(bytes, tarballUrl, options);

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
    artifact,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}
