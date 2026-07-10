import { highestSemver } from "./semver.js";
import type { PackageMetadata, RegistryReputation } from "./types.js";

const REGISTRY = "https://registry.npmjs.org";

export class PackageNotFoundError extends Error {
  constructor(name: string) {
    super(`Package "${name}" not found on the npm registry`);
    this.name = "PackageNotFoundError";
  }
}

/** Split "pkg@1.2.3" / "@scope/pkg@1.2.3" into name + optional version. */
export function parsePackageSpec(spec: string): {
  name: string;
  version?: string;
} {
  const at = spec.lastIndexOf("@");
  if (at > 0) {
    return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  }
  return { name: spec };
}

export async function fetchPackageMetadata(
  name: string,
  requestedVersion?: string,
): Promise<PackageMetadata> {
  const res = await fetch(`${REGISTRY}/${encodeURIComponent(name).replace("%40", "@")}`, {
    headers: { accept: "application/json" },
  });
  if (res.status === 404) throw new PackageNotFoundError(name);
  if (!res.ok) {
    throw new Error(`npm registry responded with ${res.status} for ${name}`);
  }
  const doc = (await res.json()) as {
    "dist-tags"?: Record<string, string>;
    versions?: Record<string, any>;
    time?: Record<string, string>;
  };

  // Without an explicit version or a `latest` dist-tag (rare, but registry
  // key order is NOT guaranteed to be publish order), fall back to the
  // semver-highest published version rather than whatever key comes last.
  const version =
    requestedVersion ?? doc["dist-tags"]?.latest ?? highestSemver(Object.keys(doc.versions ?? {}));
  if (!version || !doc.versions?.[version]) {
    throw new Error(`Version "${requestedVersion ?? "latest"}" of ${name} not found`);
  }
  const manifest = doc.versions[version];

  // A manifest without dist.tarball (unpublished/malformed version) would
  // otherwise surface as an opaque fetch(undefined) failure mid-analysis.
  const tarballUrl = manifest.dist?.tarball;
  if (typeof tarballUrl !== "string" || tarballUrl.length === 0) {
    throw new Error(`${name}@${version} has no downloadable tarball on the npm registry`);
  }

  const publishDate = doc.time?.[version];
  // Package age is measured from the FIRST publish of the package, not the
  // requested version — an established package releasing a new version is not
  // a "recently published package".
  const createdDate = doc.time?.created ?? publishDate;
  const ageInDays = createdDate
    ? Math.floor((Date.now() - new Date(createdDate).getTime()) / 86_400_000)
    : undefined;

  const repository = manifest.repository;
  const repositoryUrl =
    typeof repository === "string" ? repository : repository?.url;

  const registryReputation = extractRegistryReputation(doc, manifest, version, publishDate);

  return {
    name,
    version,
    description: manifest.description,
    license: typeof manifest.license === "string" ? manifest.license : manifest.license?.type,
    repositoryUrl,
    maintainers: (manifest.maintainers ?? []).map(
      (m: { name?: string } | string) => (typeof m === "string" ? m : m.name ?? "unknown"),
    ),
    publishDate,
    ageInDays,
    tarballUrl,
    integrity: typeof manifest.dist?.integrity === "string" ? manifest.dist.integrity : undefined,
    shasum: typeof manifest.dist?.shasum === "string" ? manifest.dist.shasum : undefined,
    scripts: manifest.scripts ?? {},
    dependencyCount: Object.keys(manifest.dependencies ?? {}).length,
    directDependencies: Object.keys(manifest.dependencies ?? {}).sort(),
    dependencyRanges:
      typeof manifest.dependencies === "object" && manifest.dependencies !== null
        ? { ...manifest.dependencies }
        : undefined,
    unpackedSize:
      typeof manifest.dist?.unpackedSize === "number" ? manifest.dist.unpackedSize : undefined,
    fileCount: typeof manifest.dist?.fileCount === "number" ? manifest.dist.fileCount : undefined,
    registryReputation,
  };
}

/** Normalize a maintainers array (objects or strings) to plain names. */
function maintainerNames(list: unknown): string[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((m: { name?: string } | string) =>
    typeof m === "string" ? m : (m.name ?? "unknown"),
  );
}

/**
 * Pull the reputation-relevant fields out of the full packument (which is
 * already fetched — this adds zero network cost). The previous version is the
 * one published immediately before this one by TIME, not by semver, so a
 * backport release still measures the real publishing cadence.
 */
function extractRegistryReputation(
  doc: {
    "dist-tags"?: Record<string, string>;
    versions?: Record<string, any>;
    time?: Record<string, string>;
  },
  manifest: any,
  version: string,
  publishDate: string | undefined,
): RegistryReputation {
  let previousVersion: string | undefined;
  let previousVersionPublishDate: string | undefined;
  if (publishDate && doc.time) {
    const publishTime = new Date(publishDate).getTime();
    let best = -Infinity;
    for (const [v, iso] of Object.entries(doc.time)) {
      if (v === "created" || v === "modified" || v === version) continue;
      const t = new Date(iso).getTime();
      if (Number.isFinite(t) && t < publishTime && t > best) {
        best = t;
        previousVersion = v;
        previousVersionPublishDate = iso;
      }
    }
  }

  const latestTag = doc["dist-tags"]?.latest;
  const latestManifest = latestTag ? doc.versions?.[latestTag] : undefined;
  const latestRepository = latestManifest?.repository;
  const latestRepositoryUrl =
    typeof latestRepository === "string" ? latestRepository : latestRepository?.url;
  const latestVersionPublishDate = latestTag ? doc.time?.[latestTag] : undefined;
  const latestHasProvenance = latestManifest
    ? typeof latestManifest.dist?.attestations === "object" &&
      latestManifest.dist.attestations !== null
    : undefined;

  return {
    previousVersion,
    previousVersionPublishDate,
    deprecated:
      typeof manifest.deprecated === "string" || manifest.deprecated === true
        ? manifest.deprecated
        : undefined,
    hasProvenance:
      typeof manifest.dist?.attestations === "object" && manifest.dist.attestations !== null,
    versionMaintainers: maintainerNames(manifest.maintainers),
    previousVersionMaintainers: previousVersion
      ? maintainerNames(doc.versions?.[previousVersion]?.maintainers)
      : undefined,
    publisher: typeof manifest._npmUser?.name === "string" ? manifest._npmUser.name : undefined,
    latestRepositoryUrl,
    latestVersion: latestTag,
    latestVersionPublishDate,
    latestHasProvenance,
  };
}
