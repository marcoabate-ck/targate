import type { PackageMetadata } from "./types.js";

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

  const version =
    requestedVersion ?? doc["dist-tags"]?.latest ?? Object.keys(doc.versions ?? {}).pop();
  if (!version || !doc.versions?.[version]) {
    throw new Error(`Version "${requestedVersion ?? "latest"}" of ${name} not found`);
  }
  const manifest = doc.versions[version];

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
    tarballUrl: manifest.dist?.tarball,
    scripts: manifest.scripts ?? {},
    dependencyCount: Object.keys(manifest.dependencies ?? {}).length,
  };
}
