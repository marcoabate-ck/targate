import type { PackageSignals } from "./pipeline.js";
import { isHardBlock } from "./rules.js";
import { computeSecurityScore } from "./score.js";
import { compareSemver } from "./semver.js";
import type { MaliciousRecord, RiskLevel } from "./types.js";

/**
 * Deterministic version-to-version diff. Many supply-chain attacks arrive as a
 * new *version* of a trusted package, not a new package — this surfaces exactly
 * what changed between two versions and rates how risky the change is. Pure: no
 * network, no AI (a diff is a statement of facts; the AI already judges the new
 * version when it's actually installed).
 */

export interface ScriptChange {
  hook: string;
  before?: string;
  after?: string;
}

export interface DepChange {
  name: string;
  beforeRange?: string; // absent = added
  afterRange?: string; // absent = removed
  /** afterRange points outside the registry (git+/http(s)/file: specifier). */
  nonRegistrySpec: boolean;
}

export interface VersionDiff {
  package: string;
  from: { version: string; publishDate?: string; unpackedSize?: number; fileCount?: number };
  to: { version: string; publishDate?: string; unpackedSize?: number; fileCount?: number };
  direction: "upgrade" | "downgrade" | "same";
  lifecycleScripts: { added: ScriptChange[]; removed: ScriptChange[]; changed: ScriptChange[] };
  /** scriptCommandFindings present in `to` and absent in `from`. */
  newScriptFindings: string[];
  dependencies: { added: DepChange[]; removed: DepChange[]; changed: DepChange[] };
  maintainers: { added: string[]; removed: string[] };
  repositoryChanged: { before?: string; after?: string } | null;
  nativeSurface: { added: string[]; newBinaries: string[]; newAndroidPermissions: string[] };
  advisories: { added: MaliciousRecord[]; resolved: MaliciousRecord[] };
  knownMalicious: { before: boolean; after: boolean };
  size: { unpackedSizeDelta?: number; fileCountDelta?: number } | null;
  provenanceLost: boolean;
  deprecatedAdded: string | false;
  score: { before: number; after: number; delta: number };
  /** OSV was unavailable on either side — the advisory delta is UNKNOWN. */
  osvUnavailable: boolean;
  diffRisk: RiskLevel;
  riskReasons: string[];
}

const NON_REGISTRY_SPEC = /^(git\+|git:|https?:|file:|github:|[^@\s/]+\/[^@\s/]+$)/;

function nativeSurfaceLabels(s: PackageSignals["signals"]["nativeSurface"]): string[] {
  return [
    s.hasIos ? "iOS sources" : null,
    s.hasAndroid ? "Android sources" : null,
    s.hasPodspec ? "Podspec" : null,
    s.hasGradle ? "Gradle" : null,
    s.hasCMake ? "CMake" : null,
  ].filter((x): x is string => x !== null);
}

export function diffPackageVersions(a: PackageSignals, b: PackageSignals): VersionDiff {
  const sa = a.signals;
  const sb = b.signals;
  const riskReasons: string[] = [];

  // Lifecycle scripts
  const aHooks = sa.lifecycleScripts;
  const bHooks = sb.lifecycleScripts;
  const lifecycleScripts = { added: [] as ScriptChange[], removed: [] as ScriptChange[], changed: [] as ScriptChange[] };
  for (const hook of new Set([...Object.keys(aHooks), ...Object.keys(bHooks)])) {
    const before = aHooks[hook];
    const after = bHooks[hook];
    if (before === undefined && after !== undefined) lifecycleScripts.added.push({ hook, after });
    else if (before !== undefined && after === undefined) lifecycleScripts.removed.push({ hook, before });
    else if (before !== after) lifecycleScripts.changed.push({ hook, before, after });
  }

  const beforeFindings = new Set(sa.scriptCommandFindings);
  const newScriptFindings = sb.scriptCommandFindings.filter((f) => !beforeFindings.has(f));

  // Dependencies (by declared range where available, else presence)
  const aRanges = a.metadata.dependencyRanges ?? Object.fromEntries(sa.directDependencies.map((d) => [d, ""]));
  const bRanges = b.metadata.dependencyRanges ?? Object.fromEntries(sb.directDependencies.map((d) => [d, ""]));
  const dependencies = { added: [] as DepChange[], removed: [] as DepChange[], changed: [] as DepChange[] };
  for (const name of new Set([...Object.keys(aRanges), ...Object.keys(bRanges)])) {
    const beforeRange = aRanges[name];
    const afterRange = bRanges[name];
    const nonRegistrySpec = afterRange !== undefined && NON_REGISTRY_SPEC.test(afterRange);
    if (beforeRange === undefined) dependencies.added.push({ name, afterRange, nonRegistrySpec });
    else if (afterRange === undefined) dependencies.removed.push({ name, beforeRange, nonRegistrySpec: false });
    else if (beforeRange !== afterRange)
      dependencies.changed.push({ name, beforeRange, afterRange, nonRegistrySpec });
  }

  // Maintainers
  const aMaint = new Set(a.metadata.maintainers);
  const bMaint = new Set(b.metadata.maintainers);
  const maintainers = {
    added: [...bMaint].filter((m) => !aMaint.has(m)),
    removed: [...aMaint].filter((m) => !bMaint.has(m)),
  };

  // Repository
  const repoBefore = a.metadata.repositoryUrl;
  const repoAfter = b.metadata.repositoryUrl;
  const repositoryChanged = repoBefore !== repoAfter ? { before: repoBefore, after: repoAfter } : null;

  // Native surface
  const aLabels = new Set(nativeSurfaceLabels(sa.nativeSurface));
  const nativeAdded = nativeSurfaceLabels(sb.nativeSurface).filter((l) => !aLabels.has(l));
  const aBinaries = new Set(sa.nativeSurface.binaryArtifacts);
  const newBinaries = sb.nativeSurface.binaryArtifacts.filter((x) => !aBinaries.has(x));
  const aPerms = new Set(sa.nativeSurface.androidPermissions);
  const newAndroidPermissions = sb.nativeSurface.androidPermissions.filter((p) => !aPerms.has(p));

  // Advisories
  const aAdv = new Set(sa.advisories.map((x) => x.id));
  const bAdv = new Set(sb.advisories.map((x) => x.id));
  const advisories = {
    added: sb.advisories.filter((x) => !aAdv.has(x.id)),
    resolved: sa.advisories.filter((x) => !bAdv.has(x.id)),
  };

  // Size
  const size =
    a.metadata.unpackedSize !== undefined && b.metadata.unpackedSize !== undefined
      ? {
          unpackedSizeDelta: b.metadata.unpackedSize - a.metadata.unpackedSize,
          fileCountDelta:
            a.metadata.fileCount !== undefined && b.metadata.fileCount !== undefined
              ? b.metadata.fileCount - a.metadata.fileCount
              : undefined,
        }
      : null;

  const provenanceLost = sa.reputation.hasProvenance && !sb.reputation.hasProvenance;
  const deprecatedAdded = sa.reputation.deprecated === false && sb.reputation.deprecated !== false
    ? sb.reputation.deprecated
    : false;

  const scoreBefore = computeSecurityScore(sa).total;
  const scoreAfter = computeSecurityScore(sb).total;
  const osvUnavailable = sa.osvUnavailable || sb.osvUnavailable;

  // ---- Risk rubric (each fired rule appends to riskReasons) ----
  let mediumCount = 0;
  const high = (r: string) => riskReasons.push(`[high] ${r}`);
  const medium = (r: string) => {
    riskReasons.push(`[medium] ${r}`);
    mediumCount++;
  };

  if (sb.knownMalicious && !sa.knownMalicious) high("the new version is a known malicious package");
  if (isHardBlock(sb) && !isHardBlock(sa)) high("the new version introduces a hard-block install pattern");
  for (const s of lifecycleScripts.added) high(`lifecycle script added: ${s.hook}`);
  for (const s of lifecycleScripts.changed) high(`lifecycle script changed: ${s.hook}`);
  for (const f of newScriptFindings) high(`new suspicious script command: ${f}`);
  for (const d of [...dependencies.added, ...dependencies.changed])
    if (d.nonRegistrySpec) high(`dependency ${d.name} now points outside the registry: ${d.afterRange}`);

  if (dependencies.added.some((d) => !d.nonRegistrySpec)) medium("dependencies added");
  if (maintainers.added.length > 0 || maintainers.removed.length > 0) medium("maintainer set changed");
  if (repositoryChanged) medium("repository URL changed");
  if (provenanceLost) medium("npm provenance attestation lost");
  if (deprecatedAdded) medium("the new version is deprecated");
  if (nativeAdded.length > 0 || newBinaries.length > 0 || newAndroidPermissions.length > 0)
    medium("new native surface");
  if (advisories.added.length > 0) medium("new vulnerability advisories");
  if (
    size?.unpackedSizeDelta !== undefined &&
    a.metadata.unpackedSize !== undefined &&
    size.unpackedSizeDelta > 0.5 * a.metadata.unpackedSize &&
    size.unpackedSizeDelta > 500_000
  )
    medium("package size grew sharply");
  if (scoreBefore - scoreAfter >= 15) medium("security score dropped by 15+ points");
  if (osvUnavailable) medium("OSV lookup unavailable — advisory changes are UNKNOWN");

  const hasHigh = riskReasons.some((r) => r.startsWith("[high]"));
  const diffRisk: RiskLevel = hasHigh || mediumCount >= 2 ? "high" : mediumCount >= 1 ? "medium" : "low";

  const cmp = compareSemver(sb.version, sa.version);

  return {
    package: sa.package,
    from: {
      version: sa.version,
      publishDate: a.metadata.publishDate,
      unpackedSize: a.metadata.unpackedSize,
      fileCount: a.metadata.fileCount,
    },
    to: {
      version: sb.version,
      publishDate: b.metadata.publishDate,
      unpackedSize: b.metadata.unpackedSize,
      fileCount: b.metadata.fileCount,
    },
    direction: cmp > 0 ? "upgrade" : cmp < 0 ? "downgrade" : "same",
    lifecycleScripts,
    newScriptFindings,
    dependencies,
    maintainers,
    repositoryChanged,
    nativeSurface: { added: nativeAdded, newBinaries, newAndroidPermissions },
    advisories,
    knownMalicious: { before: sa.knownMalicious, after: sb.knownMalicious },
    size,
    provenanceLost,
    deprecatedAdded,
    score: { before: scoreBefore, after: scoreAfter, delta: scoreAfter - scoreBefore },
    osvUnavailable,
    diffRisk,
    riskReasons,
  };
}
