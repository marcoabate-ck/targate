import type { ArtifactSignal, PackageMetadata, Signals } from "../types.js";
import type { OsvResult } from "../osv.js";
import { deriveReputation, reputationSkipped, type ReputationLookup } from "../reputation.js";
import { analyzeContent } from "./content.js";
import { analyzeNativeSurface, hasNativeCode } from "./native.js";
import { analyzeRnHardening } from "./rn-hardening.js";
import { extractLifecycleScripts, inspectScriptCommand } from "./scripts.js";
import { checkNameSimilarity } from "./similarity.js";
import type { ResolvedResourceLimits } from "../resource-limits.js";

export const RECENT_PUBLISH_DAYS = 30;

/** Fail-safe signal set when a package cannot be inspected within budgets.
 * False booleans here are placeholders only; analysisDegraded prevents them
 * from ever being interpreted as a clean allow. */
export function buildDegradedSignals(
  metadata: PackageMetadata,
  osv: OsvResult,
  reason: string,
  reputation: ReputationLookup = reputationSkipped(),
  options: { internalScope?: boolean; artifact?: ArtifactSignal } = {},
): Signals {
  const lifecycleScripts = extractLifecycleScripts(metadata.scripts);
  const scriptCommandFindings = Object.entries(lifecycleScripts).flatMap(([name, command]) =>
    inspectScriptCommand(name, command),
  );
  return {
    package: metadata.name,
    version: metadata.version,
    artifact: options.artifact ?? {
      trust: "unverified",
      digest: "unavailable",
      registryUrl: metadata.registryUrl ?? "unknown",
      tarballUrl: metadata.tarballUrl,
      reasons: [reason],
    },
    lifecycleScripts,
    hasLifecycleScripts: Object.keys(lifecycleScripts).length > 0,
    scriptCommandFindings,
    hasNativeCode: false,
    nativeSurface: {
      hasIos: false, hasAndroid: false, hasPodspec: false, hasGradle: false,
      hasCMake: false, hasRnConfig: false, binaryArtifacts: [], androidPermissions: [],
    },
    rnHardening: {
      podspecFindings: [], gradleFindings: [], dangerousPermissions: [],
      iosFrameworkFindings: [], autolinkingFindings: [], compatNotes: [],
    },
    content: {
      hasProcessEnvAccess: false, hasChildProcessUsage: false, hasNetworkCalls: false,
      hasEvalUsage: false, hasMinifiedCode: false, suspiciousFiles: [], installTimeFindings: [],
    },
    knownMalicious: osv.knownMalicious,
    maliciousRecords: osv.maliciousRecords,
    advisories: osv.advisories,
    osvUnavailable: osv.unavailable,
    internalScope: options.internalScope || undefined,
    repositoryMissing: !metadata.repositoryUrl,
    recentPublish: metadata.ageInDays !== undefined && metadata.ageInDays <= RECENT_PUBLISH_DAYS,
    ageInDays: metadata.ageInDays,
    nameSimilarity: options.internalScope ? null : checkNameSimilarity(metadata.name),
    dependencyCount: metadata.dependencyCount,
    directDependencies: metadata.directDependencies,
    reputation: deriveReputation(metadata, reputation),
    analysisDegraded: [reason],
  };
}

/** Combine all deterministic analyzers into the structured signal object. */
export async function buildSignals(
  metadata: PackageMetadata,
  packageDir: string,
  osv: OsvResult,
  // Network lookups are injected (like osv) so this stays offline and pure.
  reputation: ReputationLookup = reputationSkipped(),
  options: {
    /** Policy internalScopes matched — external checks were skipped and
     *  typosquat similarity does not apply to a private name. */
    internalScope?: boolean;
    /** Identity of the exact tarball extracted at packageDir. */
    artifact?: ArtifactSignal;
    resourceLimits?: ResolvedResourceLimits;
  } = {},
): Promise<Signals> {
  const lifecycleScripts = extractLifecycleScripts(metadata.scripts);
  const nativeSurface = await analyzeNativeSurface(packageDir);
  const content = await analyzeContent(packageDir, lifecycleScripts, options.resourceLimits);
  const native = hasNativeCode(nativeSurface);
  const rnHardening = await analyzeRnHardening(
    packageDir,
    nativeSurface.androidPermissions,
    native,
  );

  // Inspect the lifecycle command strings themselves (curl|bash, wget,
  // node -e, credential file reads) — distinct from analyzeContent, which
  // scans the *files* those commands reference.
  const scriptCommandFindings: string[] = [];
  for (const [name, command] of Object.entries(lifecycleScripts)) {
    scriptCommandFindings.push(...inspectScriptCommand(name, command));
  }

  return {
    package: metadata.name,
    version: metadata.version,
    artifact: options.artifact ?? {
      trust: "unverified",
      digest: "unavailable",
      registryUrl: metadata.registryUrl ?? "unknown",
      tarballUrl: metadata.tarballUrl,
      reasons: ["artifact identity was not supplied by the caller"],
    },
    lifecycleScripts,
    hasLifecycleScripts: Object.keys(lifecycleScripts).length > 0,
    scriptCommandFindings,
    hasNativeCode: native,
    nativeSurface,
    rnHardening,
    content,
    knownMalicious: osv.knownMalicious,
    maliciousRecords: osv.maliciousRecords,
    advisories: osv.advisories,
    osvUnavailable: osv.unavailable,
    internalScope: options.internalScope || undefined,
    repositoryMissing: !metadata.repositoryUrl,
    recentPublish:
      metadata.ageInDays !== undefined && metadata.ageInDays <= RECENT_PUBLISH_DAYS,
    ageInDays: metadata.ageInDays,
    // Typosquat similarity compares against POPULAR PUBLIC names — meaningless
    // (and noisy) for a company-internal package.
    nameSimilarity: options.internalScope ? null : checkNameSimilarity(metadata.name),
    dependencyCount: metadata.dependencyCount,
    directDependencies: metadata.directDependencies,
    reputation: deriveReputation(metadata, reputation),
  };
}
