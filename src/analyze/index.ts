import type { PackageMetadata, Signals } from "../types.js";
import type { OsvResult } from "../osv.js";
import { analyzeContent } from "./content.js";
import { analyzeNativeSurface, hasNativeCode } from "./native.js";
import { analyzeRnHardening } from "./rn-hardening.js";
import { extractLifecycleScripts } from "./scripts.js";
import { checkNameSimilarity } from "./similarity.js";

export const RECENT_PUBLISH_DAYS = 30;

/** Combine all deterministic analyzers into the structured signal object. */
export async function buildSignals(
  metadata: PackageMetadata,
  packageDir: string,
  osv: OsvResult,
): Promise<Signals> {
  const lifecycleScripts = extractLifecycleScripts(metadata.scripts);
  const nativeSurface = await analyzeNativeSurface(packageDir);
  const content = await analyzeContent(packageDir, lifecycleScripts);
  const native = hasNativeCode(nativeSurface);
  const rnHardening = await analyzeRnHardening(
    packageDir,
    nativeSurface.androidPermissions,
    native,
  );

  return {
    package: metadata.name,
    version: metadata.version,
    lifecycleScripts,
    hasLifecycleScripts: Object.keys(lifecycleScripts).length > 0,
    hasNativeCode: native,
    nativeSurface,
    rnHardening,
    content,
    knownMalicious: osv.knownMalicious,
    maliciousRecords: osv.maliciousRecords,
    advisories: osv.advisories,
    repositoryMissing: !metadata.repositoryUrl,
    recentPublish:
      metadata.ageInDays !== undefined && metadata.ageInDays <= RECENT_PUBLISH_DAYS,
    ageInDays: metadata.ageInDays,
    nameSimilarity: checkNameSimilarity(metadata.name),
    dependencyCount: metadata.dependencyCount,
  };
}
