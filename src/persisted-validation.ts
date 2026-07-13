import type { RiskAssessment, Signals } from "./types.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

export function isValidIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return false;
  return Number.isFinite(Date.parse(value));
}

export function isValidRiskAssessment(value: unknown): value is RiskAssessment {
  if (!isRecord(value)) return false;
  const deterministic = value.deterministic;
  return (
    ["low", "medium", "high"].includes(String(value.risk)) &&
    ["allow", "allow_with_warnings", "require_approval", "block"].includes(String(value.decision)) &&
    typeof value.summary === "string" &&
    isStringArray(value.reasons) &&
    typeof value.recommendedAction === "string" &&
    (value.suggestedAlternatives === undefined || isStringArray(value.suggestedAlternatives)) &&
    (value.source === "ai" || value.source === "rules") &&
    (deterministic === undefined ||
      (isRecord(deterministic) &&
        ["low", "medium", "high"].includes(String(deterministic.risk)) &&
        ["allow", "allow_with_warnings", "require_approval", "block"].includes(String(deterministic.decision)) &&
        isStringArray(deterministic.reasons)))
  );
}

function validArtifact(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    [
      "public-equivalent", "lockfile-verified", "history-verified", "registry-consistent",
      "private-only", "unverified", "public-unavailable", "mutated",
    ].includes(String(value.trust)) &&
    typeof value.digest === "string" &&
    typeof value.registryUrl === "string" &&
    typeof value.tarballUrl === "string" &&
    isStringArray(value.reasons)
  );
}

/** Strict enough that every property consumed by report/score code is safe. */
export function isValidSignals(value: unknown): value is Signals {
  if (!isRecord(value)) return false;
  const native = value.nativeSurface;
  const rn = value.rnHardening;
  const content = value.content;
  const rep = value.reputation;
  if (!isRecord(native) || !isRecord(rn) || !isRecord(content) || !isRecord(rep)) return false;
  const bools = (obj: Record<string, unknown>, keys: string[]) => keys.every((key) => typeof obj[key] === "boolean");
  const arrays = (obj: Record<string, unknown>, keys: string[]) => keys.every((key) => isStringArray(obj[key]));
  if (!isRecord(rep.downloads) || !isRecord(rep.repo)) return false;
  return (
    typeof value.package === "string" &&
    typeof value.version === "string" &&
    validArtifact(value.artifact) &&
    isRecord(value.lifecycleScripts) && Object.values(value.lifecycleScripts).every((v) => typeof v === "string") &&
    bools(value, ["hasLifecycleScripts", "hasNativeCode", "knownMalicious", "osvUnavailable", "repositoryMissing", "recentPublish"]) &&
    isStringArray(value.scriptCommandFindings) &&
    bools(native, ["hasIos", "hasAndroid", "hasPodspec", "hasGradle", "hasCMake", "hasRnConfig"]) &&
    arrays(native, ["binaryArtifacts", "androidPermissions"]) &&
    arrays(rn, ["podspecFindings", "gradleFindings", "dangerousPermissions", "iosFrameworkFindings", "autolinkingFindings", "compatNotes"]) &&
    bools(content, ["hasProcessEnvAccess", "hasChildProcessUsage", "hasNetworkCalls", "hasEvalUsage", "hasMinifiedCode"]) &&
    arrays(content, ["suspiciousFiles", "installTimeFindings"]) &&
    Array.isArray(value.maliciousRecords) && value.maliciousRecords.every((r) => isRecord(r) && typeof r.id === "string") &&
    Array.isArray(value.advisories) && value.advisories.every((r) => isRecord(r) && typeof r.id === "string") &&
    (value.ageInDays === undefined || typeof value.ageInDays === "number") &&
    (value.nameSimilarity === null || (isRecord(value.nameSimilarity) && typeof value.nameSimilarity.similarTo === "string" && typeof value.nameSimilarity.distance === "number")) &&
    typeof value.dependencyCount === "number" && isStringArray(value.directDependencies) &&
    typeof rep.releaseGapAnomaly === "boolean" && typeof rep.maintainerCount === "number" &&
    typeof rep.repositoryMismatch === "boolean" && typeof rep.hasProvenance === "boolean" &&
    (rep.deprecated === false || typeof rep.deprecated === "string") &&
    ["ok", "unavailable", "skipped"].includes(String(rep.downloads.status)) &&
    ["ok", "not-github", "not-found", "rate-limited", "unavailable", "skipped"].includes(String(rep.repo.status)) &&
    (value.analysisDegraded === undefined || isStringArray(value.analysisDegraded))
  );
}
