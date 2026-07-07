export type RiskLevel = "low" | "medium" | "high";

export type Decision =
  | "allow"
  | "allow_with_warnings"
  | "require_approval"
  | "block";

/**
 * Severity rank of each decision. The single source of truth for "which
 * decision is stricter" — used everywhere decisions are escalated or clamped
 * (rules, policy, transitive aggregation). Higher = stricter.
 */
export const DECISION_SEVERITY: Record<Decision, number> = {
  allow: 0,
  allow_with_warnings: 1,
  require_approval: 2,
  block: 3,
};

export interface PackageMetadata {
  name: string;
  version: string;
  description?: string;
  license?: string;
  repositoryUrl?: string;
  maintainers: string[];
  publishDate?: string;
  ageInDays?: number;
  tarballUrl: string;
  scripts: Record<string, string>;
  dependencyCount: number;
  directDependencies: string[];
}

export interface NameSimilarity {
  similarTo: string;
  distance: number;
}

export interface MaliciousRecord {
  id: string;
  summary?: string;
}

export interface NativeSurface {
  hasIos: boolean;
  hasAndroid: boolean;
  hasPodspec: boolean;
  hasGradle: boolean;
  hasCMake: boolean;
  hasRnConfig: boolean;
  binaryArtifacts: string[];
  androidPermissions: string[];
}

export interface ContentFindings {
  hasProcessEnvAccess: boolean;
  hasChildProcessUsage: boolean;
  hasNetworkCalls: boolean;
  hasEvalUsage: boolean;
  hasMinifiedCode: boolean;
  suspiciousFiles: string[];
  installTimeFindings: string[];
}

export interface RnHardeningSignals {
  podspecFindings: string[];
  gradleFindings: string[];
  dangerousPermissions: string[];
  iosFrameworkFindings: string[];
  autolinkingFindings: string[];
  compatNotes: string[];
}

export interface Signals {
  package: string;
  version: string;
  lifecycleScripts: Record<string, string>;
  hasLifecycleScripts: boolean;
  /** Deterministic findings from inspecting the lifecycle command strings. */
  scriptCommandFindings: string[];
  hasNativeCode: boolean;
  nativeSurface: NativeSurface;
  rnHardening: RnHardeningSignals;
  content: ContentFindings;
  knownMalicious: boolean;
  maliciousRecords: MaliciousRecord[];
  advisories: MaliciousRecord[];
  /**
   * True when the OSV lookup could not be completed (network error, offline).
   * A malicious-package record cannot be ruled out — treat as "unknown", not
   * "clean". See the OSV failure handling in the README.
   */
  osvUnavailable: boolean;
  repositoryMissing: boolean;
  recentPublish: boolean;
  ageInDays?: number;
  nameSimilarity: NameSimilarity | null;
  dependencyCount: number;
  /** Direct dependency names (transitive deps are NOT analyzed — see README). */
  directDependencies: string[];
}

export interface RiskAssessment {
  risk: RiskLevel;
  decision: Decision;
  summary: string;
  reasons: string[];
  recommendedAction: string;
  suggestedAlternatives?: string[];
  source: "ai" | "rules";
}

export type PackageManager = "pnpm" | "npm" | "yarn";
