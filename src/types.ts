export type RiskLevel = "low" | "medium" | "high";

export type Decision =
  | "allow"
  | "allow_with_warnings"
  | "require_approval"
  | "block";

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
  weeklyDownloads?: number;
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

export interface Signals {
  package: string;
  version: string;
  lifecycleScripts: Record<string, string>;
  hasLifecycleScripts: boolean;
  hasNativeCode: boolean;
  nativeSurface: NativeSurface;
  content: ContentFindings;
  knownMalicious: boolean;
  maliciousRecords: MaliciousRecord[];
  advisories: MaliciousRecord[];
  repositoryMissing: boolean;
  recentPublish: boolean;
  ageInDays?: number;
  nameSimilarity: NameSimilarity | null;
  dependencyCount: number;
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
