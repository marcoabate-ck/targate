import type { MaintainerIntel } from "./maintainer-intel.js";

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
  /** SRI hash from the registry manifest (dist.integrity, e.g. "sha512-…"). */
  integrity?: string;
  /** Legacy sha1 hex digest from the registry manifest (dist.shasum). */
  shasum?: string;
  scripts: Record<string, string>;
  dependencyCount: number;
  directDependencies: string[];
  /** Direct dependency name -> declared range (manifest.dependencies). */
  dependencyRanges?: Record<string, string>;
  /** Declared optionalDependencies names (e.g. esbuild's platform binaries). */
  optionalDependencyNames?: string[];
  /** Declared peerDependencies names. */
  peerDependencyNames?: string[];
  /** dist.unpackedSize from the version manifest, when the registry provides it. */
  unpackedSize?: number;
  /** dist.fileCount from the version manifest. */
  fileCount?: number;
  /** Registry the packument was fetched from (npmjs unless .npmrc says otherwise). */
  registryUrl?: string;
  /** How the registry was chosen: a per-scope .npmrc rule, a global registry=
   *  override, or the npmjs default. */
  registrySource?: "scope" | "global" | "default";
  /** Reputation-relevant fields extracted from the full packument (already
   *  fetched), so reputation can be derived without extra registry calls. */
  registryReputation: RegistryReputation;
}

/** Fields the full packument carries that only reputation scoring consumes. */
export interface RegistryReputation {
  /** The version published immediately before this one (by publish TIME, not
   *  semver — a backport still measures real publishing cadence). */
  previousVersion?: string;
  previousVersionPublishDate?: string;
  /** manifest.deprecated: npm's deprecation message (or `true`). */
  deprecated?: string | true;
  /** dist.attestations present on this version (npm provenance). */
  hasProvenance: boolean;
  /** manifest.maintainers of THIS version (absent in some old packuments). */
  versionMaintainers?: string[];
  /** manifest.maintainers of the previous (by publish time) version. */
  previousVersionMaintainers?: string[];
  /** manifest._npmUser?.name — the account that published this version. */
  publisher?: string;
  /** repository URL of the dist-tags.latest manifest, for mismatch detection. */
  latestRepositoryUrl?: string;
  /** dist-tags.latest at fetch time (may differ from the analyzed version). */
  latestVersion?: string;
  latestVersionPublishDate?: string;
  /** Whether dist-tags.latest carries a provenance attestation. */
  latestHasProvenance?: boolean;
}

/** Result state of an optional external lookup. Mirrors the osvUnavailable
 *  philosophy: "unavailable" means UNKNOWN, never "clean". */
export type LookupStatus = "ok" | "unavailable" | "skipped";

export interface DownloadsSignal {
  status: LookupStatus;
  /** Sum of the last 7 daily buckets from the npm downloads range endpoint. */
  weeklyDownloads?: number;
  /** avg(last 7 days) vs avg(prior 21 days). Undefined when <28d of data. */
  trend?: "stable" | "spike" | "drop";
  /** Human detail for spike/drop, with both averages and the ratio. */
  trendDetail?: string;
}

export interface RepoStatusSignal {
  status:
    | "ok" //           GitHub answered; `archived` is authoritative
    | "not-github" //   repo host is not github.com — signal not applicable
    | "not-found" //    404: deleted, renamed, or private — itself a warning
    | "rate-limited" // quota exhausted — UNKNOWN (set GITHUB_TOKEN to raise it)
    | "unavailable" //  network error / timeout — UNKNOWN
    | "skipped"; //     --no-reputation, or no repository URL
  /** Only present when status === "ok" — never inferred on a failure path. */
  archived?: boolean;
}

export interface MaintainerChangeSignal {
  changed: boolean;
  /** e.g. 'publisher "mallory" was not a maintainer of the previous version'. */
  detail?: string;
}

export interface ReputationSignals {
  /** Days since THIS version was published (package age is Signals.ageInDays). */
  versionAgeDays?: number;
  /** Days between this version's publish and the previous version's. */
  releaseAfterInactivityDays?: number;
  /** True when the release gap is ≥365 days AND this version is ≤30 days old —
   *  a fresh release after long dormancy, a classic takeover pattern. */
  releaseGapAnomaly: boolean;
  maintainerCount: number;
  /** null when the packument lacks per-version maintainer data (not derivable
   *  — rendered as unknown, never as "no change"). */
  maintainerChange: MaintainerChangeSignal | null;
  /** Repo URL present but suspicious (differs from latest's, or no host). */
  repositoryMismatch: boolean;
  repositoryMismatchDetail?: string;
  /** npm provenance attestation present on this version. */
  hasProvenance: boolean;
  /** Deprecation message, or false when not deprecated. */
  deprecated: string | false;
  downloads: DownloadsSignal;
  repo: RepoStatusSignal;
  /** Maintainer portfolio intelligence (root-package analysis only). Absent
   *  when not gathered (transitive packages, or --no-reputation). */
  maintainerIntel?: MaintainerIntel;
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

/** How strongly the analyzed tarball bytes are bound to an independent identity. */
export type ArtifactTrust =
  | "public-equivalent"
  | "lockfile-verified"
  | "history-verified"
  | "registry-consistent"
  | "private-only"
  | "unverified"
  | "public-unavailable"
  | "mutated";

export interface ArtifactSignal {
  trust: ArtifactTrust;
  /** Canonical digest of the bytes targate actually inspected. */
  digest: string;
  registryUrl: string;
  tarballUrl: string;
  registryIntegrity?: string;
  lockfileIntegrity?: string;
  publicIntegrity?: string;
  historicalIntegrity?: string;
  publicRegistryUrl?: string;
  reasons: string[];
  /**
   * Registry-metadata vs tarball-manifest divergences that are NOT byte
   * tampering: the artifact bytes are independently checksum-verified, so the
   * tarball is authentic and authoritative, but its package.json disagrees
   * with the registry packument on a field npm can legitimately normalize
   * (e.g. lifecycle scripts). Surfaced as an approvable require_approval
   * reason rather than a mutated hard block. Identity fields (name/version)
   * and the dependency graph stay hard blocks — they define the artifact.
   */
  metadataDrift?: string[];
}

/** Trust levels where the tarball bytes match reviewed/independent checksum
 *  evidence — the artifact is authentic even if registry metadata diverges. */
export function isChecksumVerified(trust: ArtifactTrust): boolean {
  return (
    trust === "public-equivalent" ||
    trust === "lockfile-verified" ||
    trust === "history-verified" ||
    trust === "registry-consistent" ||
    trust === "private-only"
  );
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
  /** Cryptographic identity of the exact tarball inspected by targate. */
  artifact: ArtifactSignal;
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
  /**
   * The package belongs to a policy-declared internal scope: lookups that
   * would leak the package name to third parties (OSV, npm downloads,
   * maintainer search, GitHub) were deliberately SKIPPED, and typosquat
   * similarity does not apply. Distinct from osvUnavailable — this is a
   * choice, not a failure — but equally "not externally checked".
   */
  internalScope?: boolean;
  repositoryMissing: boolean;
  recentPublish: boolean;
  ageInDays?: number;
  nameSimilarity: NameSimilarity | null;
  dependencyCount: number;
  /** Direct dependency names (transitive deps are NOT analyzed — see README). */
  directDependencies: string[];
  /** Reputational & temporal signals (registry-derived + optional external
   *  lookups). Informational: consumed by the score and the AI, never by
   *  evaluateRules. */
  reputation: ReputationSignals;
  /** Reasons static/network analysis could not complete within its safety
   * budgets. Presence is always rendered as UNKNOWN and requires approval. */
  analysisDegraded?: string[];
}

/** The rules engine's own verdict, captured alongside an AI assessment so the
 *  output can show "deterministic findings" vs "AI interpretation". */
export interface DeterministicVerdict {
  decision: Decision;
  risk: RiskLevel;
  reasons: string[];
}

export interface RiskAssessment {
  risk: RiskLevel;
  decision: Decision;
  summary: string;
  reasons: string[];
  recommendedAction: string;
  suggestedAlternatives?: string[];
  source: "ai" | "rules";
  /** Present on AI-sourced assessments: what the rules engine concluded on the
   *  same signals. The AI can only ever be stricter than this verdict. */
  deterministic?: DeterministicVerdict;
}

export type PackageManager = "pnpm" | "npm" | "yarn";

/**
 * Scope of the opt-in AI source-code audit:
 * - "off": never audit (default).
 * - "flagged": audit only packages the deterministic pass already flagged
 *   (require_approval/block/unknown, or with content/script/native findings).
 * - "direct": audit the project's direct dependencies (+ the named package).
 * - "all": audit every package in the command's scope (most expensive).
 */
export type CodeAuditScope = "off" | "flagged" | "direct" | "all";

/** Severity of a single AI source-audit finding. */
export type SourceAuditSeverity = "info" | "low" | "medium" | "high";

/**
 * One issue the AI reported while reading a package's actual source (the
 * opt-in `--audit-code` pass). Findings are ADVISORY inputs to the verdict:
 * they can only escalate the decision through the deterministic clamp, never
 * downgrade it.
 */
export interface SourceAuditFinding {
  severity: SourceAuditSeverity;
  /** POSIX package-relative path the finding is in. */
  file: string;
  /** 1-indexed line, when the model localizes it. */
  line?: number;
  /** One-sentence description of the issue. */
  summary: string;
}

/** The result of an AI source-code audit of one package. */
export interface SourceAuditResult {
  findings: SourceAuditFinding[];
  /** POSIX relPaths actually sent to the model. */
  filesAnalyzed: string[];
  /** Candidate files/bytes NOT sent, with why — never a silent truncation. */
  dropped: { count: number; reason: string }[];
  /** "ai" when a model produced it; "skipped" when selection yielded nothing. */
  source: "ai" | "skipped";
}
