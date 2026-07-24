/**
 * Public entry point of the "targate" package: the types other tooling may
 * import. Repository config itself is declarative (`.yaml`/`.yml`/`.json`) and
 * parsed, never executed, so there are no runtime config helpers here.
 */
export type { DependencyPolicy, PolicyFile, RegistryPolicy } from "./policy.js";
export type { AiCachePolicy } from "./ai-cache.js";
export type { ResourceLimits, ResolvedResourceLimits } from "./resource-limits.js";
export type { ApprovalRecord, ApprovalsMap } from "./approvals.js";
export type { ArtifactSignal, ArtifactTrust, Decision, RiskAssessment, RiskLevel, Signals } from "./types.js";
export type { ScriptPolicy } from "./trust-decision.js";
export type { InstallPlan, PlanPackageSpec } from "./install-plan.js";
export type { LockedPackageArtifact } from "./lockfile.js";
export {
  assertCompleteFileIndex,
  buildPackageFileIndex,
} from "./analyze/file-index.js";
export type { IndexedFile, PackageFileIndex } from "./analyze/file-index.js";
