import path from "node:path";
import { readFile } from "node:fs/promises";
import { buildDegradedSignals, buildSignals } from "./analyze/index.js";
import { INSTALL_TIME_SCRIPT_NAMES } from "./analyze/scripts.js";
import { buildPackageFileIndex } from "./analyze/file-index.js";
import { selectAuditFiles } from "./analyze/source-select.js";
import { historicalArtifactDigest } from "./artifact-ledger.js";
import { assessRisk, auditSourceWithCache, resolveBatchProvider, type AssessOptions } from "./ai.js";
import { isInternalScope } from "./npmrc.js";
import { osvSkipped, osvUnavailable, queryOsv, type OsvResult } from "./osv.js";
import { applyPolicy, type LoadedPolicy } from "./policy.js";
import { artifactMirrorFor } from "./policy.js";
import type { AiProvider, SourceAuditInput } from "./providers/types.js";
import { quarantineTarball } from "./quarantine.js";
import { fetchArtifactEvidence, fetchPackageMetadata } from "./registry.js";
import { fetchMaintainerIntel } from "./maintainer-intel.js";
import { fetchReputation, reputationSkipped, type ReputationLookup } from "./reputation.js";
import { computeSecurityScore, type SecurityScore } from "./score.js";
import { applyOsvFailurePolicy, evaluateRules, foldSourceAudit } from "./rules.js";
import { isChecksumVerified } from "./types.js";
import type {
  CodeAuditScope,
  PackageMetadata,
  RiskAssessment,
  Signals,
  SourceAuditResult,
} from "./types.js";
import type { LockedPackageArtifact } from "./lockfile.js";
import { ResourceLimitError, resolveResourceLimits, withScanBudget } from "./resource-limits.js";

/**
 * The single per-package analysis pipeline, shared by `targate add`, `targate ci`
 * and the transitive (--deep) walker:
 *
 *   registry metadata → tarball quarantine → OSV lookup → deterministic
 *   signals → AI/rules assessment (+ OSV failure policy) → team policy.
 *
 * Emits progress through onStage so each command renders it its own way.
 */

export type AnalysisStage =
  | "metadata"
  | "quarantine"
  | "osv"
  | "osv-failed"
  | "internal-scope"
  | "reputation"
  | "reputation-degraded"
  | "resource-limit"
  | "signals"
  | "assessment"
  | "policy";

export interface AnalyzePackageOptions {
  assess: AssessOptions;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Already-loaded team policy (applied on top of the assessment). */
  policy?: LoadedPolicy | null;
  /**
   * Pre-fetched OSV result (e.g. from a batched queryOsvBatch over a whole
   * tree). When provided, the per-package OSV round-trip is skipped.
   */
  osv?: OsvResult;
  /** Skip the external reputation lookups (npm downloads, GitHub repo status). */
  noReputation?: boolean;
  /** Gather maintainer portfolio intelligence (root-package analysis only —
   *  too expensive to fan out across a transitive tree). Ignored when
   *  noReputation is set. */
  maintainerIntel?: boolean;
  /** Artifact selected by the immutable lockfile plan, when one exists. */
  lockedArtifact?: LockedPackageArtifact;
  /** Whether lockedArtifact came from a pre-existing reviewed lockfile. */
  lockfileTrusted?: boolean;
  /** Already-fetched exact metadata, used when a staged plan must be built first. */
  metadata?: PackageMetadata;
  /** Project root for the artifact ledger. */
  cwd?: string;
  /** AI source-code audit scope for this package (default "off"). */
  codeAudit?: CodeAuditScope;
  /** True when this package is a direct dependency of the project (scope "direct"). */
  isDirect?: boolean;
  onStage?: (stage: AnalysisStage, detail?: string) => void;
}

export interface PackageAnalysis {
  metadata: PackageMetadata;
  signals: Signals;
  assessment: RiskAssessment;
  /** Informational 0–100 risk-signal aggregation — never drives the decision. */
  score: SecurityScore;
  /** Present when the AI source-code audit ran for this package. */
  sourceAudit?: SourceAuditResult;
}

/**
 * Source excerpts captured while the tarball was still extracted, plus the
 * artifact digest that keys the audit cache. Held on PackageSignals so the AI
 * audit can run later (with a provider + cache) without keeping the temp dir
 * alive. NOT part of the cache-keyed Signals — the digest already binds bytes.
 */
export interface PendingAudit {
  input: SourceAuditInput;
  digest: string;
  dropped: { count: number; reason: string }[];
}

export interface PackageSignals {
  metadata: PackageMetadata;
  signals: Signals;
  /** Present when this package was selected for the AI source-code audit. */
  audit?: PendingAudit;
}

/** True when the deterministic pass gives targate a reason to look harder. */
function isPackageFlagged(signals: Signals): boolean {
  const decision = evaluateRules(signals).decision;
  if (decision === "require_approval" || decision === "block") return true;
  if (signals.analysisDegraded?.length) return true;
  if (Object.keys(signals.lifecycleScripts).length > 0) return true;
  if (signals.hasNativeCode) return true;
  const c = signals.content;
  return Boolean(
    c &&
      (c.hasProcessEnvAccess ||
        c.hasChildProcessUsage ||
        c.hasNetworkCalls ||
        c.hasEvalUsage ||
        c.hasMinifiedCode ||
        c.suspiciousFiles.length > 0 ||
        c.installTimeFindings.length > 0),
  );
}

/** Decide whether THIS package should be source-audited under the given scope. */
function shouldAuditPackage(
  scope: CodeAuditScope | undefined,
  signals: Signals,
  isDirect: boolean | undefined,
): boolean {
  switch (scope) {
    case "all":
      return true;
    case "direct":
      return isDirect === true;
    case "flagged":
      return isPackageFlagged(signals);
    default:
      return false; // "off" / undefined
  }
}

function stringMap(value: unknown): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

function sameMap(a: Record<string, string>, b: Record<string, string>): boolean {
  const normalize = (value: Record<string, string>) =>
    JSON.stringify(Object.fromEntries(Object.entries(value).sort(([x], [y]) => x.localeCompare(y))));
  return normalize(a) === normalize(b);
}

function sameNames(a: string[], b: string[]): boolean {
  return [...a].sort().join("\0") === [...b].sort().join("\0");
}

/**
 * npm executes the package.json inside the tarball, not a separately trusted
 * packument copy. Use that manifest for analysis and hard-block any critical
 * disagreement a compromised registry could use to hide scripts/dependencies.
 */
async function bindMetadataToTarball(
  metadata: PackageMetadata,
  packageDir: string,
  artifact: Signals["artifact"],
): Promise<PackageMetadata> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path.join(packageDir, "package.json"), "utf8"));
  } catch (err) {
    artifact.trust = "mutated";
    artifact.reasons.push(
      `tarball package.json is missing or invalid: ${err instanceof Error ? err.message : String(err)}`,
    );
    return metadata;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    artifact.trust = "mutated";
    artifact.reasons.push("tarball package.json is not an object");
    return metadata;
  }
  const manifest = raw as Record<string, unknown>;
  const scripts = stringMap(manifest.scripts);
  const dependencies = stringMap(manifest.dependencies);
  const optionalDependencies = stringMap(manifest.optionalDependencies);
  const peerDependencies = stringMap(manifest.peerDependencies);

  if (manifest.name !== metadata.name || manifest.version !== metadata.version) {
    artifact.trust = "mutated";
    artifact.reasons.push(
      `tarball manifest identity ${String(manifest.name)}@${String(manifest.version)} does not match registry identity ${metadata.name}@${metadata.version}`,
    );
  }
  // Only INSTALL-TIME hooks (preinstall/install/postinstall) execute on a
  // registry install, so only they matter for artifact integrity. Differences
  // in non-install scripts (test/build/lint) or pack-time hooks never run and
  // are ignored — comparing the full scripts map would falsely flag ordinary
  // packages (dayjs, retry, utils-merge…) whose tarball declares dev scripts
  // the registry packument omits.
  const tarballHidesInstallHook = INSTALL_TIME_SCRIPT_NAMES.some(
    (name) => scripts[name] !== undefined && scripts[name] !== metadata.scripts[name],
  );
  const packumentOverDeclaresInstallHook = INSTALL_TIME_SCRIPT_NAMES.some(
    (name) => scripts[name] === undefined && metadata.scripts[name] !== undefined,
  );
  if (tarballHidesInstallHook) {
    // The tarball runs (or alters) an install-time script the registry metadata
    // doesn't declare — the compromised-mirror hidden-execution attack.
    artifact.trust = "mutated";
    artifact.reasons.push(
      "tarball package.json runs install-time lifecycle scripts hidden from the registry metadata",
    );
  } else if (packumentOverDeclaresInstallHook) {
    // The reverse: the packument declares an install-time script the authentic,
    // checksum-verified tarball drops (npm normalizes these — fsevents keeps an
    // `install` entry its tarball removed). Nothing extra runs. Approvable drift
    // on verified bytes; a hard block only when the bytes themselves are unverified.
    if (isChecksumVerified(artifact.trust)) {
      (artifact.metadataDrift ??= []).push(
        "registry metadata declares install-time lifecycle scripts absent from the checksum-verified tarball package.json",
      );
    } else {
      artifact.trust = "mutated";
      artifact.reasons.push(
        "registry install-time lifecycle scripts differ from the unverified tarball package.json",
      );
    }
  }
  // Dependency-metadata divergences (dependencies / optionalDependencies /
  // peerDependencies) between the registry packument and the authentic tarball
  // manifest are NOT install-time execution and do not change the artifact's
  // identity — npm installs from the tarball manifest, which the checksum
  // already binds. On checksum-verified bytes this is approvable drift (a
  // reviewer vouches for the authentic tarball with a version-pinned
  // `targate approve`), mirroring packumentOverDeclaresInstallHook above. On
  // UNVERIFIED bytes the same divergence stays a mutated hard block: without a
  // checksum we cannot tell authentic drift from a substituted artifact.
  const verifiedBytes = isChecksumVerified(artifact.trust);
  const noteDependencyDivergence = (verifiedReason: string, mutatedReason: string): void => {
    if (verifiedBytes) {
      (artifact.metadataDrift ??= []).push(verifiedReason);
    } else {
      artifact.trust = "mutated";
      artifact.reasons.push(mutatedReason);
    }
  };
  if (!sameMap(dependencies, metadata.dependencyRanges ?? {})) {
    noteDependencyDivergence(
      "registry dependencies differ from the checksum-verified tarball package.json (the authentic tarball is authoritative)",
      "registry dependencies differ from the unverified tarball package.json",
    );
  }
  if (!sameNames(Object.keys(optionalDependencies), metadata.optionalDependencyNames ?? [])) {
    noteDependencyDivergence(
      "registry optionalDependencies differ from the checksum-verified tarball package.json (the authentic tarball is authoritative)",
      "registry optionalDependencies differ from the unverified tarball package.json",
    );
  }
  if (!sameNames(Object.keys(peerDependencies), metadata.peerDependencyNames ?? [])) {
    noteDependencyDivergence(
      "registry peerDependencies differ from the checksum-verified tarball package.json (the authentic tarball is authoritative)",
      "registry peerDependencies differ from the unverified tarball package.json",
    );
  }

  return {
    ...metadata,
    scripts,
  };
}

/**
 * The I/O half of the pipeline: registry metadata -> tarball quarantine ->
 * OSV -> deterministic signals. Split out from analyzePackage so a tree walk
 * can build every package's signals first (concurrently) and then batch the
 * AI assessment across them. The tarball is cleaned up here; only the small
 * signals object is retained.
 */
export async function buildPackageSignals(
  name: string,
  version: string | undefined,
  opts: Pick<
    AnalyzePackageOptions,
    "failOnOsvError" | "osv" | "noReputation" | "maintainerIntel" | "onStage" | "policy" | "lockedArtifact" | "lockfileTrusted" | "metadata" | "cwd" | "codeAudit" | "isDirect"
  >,
): Promise<PackageSignals> {
  const resourcePolicy = opts.policy?.policy.resourceLimits;
  const limits = resolveResourceLimits(resourcePolicy);
  const metadata = opts.metadata ?? await fetchPackageMetadata(name, version, resourcePolicy);
  opts.onStage?.("metadata", `${metadata.name}@${metadata.version}`);

  // Policy internalScopes: this package's NAME is private. Every lookup that
  // would send it to a third party (OSV, npm downloads API, maintainer
  // search, GitHub) is skipped — visibly, in the report and the score.
  const internal = isInternalScope(
    metadata.name,
    opts.policy?.policy.dependencyPolicy.internalScopes,
  );
  if (internal) {
    opts.onStage?.(
      "internal-scope",
      "OSV, downloads, maintainer and GitHub lookups skipped (name privacy)",
    );
  }
  // A package served by a scope-mapped private registry is invisible to the
  // npmjs-only services (downloads API, maintainer search) — skip those two,
  // keep OSV and GitHub. A GLOBAL registry override is typically a mirror of
  // public packages, so everything still applies there.
  const privateRegistry = metadata.registrySource === "scope";

  // A global registry override is already treated elsewhere as an npm mirror.
  // Scoped registries only compare publicly when the declarative policy says
  // what they mirror. internalScopes always win to preserve name privacy.
  const mirror = internal
    ? undefined
    : artifactMirrorFor(metadata.registryUrl ?? "", metadata.registrySource, opts.policy?.policy);
  const publicArtifactPromise = mirror
    ? fetchArtifactEvidence(metadata.name, metadata.version, mirror, resourcePolicy)
    : Promise.resolve({ status: "skipped" as const });
  const historicalIntegrityPromise = historicalArtifactDigest(
    metadata.registryUrl ?? "unknown",
    metadata.name,
    metadata.version,
    opts.cwd,
  );

  // Reputation lookups (npm downloads, GitHub repo status, and — root-only —
  // maintainer intelligence) start now so they overlap the tarball download
  // and OSV. fetchReputation never rejects — a failed lookup degrades to an
  // "unknown" status surfaced in the report.
  const reputationPromise =
    opts.noReputation || internal
      ? Promise.resolve(reputationSkipped())
      : (async (): Promise<ReputationLookup> => {
          const [base, maintainerIntel] = await Promise.all([
            fetchReputation(metadata.name, metadata.repositoryUrl, {
              skipDownloads: privateRegistry,
              resourceLimits: resourcePolicy,
            }),
            opts.maintainerIntel && !privateRegistry
              ? fetchMaintainerIntel(metadata, resourcePolicy)
              : Promise.resolve(undefined),
          ]);
          return { ...base, maintainerIntel };
        })();

  const obtainOsv = async (): Promise<OsvResult> => {
    if (internal) return osvSkipped();
    if (opts.osv) {
      opts.onStage?.(opts.osv.unavailable ? "osv-failed" : "osv");
      return opts.osv;
    }
    try {
      const result = await queryOsv(metadata.name, metadata.version, resourcePolicy);
      opts.onStage?.("osv");
      return result;
    } catch {
      opts.onStage?.("osv-failed");
      return osvUnavailable();
    }
  };

  // Start every independent I/O branch as soon as exact metadata is known.
  // Quarantine resolves public/history evidence only when it needs to verify
  // the downloaded bytes, so those network/disk operations overlap too.
  const osvPromise = obtainOsv();

  let quarantine;
  try {
    quarantine = await quarantineTarball(metadata.tarballUrl, {
      packageName: metadata.name,
      version: metadata.version,
      registryUrl: metadata.registryUrl ?? "unknown",
      registry: { integrity: metadata.integrity, shasum: metadata.shasum },
      lockfile: opts.lockedArtifact?.integrity
        ? { integrity: opts.lockedArtifact.integrity }
        : undefined,
      lockfileTrusted: opts.lockfileTrusted,
      historicalIntegrity: historicalIntegrityPromise,
      publicArtifact: publicArtifactPromise,
      resourceLimits: resourcePolicy,
    });
  } catch (err) {
    if (!(err instanceof ResourceLimitError)) throw err;
    const reason = `${err.kind}: ${err.message}`;
    opts.onStage?.("resource-limit", reason);
    const [osv, reputation] = await Promise.all([osvPromise, reputationPromise]);
    return {
      metadata,
      signals: buildDegradedSignals(metadata, osv, reason, reputation, { internalScope: internal }),
    };
  }
  opts.onStage?.("quarantine");

  try {
    const boundMetadata = await bindMetadataToTarball(
      metadata,
      quarantine.packageDir,
      quarantine.artifact,
    );
    const [osv, reputation] = await Promise.all([osvPromise, reputationPromise]);
    if (!opts.noReputation && !internal) {
      const degraded = [
        reputation.downloads.status === "unavailable" ? "download stats unavailable" : null,
        reputation.repo.status === "rate-limited"
          ? "GitHub rate-limited (set GITHUB_TOKEN to raise the limit)"
          : reputation.repo.status === "unavailable"
            ? "GitHub unreachable"
            : null,
      ].filter(Boolean);
      opts.onStage?.(
        degraded.length > 0 ? "reputation-degraded" : "reputation",
        degraded.join("; ") || undefined,
      );
    }

    let signals: Signals;
    try {
      signals = await withScanBudget(
        buildSignals(boundMetadata, quarantine.packageDir, osv, reputation, {
          internalScope: internal,
          artifact: quarantine.artifact,
          resourceLimits: limits,
        }),
        limits.maxScanDuration,
      );
    } catch (err) {
      if (!(err instanceof ResourceLimitError)) throw err;
      const reason = `${err.kind}: ${err.message}`;
      opts.onStage?.("resource-limit", reason);
      signals = buildDegradedSignals(boundMetadata, osv, reason, reputation, {
        internalScope: internal,
        artifact: quarantine.artifact,
      });
    }
    opts.onStage?.("signals");

    // Capture the risky source subset for the AI audit WHILE the tarball is
    // still extracted (cleanup below deletes it). This is only selection +
    // bounded reads — the model call happens later, with a provider + cache.
    let audit: PendingAudit | undefined;
    if (!internal && shouldAuditPackage(opts.codeAudit, signals, opts.isDirect)) {
      try {
        const index = await buildPackageFileIndex(quarantine.packageDir, limits);
        const selection = await selectAuditFiles(index, signals.lifecycleScripts, [], limits);
        if (selection.files.length > 0) {
          audit = {
            input: {
              package: boundMetadata.name,
              version: boundMetadata.version,
              files: selection.files.map((f) => ({
                relPath: f.relPath,
                content: f.content,
                truncated: f.truncated,
              })),
            },
            digest: signals.artifact.digest,
            dropped: selection.dropped,
          };
        }
      } catch {
        /* audit is advisory — a selection failure must never fail analysis */
      }
    }
    return { metadata: boundMetadata, signals, audit };
  } finally {
    await quarantine.cleanup();
  }
}

/**
 * Run the AI source-code audit for a prepared package and fold its findings
 * into the verdict — ESCALATION ONLY (foldSourceAudit + clampDecision keep the
 * deterministic floor). Returns the (possibly escalated) assessment plus a
 * SourceAuditResult for reporting. An audit error degrades to no change.
 */
export async function applySourceAudit(
  provider: AiProvider | null,
  audit: PendingAudit | undefined,
  assessment: RiskAssessment,
  signals: Signals,
  assess: Pick<AssessOptions, "cache" | "cwd">,
): Promise<{ assessment: RiskAssessment; result?: SourceAuditResult }> {
  if (!audit || !provider?.analyzeSource) return { assessment };
  const filesAnalyzed = audit.input.files.map((f) => f.relPath);
  try {
    const findings = await auditSourceWithCache(provider, audit.input, audit.digest, {
      cache: assess.cache,
      cwd: assess.cwd,
    });
    return {
      assessment: foldSourceAudit(assessment, findings, signals),
      result: { findings, filesAnalyzed, dropped: audit.dropped, source: "ai" },
    };
  } catch {
    // Model/transport failure: never worsen or break the verdict on it.
    return { assessment, result: { findings: [], filesAnalyzed, dropped: audit.dropped, source: "skipped" } };
  }
}

/**
 * Turn deterministic signals into a final assessment: AI/rules verdict (with
 * the AI cache + clamp inside assessRisk) -> OSV-failure policy -> team
 * policy. Shared by analyzePackage and the batched tree path so both apply
 * the exact same post-assessment escalations.
 */
export async function finalizeAssessment(
  signals: Signals,
  assessment: RiskAssessment,
  opts: Pick<AnalyzePackageOptions, "failOnOsvError" | "policy" | "onStage">,
): Promise<RiskAssessment> {
  let result = applyOsvFailurePolicy(assessment, signals, opts.failOnOsvError ?? false);
  opts.onStage?.("assessment", result.source);
  if (opts.policy) {
    result = applyPolicy(result, signals, opts.policy.policy);
    opts.onStage?.("policy", path.basename(opts.policy.file));
  }
  return result;
}

export async function analyzePackage(
  name: string,
  version: string | undefined,
  opts: AnalyzePackageOptions,
): Promise<PackageAnalysis> {
  const { metadata, signals, audit } = await buildPackageSignals(name, version, {
    ...opts,
    cwd: opts.cwd ?? opts.assess.cwd,
  });
  // Computed BEFORE the assessment on purpose: the score is a pure function of
  // the signals and stays independent of the AI/rules verdict.
  const score = computeSecurityScore(signals);
  const assessment = await finalizeAssessment(signals, await assessRisk(signals, opts.assess), opts);
  // Optional AI source-code audit — folded escalation-only over the verdict.
  const audited = await applySourceAudit(
    resolveBatchProvider(opts.assess),
    audit,
    assessment,
    signals,
    opts.assess,
  );
  return { metadata, signals, assessment: audited.assessment, score, sourceAudit: audited.result };
}
