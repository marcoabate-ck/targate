import path from "node:path";
import { readFile } from "node:fs/promises";
import { buildSignals } from "./analyze/index.js";
import { historicalArtifactDigest } from "./artifact-ledger.js";
import { assessRisk, type AssessOptions } from "./ai.js";
import { isInternalScope } from "./npmrc.js";
import { osvSkipped, osvUnavailable, queryOsv, type OsvResult } from "./osv.js";
import { applyPolicy, type LoadedPolicy } from "./policy.js";
import { artifactMirrorFor } from "./policy.js";
import { quarantineTarball } from "./quarantine.js";
import { fetchArtifactEvidence, fetchPackageMetadata } from "./registry.js";
import { fetchMaintainerIntel } from "./maintainer-intel.js";
import { fetchReputation, reputationSkipped, type ReputationLookup } from "./reputation.js";
import { computeSecurityScore, type SecurityScore } from "./score.js";
import { applyOsvFailurePolicy } from "./rules.js";
import type { PackageMetadata, RiskAssessment, Signals } from "./types.js";
import type { LockedPackageArtifact } from "./lockfile.js";

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
  onStage?: (stage: AnalysisStage, detail?: string) => void;
}

export interface PackageAnalysis {
  metadata: PackageMetadata;
  signals: Signals;
  assessment: RiskAssessment;
  /** Informational 0–100 risk-signal aggregation — never drives the decision. */
  score: SecurityScore;
}

export interface PackageSignals {
  metadata: PackageMetadata;
  signals: Signals;
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
  if (!sameMap(scripts, metadata.scripts)) {
    artifact.trust = "mutated";
    artifact.reasons.push("registry lifecycle scripts differ from the tarball package.json");
  }
  if (!sameMap(dependencies, metadata.dependencyRanges ?? {})) {
    artifact.trust = "mutated";
    artifact.reasons.push("registry dependencies differ from the tarball package.json");
  }
  if (!sameNames(Object.keys(optionalDependencies), metadata.optionalDependencyNames ?? [])) {
    artifact.trust = "mutated";
    artifact.reasons.push("registry optionalDependencies differ from the tarball package.json");
  }
  if (!sameNames(Object.keys(peerDependencies), metadata.peerDependencyNames ?? [])) {
    artifact.trust = "mutated";
    artifact.reasons.push("registry peerDependencies differ from the tarball package.json");
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
    "failOnOsvError" | "osv" | "noReputation" | "maintainerIntel" | "onStage" | "policy" | "lockedArtifact" | "lockfileTrusted" | "metadata" | "cwd"
  >,
): Promise<PackageSignals> {
  const metadata = opts.metadata ?? await fetchPackageMetadata(name, version);
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
    ? fetchArtifactEvidence(metadata.name, metadata.version, mirror)
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
            }),
            opts.maintainerIntel && !privateRegistry
              ? fetchMaintainerIntel(metadata)
              : Promise.resolve(undefined),
          ]);
          return { ...base, maintainerIntel };
        })();

  const [publicArtifact, historicalIntegrity] = await Promise.all([
    publicArtifactPromise,
    historicalIntegrityPromise,
  ]);
  const quarantine = await quarantineTarball(metadata.tarballUrl, {
    packageName: metadata.name,
    version: metadata.version,
    registryUrl: metadata.registryUrl ?? "unknown",
    registry: { integrity: metadata.integrity, shasum: metadata.shasum },
    lockfile: opts.lockedArtifact?.integrity
      ? { integrity: opts.lockedArtifact.integrity }
      : undefined,
    lockfileTrusted: opts.lockfileTrusted,
    historicalIntegrity,
    publicArtifact,
  });
  opts.onStage?.("quarantine");

  try {
    const boundMetadata = await bindMetadataToTarball(
      metadata,
      quarantine.packageDir,
      quarantine.artifact,
    );
    let osv: OsvResult;
    if (internal) {
      osv = osvSkipped(); // never send an internal package name to OSV
    } else if (opts.osv) {
      osv = opts.osv;
      opts.onStage?.(osv.unavailable ? "osv-failed" : "osv");
    } else {
      try {
        osv = await queryOsv(metadata.name, metadata.version);
        opts.onStage?.("osv");
      } catch {
        osv = osvUnavailable();
        opts.onStage?.("osv-failed");
      }
    }

    const reputation = await reputationPromise;
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

    const signals = await buildSignals(boundMetadata, quarantine.packageDir, osv, reputation, {
      internalScope: internal,
      artifact: quarantine.artifact,
    });
    opts.onStage?.("signals");
    return { metadata: boundMetadata, signals };
  } finally {
    await quarantine.cleanup();
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
  const { metadata, signals } = await buildPackageSignals(name, version, {
    ...opts,
    cwd: opts.cwd ?? opts.assess.cwd,
  });
  // Computed BEFORE the assessment on purpose: the score is a pure function of
  // the signals and stays independent of the AI/rules verdict.
  const score = computeSecurityScore(signals);
  const assessment = await finalizeAssessment(signals, await assessRisk(signals, opts.assess), opts);
  return { metadata, signals, assessment, score };
}
