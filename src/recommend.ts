import { mapLimit } from "./concurrency.js";
import { buildPackageSignals, finalizeAssessment } from "./pipeline.js";
import type { LoadedPolicy } from "./policy.js";
import { computeSecurityScore, type SecurityScore } from "./score.js";
import { evaluateRules, isHardBlock } from "./rules.js";
import type { RiskAssessment, Signals } from "./types.js";

/**
 * `targate recommend "<need>"` — the dependency ADVISOR: instead of gating a
 * package the user already picked, suggest what to pick. npm's search API
 * supplies candidates for the need; each candidate then goes through the SAME
 * deterministic pipeline as `targate add` (tarball quarantine, script/content
 * analysis, OSV, reputation, security score, rules verdict) and the survivors
 * are ranked. Deliberately no AI: a recommendation must be reproducible, and
 * the score + rules reasons ARE the explanation.
 *
 * Honesty note (rendered by the command): candidate DISCOVERY is npm search
 * relevance — targate ranks the safety of what search returned; it does not
 * know every package that could serve the need.
 */

const SEARCH_API = "https://registry.npmjs.org/-/v1/search";
const SEARCH_TIMEOUT_MS = 8_000;
/** Candidates analyzed when --limit is not given. */
export const DEFAULT_RECOMMEND_LIMIT = 5;
/** Hard cap — every candidate costs a tarball download + full analysis. */
export const MAX_RECOMMEND_LIMIT = 15;
/** Analysis pool width (same spirit as the --deep walker, but small). */
const ANALYZE_CONCURRENCY = 4;

export interface RecommendCandidate {
  name: string;
  /** Latest version per the search index (the analysis re-resolves latest). */
  version?: string;
  description?: string;
  weeklyDownloads?: number;
}

export class RecommendSearchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecommendSearchError";
  }
}

/**
 * Free-text candidate search. NOT fail-open like the reputation lookups —
 * finding candidates is the whole command, so a failure is a real error.
 */
export async function searchCandidates(
  query: string,
  size: number,
): Promise<RecommendCandidate[]> {
  const url = `${SEARCH_API}?text=${encodeURIComponent(query)}&size=${size}`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(SEARCH_TIMEOUT_MS),
    });
  } catch {
    throw new RecommendSearchError("npm search is unreachable — cannot discover candidates.");
  }
  if (!res.ok) {
    throw new RecommendSearchError(`npm search responded with HTTP ${res.status}.`);
  }
  const doc = (await res.json()) as {
    objects?: {
      package?: { name?: string; version?: string; description?: string };
      downloads?: { weekly?: number };
    }[];
  };
  return (doc.objects ?? [])
    .filter((o) => typeof o.package?.name === "string")
    .map((o) => ({
      name: o.package!.name!,
      version: typeof o.package?.version === "string" ? o.package.version : undefined,
      description: o.package?.description,
      weeklyDownloads: typeof o.downloads?.weekly === "number" ? o.downloads.weekly : undefined,
    }));
}

export interface Recommendation {
  name: string;
  version: string;
  description?: string;
  weeklyDownloads?: number;
  score: SecurityScore;
  /** Deterministic rules verdict on the same signals `targate add` would see. */
  assessment: RiskAssessment;
  signals: Signals;
}

export interface RejectedCandidate {
  name: string;
  version?: string;
  reason: string;
}

export interface RecommendReport {
  query: string;
  /** Candidates the search returned and we analyzed. */
  analyzed: number;
  /** Ranked, safest first. */
  recommendations: Recommendation[];
  /** Candidates excluded outright, with the disqualifying reason. */
  rejected: RejectedCandidate[];
}

/** Disqualify before ranking: an advisor must never SUGGEST these. */
function disqualify(signals: Signals): string | null {
  if (signals.knownMalicious) {
    return `known malicious-package record (${signals.maliciousRecords.map((r) => r.id).join(", ")})`;
  }
  if (isHardBlock(signals)) return "hard block: install-time remote code execution pattern";
  if (signals.reputation.deprecated) return "deprecated by its maintainers";
  return null;
}

/**
 * Ranking, safest first: security score desc, adoption (weekly downloads)
 * desc as the tie-breaker, name for stability. The score already prices in
 * advisories, scripts, contents, reputation, and maintainer signals.
 */
export function rankRecommendations(list: Recommendation[]): Recommendation[] {
  return [...list].sort(
    (a, b) =>
      b.score.total - a.score.total ||
      (b.weeklyDownloads ?? 0) - (a.weeklyDownloads ?? 0) ||
      a.name.localeCompare(b.name),
  );
}

export interface RecommendOptions {
  limit?: number;
  noReputation?: boolean;
  failOnOsvError?: boolean;
  policy?: LoadedPolicy | null;
  /** Per-candidate progress (human rendering). */
  onCandidate?: (name: string, outcome: "ok" | "rejected" | "error", detail?: string) => void;
  /** Injectable for tests. */
  search?: typeof searchCandidates;
}

/** Search → analyze top N with the real pipeline → disqualify → rank. */
export async function recommendPackages(
  query: string,
  opts: RecommendOptions = {},
): Promise<RecommendReport> {
  const limit = Math.min(Math.max(opts.limit ?? DEFAULT_RECOMMEND_LIMIT, 1), MAX_RECOMMEND_LIMIT);
  const candidates = (await (opts.search ?? searchCandidates)(query, limit)).slice(0, limit);

  const recommendations: Recommendation[] = [];
  const rejected: RejectedCandidate[] = [];

  await mapLimit(candidates, ANALYZE_CONCURRENCY, async (candidate) => {
    try {
      const { metadata, signals } = await buildPackageSignals(candidate.name, undefined, {
        noReputation: opts.noReputation,
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
        maintainerIntel: true,
      });
      const reason = disqualify(signals);
      if (reason) {
        rejected.push({ name: metadata.name, version: metadata.version, reason });
        opts.onCandidate?.(metadata.name, "rejected", reason);
        return;
      }
      // Rules verdict + the same post-assessment escalations `targate add`
      // applies (OSV-failure policy, team policy) — an advisor in a repo with
      // a team policy must respect it.
      const assessment = await finalizeAssessment(signals, evaluateRules(signals), {
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
      });
      if (assessment.decision === "block") {
        const blockReason =
          assessment.reasons.find((r) => r.startsWith("[policy]")) ??
          assessment.reasons[0] ??
          "blocked by the rules engine";
        rejected.push({ name: metadata.name, version: metadata.version, reason: blockReason });
        opts.onCandidate?.(metadata.name, "rejected", blockReason);
        return;
      }
      recommendations.push({
        name: metadata.name,
        version: metadata.version,
        description: metadata.description ?? candidate.description,
        weeklyDownloads: candidate.weeklyDownloads,
        score: computeSecurityScore(signals),
        assessment,
        signals,
      });
      opts.onCandidate?.(metadata.name, "ok");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      rejected.push({ name: candidate.name, version: candidate.version, reason: `analysis failed: ${message}` });
      opts.onCandidate?.(candidate.name, "error", message);
    }
  });

  return {
    query,
    analyzed: candidates.length,
    recommendations: rankRecommendations(recommendations),
    rejected,
  };
}
