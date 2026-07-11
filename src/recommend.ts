import type { AssessOptions } from "./ai.js";
import { mapLimit } from "./concurrency.js";
import { buildPackageSignals, finalizeAssessment } from "./pipeline.js";
import type { LoadedPolicy } from "./policy.js";
import { resolveProvider } from "./providers/index.js";
import { PackageNotFoundError } from "./registry.js";
import { computeSecurityScore, type SecurityScore } from "./score.js";
import { evaluateRules, isHardBlock } from "./rules.js";
import type { RiskAssessment, Signals } from "./types.js";

/**
 * `targate recommend "<need>"` — the dependency ADVISOR: instead of gating a
 * package the user already picked, suggest what to pick.
 *
 * Candidates come from TWO sources, merged and deduped:
 *   1. npm's search API (text relevance), and
 *   2. the configured AI provider, asked to propose exact package names for
 *      the need (skipped with --no-ai or when no provider is configured;
 *      an AI failure degrades to search-only — never fatal).
 *
 * The AI only ever CONTRIBUTES NAMES. Every candidate — whatever its source —
 * is resolved on the registry (which kills hallucinated names) and analyzed
 * by the SAME deterministic pipeline as `targate add` (tarball quarantine,
 * script/content analysis, OSV, reputation, security score, rules verdict +
 * team policy). Scoring and ranking are fully deterministic: the AI cannot
 * boost, demote, or vouch for anything.
 *
 * Honesty note (rendered by the command): discovery is npm search relevance
 * plus AI knowledge — targate ranks the safety of what was discovered; it
 * does not know every package that could serve the need.
 */

const SEARCH_API = "https://registry.npmjs.org/-/v1/search";
const SEARCH_TIMEOUT_MS = 8_000;
/** Candidates analyzed when --limit is not given. */
export const DEFAULT_RECOMMEND_LIMIT = 5;
/** Hard cap — every candidate costs a tarball download + full analysis. */
export const MAX_RECOMMEND_LIMIT = 15;
/** Analysis pool width (same spirit as the --deep walker, but small). */
const ANALYZE_CONCURRENCY = 4;

/** Where a candidate came from — carried through to the final report. */
export type CandidateSource = "npm-search" | "ai" | "both";

export interface RecommendCandidate {
  name: string;
  /** Latest version per the search index (the analysis re-resolves latest). */
  version?: string;
  description?: string;
  weeklyDownloads?: number;
  source: CandidateSource;
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
      source: "npm-search" as const,
    }));
}

export interface Recommendation {
  name: string;
  version: string;
  description?: string;
  weeklyDownloads?: number;
  /** Which discovery source(s) proposed this candidate. */
  source: CandidateSource;
  score: SecurityScore;
  /** Deterministic rules verdict on the same signals `targate add` would see. */
  assessment: RiskAssessment;
  signals: Signals;
}

export interface RejectedCandidate {
  name: string;
  version?: string;
  reason: string;
  source?: CandidateSource;
}

/** What the AI contributed to discovery (names only — never verdicts). */
export interface AiSuggestionsInfo {
  /** "skipped" = --no-ai / no provider; "unavailable" = the provider failed. */
  status: "ok" | "skipped" | "unavailable";
  provider?: string;
  model?: string;
  /** Validated names the AI proposed (pre-registry-resolution). */
  names: string[];
  detail?: string;
}

export interface RecommendReport {
  query: string;
  /** Merged candidates (search ∪ AI) that were analyzed. */
  analyzed: number;
  /** Ranked, safest first. */
  recommendations: Recommendation[];
  /** Candidates excluded outright, with the disqualifying reason. */
  rejected: RejectedCandidate[];
  aiSuggestions: AiSuggestionsInfo;
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
  /** Provider selection for AI candidate suggestions (useAi: false → skipped). */
  assess?: AssessOptions;
  /** Per-candidate progress (human rendering). */
  onCandidate?: (name: string, outcome: "ok" | "rejected" | "error", detail?: string) => void;
  /** Injectable for tests. */
  search?: typeof searchCandidates;
  /** Injectable for tests: overrides the provider-backed AI suggestions. */
  suggest?: (query: string, count: number) => Promise<string[]>;
}

/**
 * Ask the configured AI provider for candidate names. Fail-open by design:
 * recommend works search-only without a provider, and an AI failure must
 * never kill the command — it degrades, visibly, to "unavailable".
 */
async function gatherAiSuggestions(
  query: string,
  count: number,
  opts: RecommendOptions,
): Promise<AiSuggestionsInfo> {
  if (opts.suggest) {
    try {
      return { status: "ok", names: await opts.suggest(query, count) };
    } catch (err) {
      return { status: "unavailable", names: [], detail: err instanceof Error ? err.message : String(err) };
    }
  }
  if (!opts.assess?.useAi) return { status: "skipped", names: [], detail: "AI disabled (--no-ai)" };
  let provider;
  try {
    provider = resolveProvider(opts.assess);
  } catch (err) {
    return { status: "unavailable", names: [], detail: err instanceof Error ? err.message : String(err) };
  }
  if (!provider) return { status: "skipped", names: [], detail: "no AI provider configured" };
  if (!provider.suggestPackages) {
    return { status: "skipped", names: [], provider: provider.name, model: provider.model, detail: "provider has no suggestion support" };
  }
  try {
    const names = await provider.suggestPackages(query, count);
    return { status: "ok", provider: provider.name, model: provider.model, names };
  } catch (err) {
    return {
      status: "unavailable",
      provider: provider.name,
      model: provider.model,
      names: [],
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Merge search + AI candidates, deduped by name, source-tagged. Pure. */
export function mergeCandidates(
  fromSearch: RecommendCandidate[],
  aiNames: string[],
): RecommendCandidate[] {
  const merged = new Map<string, RecommendCandidate>();
  for (const c of fromSearch) merged.set(c.name, c);
  for (const name of aiNames) {
    const existing = merged.get(name);
    if (existing) merged.set(name, { ...existing, source: "both" });
    else merged.set(name, { name, source: "ai" });
  }
  return [...merged.values()];
}

/** Search + AI suggestions → merge → analyze with the real pipeline → disqualify → rank. */
export async function recommendPackages(
  query: string,
  opts: RecommendOptions = {},
): Promise<RecommendReport> {
  const limit = Math.min(Math.max(opts.limit ?? DEFAULT_RECOMMEND_LIMIT, 1), MAX_RECOMMEND_LIMIT);
  // Both discovery sources run concurrently; each contributes up to `limit`
  // names, so the merged set is bounded at 2×limit.
  const [found, aiSuggestions] = await Promise.all([
    (opts.search ?? searchCandidates)(query, limit),
    gatherAiSuggestions(query, limit, opts),
  ]);
  const candidates = mergeCandidates(found.slice(0, limit), aiSuggestions.names);

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
        rejected.push({ name: metadata.name, version: metadata.version, reason, source: candidate.source });
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
        rejected.push({ name: metadata.name, version: metadata.version, reason: blockReason, source: candidate.source });
        opts.onCandidate?.(metadata.name, "rejected", blockReason);
        return;
      }
      recommendations.push({
        name: metadata.name,
        version: metadata.version,
        description: metadata.description ?? candidate.description,
        weeklyDownloads: candidate.weeklyDownloads,
        source: candidate.source,
        score: computeSecurityScore(signals),
        assessment,
        signals,
      });
      opts.onCandidate?.(metadata.name, "ok");
    } catch (err) {
      // Hallucination guard: an AI-proposed name that the registry does not
      // know is called out as such, not as a generic failure.
      const message =
        err instanceof PackageNotFoundError && candidate.source === "ai"
          ? "suggested by the AI but does not exist on the npm registry"
          : `analysis failed: ${err instanceof Error ? err.message : String(err)}`;
      rejected.push({
        name: candidate.name,
        version: candidate.version,
        reason: message,
        source: candidate.source,
      });
      opts.onCandidate?.(candidate.name, "error", message);
    }
  });

  return {
    query,
    analyzed: candidates.length,
    recommendations: rankRecommendations(recommendations),
    rejected,
    aiSuggestions,
  };
}
