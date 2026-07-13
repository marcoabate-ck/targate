import type { MaintainerIntel } from "./maintainer-intel.js";
import type {
  DownloadsSignal,
  MaintainerChangeSignal,
  PackageMetadata,
  ReputationSignals,
  RepoStatusSignal,
} from "./types.js";
import { fetchWithTimeout, readResponseJson } from "./network.js";
import { networkBudget, type ResourceLimits } from "./resource-limits.js";

/**
 * External reputation lookups: npm downloads (adoption + spike/drop trend)
 * and GitHub repo status (archived / gone). Both are OPTIONAL and fail-open —
 * mirroring how the OSV lookup degrades: a failed lookup yields an "unknown"
 * status that is surfaced to the user, never a silent "looks fine", and never
 * a failed analysis.
 *
 * GitHub follows the AI-key strategy: an optional GITHUB_TOKEN (or GH_TOKEN)
 * is auto-detected from the environment; unauthenticated works at 60 req/h.
 * When the quota is exhausted, a circuit breaker short-circuits every further
 * GitHub lookup this run (critical for --deep trees) and the report tells the
 * user to set GITHUB_TOKEN.
 */

const DOWNLOADS_API = "https://api.npmjs.org/downloads/range/last-month";
const GITHUB_API = "https://api.github.com/repos";
const LOOKUP_TIMEOUT_MS = 5_000;

/** Spike: recent avg ≥5× the prior-21-day avg, with an absolute floor so tiny
 *  packages (3 → 20 downloads/day) don't read as spikes. */
const SPIKE_RATIO = 5;
const SPIKE_MIN_WEEKLY = 1_000;
/** Drop: recent avg ≤0.2× the prior avg, when there was real traffic to lose. */
const DROP_RATIO = 0.2;
const DROP_MIN_BASE_PER_DAY = 100;
/** A release after ≥ this gap, when the version is fresh, is anomalous. */
export const RELEASE_GAP_ANOMALY_DAYS = 365;
const RELEASE_GAP_FRESH_DAYS = 30;

export interface ReputationLookup {
  downloads: DownloadsSignal;
  repo: RepoStatusSignal;
  /** Maintainer intelligence, when gathered (root-package analysis only). */
  maintainerIntel?: MaintainerIntel;
}

/** All sub-lookups skipped (--no-reputation, or tests). */
export function reputationSkipped(): ReputationLookup {
  return { downloads: { status: "skipped" }, repo: { status: "skipped" } };
}

// Per-run memoization: a --deep tree with foo@1.0.0 and foo@1.2.0 fetches
// downloads once; a monorepo tree of 40 packages sharing one GitHub repo makes
// one request. Memoizing the PROMISE means concurrent workers share in-flight
// requests. Reset via resetReputationCacheForTests().
const downloadsMemo = new Map<string, Promise<DownloadsSignal>>();
const repoMemo = new Map<string, Promise<RepoStatusSignal>>();
/** Once GitHub reports an exhausted quota, stop asking for the rest of the run. */
let githubRateLimited = false;

export function resetReputationCacheForTests(): void {
  downloadsMemo.clear();
  repoMemo.clear();
  githubRateLimited = false;
}

/** Never throws — each sub-lookup degrades independently to its unknown state. */
export async function fetchReputation(
  name: string,
  repositoryUrl: string | undefined,
  opts?: {
    githubToken?: string;
    /** The npmjs downloads API cannot know packages served by another
     *  registry — skip the lookup instead of reporting a bogus "unknown". */
    skipDownloads?: boolean;
    resourceLimits?: ResourceLimits;
  },
): Promise<ReputationLookup> {
  const [downloads, repo] = await Promise.all([
    opts?.skipDownloads
      ? Promise.resolve<DownloadsSignal>({ status: "skipped" })
      : fetchDownloads(name, opts?.resourceLimits),
    fetchRepoStatus(repositoryUrl, opts?.githubToken, opts?.resourceLimits),
  ]);
  return { downloads, repo };
}

async function fetchDownloads(name: string, limits?: ResourceLimits): Promise<DownloadsSignal> {
  let memo = downloadsMemo.get(name);
  if (!memo) {
    memo = fetchDownloadsUncached(name, limits);
    downloadsMemo.set(name, memo);
  }
  return memo;
}

async function fetchDownloadsUncached(name: string, limits?: ResourceLimits): Promise<DownloadsSignal> {
  try {
    const budget = networkBudget(limits);
    const res = await fetchWithTimeout(
      // The downloads API accepts "@scope/pkg" with a literal slash, like the registry.
      `${DOWNLOADS_API}/${encodeURIComponent(name).replace("%40", "@").replace("%2F", "/")}`,
      { headers: { accept: "application/json" } },
      { ...budget, timeoutMs: limits?.networkTimeoutMs ?? LOOKUP_TIMEOUT_MS },
    );
    if (!res.ok) return { status: "unavailable" };
    const body = await readResponseJson<{
      downloads?: { day: string; downloads: number }[];
      error?: string;
    }>(res, budget.maxResponseBytes, "npm downloads response");
    // A very new package yields an error body — adoption is UNKNOWN, not zero.
    if (!Array.isArray(body.downloads)) return { status: "unavailable" };
    return { status: "ok", ...classifyDownloadTrend(body.downloads) };
  } catch {
    return { status: "unavailable" };
  }
}

/** Pure trend classifier over the daily download buckets, exported for tests. */
export function classifyDownloadTrend(
  days: { day: string; downloads: number }[],
): Pick<DownloadsSignal, "weeklyDownloads" | "trend" | "trendDetail"> {
  const counts = days.map((d) => d.downloads);
  const weeklyDownloads = counts.slice(-7).reduce((a, b) => a + b, 0);
  if (counts.length < 28) return { weeklyDownloads };

  const recent = weeklyDownloads / 7;
  const prior = counts.slice(-28, -7);
  const base = prior.reduce((a, b) => a + b, 0) / prior.length;

  const fmt = (n: number) => Math.round(n).toLocaleString("en-US");
  if (recent >= SPIKE_RATIO * base && weeklyDownloads >= SPIKE_MIN_WEEKLY) {
    const ratio = base > 0 ? (recent / base).toFixed(1) : "∞";
    return {
      weeklyDownloads,
      trend: "spike",
      trendDetail: `7d avg ${fmt(recent)}/day vs prior 21d avg ${fmt(base)}/day (${ratio}x)`,
    };
  }
  if (recent <= DROP_RATIO * base && base >= DROP_MIN_BASE_PER_DAY) {
    return {
      weeklyDownloads,
      trend: "drop",
      trendDetail: `7d avg ${fmt(recent)}/day vs prior 21d avg ${fmt(base)}/day`,
    };
  }
  return { weeklyDownloads, trend: "stable" };
}

/** github.com URLs in their common npm forms -> {owner, repo}; null otherwise. */
export function parseGitHubRepo(url: string): { owner: string; repo: string } | null {
  const cleaned = url
    .trim()
    .replace(/^git\+/, "")
    .replace(/\.git(#.*)?$/, "");

  // Shorthand: "github:owner/repo" (npm expands bare "owner/repo" to this).
  const short = /^github:([^/]+)\/([^/#]+)/.exec(cleaned);
  if (short) return { owner: short[1], repo: short[2] };

  // ssh: git@github.com:owner/repo  |  ssh://git@github.com/owner/repo
  const ssh = /^(?:ssh:\/\/)?git@github\.com[:/]([^/]+)\/([^/#]+)/.exec(cleaned);
  if (ssh) return { owner: ssh[1], repo: ssh[2] };

  // http(s) / git protocol
  const web = /^(?:https?|git):\/\/(?:www\.)?github\.com\/([^/]+)\/([^/#?]+)/.exec(cleaned);
  if (web) return { owner: web[1], repo: web[2] };

  return null;
}

async function fetchRepoStatus(
  repositoryUrl: string | undefined,
  githubToken?: string,
  limits?: ResourceLimits,
): Promise<RepoStatusSignal> {
  if (!repositoryUrl) return { status: "skipped" };
  const parsed = parseGitHubRepo(repositoryUrl);
  if (!parsed) return { status: "not-github" };

  const key = `${parsed.owner}/${parsed.repo}`.toLowerCase();
  let memo = repoMemo.get(key);
  if (!memo) {
    memo = fetchRepoStatusUncached(parsed.owner, parsed.repo, githubToken, limits);
    repoMemo.set(key, memo);
  }
  return memo;
}

async function fetchRepoStatusUncached(
  owner: string,
  repo: string,
  githubToken?: string,
  limits?: ResourceLimits,
): Promise<RepoStatusSignal> {
  if (githubRateLimited) return { status: "rate-limited" };
  const token = githubToken ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  try {
    const budget = networkBudget(limits);
    const res = await fetchWithTimeout(`${GITHUB_API}/${owner}/${repo}`, {
      headers: {
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        // GitHub rejects requests without a user agent.
        "user-agent": "targate",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
    }, { ...budget, timeoutMs: limits?.networkTimeoutMs ?? LOOKUP_TIMEOUT_MS });
    if (res.status === 404) return { status: "not-found" };
    if (
      (res.status === 403 || res.status === 429) &&
      res.headers.get("x-ratelimit-remaining") === "0"
    ) {
      githubRateLimited = true; // trip the breaker for the rest of the run
      return { status: "rate-limited" };
    }
    if (!res.ok) return { status: "unavailable" };
    const body = await readResponseJson<{ archived?: boolean }>(
      res, budget.maxResponseBytes, "GitHub repository response",
    );
    return { status: "ok", archived: Boolean(body.archived) };
  } catch {
    return { status: "unavailable" };
  }
}

/** Pure merge of registry-derived + network reputation into ReputationSignals. */
export function deriveReputation(
  metadata: PackageMetadata,
  lookup: ReputationLookup,
  now: number = Date.now(),
): ReputationSignals {
  // Defensive: metadata may come from persisted JSON written by an older
  // targate (e.g. a stale .targate/last-run.json) without the carrier.
  const reg = metadata.registryReputation ?? { hasProvenance: false };

  const versionAgeDays = metadata.publishDate
    ? Math.floor((now - new Date(metadata.publishDate).getTime()) / 86_400_000)
    : undefined;

  const releaseAfterInactivityDays =
    metadata.publishDate && reg.previousVersionPublishDate
      ? Math.floor(
          (new Date(metadata.publishDate).getTime() -
            new Date(reg.previousVersionPublishDate).getTime()) /
            86_400_000,
        )
      : undefined;

  const releaseGapAnomaly =
    releaseAfterInactivityDays !== undefined &&
    versionAgeDays !== undefined &&
    releaseAfterInactivityDays >= RELEASE_GAP_ANOMALY_DAYS &&
    versionAgeDays <= RELEASE_GAP_FRESH_DAYS;

  const { repositoryMismatch, repositoryMismatchDetail } = detectRepositoryMismatch(metadata);

  return {
    versionAgeDays,
    releaseAfterInactivityDays,
    releaseGapAnomaly,
    maintainerCount: metadata.maintainers.length,
    maintainerChange: detectMaintainerChange(reg),
    repositoryMismatch,
    repositoryMismatchDetail,
    hasProvenance: reg.hasProvenance,
    deprecated:
      reg.deprecated === undefined
        ? false
        : reg.deprecated === true
          ? "deprecated (no message)"
          : reg.deprecated,
    downloads: lookup.downloads,
    repo: lookup.repo,
    maintainerIntel: lookup.maintainerIntel,
  };
}

function detectMaintainerChange(
  reg: PackageMetadata["registryReputation"],
): MaintainerChangeSignal | null {
  // No previous release, or the packument strips per-version maintainer data
  // (old packages, some mirrors): the history is NOT derivable. null is
  // rendered as unknown — never as "no change".
  if (!reg.previousVersion || !reg.versionMaintainers || !reg.previousVersionMaintainers) {
    return null;
  }
  const previous = new Set(reg.previousVersionMaintainers);
  const current = new Set(reg.versionMaintainers);

  if (reg.publisher && !previous.has(reg.publisher)) {
    return {
      changed: true,
      detail: `publisher "${reg.publisher}" was not a maintainer of ${reg.previousVersion}`,
    };
  }
  const added = [...current].filter((m) => !previous.has(m));
  const removed = [...previous].filter((m) => !current.has(m));
  if (added.length > 0 || removed.length > 0) {
    const parts = [
      added.length > 0 ? `added: ${added.join(", ")}` : null,
      removed.length > 0 ? `removed: ${removed.join(", ")}` : null,
    ].filter(Boolean);
    return { changed: true, detail: `since ${reg.previousVersion} — ${parts.join("; ")}` };
  }
  return { changed: false };
}

function detectRepositoryMismatch(metadata: PackageMetadata): {
  repositoryMismatch: boolean;
  repositoryMismatchDetail?: string;
} {
  const url = metadata.repositoryUrl;
  if (!url) return { repositoryMismatch: false }; // missing is Signals.repositoryMissing

  const normalized = normalizeRepoUrl(url);
  if (!normalized) {
    return {
      repositoryMismatch: true,
      repositoryMismatchDetail: `repository URL has no recognizable host: ${url}`,
    };
  }

  const latest = metadata.registryReputation?.latestRepositoryUrl;
  if (latest) {
    const latestNormalized = normalizeRepoUrl(latest);
    if (latestNormalized && latestNormalized !== normalized) {
      return {
        repositoryMismatch: true,
        repositoryMismatchDetail: `this version points at ${normalized} but the latest version points at ${latestNormalized}`,
      };
    }
  }
  return { repositoryMismatch: false };
}

/** "git+https://github.com/A/B.git" -> "github.com/a/b"; null when hostless. */
function normalizeRepoUrl(url: string): string | null {
  const cleaned = url
    .trim()
    .toLowerCase()
    .replace(/^git\+/, "")
    .replace(/\.git(#.*)?$/, "")
    .replace(/\/+$/, "");
  const gh = parseGitHubRepo(cleaned);
  if (gh) return `github.com/${gh.owner}/${gh.repo}`;
  const web = /^(?:https?|git|ssh):\/\/(?:[^@/]+@)?([^/:]+)[/:](.+)$/.exec(cleaned);
  if (web) return `${web[1]}/${web[2]}`;
  const scp = /^[^@/]+@([^:/]+):(.+)$/.exec(cleaned); // git@host:owner/repo
  if (scp) return `${scp[1]}/${scp[2]}`;
  return null;
}
