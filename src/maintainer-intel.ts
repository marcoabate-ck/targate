import type { LookupStatus, PackageMetadata } from "./types.js";

/**
 * Maintainer intelligence via the public npm search API. For each maintainer
 * of a package we fetch their portfolio — how many packages they publish and
 * how popular those are — which turns "a maintainer was added" into "a
 * maintainer with no track record was added". Fail-open like the other
 * reputation lookups: an unreachable API yields status "unavailable", never a
 * false "looks fine".
 *
 * Deliberately NOT derived: account age / creation date — npm exposes no
 * public account API, so we make no claims about it.
 */

const SEARCH_API = "https://registry.npmjs.org/-/v1/search";
const LOOKUP_TIMEOUT_MS = 5_000;
/** A maintainer publishing something this popular has a real track record. */
const ESTABLISHED_WEEKLY_DOWNLOADS = 10_000;
/** How many of a package's maintainers to look up (cost cap). */
const MAX_MAINTAINERS = 5;

export interface MaintainerPortfolio {
  name: string;
  status: LookupStatus;
  /** Total packages this account can publish (search `total`). */
  packageCount?: number;
  /** Up to two of their packages, most-downloaded first. */
  topPackages?: { name: string; weeklyDownloads?: number }[];
  /** True when any package in the portfolio clears the popularity bar. */
  hasEstablishedPackage?: boolean;
}

export interface MaintainerIntel {
  /** "ok" = every consulted maintainer resolved; "unavailable" = at least one
   *  lookup failed; "skipped" = disabled (--no-reputation). */
  status: LookupStatus;
  maintainers: MaintainerPortfolio[];
  /** True when the package has more maintainers than we looked up. */
  truncated: boolean;
  /** Maintainers added since the previous release whose portfolio is ≤1
   *  package — i.e. this package is essentially their only one. Empty when the
   *  maintainer history is not derivable. */
  newMaintainerNoTrackRecord: string[];
}

export function maintainerIntelSkipped(): MaintainerIntel {
  return { status: "skipped", maintainers: [], truncated: false, newMaintainerNoTrackRecord: [] };
}

// Promise-memoized per lowercase maintainer name for the run.
const portfolioMemo = new Map<string, Promise<MaintainerPortfolio>>();

export function resetMaintainerIntelCacheForTests(): void {
  portfolioMemo.clear();
}

export async function fetchMaintainerPortfolio(name: string): Promise<MaintainerPortfolio> {
  const key = name.toLowerCase();
  let memo = portfolioMemo.get(key);
  if (!memo) {
    memo = fetchMaintainerPortfolioUncached(name);
    portfolioMemo.set(key, memo);
  }
  return memo;
}

interface SearchObject {
  package?: { name?: string };
  downloads?: { weekly?: number };
}

async function fetchMaintainerPortfolioUncached(name: string): Promise<MaintainerPortfolio> {
  try {
    const url = `${SEARCH_API}?text=maintainer:${encodeURIComponent(name)}&size=5`;
    const res = await fetch(url, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    });
    if (!res.ok) return { name, status: "unavailable" };
    const body = (await res.json()) as { objects?: SearchObject[]; total?: number };
    if (!Array.isArray(body.objects) || typeof body.total !== "number") {
      return { name, status: "unavailable" };
    }
    const ranked = body.objects
      .map((o) => ({ name: o.package?.name ?? "", weeklyDownloads: o.downloads?.weekly }))
      .filter((p) => p.name)
      .sort((a, b) => (b.weeklyDownloads ?? 0) - (a.weeklyDownloads ?? 0));
    return {
      name,
      status: "ok",
      packageCount: body.total,
      topPackages: ranked.slice(0, 2),
      hasEstablishedPackage: ranked.some((p) => (p.weeklyDownloads ?? 0) >= ESTABLISHED_WEEKLY_DOWNLOADS),
    };
  } catch {
    return { name, status: "unavailable" };
  }
}

/** Look up the portfolios of a package's maintainers and derive the intel. */
export async function fetchMaintainerIntel(metadata: PackageMetadata): Promise<MaintainerIntel> {
  const all = metadata.maintainers;
  const consulted = all.slice(0, MAX_MAINTAINERS);
  const portfolios = await Promise.all(consulted.map((m) => fetchMaintainerPortfolio(m)));

  const status: LookupStatus = portfolios.some((p) => p.status === "unavailable")
    ? "unavailable"
    : "ok";

  return {
    status,
    maintainers: portfolios,
    truncated: all.length > consulted.length,
    newMaintainerNoTrackRecord: deriveNoTrackRecord(metadata, portfolios),
  };
}

function deriveNoTrackRecord(
  metadata: PackageMetadata,
  portfolios: MaintainerPortfolio[],
): string[] {
  const reg = metadata.registryReputation;
  // Not derivable without both maintainer lists → no claim.
  if (!reg?.versionMaintainers || !reg.previousVersionMaintainers) return [];
  const previous = new Set(reg.previousVersionMaintainers);
  const added = reg.versionMaintainers.filter((m) => !previous.has(m));
  const byName = new Map(portfolios.map((p) => [p.name, p]));
  return added.filter((m) => {
    const p = byName.get(m);
    // Only claim "no track record" when we actually know the portfolio.
    return p?.status === "ok" && (p.packageCount ?? 0) <= 1;
  });
}
