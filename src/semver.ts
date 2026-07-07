/**
 * Minimal semver ordering — enough to pick the HIGHEST version out of a set
 * (lockfile ambiguity, registry `latest` fallback). Not a full range
 * resolver: numeric major.minor.patch comparison, with a prerelease sorting
 * before its own release ("1.2.0-rc.1" < "1.2.0"). Lexicographic string
 * sort is wrong for versions ("1.9.0" > "1.10.0") — never use it here.
 */
export function compareSemver(a: string, b: string): number {
  const coreA = a.split(/[-+]/)[0].split(".").map(Number);
  const coreB = b.split(/[-+]/)[0].split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (coreA[i] ?? 0) - (coreB[i] ?? 0);
    if (Number.isNaN(d)) return a.localeCompare(b); // non-numeric segment — fall back
    if (d !== 0) return d;
  }
  const preA = a.includes("-");
  const preB = b.includes("-");
  if (preA !== preB) return preA ? -1 : 1; // prerelease < release
  return a.localeCompare(b); // stable tiebreak (incl. between prereleases)
}

/** Highest version in the list, or undefined for an empty list. */
export function highestSemver(versions: string[]): string | undefined {
  if (versions.length === 0) return undefined;
  return versions.reduce((max, v) => (compareSemver(v, max) > 0 ? v : max));
}
