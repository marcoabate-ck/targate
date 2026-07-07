/**
 * Minimal semver ordering — enough to pick the HIGHEST version out of a set
 * (lockfile ambiguity, registry `latest` fallback). Not a full range
 * resolver: numeric major.minor.patch comparison, with a prerelease sorting
 * before its own release ("1.2.0-rc.1" < "1.2.0"). Build metadata ("+…") is
 * ignored, per semver §10. Lexicographic string sort is wrong for versions
 * ("1.9.0" > "1.10.0") — never use it here.
 *
 * Known simplification: two prereleases of the same core version are ordered
 * lexically (so "rc.2" sorts after "rc.10"), not by the full dot-separated
 * identifier rules. That only affects the tiebreak between two prereleases of
 * the same release, which never arises when picking a highest STABLE version.
 */
export function compareSemver(a: string, b: string): number {
  // Strip build metadata ("+…") entirely — it must not affect precedence.
  const pre = (v: string): string => {
    const dash = v.indexOf("-");
    return dash === -1 ? "" : v.slice(dash + 1).split("+")[0];
  };
  const coreA = a.split(/[-+]/)[0].split(".").map(Number);
  const coreB = b.split(/[-+]/)[0].split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (coreA[i] ?? 0) - (coreB[i] ?? 0);
    if (Number.isNaN(d)) return a.localeCompare(b); // non-numeric segment — fall back
    if (d !== 0) return d;
  }
  const preA = pre(a);
  const preB = pre(b);
  if (!preA && !preB) return 0; // equal cores, both stable, build metadata ignored
  if (!preA || !preB) return preA ? -1 : 1; // prerelease < its own release
  return preA.localeCompare(preB); // both prereleases — lexical tiebreak
}

/** Highest version in the list, or undefined for an empty list. */
export function highestSemver(versions: string[]): string | undefined {
  if (versions.length === 0) return undefined;
  return versions.reduce((max, v) => (compareSemver(v, max) > 0 ? v : max));
}
