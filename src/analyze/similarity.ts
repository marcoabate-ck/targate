import type { NameSimilarity } from "../types.js";

/**
 * Popular packages a typosquatter would plausibly imitate. Curated for the
 * React Native ecosystem plus high-download npm staples.
 */
export const POPULAR_PACKAGES = [
  "react",
  "react-dom",
  "react-native",
  "react-native-mmkv",
  "react-native-keychain",
  "react-native-reanimated",
  "react-native-gesture-handler",
  "react-native-screens",
  "react-native-safe-area-context",
  "react-native-svg",
  "react-native-video",
  "react-native-webview",
  "react-native-config",
  "react-native-device-info",
  "react-native-permissions",
  "react-native-vector-icons",
  "react-native-fast-image",
  "expo",
  "expo-secure-store",
  "expo-constants",
  "expo-camera",
  "axios",
  "lodash",
  "moment",
  "dayjs",
  "zustand",
  "redux",
  "react-redux",
  "typescript",
  "jest",
  "eslint",
  "prettier",
  "chalk",
  "commander",
  "express",
  "dotenv",
  "uuid",
  "zod",
];

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Common affixes typosquatters bolt onto a popular name (`reactjs`, `js-lodash`).
 * Deliberately NARROW: generic affixes like `-cli`, `-official`, or `2` were
 * dropped because they match legitimate official packages (`expo-cli`,
 * `react-native-cli`) — a false positive there escalates a real install to
 * require_approval.
 */
const SQUAT_AFFIXES = ["js", "-js", ".js", "-npm", "npm-"];

/**
 * Check whether a package name is suspiciously close to a popular package.
 * An exact match is fine (it IS the popular package); distance 1-2 on a
 * sufficiently long name — or a popular name wrapped in a common affix — is a
 * typosquatting signal.
 */
export function checkNameSimilarity(
  name: string,
  candidates: string[] = POPULAR_PACKAGES,
): NameSimilarity | null {
  if (candidates.includes(name)) return null;

  let best: NameSimilarity | null = null;
  for (const candidate of candidates) {
    // Skip trivially short names where small distances are meaningless
    if (candidate.length < 4) continue;
    const distance = levenshtein(name, candidate);
    const threshold = candidate.length >= 10 ? 2 : 1;
    // A flat distance cap misses the classic short-name suffix squat
    // (`reactjs` vs `react`, `lodashjs` vs `lodash` — distance 2 on a name
    // under 10 chars). Treat a popular name wrapped in a common affix as a
    // hit regardless of length.
    const isAffixSquat = SQUAT_AFFIXES.some(
      (affix) => name === `${candidate}${affix}` || name === `${affix}${candidate}`,
    );
    if (
      (distance <= threshold || isAffixSquat) &&
      (best === null || distance < best.distance)
    ) {
      best = { similarTo: candidate, distance };
    }
  }
  return best;
}
