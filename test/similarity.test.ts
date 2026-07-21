import { describe, expect, it } from "vitest";
import { checkNameSimilarity, levenshtein } from "../src/analyze/similarity.js";

describe("levenshtein", () => {
  it("computes edit distance", () => {
    expect(levenshtein("abc", "abc")).toBe(0);
    expect(levenshtein("abc", "abd")).toBe(1);
    expect(levenshtein("abc", "")).toBe(3);
    expect(levenshtein("react-native-mmkv", "react-native-mkkv")).toBe(1);
  });
});

describe("checkNameSimilarity", () => {
  it("returns null for the popular package itself", () => {
    expect(checkNameSimilarity("react-native-mmkv")).toBeNull();
    expect(checkNameSimilarity("axios")).toBeNull();
  });

  it("flags 1-2 edit typos of popular packages", () => {
    expect(checkNameSimilarity("react-native-mmkvv")?.similarTo).toBe(
      "react-native-mmkv",
    );
    expect(checkNameSimilarity("react-native-mkkv")?.similarTo).toBe(
      "react-native-mmkv",
    );
  });

  it("does not flag clearly different names", () => {
    expect(checkNameSimilarity("my-totally-original-package")).toBeNull();
  });

  it("uses a tighter threshold for short names", () => {
    // distance 1 from "axios" (5 chars) should flag
    expect(checkNameSimilarity("axio5")?.similarTo).toBe("axios");
    // distance 2 from a short name should NOT flag
    expect(checkNameSimilarity("axi5o")).toBeNull();
  });

  // Regression (P1.5): the flat distance-1 cap for short names missed the
  // classic common-suffix squat (distance 2 on a <10-char name).
  it("flags common-affix squats of short popular names", () => {
    expect(checkNameSimilarity("reactjs")?.similarTo).toBe("react");
    expect(checkNameSimilarity("axios-js")?.similarTo).toBe("axios");
  });
});
