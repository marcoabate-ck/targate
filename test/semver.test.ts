import { describe, expect, it } from "vitest";
import { compareSemver, highestSemver } from "../src/semver.js";

describe("compareSemver", () => {
  it("orders numerically, not lexicographically", () => {
    expect(compareSemver("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareSemver("1.9.0", "1.10.0")).toBeLessThan(0);
    expect(compareSemver("10.0.0", "9.99.99")).toBeGreaterThan(0);
  });

  it("treats equal versions as equal", () => {
    expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
  });

  it("sorts a prerelease before its release", () => {
    expect(compareSemver("1.2.0-rc.1", "1.2.0")).toBeLessThan(0);
    expect(compareSemver("1.2.0", "1.2.0-rc.1")).toBeGreaterThan(0);
  });
});

describe("highestSemver", () => {
  it("picks the semver-highest version", () => {
    expect(highestSemver(["1.9.0", "1.10.0", "1.2.3"])).toBe("1.10.0");
  });

  it("prefers the release over its prerelease", () => {
    expect(highestSemver(["2.0.0-beta.1", "2.0.0", "1.9.9"])).toBe("2.0.0");
  });

  it("returns undefined for an empty list", () => {
    expect(highestSemver([])).toBeUndefined();
  });
});
