import { describe, expect, it } from "vitest";
import { parsePackageSpec } from "../src/registry.js";

describe("parsePackageSpec", () => {
  it("parses a bare name", () => {
    expect(parsePackageSpec("left-pad")).toEqual({ name: "left-pad" });
  });

  it("parses name@version", () => {
    expect(parsePackageSpec("left-pad@1.3.0")).toEqual({
      name: "left-pad",
      version: "1.3.0",
    });
  });

  it("parses scoped packages", () => {
    expect(parsePackageSpec("@react-native/metro-config")).toEqual({
      name: "@react-native/metro-config",
    });
  });

  it("parses scoped packages with a version", () => {
    expect(parsePackageSpec("@react-native/metro-config@0.75.0")).toEqual({
      name: "@react-native/metro-config",
      version: "0.75.0",
    });
  });
});
