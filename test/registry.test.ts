import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchPackageMetadata, parsePackageSpec } from "../src/registry.js";

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

function stubRegistry(doc: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    })),
  );
}

describe("fetchPackageMetadata (stubbed registry)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects a version manifest without a downloadable tarball", async () => {
    stubRegistry({
      "dist-tags": { latest: "1.0.0" },
      versions: { "1.0.0": { name: "broken-pkg" } }, // no dist.tarball
      time: { created: "2020-01-01T00:00:00Z" },
    });
    await expect(fetchPackageMetadata("broken-pkg")).rejects.toThrow(
      /has no downloadable tarball/,
    );
  });

  it("falls back to the semver-highest version when dist-tags.latest is missing", async () => {
    // Keys deliberately ordered so the LAST one is not the newest.
    stubRegistry({
      versions: {
        "1.2.0": { name: "pkg", dist: { tarball: "https://reg/pkg-1.2.0.tgz" } },
        "1.10.0": { name: "pkg", dist: { tarball: "https://reg/pkg-1.10.0.tgz" } },
        "1.9.0": { name: "pkg", dist: { tarball: "https://reg/pkg-1.9.0.tgz" } },
      },
      time: { created: "2020-01-01T00:00:00Z" },
    });
    const metadata = await fetchPackageMetadata("pkg");
    expect(metadata.version).toBe("1.10.0");
    expect(metadata.tarballUrl).toBe("https://reg/pkg-1.10.0.tgz");
  });
});
