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

  it("extracts registry reputation from the full packument", async () => {
    stubRegistry({
      "dist-tags": { latest: "2.0.0" },
      versions: {
        "1.0.0": {
          name: "pkg",
          dist: { tarball: "https://reg/pkg-1.0.0.tgz" },
          maintainers: [{ name: "alice" }],
        },
        "2.0.0": {
          name: "pkg",
          dist: {
            tarball: "https://reg/pkg-2.0.0.tgz",
            attestations: { url: "https://registry.npmjs.org/-/npm/v1/attestations/pkg@2.0.0" },
          },
          deprecated: "use pkg-next instead",
          maintainers: [{ name: "alice" }, { name: "bob" }],
          _npmUser: { name: "bob" },
          repository: { url: "git+https://github.com/o/pkg.git" },
        },
      },
      time: {
        created: "2020-01-01T00:00:00Z",
        modified: "2024-06-02T00:00:00Z",
        "1.0.0": "2020-01-01T00:00:00Z",
        "2.0.0": "2024-06-01T00:00:00Z",
      },
    });
    const metadata = await fetchPackageMetadata("pkg", "2.0.0");
    expect(metadata.registryReputation).toEqual({
      previousVersion: "1.0.0",
      previousVersionPublishDate: "2020-01-01T00:00:00Z",
      deprecated: "use pkg-next instead",
      hasProvenance: true,
      versionMaintainers: ["alice", "bob"],
      previousVersionMaintainers: ["alice"],
      publisher: "bob",
      latestRepositoryUrl: "git+https://github.com/o/pkg.git",
      latestVersion: "2.0.0",
      latestVersionPublishDate: "2024-06-01T00:00:00Z",
      latestHasProvenance: true,
    });
  });

  it("extracts size, file count and dependency ranges from the manifest", async () => {
    stubRegistry({
      "dist-tags": { latest: "1.0.0" },
      versions: {
        "1.0.0": {
          name: "pkg",
          dist: { tarball: "https://reg/pkg-1.0.0.tgz", unpackedSize: 12345, fileCount: 7 },
          dependencies: { lodash: "^4.17.21", helper: "git+https://github.com/x/helper.git" },
        },
      },
      time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
    });
    const metadata = await fetchPackageMetadata("pkg");
    expect(metadata.unpackedSize).toBe(12345);
    expect(metadata.fileCount).toBe(7);
    expect(metadata.dependencyRanges).toEqual({
      lodash: "^4.17.21",
      helper: "git+https://github.com/x/helper.git",
    });
  });

  it("handles a first release (no previous version) and absent optional fields", async () => {
    stubRegistry({
      "dist-tags": { latest: "1.0.0" },
      versions: { "1.0.0": { name: "pkg", dist: { tarball: "https://reg/pkg-1.0.0.tgz" } } },
      time: { created: "2026-01-01T00:00:00Z", "1.0.0": "2026-01-01T00:00:00Z" },
    });
    const metadata = await fetchPackageMetadata("pkg");
    expect(metadata.registryReputation.previousVersion).toBeUndefined();
    expect(metadata.registryReputation.previousVersionPublishDate).toBeUndefined();
    expect(metadata.registryReputation.deprecated).toBeUndefined();
    expect(metadata.registryReputation.hasProvenance).toBe(false);
    expect(metadata.registryReputation.publisher).toBeUndefined();
  });
});
