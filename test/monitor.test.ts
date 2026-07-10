import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  alwaysOnFindings,
  baselinePath,
  diffSnapshots,
  readBaseline,
  writeBaseline,
  type MonitorSnapshot,
} from "../src/monitor.js";

function snap(overrides: Partial<MonitorSnapshot> = {}): MonitorSnapshot {
  return {
    name: "widget",
    version: "1.0.0",
    knownMalicious: false,
    maliciousIds: [],
    advisoryIds: [],
    osvUnavailable: false,
    deprecated: false,
    hasProvenance: false,
    maintainers: ["alice"],
    repositoryUrl: "https://github.com/x/widget",
    latestVersion: "1.0.0",
    latestVersionPublishDate: "2024-01-01T00:00:00Z",
    latestHasProvenance: false,
    downloadsStatus: "ok",
    weeklyDownloads: 1000,
    downloadsTrend: "stable",
    repoStatus: "ok",
    repoArchived: false,
    capturedAt: "2026-07-10T00:00:00Z",
    ...overrides,
  };
}

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "targate-monitor-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("alwaysOnFindings", () => {
  it("fires known-malicious as critical, deprecated/archived/gone as warn", () => {
    expect(alwaysOnFindings(snap({ knownMalicious: true, maliciousIds: ["MAL-1"] }))[0]).toMatchObject({
      kind: "known-malicious",
      severity: "critical",
    });
    expect(alwaysOnFindings(snap({ deprecated: "use x" }))[0].kind).toBe("deprecated");
    expect(alwaysOnFindings(snap({ repoStatus: "ok", repoArchived: true }))[0].kind).toBe("repo-archived");
    expect(alwaysOnFindings(snap({ repoStatus: "not-found" }))[0].kind).toBe("repo-gone");
  });

  it("emits nothing for a clean snapshot", () => {
    expect(alwaysOnFindings(snap())).toEqual([]);
  });

  it("escalates OSV-unavailable to warn only under failOnOsvError", () => {
    expect(alwaysOnFindings(snap({ osvUnavailable: true }))[0].severity).toBe("info");
    expect(alwaysOnFindings(snap({ osvUnavailable: true }), true)[0].severity).toBe("warn");
  });
});

describe("diffSnapshots", () => {
  it("detects a new advisory", () => {
    const e = diffSnapshots(snap(), snap({ advisoryIds: ["GHSA-new"] }));
    expect(e.find((x) => x.kind === "new-advisory")).toBeDefined();
  });

  it("detects maintainer additions and removals", () => {
    const e = diffSnapshots(snap({ maintainers: ["alice"] }), snap({ maintainers: ["alice", "mallory"] }));
    expect(e.find((x) => x.kind === "maintainer-added")?.detail).toContain("mallory");
    const e2 = diffSnapshots(snap({ maintainers: ["alice", "bob"] }), snap({ maintainers: ["alice"] }));
    expect(e2.find((x) => x.kind === "maintainer-removed")?.detail).toContain("bob");
  });

  it("flags a repository change and provenance removal", () => {
    const e = diffSnapshots(
      snap({ repositoryUrl: "https://github.com/x/widget", latestHasProvenance: true }),
      snap({ repositoryUrl: "https://github.com/evil/widget", latestHasProvenance: false }),
    );
    expect(e.find((x) => x.kind === "repository-changed")).toBeDefined();
    expect(e.find((x) => x.kind === "provenance-removed")).toBeDefined();
  });

  it("distinguishes a normal new version from a suspicious one", () => {
    const normal = diffSnapshots(
      snap({ latestVersion: "1.0.0", latestVersionPublishDate: "2024-01-01T00:00:00Z" }),
      snap({ latestVersion: "1.1.0", latestVersionPublishDate: "2024-02-01T00:00:00Z" }),
    );
    expect(normal.find((x) => x.kind === "new-version")).toBeDefined();

    const notGreater = diffSnapshots(
      snap({ latestVersion: "2.0.0" }),
      snap({ latestVersion: "1.9.9" }),
    );
    expect(notGreater.find((x) => x.kind === "suspicious-new-version")).toBeDefined();

    const afterDormancy = diffSnapshots(
      snap({ latestVersion: "1.0.0", latestVersionPublishDate: "2020-01-01T00:00:00Z" }),
      snap({ latestVersion: "1.1.0", latestVersionPublishDate: "2024-01-01T00:00:00Z" }),
    );
    expect(afterDormancy.find((x) => x.kind === "suspicious-new-version")).toBeDefined();
  });

  it("flags a download drop as warn, a spike as info", () => {
    expect(
      diffSnapshots(snap({ downloadsTrend: "stable" }), snap({ downloadsTrend: "drop" })).find((x) => x.kind === "download-drop")?.severity,
    ).toBe("warn");
    expect(
      diffSnapshots(snap({ downloadsTrend: "stable" }), snap({ downloadsTrend: "spike" })).find((x) => x.kind === "download-spike")?.severity,
    ).toBe("info");
  });
});

describe("baseline IO", () => {
  it("round-trips a baseline atomically (no .tmp left behind)", async () => {
    await writeBaseline([snap()], dir);
    const b = await readBaseline(dir);
    expect(b?.schemaVersion).toBe(1);
    expect(b?.snapshots["widget@1.0.0"].name).toBe("widget");
    const files = (await import("node:fs/promises")).readdir(path.join(dir, ".targate"));
    expect(await files).toEqual(["monitor-baseline.json"]);
  });

  it("returns null for a missing or wrong-schema baseline (caller rebuilds)", async () => {
    expect(await readBaseline(dir)).toBeNull();
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(baselinePath(dir), JSON.stringify({ schemaVersion: 99, snapshots: {} }));
    expect(await readBaseline(dir)).toBeNull();
  });

  it("returns null for corrupt JSON", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(baselinePath(dir), "{not json");
    expect(await readBaseline(dir)).toBeNull();
  });
});
