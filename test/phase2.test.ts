import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getApproval, loadApprovals, recordApproval } from "../src/approvals.js";
import { diffLockfiles, extractLockfileEntries } from "../src/lockfile.js";
import { recordBuildApproval } from "../src/pnpm-builds.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("approvals cache", () => {
  it("records and retrieves version-specific approvals", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    await recordApproval("some-native-pkg", "2.0.0", "no-scripts", dir);

    const approvals = await loadApprovals(dir);
    expect(getApproval(approvals, "some-native-pkg", "2.0.0")?.mode).toBe("no-scripts");
    expect(getApproval(approvals, "some-native-pkg", "2.0.1")).toBeNull();
  });

  it("returns empty map when no cache exists", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    expect(await loadApprovals(dir)).toEqual({});
  });

  it("keeps existing entries when adding new ones", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    await recordApproval("a", "1.0.0", "normal", dir);
    await recordApproval("b", "2.0.0", "no-scripts", dir);
    const approvals = await loadApprovals(dir);
    expect(Object.keys(approvals)).toEqual(["a@1.0.0", "b@2.0.0"]);
  });
});

describe("pnpm approve-builds integration", () => {
  it("adds approved packages to onlyBuiltDependencies", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    await writeFile(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - '.'\n");

    await recordBuildApproval("esbuild", "approved", dir);
    const content = await readFile(path.join(dir, "pnpm-workspace.yaml"), "utf8");
    expect(content).toContain("onlyBuiltDependencies");
    expect(content).toContain("esbuild");
    expect(content).toContain("packages:"); // existing content preserved
  });

  it("adds ignored packages to ignoredBuiltDependencies", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    await writeFile(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - '.'\n");

    await recordBuildApproval("sketchy-pkg", "ignored", dir);
    const content = await readFile(path.join(dir, "pnpm-workspace.yaml"), "utf8");
    expect(content).toContain("ignoredBuiltDependencies");
    expect(content).toContain("sketchy-pkg");
  });

  it("moves a package between lists instead of duplicating it", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    await writeFile(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - '.'\n");

    await recordBuildApproval("pkg-x", "ignored", dir);
    await recordBuildApproval("pkg-x", "approved", dir);
    const content = await readFile(path.join(dir, "pnpm-workspace.yaml"), "utf8");
    const ignoredSection = content.match(/ignoredBuiltDependencies:[\s\S]*?(?=\w|$)/)?.[0] ?? "";
    expect(ignoredSection).not.toContain("pkg-x");
    expect(content).toContain("onlyBuiltDependencies");
  });

  it("does nothing without pnpm-workspace.yaml unless asked to create it", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-test-"));
    expect(await recordBuildApproval("pkg", "approved", dir)).toBeNull();
    expect(
      await recordBuildApproval("pkg", "approved", dir, { createWorkspaceFile: true }),
    ).not.toBeNull();
  });
});

describe("lockfile diff", () => {
  it("parses npm package-lock entries", () => {
    const lock = JSON.stringify({
      packages: {
        "": { name: "root" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/@scope/pkg": { version: "2.0.0" },
      },
    });
    const entries = extractLockfileEntries("npm", lock);
    expect(entries).toContain("left-pad@1.3.0");
    expect(entries).toContain("@scope/pkg@2.0.0");
  });

  it("parses pnpm lockfile entries", () => {
    const lock = [
      "packages:",
      "",
      "  left-pad@1.3.0:",
      "    resolution: {integrity: sha512-xyz}",
      "",
      "  '@scope/pkg@2.0.0':",
      "    resolution: {integrity: sha512-abc}",
    ].join("\n");
    const entries = extractLockfileEntries("pnpm", lock);
    expect(entries).toContain("left-pad@1.3.0");
  });

  it("parses yarn v1 lockfile entries", () => {
    const lock = [
      'left-pad@^1.3.0:',
      '  version "1.3.0"',
      '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"',
      "",
      '"@scope/pkg@^2.0.0":',
      '  version "2.0.0"',
    ].join("\n");
    const entries = extractLockfileEntries("yarn", lock);
    expect(entries).toContain("left-pad@1.3.0");
    expect(entries).toContain("@scope/pkg@2.0.0");
  });

  it("diffs before/after snapshots", () => {
    const before = JSON.stringify({
      packages: { "node_modules/a": { version: "1.0.0" } },
    });
    const after = JSON.stringify({
      packages: {
        "node_modules/a": { version: "1.0.0" },
        "node_modules/b": { version: "2.0.0" },
        "node_modules/c": { version: "3.0.0" },
      },
    });
    const diff = diffLockfiles("npm", before, after);
    expect(diff.added).toEqual(["b@2.0.0", "c@3.0.0"]);
    expect(diff.removed).toEqual([]);
  });

  it("treats a missing before-snapshot as empty", () => {
    const after = JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0" } } });
    expect(diffLockfiles("npm", null, after).added).toEqual(["a@1.0.0"]);
  });
});
