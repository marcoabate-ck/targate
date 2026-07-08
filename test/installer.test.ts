import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildInstallCommand, detectPackageManager, gateInstall } from "../src/installer.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("detectPackageManager", () => {
  it("detects pnpm from pnpm-lock.yaml", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "pnpm-lock.yaml"), "");
    expect(detectPackageManager(dir)).toBe("pnpm");
  });

  it("detects yarn from yarn.lock", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "yarn.lock"), "");
    expect(detectPackageManager(dir)).toBe("yarn");
  });

  it("detects npm from package-lock.json", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "package-lock.json"), "{}");
    expect(detectPackageManager(dir)).toBe("npm");
  });

  it("defaults to pnpm when no lockfile exists", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    expect(detectPackageManager(dir)).toBe("pnpm");
  });
});

describe("buildInstallCommand", () => {
  it("builds normal and ignore-scripts variants", () => {
    expect(buildInstallCommand("pnpm", "left-pad@1.3.0")).toEqual([
      "pnpm",
      "add",
      "left-pad@1.3.0",
    ]);
    expect(
      buildInstallCommand("npm", "left-pad", { ignoreScripts: true }),
    ).toEqual(["npm", "install", "left-pad", "--ignore-scripts"]);
  });
});

describe("gateInstall", () => {
  it("never installs blocked packages", async () => {
    const result = await gateInstall("block", "pnpm", "evil-pkg", { assumeYes: true });
    expect(result.mode).toBe("blocked");
    expect(result.command).toBeUndefined();
  });

  it("never auto-approves require_approval even with --yes", async () => {
    const result = await gateInstall("require_approval", "pnpm", "some-pkg", {
      assumeYes: true,
    });
    expect(result.mode).toBe("skipped");
  });

  it("skips install on dry-run but reports the command", async () => {
    const result = await gateInstall("allow", "pnpm", "left-pad", { dryRun: true });
    expect(result.mode).toBe("skipped");
    expect(result.command).toEqual(["pnpm", "add", "left-pad"]);
    expect(result.installed).toBe(false);
  });

  const yes = async () => true;
  const no = async () => false;

  it("dry-run still runs the approval flow and records the decision WITHOUT installing", async () => {
    // Approve without scripts under --dry-run: mode is recorded, nothing is installed.
    const noScripts = await gateInstall("require_approval", "pnpm", "some-pkg", {
      dryRun: true,
      confirmFn: yes,
    });
    expect(noScripts.mode).toBe("no-scripts");
    expect(noScripts.installed).toBe(false);
  });

  it("dry-run approves a SOFT block including scripts without installing", async () => {
    // First prompt (no-scripts) declined, second (full) accepted.
    let call = 0;
    const full = await gateInstall("block", "pnpm", "esbuild", {
      dryRun: true,
      overridable: true,
      confirmFn: async () => ++call === 2,
    });
    expect(full.mode).toBe("normal");
    expect(full.installed).toBe(false);
  });

  it("declining the approval installs nothing", async () => {
    const result = await gateInstall("require_approval", "pnpm", "some-pkg", {
      dryRun: true,
      confirmFn: no,
    });
    expect(result.mode).toBe("skipped");
    expect(result.installed).toBe(false);
  });

  it("a HARD block is never approvable, even in dry-run", async () => {
    const result = await gateInstall("block", "pnpm", "evil", {
      dryRun: true,
      overridable: false,
      confirmFn: yes,
    });
    expect(result.mode).toBe("blocked");
    expect(result.installed).toBe(false);
  });
});
