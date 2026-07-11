import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
    expect(result.status).toBe("blocked");
    expect(result.command).toBeUndefined();
  });

  it("never auto-approves require_approval even with --yes", async () => {
    const result = await gateInstall("require_approval", "pnpm", "some-pkg", {
      assumeYes: true,
    });
    expect(result.status).toBe("skipped");
  });

  it("skips install on dry-run but reports the command", async () => {
    const result = await gateInstall("allow", "pnpm", "left-pad", { dryRun: true });
    expect(result.status).toBe("skipped");
    expect(result.command).toEqual(["pnpm", "add", "left-pad"]);
    expect(result.installed).toBe(false);
  });

  it("a no-scripts approval forces --ignore-scripts on the allow path", async () => {
    // Security analysis finding 8: a package cleared by a "no-scripts"
    // approval must NOT run its lifecycle scripts at install time.
    const result = await gateInstall("allow_with_warnings", "pnpm", "esbuild@0.27.3", {
      dryRun: true,
      ignoreScripts: true,
    });
    expect(result.status).toBe("skipped");
    expect(result.command).toEqual(["pnpm", "add", "esbuild@0.27.3", "--ignore-scripts"]);
  });

  const no = async () => false;
  const boom = async () => {
    throw new Error("prompt should not be called");
  };

  it("dry-run is a pure preview: never prompts, reports the scripts-disabled command", async () => {
    // confirmFn throws to prove --dry-run does NOT run the approval flow.
    const result = await gateInstall("require_approval", "pnpm", "some-pkg", {
      dryRun: true,
      confirmFn: boom,
    });
    expect(result.status).toBe("skipped");
    expect(result.command).toEqual(["pnpm", "add", "some-pkg", "--ignore-scripts"]);
    expect(result.installed).toBe(false);
  });

  it("dry-run previews a SOFT block without prompting or installing", async () => {
    const result = await gateInstall("block", "pnpm", "esbuild", {
      dryRun: true,
      overridable: true,
      confirmFn: boom,
    });
    expect(result.status).toBe("skipped");
    expect(result.installed).toBe(false);
  });

  it("declining every approval prompt installs nothing", async () => {
    // Interactive (not dry-run): both prompts declined → nothing runs.
    const result = await gateInstall("require_approval", "pnpm", "some-pkg", {
      confirmFn: no,
    });
    expect(result.status).toBe("skipped");
    expect(result.installed).toBe(false);
  });

  it("a HARD block is never installable or approvable", async () => {
    const result = await gateInstall("block", "pnpm", "evil", {
      overridable: false,
      confirmFn: boom,
    });
    expect(result.status).toBe("blocked");
    expect(result.installed).toBe(false);
  });

  it("fails when the installed lockfile differs from the reviewed plan", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-plan-verify-"));
    const lock = path.join(dir, "package-lock.json");
    const script = path.join(dir, "mutate-lock.mjs");
    await writeFile(
      script,
      'import { writeFileSync } from "node:fs"; writeFileSync(process.argv[2], "changed");',
    );

    const result = await gateInstall("allow", "npm", "example@1.0.0", {
      assumeYes: true,
      commands: {
        normal: [process.execPath, script, lock],
        noScripts: [process.execPath, script, lock],
      },
      beforeInstall: async () => writeFile(lock, "reviewed"),
      verifyInstall: async () => (await readFile(lock, "utf8")) === "reviewed",
    });

    expect(result).toMatchObject({
      status: "failed",
      exitCode: 1,
      installed: false,
      reason: "Installed lockfile does not match the reviewed plan.",
    });
  });
});
