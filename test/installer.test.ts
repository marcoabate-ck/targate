import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildInstallCommand,
  cacheCleanCommand,
  detectInstallClient,
  detectPackageManager,
  gateInstall,
  lockfilePortableBehindProxy,
} from "../src/installer.js";

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

describe("detectInstallClient", () => {
  it("detects bun from bun.lockb or bun.lock", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "bun.lockb"), "");
    expect(detectInstallClient(dir)).toBe("bun");
    await rm(path.join(dir, "bun.lockb"));
    await writeFile(path.join(dir, "bun.lock"), "");
    expect(detectInstallClient(dir)).toBe("bun");
  });

  it("treats a bare yarn.lock as yarn-classic", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "yarn.lock"), "");
    expect(detectInstallClient(dir)).toBe("yarn-classic");
  });

  it("detects yarn-berry via .yarnrc.yml", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "yarn.lock"), "");
    await writeFile(path.join(dir, ".yarnrc.yml"), "nodeLinker: node-modules\n");
    expect(detectInstallClient(dir)).toBe("yarn-berry");
  });

  it("detects yarn-berry via packageManager yarn@>=2", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "yarn.lock"), "");
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ packageManager: "yarn@4.1.0" }));
    expect(detectInstallClient(dir)).toBe("yarn-berry");
    // yarn@1.x stays classic
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ packageManager: "yarn@1.22.22" }));
    expect(detectInstallClient(dir)).toBe("yarn-classic");
  });

  it("detects pnpm and npm, defaults to pnpm", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "pnpm-lock.yaml"), "");
    expect(detectInstallClient(dir)).toBe("pnpm");
    await rm(path.join(dir, "pnpm-lock.yaml"));
    await writeFile(path.join(dir, "package-lock.json"), "{}");
    expect(detectInstallClient(dir)).toBe("npm");
    await rm(path.join(dir, "package-lock.json"));
    expect(detectInstallClient(dir)).toBe("pnpm");
  });
});

describe("lockfilePortableBehindProxy", () => {
  it("is true for npm/pnpm/yarn-berry, false for yarn-classic/bun", () => {
    expect(lockfilePortableBehindProxy("npm")).toBe(true);
    expect(lockfilePortableBehindProxy("pnpm")).toBe(true);
    expect(lockfilePortableBehindProxy("yarn-berry")).toBe(true);
    expect(lockfilePortableBehindProxy("yarn-classic")).toBe(false);
    expect(lockfilePortableBehindProxy("bun")).toBe(false);
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

describe("cacheCleanCommand", () => {
  it("maps each package manager to its cache-clearing command", () => {
    expect(cacheCleanCommand("npm")).toBe("npm cache clean --force");
    expect(cacheCleanCommand("yarn")).toBe("yarn cache clean");
    expect(cacheCleanCommand("pnpm")).toBe("pnpm store prune");
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
