import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  applyInstallPlan,
  buildPlanResolveCommand,
  contentFingerprint,
  resolveInstallPlan,
  verifyInstallPlan,
} from "../src/install-plan.js";
import { lockfileName } from "../src/lockfile.js";
import type { PackageManager } from "../src/types.js";

let dir: string;
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("InstallPlan", () => {
  it.each([
    ["npm", "--package-lock-only"],
    ["pnpm", "--lockfile-only"],
    ["yarn", "--non-interactive"],
  ] as const)("uses the real %s resolver", (pm, marker) => {
    const command = buildPlanResolveCommand(pm, {
      name: "root",
      version: "1.0.0",
      spec: "root@1.0.0",
    });
    expect(command[0]).toBe(pm);
    expect(command).toContain(marker);
  });

  // Regression (P2): a spec beginning with "-" would be parsed as a flag by the
  // package manager (argv flag injection).
  it("rejects a package spec that looks like a flag", () => {
    expect(() =>
      buildPlanResolveCommand("npm", { name: "-x", version: "1", spec: "--registry=http://evil" }),
    ).toThrow(/looks like a flag/);
  });

  it.each(["npm", "pnpm", "yarn"] as const)(
    "captures and applies a staged %s lockfile without a second resolution",
    async (pm: PackageManager) => {
      dir = await mkdtemp(path.join(tmpdir(), "targate-plan-test-"));
      await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
      const plannedLock = pm === "npm"
        ? JSON.stringify({ packages: { "node_modules/dep": { version: "2.0.0" } } })
        : pm === "pnpm"
          ? "packages:\n  dep@2.0.0:\n"
          : 'dep@^2.0.0:\n  version "2.0.0"\n';
      const run = vi.fn(async (command: string[], cwd: string) => {
        await writeFile(path.join(cwd, "package.json"), JSON.stringify({ name: "fixture", dependencies: { root: "1.0.0" } }));
        await writeFile(path.join(cwd, lockfileName(pm)), plannedLock);
        expect(command[0]).toBe(pm);
      });
      const plan = await resolveInstallPlan({
        packageManager: pm,
        cwd: dir,
        root: { name: "root", version: "1.0.0", spec: "root@1.0.0" },
        run,
      });

      expect(plan.fingerprint).toBe(contentFingerprint(plannedLock));
      expect(plan.packages).toEqual([{ name: "dep", version: "2.0.0" }]);
      await applyInstallPlan(plan, dir);
      expect(await readFile(path.join(dir, lockfileName(pm)), "utf8")).toBe(plannedLock);
      expect(await verifyInstallPlan(plan, dir)).toBe(true);
      expect(run).toHaveBeenCalledTimes(1);
    },
  );

  it("detects lockfile drift after review", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-plan-drift-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    await writeFile(path.join(dir, "package-lock.json"), JSON.stringify({ packages: {} }));
    const plan = await resolveInstallPlan({ packageManager: "npm", cwd: dir });
    await writeFile(path.join(dir, "package-lock.json"), JSON.stringify({ packages: { changed: {} } }));
    expect(await verifyInstallPlan(plan, dir)).toBe(false);
  });

  it("requires explicit --update-lockfile intent when a project has no lockfile", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-plan-no-lock-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    await expect(resolveInstallPlan({ packageManager: "npm", cwd: dir })).rejects.toThrow(
      "--update-lockfile",
    );
  });

  it("refuses to overwrite manifest or lockfile changes made during review", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-plan-input-drift-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    const run = async (_command: string[], cwd: string) => {
      await writeFile(path.join(cwd, "package.json"), JSON.stringify({ name: "fixture", dependencies: { root: "1.0.0" } }));
      await writeFile(path.join(cwd, "package-lock.json"), JSON.stringify({ packages: {} }));
    };
    const plan = await resolveInstallPlan({
      packageManager: "npm",
      cwd: dir,
      root: { name: "root", version: "1.0.0", spec: "root@1.0.0" },
      run,
    });
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "user-change" }));
    await expect(applyInstallPlan(plan, dir)).rejects.toThrow("changed after review");
  });
});
