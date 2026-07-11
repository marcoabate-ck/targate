import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { extractLockfileEntries, lockfileName } from "./lockfile.js";
import type { TreePackage } from "./transitive.js";
import type { PackageManager } from "./types.js";

const execFileAsync = promisify(execFile);
const RESOLVE_TIMEOUT_MS = 180_000;

export interface PlanPackageSpec {
  name: string;
  version: string;
  spec: string;
}

export interface InstallPlan {
  packageManager: PackageManager;
  root?: PlanPackageSpec;
  manifestContent: string;
  lockfileContent: string;
  packages: TreePackage[];
  fingerprint: string;
  source: "existing" | "resolved";
  baseManifestFingerprint: string;
  baseLockfileFingerprint?: string;
}

export interface ResolveInstallPlanOptions {
  packageManager: PackageManager;
  cwd?: string;
  root?: PlanPackageSpec;
  /** Re-resolve an existing project lockfile instead of reviewing it as-is. */
  updateLockfile?: boolean;
  /** Test seam. The callback must produce the staged package manifest + lockfile. */
  run?: (command: string[], cwd: string) => Promise<void>;
}

export function contentFingerprint(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export function packagesFromLockfile(
  pm: PackageManager,
  content: string,
  root?: PlanPackageSpec,
): TreePackage[] {
  const packages: TreePackage[] = [];
  for (const entry of extractLockfileEntries(pm, content)) {
    const at = entry.lastIndexOf("@");
    if (at <= 0) continue;
    const pkg = { name: entry.slice(0, at), version: entry.slice(at + 1) };
    if (root && pkg.name === root.name && pkg.version === root.version) continue;
    packages.push(pkg);
  }
  return packages.sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
}

export function buildPlanResolveCommand(
  pm: PackageManager,
  root?: PlanPackageSpec,
): string[] {
  const spec = root?.spec;
  switch (pm) {
    case "npm":
      return [
        "npm",
        "install",
        ...(spec ? [spec] : []),
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--loglevel=error",
      ];
    case "pnpm":
      return [
        "pnpm",
        root ? "add" : "install",
        ...(spec ? [spec] : []),
        "--lockfile-only",
        "--ignore-scripts",
      ];
    case "yarn":
      return [
        "yarn",
        root ? "add" : "install",
        ...(spec ? [spec] : []),
        "--ignore-scripts",
        "--non-interactive",
      ];
  }
}

async function runResolver(command: string[], cwd: string): Promise<void> {
  const [rawBin, ...args] = command;
  const bin = process.platform === "win32" ? `${rawBin}.cmd` : rawBin;
  await execFileAsync(bin, args, { cwd, timeout: RESOLVE_TIMEOUT_MS });
}

async function copyResolutionConfig(cwd: string, staged: string): Promise<void> {
  for (const name of [".npmrc", ".yarnrc", ".yarnrc.yml"]) {
    const source = path.join(cwd, name);
    if (existsSync(source)) await copyFile(source, path.join(staged, name));
  }
}

export async function resolveInstallPlan(
  opts: ResolveInstallPlanOptions,
): Promise<InstallPlan> {
  const cwd = opts.cwd ?? process.cwd();
  const manifestPath = path.join(cwd, "package.json");
  if (!existsSync(manifestPath)) throw new Error(`No package.json found in ${cwd}`);

  const manifestContent = await readFile(manifestPath, "utf8");
  const lockPath = path.join(cwd, lockfileName(opts.packageManager));
  const existingLock = existsSync(lockPath) ? await readFile(lockPath, "utf8") : null;
  const baseManifestFingerprint = contentFingerprint(manifestContent);
  const baseLockfileFingerprint = existingLock ? contentFingerprint(existingLock) : undefined;

  if (!opts.root && existingLock && !opts.updateLockfile) {
    return {
      packageManager: opts.packageManager,
      manifestContent,
      lockfileContent: existingLock,
      packages: packagesFromLockfile(opts.packageManager, existingLock),
      fingerprint: contentFingerprint(existingLock),
      source: "existing",
      baseManifestFingerprint,
      baseLockfileFingerprint,
    };
  }
  if (!opts.root && !existingLock && !opts.updateLockfile) {
    throw new Error(
      `No ${lockfileName(opts.packageManager)} found. Re-run with --update-lockfile to create and review one.`,
    );
  }

  const staged = await mkdtemp(path.join(tmpdir(), "targate-plan-"));
  try {
    await writeFile(path.join(staged, "package.json"), manifestContent);
    if (existingLock) await writeFile(path.join(staged, lockfileName(opts.packageManager)), existingLock);
    await copyResolutionConfig(cwd, staged);
    const command = buildPlanResolveCommand(opts.packageManager, opts.root);
    try {
      await (opts.run ?? runResolver)(command, staged);
    } catch (err) {
      throw new Error(
        `${opts.packageManager} could not produce the staged install plan: ${
          err instanceof Error ? err.message.split("\n")[0] : String(err)
        }`,
      );
    }

    const stagedLockPath = path.join(staged, lockfileName(opts.packageManager));
    if (!existsSync(stagedLockPath)) {
      throw new Error(`${opts.packageManager} did not produce ${lockfileName(opts.packageManager)}`);
    }
    const plannedManifest = await readFile(path.join(staged, "package.json"), "utf8");
    const lockfileContent = await readFile(stagedLockPath, "utf8");
    return {
      packageManager: opts.packageManager,
      root: opts.root,
      manifestContent: plannedManifest,
      lockfileContent,
      packages: packagesFromLockfile(opts.packageManager, lockfileContent, opts.root),
      fingerprint: contentFingerprint(lockfileContent),
      source: "resolved",
      baseManifestFingerprint,
      baseLockfileFingerprint,
    };
  } finally {
    await rm(staged, { recursive: true, force: true });
  }
}

async function currentFingerprint(file: string): Promise<string | undefined> {
  if (!existsSync(file)) return undefined;
  return contentFingerprint(await readFile(file, "utf8"));
}

/** Apply a reviewed staged manifest + lockfile only if the project did not drift. */
export async function applyInstallPlan(
  plan: InstallPlan,
  cwd: string = process.cwd(),
): Promise<void> {
  const manifestPath = path.join(cwd, "package.json");
  const lockPath = path.join(cwd, lockfileName(plan.packageManager));
  const manifestNow = await currentFingerprint(manifestPath);
  const lockNow = await currentFingerprint(lockPath);
  if (manifestNow !== plan.baseManifestFingerprint || lockNow !== plan.baseLockfileFingerprint) {
    throw new Error("Project manifest or lockfile changed after review; generate a new install plan.");
  }
  await writeFile(manifestPath, plan.manifestContent);
  await writeFile(lockPath, plan.lockfileContent);
}

/** Verify that the installed lockfile is byte-for-byte the one that was reviewed. */
export async function verifyInstallPlan(
  plan: InstallPlan,
  cwd: string = process.cwd(),
): Promise<boolean> {
  const lockPath = path.join(cwd, lockfileName(plan.packageManager));
  const manifestPath = path.join(cwd, "package.json");
  const expectedManifest = plan.source === "existing"
    ? plan.baseManifestFingerprint
    : contentFingerprint(plan.manifestContent);
  return (
    (await currentFingerprint(lockPath)) === plan.fingerprint &&
    (await currentFingerprint(manifestPath)) === expectedManifest
  );
}
