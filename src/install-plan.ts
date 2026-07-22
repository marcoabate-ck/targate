import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { extractLockfileArtifacts, lockfileName } from "./lockfile.js";
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
  /** Fingerprint of the canonical name/version/URL/integrity artifact list. */
  artifactFingerprint: string;
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
  for (const artifact of extractLockfileArtifacts(pm, content)) {
    const pkg: TreePackage = { ...artifact };
    if (root && pkg.name === root.name && pkg.version === root.version) continue;
    packages.push(pkg);
  }
  return packages.sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
}

function artifactFingerprint(packages: TreePackage[]): string {
  return contentFingerprint(
    JSON.stringify(
      packages.map(({ name, version, resolved, integrity }) => ({
        name,
        version,
        resolved: resolved ?? null,
        integrity: integrity ?? null,
      })),
    ),
  );
}

function planFingerprint(lockfileContent: string): string {
  // Artifact URLs and integrity values are bytes inside the lockfile; the
  // separate artifactFingerprint makes that binding explicit and inspectable.
  return contentFingerprint(lockfileContent);
}

export function buildPlanResolveCommand(
  pm: PackageManager,
  root?: PlanPackageSpec,
): string[] {
  const spec = root?.spec;
  // A spec beginning with "-" would be parsed as an option by the package
  // manager (argv flag injection). Valid npm specs never start with a dash.
  if (spec && spec.startsWith("-")) {
    throw new Error(`Refusing package spec that looks like a flag: ${spec}`);
  }
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
  // Only bare command names (npm/pnpm/yarn) get the Windows `.cmd` shim suffix;
  // an absolute path or a name with an extension (e.g. node.exe) spawns as-is.
  const isBareName = !rawBin.includes("/") && !rawBin.includes("\\") && !path.extname(rawBin);
  const winShim = process.platform === "win32" && isBareName;
  const bin = winShim ? `${rawBin}.cmd` : rawBin;
  // shell:true is required to exec a `.cmd` on Node >=18.20.2 (CVE-2024-27980),
  // else EINVAL. Specs are dash-guarded; args carry no shell metacharacters.
  await execFileAsync(bin, args, { cwd, timeout: RESOLVE_TIMEOUT_MS, shell: winShim });
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
    const packages = packagesFromLockfile(opts.packageManager, existingLock);
    return {
      packageManager: opts.packageManager,
      manifestContent,
      lockfileContent: existingLock,
      packages,
      artifactFingerprint: artifactFingerprint(packages),
      fingerprint: planFingerprint(existingLock),
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
    const packages = packagesFromLockfile(opts.packageManager, lockfileContent, opts.root);
    return {
      packageManager: opts.packageManager,
      root: opts.root,
      manifestContent: plannedManifest,
      lockfileContent,
      packages,
      artifactFingerprint: artifactFingerprint(packages),
      fingerprint: planFingerprint(lockfileContent),
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
  if (!existsSync(lockPath)) return false;
  const currentLock = await readFile(lockPath, "utf8");
  const currentPackages = packagesFromLockfile(plan.packageManager, currentLock, plan.root);
  return (
    planFingerprint(currentLock) === plan.fingerprint &&
    artifactFingerprint(currentPackages) === plan.artifactFingerprint &&
    (await currentFingerprint(manifestPath)) === expectedManifest
  );
}
