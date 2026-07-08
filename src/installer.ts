import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";
import type { Decision, PackageManager } from "./types.js";

export function detectPackageManager(cwd: string = process.cwd()): PackageManager {
  if (existsSync(path.join(cwd, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(path.join(cwd, "yarn.lock"))) return "yarn";
  if (existsSync(path.join(cwd, "package-lock.json"))) return "npm";
  return "pnpm";
}

export function buildInstallCommand(
  pm: PackageManager,
  spec: string,
  opts: { ignoreScripts?: boolean } = {},
): string[] {
  switch (pm) {
    case "pnpm":
      return ["pnpm", "add", spec, ...(opts.ignoreScripts ? ["--ignore-scripts"] : [])];
    case "yarn":
      return ["yarn", "add", spec, ...(opts.ignoreScripts ? ["--ignore-scripts"] : [])];
    case "npm":
      return ["npm", "install", spec, ...(opts.ignoreScripts ? ["--ignore-scripts"] : [])];
  }
}

/**
 * Command for a FULL project install (`targate install` — no package spec):
 * restore everything declared in the manifest/lockfile. Scripts are gated by
 * default (--ignore-scripts); --frozen-lockfile maps to each PM's immutable
 * install (npm uses `ci`).
 */
export function buildBootstrapInstallCommand(
  pm: PackageManager,
  opts: { ignoreScripts?: boolean; frozenLockfile?: boolean } = {},
): string[] {
  const scripts = opts.ignoreScripts ? ["--ignore-scripts"] : [];
  switch (pm) {
    case "pnpm":
      return ["pnpm", "install", ...scripts, ...(opts.frozenLockfile ? ["--frozen-lockfile"] : [])];
    case "yarn":
      return ["yarn", "install", ...scripts, ...(opts.frozenLockfile ? ["--frozen-lockfile"] : [])];
    case "npm":
      return ["npm", opts.frozenLockfile ? "ci" : "install", ...scripts];
  }
}

export async function confirm(question: string, defaultYes = false): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const suffix = defaultYes ? "[Y/n]" : "[y/N]";
    const answer = (await rl.question(`${question} ${suffix} `)).trim().toLowerCase();
    if (answer === "") return defaultYes;
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

export function runCommand(command: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const [bin, ...args] = command;
    const child = spawn(bin, args, { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => resolve(code ?? 1));
  });
}

export type InstallMode = "normal" | "no-scripts" | "skipped" | "blocked";

/**
 * Gate the real install behind the decision. A HARD block never installs. A
 * "soft" block (opts.overridable — a heuristic block such as env+network) is
 * treated like require_approval: a human may approve it interactively, but it
 * is never auto-installed with --yes. "require_approval" defaults to
 * scripts-disabled installs.
 */
export async function gateInstall(
  decision: Decision,
  pm: PackageManager,
  spec: string,
  opts: { assumeYes?: boolean; dryRun?: boolean; overridable?: boolean } = {},
): Promise<{ mode: InstallMode; command?: string[] }> {
  const overridableBlock = decision === "block" && opts.overridable === true;
  if (decision === "block" && !overridableBlock) {
    return { mode: "blocked" };
  }

  const normal = buildInstallCommand(pm, spec);
  const noScripts = buildInstallCommand(pm, spec, { ignoreScripts: true });

  if (decision === "require_approval" || overridableBlock) {
    if (opts.dryRun || opts.assumeYes) {
      // Never auto-approve a package that requires human review.
      return { mode: "skipped", command: noScripts };
    }
    const approveNoScripts = await confirm(
      `This package requires manual approval. Install with scripts DISABLED (${noScripts.join(" ")})?`,
    );
    if (approveNoScripts) {
      if (opts.dryRun) return { mode: "skipped", command: noScripts };
      await runCommand(noScripts);
      return { mode: "no-scripts", command: noScripts };
    }
    const approveFull = await confirm(
      `Install normally anyway, INCLUDING lifecycle scripts (${normal.join(" ")})? Only do this if a reviewer approved it.`,
    );
    if (approveFull) {
      await runCommand(normal);
      return { mode: "normal", command: normal };
    }
    return { mode: "skipped" };
  }

  // allow / allow_with_warnings
  if (opts.dryRun) return { mode: "skipped", command: normal };
  const proceed =
    opts.assumeYes ||
    (await confirm(`Proceed with install (${normal.join(" ")})?`, decision === "allow"));
  if (!proceed) return { mode: "skipped" };
  await runCommand(normal);
  return { mode: "normal", command: normal };
}
