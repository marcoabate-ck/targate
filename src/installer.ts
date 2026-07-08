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
 * is never auto-installed with --yes.
 *
 * --dry-run is a pure PREVIEW: it never prompts and never installs — it just
 * reports the recommended command (the scripts-disabled variant for anything
 * that would need approval). To approve a package without installing it, use
 * `targate approve`, not `targate add --dry-run`.
 *
 * The `installed` flag in the result says whether the package manager ran.
 */
export async function gateInstall(
  decision: Decision,
  pm: PackageManager,
  spec: string,
  opts: {
    assumeYes?: boolean;
    dryRun?: boolean;
    overridable?: boolean;
    /** Prompt implementation — injectable for tests; defaults to interactive confirm(). */
    confirmFn?: (question: string, defaultYes?: boolean) => Promise<boolean>;
  } = {},
): Promise<{ mode: InstallMode; command?: string[]; installed: boolean }> {
  const dry = opts.dryRun === true;
  const ask = opts.confirmFn ?? confirm;
  const overridableBlock = decision === "block" && opts.overridable === true;
  if (decision === "block" && !overridableBlock) {
    return { mode: "blocked", installed: false };
  }

  const normal = buildInstallCommand(pm, spec);
  const noScripts = buildInstallCommand(pm, spec, { ignoreScripts: true });

  if (decision === "require_approval" || overridableBlock) {
    // Never auto-approve a package that requires human review (--yes), and in
    // --dry-run just report the recommended (scripts-disabled) command without
    // prompting or installing. Approval itself is a separate action.
    if (opts.assumeYes || dry) {
      return { mode: "skipped", command: noScripts, installed: false };
    }
    const approveNoScripts = await ask(
      `This package needs manual approval. Approve WITHOUT lifecycle scripts (${noScripts.join(" ")})?`,
    );
    if (approveNoScripts) {
      await runCommand(noScripts);
      return { mode: "no-scripts", command: noScripts, installed: true };
    }
    const approveFull = await ask(
      `Approve INCLUDING lifecycle scripts (${normal.join(" ")})? Only do this if you trust the package.`,
    );
    if (approveFull) {
      await runCommand(normal);
      return { mode: "normal", command: normal, installed: true };
    }
    return { mode: "skipped", installed: false };
  }

  // allow / allow_with_warnings — nothing to approve; dry-run just reports.
  if (dry) return { mode: "skipped", command: normal, installed: false };
  const proceed =
    opts.assumeYes ||
    (await ask(`Proceed with install (${normal.join(" ")})?`, decision === "allow"));
  if (!proceed) return { mode: "skipped", installed: false };
  await runCommand(normal);
  return { mode: "normal", command: normal, installed: true };
}
