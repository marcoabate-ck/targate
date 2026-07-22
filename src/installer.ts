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
  // Defense-in-depth (mirrors buildPlanResolveCommand): a spec starting with
  // "-" would be parsed as an option by the package manager. Valid npm specs
  // never start with a dash.
  if (spec.startsWith("-")) {
    throw new Error(`Refusing package spec that looks like a flag: ${spec}`);
  }
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

/** cmd.exe metacharacters that are unsafe under spawn(..., {shell:true}) on
 *  Windows. A registry-resolved `name@version` never contains these. */
export const SHELL_METACHAR = /[&|<>^"%!()`\s]/;

export function runCommand(command: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const [rawBin, ...args] = command;
    // npm/pnpm/yarn are `.cmd` shims on Windows — spawn needs the extension
    // (matches runResolver in install-plan.ts). Without it the install spawn
    // fails with ENOENT on win32. Only bare command names get the shim suffix:
    // an absolute path or a name that already has an extension (e.g.
    // process.execPath = node.exe) must be spawned as-is.
    const isBareName = !rawBin.includes("/") && !rawBin.includes("\\") && !path.extname(rawBin);
    const winShim = process.platform === "win32" && isBareName;
    const bin = winShim ? `${rawBin}.cmd` : rawBin;
    // Since CVE-2024-27980's mitigation (Node >=18.20.2) Windows refuses to
    // spawn a `.cmd`/`.bat` without shell:true (throws EINVAL). shell:true means
    // cmd.exe space-joins the args with NO per-arg quoting, so a shell
    // metacharacter in any arg could inject — the dash-guard does NOT cover
    // that. In-tree callers pass only registry-resolved `name@version` + fixed
    // flags, but this is exported, so reject any metachar defensively.
    if (winShim && args.some((a) => SHELL_METACHAR.test(a))) {
      reject(new Error("refusing to run: an argument contains a shell metacharacter"));
      return;
    }
    const child = spawn(bin, args, { stdio: "inherit", shell: winShim });
    child.on("error", reject);
    child.on("exit", (code) => resolve(code ?? 1));
  });
}

export type InstallMode = "normal" | "no-scripts";

export type InstallResult =
  | { status: "installed"; mode: InstallMode; command: string[]; installed: true }
  | { status: "skipped"; command?: string[]; installed: false }
  | { status: "blocked"; installed: false }
  | { status: "failed"; command: string[]; exitCode: number; installed: false; reason?: string };

async function executeInstall(
  command: string[],
  beforeInstall?: () => Promise<void>,
  verifyInstall?: () => Promise<boolean>,
): Promise<InstallResult | null> {
  try {
    await beforeInstall?.();
    const exitCode = await runCommand(command);
    if (exitCode !== 0) return { status: "failed", command, exitCode, installed: false };
    if (verifyInstall && !(await verifyInstall())) {
      return {
        status: "failed",
        command,
        exitCode: 1,
        installed: false,
        reason: "Installed lockfile does not match the reviewed plan.",
      };
    }
    return null;
  } catch (err) {
    return {
      status: "failed",
      command,
      exitCode: 1,
      installed: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

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
    /**
     * Force --ignore-scripts on the allow path. Set when a recorded approval
     * carries mode "no-scripts": the team cleared the package but explicitly
     * did NOT authorize its lifecycle scripts, so the install must honor that.
     */
    ignoreScripts?: boolean;
    /** Override add commands, used by immutable deep-install plans. */
    commands?: { normal: string[]; noScripts: string[] };
    /** Apply the reviewed plan immediately before invoking the package manager. */
    beforeInstall?: () => Promise<void>;
    /** Verify the final lockfile fingerprint after a successful child process. */
    verifyInstall?: () => Promise<boolean>;
    /** Prompt implementation — injectable for tests; defaults to interactive confirm(). */
    confirmFn?: (question: string, defaultYes?: boolean) => Promise<boolean>;
  } = {},
): Promise<InstallResult> {
  const dry = opts.dryRun === true;
  const ask = opts.confirmFn ?? confirm;
  const overridableBlock = decision === "block" && opts.overridable === true;
  if (decision === "block" && !overridableBlock) {
    return { status: "blocked", installed: false };
  }

  const noScripts = opts.commands?.noScripts ?? buildInstallCommand(pm, spec, { ignoreScripts: true });
  // A "no-scripts" approval caps the allow path at the scripts-disabled command.
  const normal = opts.ignoreScripts
    ? noScripts
    : (opts.commands?.normal ?? buildInstallCommand(pm, spec));

  if (decision === "require_approval" || overridableBlock) {
    // Never auto-approve a package that requires human review (--yes), and in
    // --dry-run just report the recommended (scripts-disabled) command without
    // prompting or installing. Approval itself is a separate action.
    if (opts.assumeYes || dry) {
      return { status: "skipped", command: noScripts, installed: false };
    }
    const approveNoScripts = await ask(
      `This package needs manual approval. Approve WITHOUT lifecycle scripts (${noScripts.join(" ")})?`,
    );
    if (approveNoScripts) {
      const failure = await executeInstall(noScripts, opts.beforeInstall, opts.verifyInstall);
      if (failure) return failure;
      return { status: "installed", mode: "no-scripts", command: noScripts, installed: true };
    }
    const approveFull = await ask(
      `Approve INCLUDING lifecycle scripts (${normal.join(" ")})? Only do this if you trust the package.`,
    );
    if (approveFull) {
      const failure = await executeInstall(normal, opts.beforeInstall, opts.verifyInstall);
      if (failure) return failure;
      return { status: "installed", mode: "normal", command: normal, installed: true };
    }
    return { status: "skipped", installed: false };
  }

  // allow / allow_with_warnings — nothing to approve; dry-run just reports.
  if (dry) return { status: "skipped", command: normal, installed: false };
  const proceed =
    opts.assumeYes ||
    (await ask(`Proceed with install (${normal.join(" ")})?`, decision === "allow"));
  if (!proceed) return { status: "skipped", installed: false };
  const failure = await executeInstall(normal, opts.beforeInstall, opts.verifyInstall);
  if (failure) return failure;
  return {
    status: "installed",
    mode: opts.ignoreScripts ? "no-scripts" : "normal",
    command: normal,
    installed: true,
  };
}
