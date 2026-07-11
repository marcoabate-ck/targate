import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import path from "node:path";
import {
  buildApprovalContext,
  isCiEnvironment,
  loadApprovals,
  recordApproval,
} from "../approvals.js";
import {
  vetInstall,
  type InstallReport,
  type InstallVetResult,
} from "../full-install.js";
import {
  buildBootstrapInstallCommand,
  confirm,
  detectPackageManager,
  runCommand,
} from "../installer.js";
import { printJson } from "../json-output.js";
import { loadPolicy, policyFileDigest } from "../policy.js";
import { applySignedApprovalsPolicy } from "../signing.js";
import { createTreeProgress } from "../progress.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import { multiSelect } from "../select.js";
import type { PackageManager } from "../types.js";
import { recordBuildApproval } from "../pnpm-builds.js";

export interface InstallOptions {
  packageManager?: string;
  json: boolean;
  dryRun: boolean;
  assumeYes: boolean;
  failOnOsvError?: boolean;
  /** Immutable install (pnpm/yarn --frozen-lockfile, npm ci). */
  frozenLockfile?: boolean;
  /** Run lifecycle scripts during the install (default: scripts disabled). */
  allowScripts?: boolean;
  /** Tree-analysis pool width (default: 16). */
  concurrency?: number;
  /** Force isolated per-package AI calls instead of batching. */
  noAiBatch?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  /** Ignore cached AI assessments for this run (recompute; still refresh the cache). */
  noCache?: boolean;
  assess: AssessOptions;
}

const ICON: Record<string, string> = {
  allow: "✓",
  allow_with_warnings: "⚠",
  require_approval: "✋",
  block: "✗",
};

function paintResult(r: InstallVetResult): (s: string) => string {
  if (r.assessment.decision === "block") return red;
  if (r.assessment.decision === "allow") return dim;
  if (r.assessment.decision === "require_approval" && !r.approved) return yellow;
  return yellow;
}

/**
 * `targate install` — vet the WHOLE dependency tree, then gate the full bootstrap
 * install. Refuses to install when any package is blocked or requires an
 * approval that is not committed; otherwise runs the real install with
 * lifecycle scripts disabled by default.
 */
export async function installCommand(opts: InstallOptions): Promise<number> {
  const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
  if (!["pnpm", "npm", "yarn"].includes(pm)) {
    console.error(red(`Unknown package manager: ${pm}`));
    return 1;
  }

  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(dim(`\nPre-install review of the full dependency tree (${pm}) ...`));

  const policy = await loadPolicy();
  const approvals = await applySignedApprovalsPolicy(
    await loadApprovals(),
    policy?.policy.dependencyPolicy.requireSignedApprovals,
  );
  const assess: AssessOptions = {
    ...opts.assess,
    cache: resolveCacheSettings(policy?.policy.aiCache, { refresh: opts.noCache }),
    cwd: process.cwd(),
  };

  // Live feedback during the walk: spinner + done/total + ETA on a TTY,
  // milestone lines otherwise, nothing in --json.
  const progress = createTreeProgress({ json: opts.json });
  const started = Date.now();

  let report: InstallReport;
  try {
    report = await vetInstall({
      packageManager: pm,
      cwd: process.cwd(),
      assess,
      approvals,
      policy,
      failOnOsvError: opts.failOnOsvError,
      concurrency: opts.concurrency,
      noAiBatch: opts.noAiBatch,
      noReputation: opts.noReputation,
      onProgress: (phase, done, total) => progress.update(phase, done, total),
      onResult: (r, i, total) => {
        if (r.assessment.decision === "allow") return; // keep the log to what matters
        progress.log(paintResult(r)(`  ${ICON[r.assessment.decision] ?? "?"} [${i + 1}/${total}] ${r.name}@${r.version} → ${r.assessment.decision}${r.approved ? " [approved]" : ""}`));
      },
    });
  } catch (err) {
    progress.done();
    console.error(red(`\ntargate install: ${err instanceof Error ? err.message : String(err)}`));
    return 1;
  }
  progress.done(
    opts.json
      ? undefined
      : dim(`  ✓ ${report.total} packages reviewed in ${Math.round((Date.now() - started) / 1000)}s`),
  );

  const flagged = report.results.filter((r) => r.assessment.decision !== "allow");
  const unresolved = report.results.filter((r) =>
    r.unresolved ??
    (r.hardBlock === true ||
      ((r.assessment.decision === "block" || r.assessment.decision === "require_approval") &&
        !r.approved)),
  );

  if (!opts.json) {
    note("");
    note(
      bold("Dependency tree review") +
        dim(
          ` — ${report.total} packages (from ${report.source}), ${report.total - flagged.length} clean, ${flagged.length} flagged`,
        ),
    );
    for (const r of unresolved.slice(0, 25)) {
      note(
        paintResult(r)(`  ${ICON[r.assessment.decision]} ${r.name}@${r.version} — ${r.assessment.reasons[0] ?? r.assessment.summary}`),
      );
    }
    if (unresolved.length > 25) note(dim(`  … and ${unresolved.length - 25} more`));
    note("");
  }

  // Gate: refuse the install if anything is blocked or unapproved. In an
  // interactive terminal, first offer to approve the approvable ones right
  // here (arrow keys + space) instead of pointing at `targate approve` N times.
  if (report.exitCode === 2) {
    const approvable = unresolved.filter((r) => !r.hardBlock);
    const hard = unresolved.filter((r) => r.hardBlock);
    let remaining = unresolved;

    const interactive =
      !opts.json && !opts.assumeYes && !opts.dryRun && !isCiEnvironment();
    if (interactive && approvable.length > 0) {
      const picked = await multiSelect(
        `${approvable.length} package(s) need approval — select the ones you vouch for:`,
        [
          ...approvable.map((r) => ({
            label: `${r.name}@${r.version}`,
            hint: r.assessment.decision === "block" ? "soft block" : r.assessment.decision,
          })),
          ...hard.map((r) => ({
            label: `${r.name}@${r.version}`,
            hint: "HARD block — can never be approved",
            disabled: true,
          })),
        ],
        "Recorded as no-scripts in .targate/approvals.json (commit it to share; `targate approve <pkg> --allow-scripts` to allow scripts).",
      );
      if (picked && picked.length > 0) {
        const chosen = picked.map((i) => approvable[i]);
        const policyHash = policy ? await policyFileDigest(policy.file) : undefined;
        for (const r of chosen) {
          await recordApproval(r.name, r.version, "no-scripts", process.cwd(), {
            context: buildApprovalContext({
              assessment: r.assessment,
              policyFile: policy ? path.basename(policy.file) : undefined,
              policyHash,
            }),
          });
          r.approved = true;
          r.approvalMode = "no-scripts";
          r.scriptPolicy = "deny";
          r.unresolved = false;
          if (pm === "pnpm") await recordBuildApproval(r.name, "ignored");
        }
        note(
          green(
            `  ✓ approved ${chosen.length} package(s) (no-scripts) — recorded in .targate/approvals.json`,
          ),
        );
        const chosenKeys = new Set(chosen.map((r) => `${r.name}@${r.version}`));
        remaining = unresolved.filter((r) => !chosenKeys.has(`${r.name}@${r.version}`));
      }
    }

    if (remaining.length > 0) {
      if (opts.json) printJson("install", { ...report, install: { status: "blocked" as const } });
      note(
        red(
          bold(
            `\nInstall refused: ${remaining.length} package(s) are blocked or need an approval not in .targate/approvals.json.`,
          ),
        ),
      );
      note(dim("Approve individual packages with `targate approve <pkg>@<version>` (records a committable approval), or add them to the team allow list."));
      return 2;
    }
    note(green("\nAll flagged packages approved — continuing with the install."));
  }

  const treeDeniesScripts = report.results.some(
    (r) => r.scriptPolicy === "deny" || r.approvalMode === "no-scripts",
  );
  const ignoreScripts = treeDeniesScripts || !opts.allowScripts;
  const command = buildBootstrapInstallCommand(pm, {
    ignoreScripts,
    frozenLockfile: opts.frozenLockfile,
  });

  if (opts.dryRun) {
    if (opts.json) {
      printJson("install", {
        ...report,
        install: { status: "skipped" as const, command },
      });
    }
    note(green(bold("\nTree looks clean.")) + dim(`  recommended command: ${command.join(" ")}`));
    return 0;
  }

  const proceed =
    opts.assumeYes ||
    (!opts.json && await confirm(`\nTree passed review. Run the install (${command.join(" ")})?`, true));
  if (!proceed) {
    if (opts.json) printJson("install", { ...report, install: { status: "skipped" as const } });
    note(dim("\nNothing installed."));
    return 0;
  }

  let code: number;
  try {
    code = await runCommand(command);
  } catch {
    code = 1;
  }
  if (code !== 0) {
    if (opts.json) {
      printJson("install", {
        ...report,
        install: { status: "failed" as const, command, exitCode: code },
      });
    }
    note(red(`\nInstall command exited with code ${code}.`));
    return 1;
  }
  note(
    green(
      ignoreScripts
        ? "\nInstalled with lifecycle scripts disabled."
        : "\nInstalled.",
    ),
  );
  if (opts.json) {
    printJson("install", {
      ...report,
      install: {
        status: "installed" as const,
        mode: ignoreScripts ? "no-scripts" as const : "normal" as const,
        command,
      },
    });
  }
  if (ignoreScripts) {
    note(
      dim(
        "Lifecycle scripts were skipped. Enable them for vetted packages with pnpm approve-builds, or re-run with --allow-scripts once you've reviewed them.",
      ),
    );
  }
  note(cyan(`Reviewed ${report.total} packages before executing anything.`));
  return 0;
}
