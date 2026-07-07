import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import { loadApprovals } from "../approvals.js";
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
import { loadPolicy } from "../policy.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import type { PackageManager } from "../types.js";

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
 * `bye install` — vet the WHOLE dependency tree, then gate the full bootstrap
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
  const approvals = await loadApprovals();
  const assess: AssessOptions = {
    ...opts.assess,
    cache: resolveCacheSettings(policy?.policy.aiCache),
    cwd: process.cwd(),
  };

  let report: InstallReport;
  try {
    report = await vetInstall({
      packageManager: pm,
      cwd: process.cwd(),
      assess,
      approvals,
      policy,
      failOnOsvError: opts.failOnOsvError,
      onResult: (r, i, total) => {
        if (r.assessment.decision === "allow") return; // keep the log to what matters
        note(paintResult(r)(`  ${ICON[r.assessment.decision] ?? "?"} [${i + 1}/${total}] ${r.name}@${r.version} → ${r.assessment.decision}${r.approved ? " [approved]" : ""}`));
      },
    });
  } catch (err) {
    console.error(red(`\nbye install: ${err instanceof Error ? err.message : String(err)}`));
    return 1;
  }

  const flagged = report.results.filter((r) => r.assessment.decision !== "allow");
  const unresolved = report.results.filter(
    (r) => r.assessment.decision === "block" || (r.assessment.decision === "require_approval" && !r.approved),
  );

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
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

  // Gate: refuse the install if anything is blocked or unapproved.
  if (report.exitCode === 2) {
    note(
      red(
        bold(
          `\nInstall refused: ${unresolved.length} package(s) are blocked or need an approval not in .bye/approvals.json.`,
        ),
      ),
    );
    note(dim("Approve individual packages with `bye add <pkg>@<version>` (records a committable approval), or add them to the team allow list."));
    return 2;
  }

  const ignoreScripts = !opts.allowScripts;
  const command = buildBootstrapInstallCommand(pm, {
    ignoreScripts,
    frozenLockfile: opts.frozenLockfile,
  });

  if (opts.dryRun) {
    note(green(bold("\nTree looks clean.")) + dim(`  recommended command: ${command.join(" ")}`));
    return 0;
  }

  const proceed =
    opts.assumeYes ||
    (await confirm(`\nTree passed review. Run the install (${command.join(" ")})?`, true));
  if (!proceed) {
    note(dim("\nNothing installed."));
    return 0;
  }

  const code = await runCommand(command);
  if (code !== 0) {
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
