import type { AssessOptions } from "../ai.js";
import { recordArtifactObservations } from "../artifact-ledger.js";
import {
  isCiEnvironment,
} from "../approvals.js";
import { loadDenials } from "../denials.js";
import { recordTriageDecisions } from "../approval-orchestration.js";
import { resolveCodeAuditScope } from "../policy.js";
import { prepareAnalysisSession } from "../command-analysis.js";
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
import { createTreeProgress } from "../progress.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import { triage, type TriageItem } from "../triage.js";
import type { PackageManager } from "../types.js";
import {
  applyInstallPlan,
  resolveInstallPlan,
  verifyInstallPlan,
} from "../install-plan.js";

export interface InstallOptions {
  packageManager?: string;
  json: boolean;
  dryRun: boolean;
  assumeYes: boolean;
  failOnOsvError?: boolean;
  /** Re-resolve and update the lockfile before review. Immutable install remains mandatory. */
  updateLockfile?: boolean;
  /** Run lifecycle scripts during the install (default: scripts disabled). */
  allowScripts?: boolean;
  /** Turn on the AI source-code audit (scope from the team policy). */
  codeAudit?: boolean;
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

  const session = await prepareAnalysisSession(opts.assess, {
    noCache: opts.noCache,
    approvals: "policy",
  });
  const { policy, assess } = session;
  const approvals = session.approvals!;
  const denials = await loadDenials();
  const auditScope = resolveCodeAuditScope(
    opts.codeAudit ?? false,
    policy?.policy.dependencyPolicy.codeAudit,
  );

  // Live feedback during the walk: spinner + done/total + ETA on a TTY,
  // milestone lines otherwise, nothing in --json.
  const progress = createTreeProgress({ json: opts.json });
  const started = Date.now();

  let report: InstallReport;
  let plan;
  try {
    plan = await resolveInstallPlan({
      packageManager: pm,
      cwd: process.cwd(),
      updateLockfile: opts.updateLockfile,
    });
    report = await vetInstall({
      packageManager: pm,
      cwd: process.cwd(),
      assess,
      approvals,
      denials,
      policy,
      codeAudit: auditScope,
      failOnOsvError: opts.failOnOsvError,
      concurrency: opts.concurrency,
      noAiBatch: opts.noAiBatch,
      noReputation: opts.noReputation,
      plan,
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
  // interactive terminal, first triage the flagged ones right here (arrow keys
  // to approve / deny / skip, with a live detail panel) instead of pointing at
  // `targate approve` N times. Runs in --dry-run too: it never installs, but it
  // does record the committable approvals/denials, exactly like `targate approve`.
  if (report.exitCode === 2) {
    // Previously denied versions (committed in .targate/denials.json) are not
    // re-offered — they are refused without prompting again.
    const previouslyDenied = unresolved.filter((r) => r.denied);
    const approvable = unresolved.filter((r) => !r.hardBlock && !r.denied);
    const hard = unresolved.filter((r) => r.hardBlock);
    let remaining = unresolved;

    if (previouslyDenied.length > 0) {
      note(
        dim(
          `  ${previouslyDenied.length} package(s) previously denied in .targate/denials.json — not re-offered (\`targate approve <pkg>@<version>\` to reverse).`,
        ),
      );
    }

    const interactive = !opts.json && !opts.assumeYes && !isCiEnvironment();
    if (interactive && approvable.length > 0) {
      const pickable = [...approvable, ...hard];
      const items: TriageItem[] = pickable.map((r) => ({
        label: `${r.name}@${r.version}`,
        disabled: r.hardBlock === true,
        detail: {
          decision: r.assessment.decision,
          risk: r.assessment.risk,
          summary: r.assessment.summary,
          reasons: r.assessment.reasons,
          recommendedAction: r.assessment.recommendedAction,
          source: r.assessment.source,
          facts: r.assessment.suggestedAlternatives?.length
            ? [`alternatives: ${r.assessment.suggestedAlternatives.join(", ")}`]
            : undefined,
        },
      }));
      const result = await triage(
        `${approvable.length} package(s) need a decision — approve, deny, or skip each:`,
        items,
        "Approvals → .targate/approvals.json · denials → .targate/denials.json (commit to share). Approvals default to no-scripts; press s to allow scripts.",
      );
      if (result && (result.approve.length > 0 || result.deny.length > 0)) {
        const approveTargets = result.approve.map(({ index, scripts }) => ({
          name: pickable[index].name,
          version: pickable[index].version,
          assessment: pickable[index].assessment,
          scripts,
        }));
        const denyTargets = result.deny.map((index) => ({
          name: pickable[index].name,
          version: pickable[index].version,
          assessment: pickable[index].assessment,
        }));
        await recordTriageDecisions(approveTargets, denyTargets, { policy, packageManager: pm });
        if (approveTargets.length > 0) {
          note(
            green(
              `  ✓ approved ${approveTargets.length} package(s) — recorded in .targate/approvals.json`,
            ),
          );
        }
        if (denyTargets.length > 0) {
          note(
            yellow(
              `  ✗ denied ${denyTargets.length} package(s) — recorded in .targate/denials.json`,
            ),
          );
        }
        const approvedKeys = new Set(approveTargets.map((t) => `${t.name}@${t.version}`));
        remaining = unresolved.filter((r) => !approvedKeys.has(`${r.name}@${r.version}`));
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
    frozenLockfile: true,
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

  try {
    if (plan.source === "resolved") await applyInstallPlan(plan);
    if (!(await verifyInstallPlan(plan))) {
      throw new Error("Lockfile changed after review; generate a new install plan.");
    }
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    if (opts.json) {
      printJson("install", {
        ...report,
        install: { status: "failed" as const, command, exitCode: 1, reason },
      });
    }
    note(red(`\nInstall refused: ${reason}`));
    return 1;
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
  if (!(await verifyInstallPlan(plan))) {
    const reason = "Installed lockfile does not match the reviewed plan; review is required again.";
    if (opts.json) {
      printJson("install", {
        ...report,
        install: { status: "failed" as const, command, exitCode: 1, reason },
      });
    }
    note(red(`\n${reason}`));
    return 1;
  }
  let artifactLedger: { status: "recorded" | "failed"; reason?: string };
  try {
    await recordArtifactObservations(
      report.results.flatMap((result) =>
        result.artifact
          ? [{ name: result.name, version: result.version, artifact: result.artifact }]
          : [],
      ),
      process.cwd(),
    );
    artifactLedger = { status: "recorded" };
  } catch (err) {
    artifactLedger = {
      status: "failed",
      reason: err instanceof Error ? err.message : String(err),
    };
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
      artifactLedger,
    });
  }
  if (artifactLedger.status === "failed") {
    note(yellow(`Artifact identity could not be recorded: ${artifactLedger.reason}`));
  } else {
    note(dim("Artifact identities recorded in .targate/artifacts.json."));
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
