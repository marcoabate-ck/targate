import path from "node:path";
import { recordArtifactObservations } from "../artifact-ledger.js";
import type { AssessOptions } from "../ai.js";
import {
  buildApprovalContext,
  getApproval,
  isCiEnvironment,
  recordApproval,
} from "../approvals.js";
import {
  applyRootApproval,
  applyTransitiveApproval,
  recordNoScriptsApprovals,
} from "../approval-orchestration.js";
import {
  analyzeDependencyTree,
  analyzeRootPackage,
  createAnalysisStageReporter,
  persistAnalysisRun,
  prepareAnalysisSession,
} from "../command-analysis.js";
import {
  buildBootstrapInstallCommand,
  detectPackageManager,
  gateInstall,
} from "../installer.js";
import { diffLockfiles, snapshotLockfile } from "../lockfile.js";
import { extractLockfileArtifacts } from "../lockfile.js";
import { printJson } from "../json-output.js";
import { policyFileDigest } from "../policy.js";
import { describeProvider } from "../providers/index.js";
import { isHardBlock } from "../rules.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { fetchPackageMetadata, PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, renderReport, yellow } from "../report.js";
import { multiSelect } from "../select.js";
import {
  aggregateWithTransitive,
  resolveTransitiveInstallPlan,
  type TransitiveResult,
} from "../transitive.js";
import type { PackageManager } from "../types.js";
import {
  applyInstallPlan,
  verifyInstallPlan,
  type InstallPlan,
} from "../install-plan.js";

export interface CheckOptions {
  spec: string;
  packageManager?: string;
  json: boolean;
  dryRun: boolean;
  assumeYes: boolean;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Analyze the full transitive dependency tree, not just the named package. */
  deep?: boolean;
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

const STAGE_ICON: Record<string, string> = {
  allow: "✓",
  allow_with_warnings: "⚠",
  require_approval: "✋",
  block: "✗",
};

/** `targate add <package>`: analyze, decide, then gate the install. */
export async function checkCommand(opts: CheckOptions): Promise<number> {
  const { name, version } = parsePackageSpec(opts.spec);

  const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
  if (!["pnpm", "npm", "yarn"].includes(pm)) {
    console.error(red(`Unknown package manager: ${pm}`));
    return 1;
  }

  // In --json mode stdout must be ONLY the JSON document (agents parse it), so
  // human progress is suppressed. Otherwise it narrates the review.
  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(dim(`\nPre-install review started for ${bold(name)}${version ? `@${version}` : ""} ...`));

  const session = await prepareAnalysisSession(opts.assess, {
    noCache: opts.noCache,
    approvals: "policy",
  });
  const { policy, assess } = session;
  const onStage = createAnalysisStageReporter(note, { failOnOsvError: opts.failOnOsvError });

  let analysis;
  let installPlan: InstallPlan | null = null;
  try {
    // --deep resolves the immutable plan before analysis so the root tarball,
    // not only its transitives, is checked against the reviewed lockfile.
    const preloadedMetadata = opts.deep
      ? await fetchPackageMetadata(name, version, policy?.policy.resourceLimits)
      : undefined;
    if (preloadedMetadata) {
      installPlan = await resolveTransitiveInstallPlan(
        preloadedMetadata.name,
        preloadedMetadata.version,
        pm,
        process.cwd(),
      );
    }
    const lockedRoot = installPlan
      ? extractLockfileArtifacts(pm, installPlan.lockfileContent).find(
          (artifact) =>
            artifact.name === preloadedMetadata!.name &&
            artifact.version === preloadedMetadata!.version,
        )
      : undefined;
    analysis = await analyzeRootPackage({ name, version }, session, {
      failOnOsvError: opts.failOnOsvError,
      noReputation: opts.noReputation,
      maintainerIntel: true,
      metadata: preloadedMetadata,
      lockedArtifact: lockedRoot,
      lockfileTrusted: installPlan?.source === "existing",
      onStage,
    });
  } catch (err) {
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }
  const { metadata, signals, score } = analysis;
  let assessment = analysis.assessment;

  // Phase 2 — committed approval cache: a version already reviewed by the
  // team doesn't need a second human approval. A prior approval clears
  // require_approval AND a SOFT block (heuristic, e.g. esbuild's env+network
  // install script) — but never a HARD block (known-malicious / remote exec).
  // Root clearing happens BEFORE --deep aggregation, so a root approval can
  // never accidentally clear an escalation caused by unapproved transitives.
  const approvals = session.approvals!;
  const priorApproval = getApproval(approvals, metadata.name, metadata.version);
  const approvedRoot = applyRootApproval(analysis, priorApproval);
  assessment = approvedRoot.assessment;
  let enforceNoScripts = approvedRoot.enforceNoScripts;

  // Phase 7 — transitive dependency analysis (--deep): resolve the exact
  // tree npm would install, run the same pipeline on every unique
  // name@version, and let the strictest verdict in the tree gate the install.
  let deepResults: TransitiveResult[] | null = null;
  if (opts.deep) {
    // The plan was resolved before root analysis to bind its tarball too.
    if (!installPlan) throw new Error("Internal error: deep install plan missing");
    const tree = installPlan.packages;
    if (tree.length === 0) {
      note(dim(`  ✓ no transitive dependencies to analyze`));
    } else {
      note(dim(`  … analyzing ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeDependencyTree(tree, session, {
          json: opts.json,
          failOnOsvError: opts.failOnOsvError,
          concurrency: opts.concurrency,
          noAiBatch: opts.noAiBatch,
          noReputation: opts.noReputation,
          lockfileTrusted: installPlan.source === "existing",
          renderResult: (r) => {
            const icon = STAGE_ICON[r.assessment.decision] ?? "?";
            const paint = r.assessment.decision === "allow" ? dim : r.assessment.decision === "block" ? red : yellow;
            return paint(`    ${icon} ${r.name}@${r.version} → ${r.assessment.decision}`);
          },
        });

      // A flagged transitive dependency clears exactly like the root: a
      // committed approval for that exact version counts, and hard blocks
      // never clear.
      const transitiveNeedsApproval = (r: TransitiveResult): boolean =>
        !r.hardBlock &&
        (r.assessment.decision === "require_approval" || r.assessment.decision === "block");
      for (const r of deepResults) {
        const prior = getApproval(approvals, r.name, r.version);
        if (prior) {
          applyTransitiveApproval(r, prior);
          if (r.scriptPolicy === "deny") enforceNoScripts = true;
        }
        if (!transitiveNeedsApproval(r)) continue;
      }

      // Interactive terminals get an arrow-key picker to approve the rest in
      // one step instead of running `targate approve` once per package.
      const pending = deepResults.filter(transitiveNeedsApproval);
      const interactivePick =
        !opts.json && !opts.assumeYes && !opts.dryRun && !isCiEnvironment();
      if (interactivePick && pending.length > 0) {
        const hard = deepResults.filter((r) => r.hardBlock);
        const picked = await multiSelect(
          `${pending.length} transitive dependencies need approval — select the ones you vouch for:`,
          [
            ...pending.map((r) => ({
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
          const chosen = picked.map((index) => pending[index]);
          await recordNoScriptsApprovals(chosen, {
            policy,
            packageManager: pm,
            clearAssessment: true,
          });
          enforceNoScripts = true;
          note(green(`  ✓ approved ${picked.length} transitive package(s) (no-scripts)`));
        }
      }
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  // Record the run (final assessment, exactly what the user saw) so
  // `targate explain --last` can explain it without re-analyzing. Best-effort.
  await persistAnalysisRun("add", analysis, assessment, session.cwd);

  if (!opts.json) {
    console.log(renderReport(metadata, signals, assessment, score));
    if (deepResults) {
      const flagged = deepResults.filter((r) => r.assessment.decision !== "allow");
      console.log(
        bold(`Transitive dependencies`) +
          dim(
            ` — ${deepResults.length} analyzed, ${deepResults.length - flagged.length} clean, ${flagged.length} flagged`,
          ),
      );
      console.log("");
    }
  }

  const lockBefore = await snapshotLockfile(pm);

  // A soft block is approvable interactively (like require_approval) — a human
  // can clear it and the approval is recorded. A block is HARD (never
  // overridable) if the root package is a hard block, or — under --deep — any
  // analyzed transitive dependency is.
  const hardBlock =
    isHardBlock(signals) || (deepResults ?? []).some((r) => r.hardBlock);
  const overridableBlock = assessment.decision === "block" && !hardBlock;
  const needsApproval = assessment.decision === "require_approval" || overridableBlock;

  const result = await gateInstall(assessment.decision, pm, `${metadata.name}@${metadata.version}`, {
    assumeYes: opts.assumeYes,
    dryRun: opts.dryRun,
    overridable: overridableBlock,
    // A "no-scripts" prior approval is enforced, not advisory (security
    // analysis finding 8): the cleared package installs with --ignore-scripts.
    ignoreScripts: enforceNoScripts,
    commands: installPlan
      ? {
          normal: buildBootstrapInstallCommand(pm, { frozenLockfile: true }),
          noScripts: buildBootstrapInstallCommand(pm, {
            frozenLockfile: true,
            ignoreScripts: true,
          }),
        }
      : undefined,
    beforeInstall: installPlan
      ? async () => {
          await applyInstallPlan(installPlan!);
        }
      : undefined,
    verifyInstall: installPlan
      ? async () => verifyInstallPlan(installPlan!)
      : undefined,
    // --json is machine output: never write an interactive prompt to stdout.
    // Anything that would need a confirmation is declined (an agent re-runs
    // with --yes to install); --yes still auto-installs allow/warn as usual.
    confirmFn: opts.json ? async () => false : undefined,
  });

  let artifactLedger: { status: "recorded" | "failed"; reason?: string } | undefined;
  if (result.status === "installed") {
    try {
      await recordArtifactObservations([
        { name: metadata.name, version: metadata.version, artifact: signals.artifact },
        ...(deepResults ?? []).flatMap((r) =>
          r.artifact ? [{ name: r.name, version: r.version, artifact: r.artifact }] : [],
        ),
      ]);
      artifactLedger = { status: "recorded" };
    } catch (err) {
      artifactLedger = {
        status: "failed",
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  if (opts.json) {
    printJson("add", {
      metadata,
      signals,
      assessment,
      score,
      deep: deepResults,
      ...(installPlan ? { planFingerprint: installPlan.fingerprint } : {}),
      ...(installPlan ? { artifactFingerprint: installPlan.artifactFingerprint } : {}),
      install: result,
      ...(artifactLedger ? { artifactLedger } : {}),
    });
  }

  switch (result.status) {
    case "blocked":
      note(red(bold("\nInstallation blocked. This package was not installed.")));
      return 2;
    case "skipped":
      if (opts.dryRun && result.command) {
        note(dim(`\nDry run — recommended command: ${result.command.join(" ")}`));
      } else {
        note(dim("\nNothing installed."));
      }
      if (needsApproval) {
        note(
          dim(
            `  To approve ${metadata.name}@${metadata.version} without installing it, run \`targate approve ${metadata.name}@${metadata.version}\`.`,
          ),
        );
      }
      return 0;
    case "failed":
      note(red(`\nInstall command failed (${result.command.join(" ")}) with exit code ${result.exitCode}${result.reason ? `: ${result.reason}` : "."}`));
      return 1;
    case "installed": {
      // These modes are only reached on a REAL install (dry-run never prompts
      // and never reaches here — it returns "skipped").
      note(
        green(result.mode === "no-scripts" ? "\nInstalled with lifecycle scripts disabled." : "\nInstalled."),
      );
      if (artifactLedger?.status === "recorded") {
        note(dim("  ✓ artifact identity recorded in .targate/artifacts.json"));
      } else if (artifactLedger?.status === "failed") {
        note(yellow(`  ⚠ artifact identity could not be recorded: ${artifactLedger.reason}`));
      }

      // Phase 2 — record the human approval so the team doesn't re-review.
      // Covers both require_approval and a freshly-approved soft block.
      if (needsApproval) {
        const ai = assessment.source === "ai" ? describeProvider(opts.assess) : null;
        await recordApproval(metadata.name, metadata.version, result.mode, process.cwd(), {
          context: buildApprovalContext({
            assessment,
            score: score.total,
            policyFile: policy ? path.basename(policy.file) : undefined,
            policyHash: policy ? await policyFileDigest(policy.file) : undefined,
            aiProvider: ai?.provider,
            aiModel: ai?.model,
          }),
        });
        note(dim(`  ✓ approval recorded in .targate/approvals.json (commit it to share)`));
        // pnpm approve-builds edits pnpm-workspace.yaml for the install.
        if (pm === "pnpm" && signals.hasLifecycleScripts) {
          const written = await recordBuildApproval(
            metadata.name,
            result.mode === "normal" ? "approved" : "ignored",
          );
          if (written) {
            note(
              dim(`  ✓ pnpm approve-builds updated (${written}): scripts ${result.mode === "normal" ? "allowed" : "ignored"}`),
            );
          }
        }
      }

      // Phase 2 — lockfile diff preview: what did this install actually add?
      const lockAfter = await snapshotLockfile(pm);
      const diff = diffLockfiles(pm, lockBefore, lockAfter);
      if (diff.added.length > 0) {
        note(cyan(`\nLockfile diff — ${diff.added.length} package(s) added:`));
        for (const entry of diff.added.slice(0, 25)) note(dim(`  + ${entry}`));
        if (diff.added.length > 25) note(dim(`  … and ${diff.added.length - 25} more`));
      }
      return 0;
    }
  }
}
