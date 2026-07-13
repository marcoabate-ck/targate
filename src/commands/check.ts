import path from "node:path";
import { recordArtifactObservations } from "../artifact-ledger.js";
import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import {
  buildApprovalContext,
  getApproval,
  isCiEnvironment,
  loadApprovals,
  recordApproval,
} from "../approvals.js";
import {
  buildBootstrapInstallCommand,
  detectPackageManager,
  gateInstall,
} from "../installer.js";
import { diffLockfiles, snapshotLockfile } from "../lockfile.js";
import { extractLockfileArtifacts } from "../lockfile.js";
import { printJson } from "../json-output.js";
import { writeLastRun } from "../last-run.js";
import { analyzePackage, type AnalysisStage } from "../pipeline.js";
import { loadPolicy, policyFileDigest } from "../policy.js";
import { describeProvider } from "../providers/index.js";
import { applySignedApprovalsPolicy } from "../signing.js";
import { createTreeProgress } from "../progress.js";
import { isHardBlock } from "../rules.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { fetchPackageMetadata, PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, renderReport, yellow } from "../report.js";
import { multiSelect } from "../select.js";
import {
  aggregateWithTransitive,
  analyzeTransitiveDeps,
  resolveTransitiveInstallPlan,
  type TransitiveResult,
} from "../transitive.js";
import type { PackageManager } from "../types.js";
import { resolvePackageTrust } from "../trust-decision.js";
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

/** The original `targate <package>` flow: analyze, decide, gate the install. */
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

  // Team policy loads BEFORE the analysis: it configures the AI cache and is
  // applied to every assessment (root and transitive) inside the pipeline.
  const policy = await loadPolicy();

  // Interactive runs go through the AI response cache (policy-configurable).
  // CI never does — runCiCheck simply never passes cache settings.
  const assess: AssessOptions = {
    ...opts.assess,
    cache: resolveCacheSettings(policy?.policy.aiCache, { refresh: opts.noCache }),
    cwd: process.cwd(),
  };

  const onStage = (stage: AnalysisStage, detail?: string): void => {
    switch (stage) {
      case "metadata":
        return note(dim(`  ✓ npm metadata resolved (${detail})`));
      case "quarantine":
        return note(dim(`  ✓ tarball downloaded to quarantine`));
      case "osv":
        return note(dim(`  ✓ OSV/OpenSSF malicious-package lookup done`));
      case "osv-failed":
        return note(
          (opts.failOnOsvError ? red : yellow)(
            `  ⚠ OSV lookup failed — malicious-package status is UNKNOWN`,
          ),
        );
      case "internal-scope":
        return note(cyan(`  ℹ internal scope — ${detail}`));
      case "reputation":
        return note(dim(`  ✓ reputation lookups done (npm downloads, GitHub)`));
      case "reputation-degraded":
        return note(yellow(`  ⚠ reputation lookups degraded — ${detail} (signals UNKNOWN)`));
      case "resource-limit":
        return note(yellow(`  ⚠ analysis stopped at a safety limit — ${detail} (result UNKNOWN)`));
      case "signals":
        return note(dim(`  ✓ package contents inspected (scripts, native surface, RN hardening)`));
      case "assessment":
        return note(dim(`  ✓ risk assessment complete (${detail})`));
      case "policy":
        return note(dim(`  ✓ team policy applied (${detail})`));
    }
  };

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
    analysis = await analyzePackage(name, version, {
      assess,
      failOnOsvError: opts.failOnOsvError,
      policy,
      noReputation: opts.noReputation,
      maintainerIntel: true,
      metadata: preloadedMetadata,
      lockedArtifact: lockedRoot,
      lockfileTrusted: installPlan?.source === "existing",
      cwd: process.cwd(),
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
  const approvals = await applySignedApprovalsPolicy(
    await loadApprovals(),
    policy?.policy.dependencyPolicy.requireSignedApprovals,
  );
  const priorApproval = getApproval(approvals, metadata.name, metadata.version);
  const rootTrust = resolvePackageTrust(assessment, isHardBlock(signals), priorApproval);
  const softBlock = assessment.decision === "block" && !rootTrust.hardBlocked;
  // When a prior approval clears the decision, its recorded mode is binding:
  // "no-scripts" means the team cleared the package WITHOUT authorizing its
  // lifecycle scripts — the eventual install must run with --ignore-scripts.
  let enforceNoScripts = rootTrust.scriptPolicy === "deny";
  if (priorApproval && (assessment.decision === "require_approval" || softBlock)) {
    enforceNoScripts = priorApproval.mode === "no-scripts";
    assessment = {
      ...assessment,
      decision: "allow_with_warnings",
      risk: assessment.risk === "high" ? "medium" : assessment.risk,
      reasons: [
        ...assessment.reasons,
        `[team] ${metadata.name}@${metadata.version} already approved${priorApproval.approvedBy ? ` by ${priorApproval.approvedBy}` : ""} on ${priorApproval.approvedAt.slice(0, 10)} (${priorApproval.mode}).`,
      ],
    };
  }

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
      const progress = createTreeProgress({ json: opts.json });
      const started = Date.now();
      try {
        deepResults = await analyzeTransitiveDeps(tree, {
          assess,
          failOnOsvError: opts.failOnOsvError,
          policy,
          concurrency: opts.concurrency,
          noAiBatch: opts.noAiBatch,
          noReputation: opts.noReputation,
          lockfileTrusted: installPlan.source === "existing",
          onProgress: (phase, done, total) => progress.update(phase, done, total),
          onResult: (r) => {
            const icon = STAGE_ICON[r.assessment.decision] ?? "?";
            const paint = r.assessment.decision === "allow" ? dim : r.assessment.decision === "block" ? red : yellow;
            progress.log(paint(`    ${icon} ${r.name}@${r.version} → ${r.assessment.decision}`));
          },
        });
      } catch (err) {
        progress.done();
        throw err;
      }
      progress.done(
        dim(`  ✓ ${tree.length} transitive dependencies reviewed in ${Math.round((Date.now() - started) / 1000)}s`),
      );

      // A flagged transitive dependency clears exactly like the root: a
      // committed approval for that exact version counts, and hard blocks
      // never clear.
      const transitiveNeedsApproval = (r: TransitiveResult): boolean =>
        !r.hardBlock &&
        (r.assessment.decision === "require_approval" || r.assessment.decision === "block");
      const clearTransitive = (r: TransitiveResult, reason: string): void => {
        r.assessment = {
          ...r.assessment,
          decision: "allow_with_warnings",
          risk: r.assessment.risk === "high" ? "medium" : r.assessment.risk,
          reasons: [...r.assessment.reasons, reason],
        };
      };
      for (const r of deepResults) {
        const prior = getApproval(approvals, r.name, r.version);
        if (prior) {
          r.approved = true;
          r.approvalMode = prior.mode;
          r.scriptPolicy = prior.mode === "no-scripts" ? "deny" : "allow";
          if (r.scriptPolicy === "deny") enforceNoScripts = true;
        }
        if (!transitiveNeedsApproval(r)) continue;
        if (prior) {
          clearTransitive(
            r,
            `[team] ${r.name}@${r.version} already approved${prior.approvedBy ? ` by ${prior.approvedBy}` : ""} on ${prior.approvedAt.slice(0, 10)} (${prior.mode}).`,
          );
        }
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
          for (const i of picked) {
            const r = pending[i];
            await recordApproval(r.name, r.version, "no-scripts", process.cwd(), {
              context: buildApprovalContext({
                assessment: r.assessment,
                policyFile: policy ? path.basename(policy.file) : undefined,
                policyHash: policy ? await policyFileDigest(policy.file) : undefined,
              }),
            });
            r.approved = true;
            r.approvalMode = "no-scripts";
            r.scriptPolicy = "deny";
            enforceNoScripts = true;
            if (pm === "pnpm") await recordBuildApproval(r.name, "ignored");
            clearTransitive(r, `[team] approved now (no-scripts) — recorded in .targate/approvals.json.`);
          }
          note(green(`  ✓ approved ${picked.length} transitive package(s) (no-scripts)`));
        }
      }
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  // Record the run (final assessment, exactly what the user saw) so
  // `targate explain --last` can explain it without re-analyzing. Best-effort.
  await writeLastRun("add", [{ metadata, signals, assessment, score }]);

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
