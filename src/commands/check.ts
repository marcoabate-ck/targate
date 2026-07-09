import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import { getApproval, loadApprovals, recordApproval } from "../approvals.js";
import { detectPackageManager, gateInstall } from "../installer.js";
import { diffLockfiles, snapshotLockfile } from "../lockfile.js";
import { analyzePackage, type AnalysisStage } from "../pipeline.js";
import { loadPolicy } from "../policy.js";
import { isHardBlock } from "../rules.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, renderReport, yellow } from "../report.js";
import {
  aggregateWithTransitive,
  analyzeTransitiveDeps,
  resolveTransitiveTree,
  type TransitiveResult,
} from "../transitive.js";
import type { PackageManager } from "../types.js";

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
    cache: resolveCacheSettings(policy?.policy.aiCache),
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
      case "signals":
        return note(dim(`  ✓ package contents inspected (scripts, native surface, RN hardening)`));
      case "assessment":
        return note(dim(`  ✓ risk assessment complete (${detail})`));
      case "policy":
        return note(dim(`  ✓ team policy applied (${detail})`));
    }
  };

  let analysis;
  try {
    analysis = await analyzePackage(name, version, {
      assess,
      failOnOsvError: opts.failOnOsvError,
      policy,
      onStage,
    });
  } catch (err) {
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }
  const { metadata, signals } = analysis;
  let assessment = analysis.assessment;

  // Phase 7 — transitive dependency analysis (--deep): resolve the exact
  // tree npm would install, run the same pipeline on every unique
  // name@version, and let the strictest verdict in the tree gate the install.
  let deepResults: TransitiveResult[] | null = null;
  if (opts.deep) {
    const tree = await resolveTransitiveTree(metadata.name, metadata.version);
    if (tree.length === 0) {
      note(dim(`  ✓ no transitive dependencies to analyze`));
    } else {
      note(dim(`  … analyzing ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeTransitiveDeps(tree, {
        assess,
        failOnOsvError: opts.failOnOsvError,
        policy,
        concurrency: opts.concurrency,
        noAiBatch: opts.noAiBatch,
        onResult: (r) => {
          const icon = STAGE_ICON[r.assessment.decision] ?? "?";
          const paint = r.assessment.decision === "allow" ? dim : r.assessment.decision === "block" ? red : yellow;
          note(paint(`    ${icon} ${r.name}@${r.version} → ${r.assessment.decision}`));
        },
      });
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  // Phase 2 — committed approval cache: a version already reviewed by the
  // team doesn't need a second human approval. A prior approval clears
  // require_approval AND a SOFT block (heuristic, e.g. esbuild's env+network
  // install script) — but never a HARD block (known-malicious / remote exec).
  const approvals = await loadApprovals();
  const priorApproval = getApproval(approvals, metadata.name, metadata.version);
  const softBlock = assessment.decision === "block" && !isHardBlock(signals);
  // When a prior approval clears the decision, its recorded mode is binding:
  // "no-scripts" means the team cleared the package WITHOUT authorizing its
  // lifecycle scripts — the eventual install must run with --ignore-scripts.
  let enforceNoScripts = false;
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

  if (opts.json) {
    console.log(JSON.stringify({ metadata, signals, assessment, deep: deepResults }, null, 2));
  } else {
    console.log(renderReport(metadata, signals, assessment));
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
    // --json is machine output: never write an interactive prompt to stdout.
    // Anything that would need a confirmation is declined (an agent re-runs
    // with --yes to install); --yes still auto-installs allow/warn as usual.
    confirmFn: opts.json ? async () => false : undefined,
  });

  switch (result.mode) {
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
    case "no-scripts":
    case "normal": {
      // These modes are only reached on a REAL install (dry-run never prompts
      // and never reaches here — it returns "skipped").
      note(
        green(result.mode === "no-scripts" ? "\nInstalled with lifecycle scripts disabled." : "\nInstalled."),
      );

      // Phase 2 — record the human approval so the team doesn't re-review.
      // Covers both require_approval and a freshly-approved soft block.
      if (needsApproval) {
        await recordApproval(metadata.name, metadata.version, result.mode);
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
