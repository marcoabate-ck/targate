import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import { getApproval, loadApprovals, recordApproval } from "../approvals.js";
import { detectPackageManager, gateInstall } from "../installer.js";
import { diffLockfiles, snapshotLockfile } from "../lockfile.js";
import { analyzePackage, type AnalysisStage } from "../pipeline.js";
import { loadPolicy } from "../policy.js";
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
  assess: AssessOptions;
}

const STAGE_ICON: Record<string, string> = {
  allow: "✓",
  allow_with_warnings: "⚠",
  require_approval: "✋",
  block: "✗",
};

/** The original `bye <package>` flow: analyze, decide, gate the install. */
export async function checkCommand(opts: CheckOptions): Promise<number> {
  const { name, version } = parsePackageSpec(opts.spec);

  const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
  if (!["pnpm", "npm", "yarn"].includes(pm)) {
    console.error(red(`Unknown package manager: ${pm}`));
    return 1;
  }

  console.log(dim(`\nPre-install review started for ${bold(name)}${version ? `@${version}` : ""} ...`));

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
        return console.log(dim(`  ✓ npm metadata resolved (${detail})`));
      case "quarantine":
        return console.log(dim(`  ✓ tarball downloaded to quarantine`));
      case "osv":
        return console.log(dim(`  ✓ OSV/OpenSSF malicious-package lookup done`));
      case "osv-failed":
        return console.log(
          (opts.failOnOsvError ? red : yellow)(
            `  ⚠ OSV lookup failed — malicious-package status is UNKNOWN`,
          ),
        );
      case "signals":
        return console.log(dim(`  ✓ package contents inspected (scripts, native surface, RN hardening)`));
      case "assessment":
        return console.log(dim(`  ✓ risk assessment complete (${detail})`));
      case "policy":
        return console.log(dim(`  ✓ team policy applied (${detail})`));
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
      console.log(dim(`  ✓ no transitive dependencies to analyze`));
    } else {
      console.log(dim(`  … analyzing ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeTransitiveDeps(tree, {
        assess,
        failOnOsvError: opts.failOnOsvError,
        policy,
        onResult: (r) => {
          const icon = STAGE_ICON[r.assessment.decision] ?? "?";
          const paint = r.assessment.decision === "allow" ? dim : r.assessment.decision === "block" ? red : yellow;
          console.log(paint(`    ${icon} ${r.name}@${r.version} → ${r.assessment.decision}`));
        },
      });
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  // Phase 2 — committed approval cache: a version already reviewed by the
  // team doesn't need a second human approval.
  const approvals = await loadApprovals();
  const priorApproval = getApproval(approvals, metadata.name, metadata.version);
  if (priorApproval && assessment.decision === "require_approval") {
    assessment = {
      ...assessment,
      decision: "allow_with_warnings",
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

  const result = await gateInstall(assessment.decision, pm, `${metadata.name}@${metadata.version}`, {
    assumeYes: opts.assumeYes,
    dryRun: opts.dryRun,
  });

  switch (result.mode) {
    case "blocked":
      console.log(red(bold("\nInstallation blocked. This package was not installed.")));
      return 2;
    case "skipped":
      if (opts.dryRun && result.command) {
        console.log(dim(`\nDry run — recommended command: ${result.command.join(" ")}`));
      } else {
        console.log(dim("\nNothing installed."));
      }
      return 0;
    case "no-scripts":
    case "normal": {
      console.log(
        green(result.mode === "no-scripts" ? "\nInstalled with lifecycle scripts disabled." : "\nInstalled."),
      );

      // Phase 2 — record the human approval so the team doesn't re-review
      if (assessment.decision === "require_approval") {
        await recordApproval(metadata.name, metadata.version, result.mode);
        console.log(dim(`  ✓ approval recorded in .bye/approvals.json (commit it to share)`));
        if (pm === "pnpm" && signals.hasLifecycleScripts) {
          const written = await recordBuildApproval(
            metadata.name,
            result.mode === "normal" ? "approved" : "ignored",
          );
          if (written) {
            console.log(
              dim(`  ✓ pnpm approve-builds updated (${written}): scripts ${result.mode === "normal" ? "allowed" : "ignored"}`),
            );
          }
        }
      }

      // Phase 2 — lockfile diff preview: what did this install actually add?
      const lockAfter = await snapshotLockfile(pm);
      const diff = diffLockfiles(pm, lockBefore, lockAfter);
      if (diff.added.length > 0) {
        console.log(cyan(`\nLockfile diff — ${diff.added.length} package(s) added:`));
        for (const entry of diff.added.slice(0, 25)) console.log(dim(`  + ${entry}`));
        if (diff.added.length > 25) console.log(dim(`  … and ${diff.added.length - 25} more`));
      }
      return 0;
    }
  }
}
