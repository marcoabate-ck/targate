import { resolveCacheSettings } from "../ai-cache.js";
import type { AssessOptions } from "../ai.js";
import { recordApproval, type ApprovalRecord } from "../approvals.js";
import { confirm, detectPackageManager } from "../installer.js";
import { analyzePackage, type AnalysisStage } from "../pipeline.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { loadPolicy } from "../policy.js";
import { isHardBlock } from "../rules.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, dim, green, red, renderReport } from "../report.js";
import {
  aggregateWithTransitive,
  analyzeTransitiveDeps,
  resolveTransitiveTree,
  type TransitiveResult,
} from "../transitive.js";
import type { Decision } from "../types.js";

export interface ApproveOptions {
  spec: string;
  json: boolean;
  /** Non-interactive: record without asking about lifecycle scripts. */
  assumeYes: boolean;
  /** Record the approval as "normal" (lifecycle scripts allowed) rather than "no-scripts". */
  allowScripts?: boolean;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Also analyze the full transitive tree before approving. */
  deep?: boolean;
  /** Ignore cached AI assessments for this run (recompute; still refresh the cache). */
  noCache?: boolean;
  assess: AssessOptions;
}

export type ApproveOutcome = "hard-blocked" | "already-allowed" | "approvable";

/**
 * What `targate approve` can do with an assessment. Pure so it's unit-testable:
 * - a HARD block (known-malicious / remote code execution) can NEVER be
 *   approved away — approval refuses it;
 * - an `allow` / `allow_with_warnings` package installs without any approval,
 *   so there is nothing to record;
 * - everything else (`require_approval`, or a SOFT/heuristic block such as
 *   esbuild's env+network install script) is exactly what a human approval is
 *   for — record it.
 */
export function approveOutcome(decision: Decision, hardBlock: boolean): ApproveOutcome {
  if (decision === "block") return hardBlock ? "hard-blocked" : "approvable";
  if (decision === "require_approval") return "approvable";
  return "already-allowed"; // allow | allow_with_warnings
}

/**
 * Record a committable approval for a package WITHOUT installing it — the
 * explicit, first-class counterpart to the install gate in `targate add`.
 * A human runs this to clear a `require_approval` / soft block ahead of time
 * (locally or in CI); the exact version is then trusted by everyone who has
 * the committed `.targate/approvals.json`.
 */
/** True in CI environments (the standard CI env var, "false" respected). */
function isCiEnvironment(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.CI) && env.CI !== "false";
}

export async function approveCommand(opts: ApproveOptions): Promise<number> {
  // An approval is a HUMAN vouching for a version. CI is unattended by
  // definition, so recording one there is always a mistake (or an attack):
  // the reviewed, committed .targate/approvals.json is how approvals reach CI.
  if (isCiEnvironment()) {
    console.error(
      red(
        "targate approve is disabled in CI — approvals must come from a human on a dev machine. Commit .targate/approvals.json to share an approval with CI.",
      ),
    );
    return 1;
  }

  const { name, version } = parsePackageSpec(opts.spec);

  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(dim(`\nReviewing ${bold(name)}${version ? `@${version}` : ""} for approval ...`));

  const policy = await loadPolicy();
  const assess: AssessOptions = {
    ...opts.assess,
    cache: resolveCacheSettings(policy?.policy.aiCache, { refresh: opts.noCache }),
    cwd: process.cwd(),
  };

  const onStage = (stage: AnalysisStage, detail?: string): void => {
    if (stage === "assessment") note(dim(`  ✓ risk assessment complete (${detail})`));
    if (stage === "policy") note(dim(`  ✓ team policy applied (${detail})`));
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

  // --deep: the tree gates approval too. A hard block ANYWHERE in the tree
  // makes the whole thing un-approvable.
  let deepResults: TransitiveResult[] | null = null;
  if (opts.deep) {
    const tree = await resolveTransitiveTree(metadata.name, metadata.version);
    if (tree.length > 0) {
      note(dim(`  … analyzing ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeTransitiveDeps(tree, {
        assess,
        failOnOsvError: opts.failOnOsvError,
        policy,
      });
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  const hardBlock = isHardBlock(signals) || (deepResults ?? []).some((r) => r.hardBlock);
  const outcome = approveOutcome(assessment.decision, hardBlock);

  // Recording requires EXPLICIT human intent: either an interactive
  // confirmation or the --yes flag. --json alone never records — a machine
  // parsing the verdict must not create an approval as a side effect.
  const interactive = !opts.assumeYes && !opts.json;
  let approval: ApprovalRecord | null = null;

  if (outcome === "approvable") {
    // The lifecycle-scripts choice is driven by the --allow-scripts flag (like
    // `targate install`), NOT a second prompt — one prompt keeps the flow clear
    // and avoids a fragile second readline read. Default is the safer
    // scripts-disabled mode.
    const mode: ApprovalRecord["mode"] = opts.allowScripts ? "normal" : "no-scripts";
    let confirmed = opts.assumeYes;
    if (interactive) {
      if (!opts.json) console.log(renderReport(metadata, signals, assessment));
      confirmed = await confirm(
        `Record approval for ${metadata.name}@${metadata.version} (${mode}) in .targate/approvals.json? It is not installed now.`,
        true,
      );
    }
    if (confirmed) {
      await recordApproval(metadata.name, metadata.version, mode);
      approval = {
        mode,
        approvedAt: new Date().toISOString(),
        approvedBy: process.env.USER ?? process.env.USERNAME,
      };
      // On pnpm projects, persist the scripts decision through pnpm's native
      // approve-builds mechanism too, so even a later raw `pnpm install`
      // honors it (no-scripts → ignoredBuiltDependencies).
      if (signals.hasLifecycleScripts && detectPackageManager() === "pnpm") {
        const written = await recordBuildApproval(
          metadata.name,
          mode === "normal" ? "approved" : "ignored",
        );
        if (written) {
          note(
            dim(
              `  ✓ pnpm approve-builds updated (${written}): scripts ${mode === "normal" ? "allowed" : "ignored"}`,
            ),
          );
        }
      }
    }
  } else if (!opts.json) {
    // Nothing to prompt for; still show the report for context.
    console.log(renderReport(metadata, signals, assessment));
  }

  if (opts.json) {
    console.log(
      JSON.stringify({ metadata, signals, assessment, deep: deepResults, outcome, approval }, null, 2),
    );
  }

  switch (outcome) {
    case "hard-blocked":
      note(
        red(
          bold(
            `\nCannot approve ${metadata.name}@${metadata.version}: this is a HARD block (known-malicious or remote code execution). It can never be approved.`,
          ),
        ),
      );
      return 2;
    case "already-allowed":
      note(
        green(
          `\n${metadata.name}@${metadata.version} is already permitted (${assessment.decision}) — no approval needed. Run \`targate add ${metadata.name}\` to install it.`,
        ),
      );
      return 0;
    case "approvable":
      if (!approval) {
        note(dim(`\nCancelled — nothing recorded.`));
        return 0;
      }
      note(
        green(
          `\nApproved ${metadata.name}@${metadata.version} (${approval.mode}) and recorded in .targate/approvals.json.`,
        ),
      );
      note(
        dim(
          `  Commit the file to share the approval; \`targate add ${metadata.name}@${metadata.version}\` (or CI) will now pass on this exact version.`,
        ),
      );
      return 0;
  }
}
