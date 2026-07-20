import path from "node:path";
import type { AssessOptions } from "../ai.js";
import {
  buildApprovalContext,
  isCiEnvironment,
  recordApproval,
  type ApprovalRecord,
} from "../approvals.js";
import { confirm, detectPackageManager } from "../installer.js";
import {
  analyzeDependencyTree,
  analyzeRootPackage,
  createAnalysisStageReporter,
  persistAnalysisRun,
  prepareAnalysisSession,
} from "../command-analysis.js";
import { printJson } from "../json-output.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { policyFileDigest, resolveCodeAuditScope } from "../policy.js";
import { describeProvider } from "../providers/index.js";
import { approvalSigner } from "../signing.js";
import { isHardBlock } from "../rules.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, dim, green, red, renderReport } from "../report.js";
import {
  aggregateWithTransitive,
  resolveTransitiveTree,
  type TransitiveResult,
} from "../transitive.js";
import type { Decision } from "../types.js";
import { resolvePackageTrust } from "../trust-decision.js";

export interface ApproveOptions {
  spec: string;
  json: boolean;
  /** Non-interactive: record without asking about lifecycle scripts. */
  assumeYes: boolean;
  /** Record the approval as "normal" (lifecycle scripts allowed) rather than "no-scripts". */
  allowScripts?: boolean;
  /** Cryptographically sign the approval entry (SSH signature). */
  sign?: boolean;
  /** Escalate to require_approval when OSV can't be reached. */
  failOnOsvError?: boolean;
  /** Also analyze the full transitive tree before approving. */
  deep?: boolean;
  /** Turn on the AI source-code audit (scope from the team policy). */
  codeAudit?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  /** Ignore cached AI assessments for this run (recompute; still refresh the cache). */
  noCache?: boolean;
  assess: AssessOptions;
}

export type ApproveOutcome = "hard-blocked" | "already-allowed" | "approvable";

/**
 * What `targate approve` can do with an assessment. Pure so it's unit-testable:
 * - a HARD block (artifact mutation / known-malicious / remote execution) can NEVER be
 *   approved away — approval refuses it;
 * - an `allow` / `allow_with_warnings` package installs without any approval,
 *   so there is nothing to record;
 * - everything else (`require_approval`, or a SOFT/heuristic block such as
 *   esbuild's env+network install script) is exactly what a human approval is
 *   for — record it.
 */
export function approveOutcome(decision: Decision, hardBlock: boolean): ApproveOutcome {
  const trust = resolvePackageTrust(
    {
      decision,
      risk: decision === "block" ? "high" : decision === "allow" ? "low" : "medium",
      summary: "",
      reasons: [],
      recommendedAction: "",
      source: "rules",
    },
    hardBlock,
    null,
  );
  if (trust.hardBlocked) return "hard-blocked";
  if (trust.unresolved) return "approvable";
  return "already-allowed"; // allow | allow_with_warnings
}

/**
 * Record a committable approval for a package WITHOUT installing it — the
 * explicit, first-class counterpart to the install gate in `targate add`.
 * A human runs this to clear a `require_approval` / soft block ahead of time
 * (locally or in CI); the exact version is then trusted by everyone who has
 * the committed `.targate/approvals.json`.
 */
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

  const session = await prepareAnalysisSession(opts.assess, { noCache: opts.noCache });
  const { policy, assess } = session;
  const auditScope = resolveCodeAuditScope(
    opts.codeAudit ?? false,
    policy?.policy.dependencyPolicy.codeAudit,
  );
  const onStage = createAnalysisStageReporter(note, { failOnOsvError: opts.failOnOsvError });

  let analysis;
  try {
    analysis = await analyzeRootPackage({ name, version }, session, {
      failOnOsvError: opts.failOnOsvError,
      noReputation: opts.noReputation,
      maintainerIntel: true,
      codeAudit: auditScope,
      isDirect: true,
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

  // --deep: the tree gates approval too. A hard block ANYWHERE in the tree
  // makes the whole thing un-approvable.
  let deepResults: TransitiveResult[] | null = null;
  if (opts.deep) {
    const tree = await resolveTransitiveTree(metadata.name, metadata.version);
    if (tree.length > 0) {
      note(dim(`  … analyzing ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeDependencyTree(tree, session, {
          json: opts.json,
          failOnOsvError: opts.failOnOsvError,
          noReputation: opts.noReputation,
          codeAudit: auditScope,
        });
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  const hardBlock = isHardBlock(signals) || (deepResults ?? []).some((r) => r.hardBlock);
  const outcome = approveOutcome(assessment.decision, hardBlock);

  // Record the run for `targate explain --last`. Best-effort, never gates.
  await persistAnalysisRun("approve", analysis, assessment, session.cwd);

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
      if (!opts.json) console.log(renderReport(metadata, signals, assessment, score));
      confirmed = await confirm(
        `Record approval for ${metadata.name}@${metadata.version} (${mode}) in .targate/approvals.json? It is not installed now.`,
        true,
      );
    }
    if (confirmed) {
      // Trust history: record the circumstances (tool version, verdict,
      // provider/model, policy hash) alongside the approval itself.
      const ai = assessment.source === "ai" ? describeProvider(opts.assess) : null;
      const context = buildApprovalContext({
        assessment,
        score: score.total,
        policyFile: policy ? path.basename(policy.file) : undefined,
        policyHash: policy ? await policyFileDigest(policy.file) : undefined,
        aiProvider: ai?.provider,
        aiModel: ai?.model,
      });
      try {
        approval = await recordApproval(metadata.name, metadata.version, mode, process.cwd(), {
          context,
          sign: opts.sign ? approvalSigner() : undefined,
        });
      } catch (err) {
        // A signing failure must abort loudly — never silently record an
        // unsigned approval when the human asked for a signed one.
        console.error(red(`\nApproval NOT recorded: ${err instanceof Error ? err.message : String(err)}`));
        return 1;
      }
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
    console.log(renderReport(metadata, signals, assessment, score));
  }

  if (opts.json) {
    printJson("approve", { metadata, signals, assessment, score, deep: deepResults, outcome, approval, ...(analysis.sourceAudit ? { sourceAudit: analysis.sourceAudit } : {}) });
  }

  switch (outcome) {
    case "hard-blocked":
      note(
        red(
          bold(
            `\nCannot approve ${metadata.name}@${metadata.version}: this is a HARD block (artifact mutation, known-malicious record, or remote code execution). It can never be approved.`,
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
