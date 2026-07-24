import type { AssessOptions } from "../ai.js";
import {
  analyzeDependencyTree,
  analyzeRootPackage,
  createAnalysisStageReporter,
  prepareAnalysisSession,
} from "../command-analysis.js";
import { printJson } from "../json-output.js";
import { resolveCodeAuditScope } from "../policy.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, renderReport, yellow } from "../report.js";
import {
  aggregateWithTransitive,
  resolveTransitiveTree,
  type TransitiveResult,
} from "../transitive.js";
import { DECISION_SEVERITY, type SourceAuditResult } from "../types.js";

export interface AuditOptions {
  spec: string;
  json: boolean;
  /** Also audit the full transitive tree (bounded to flagged packages). */
  deep?: boolean;
  concurrency?: number;
  noAiBatch?: boolean;
  noReputation?: boolean;
  noCache?: boolean;
  failOnOsvError?: boolean;
  assess: AssessOptions;
}

const ICON: Record<string, string> = {
  allow: "✓",
  allow_with_warnings: "⚠",
  require_approval: "✋",
  block: "✗",
};

/** Render the findings the AI source-code audit reported for one package. */
function renderAuditFindings(result: SourceAuditResult | undefined): string[] {
  if (!result) {
    return [
      dim(
        "  AI source-code audit did not run (no AI provider configured, or nothing to audit).",
      ),
    ];
  }
  const lines: string[] = [
    dim(`  audited ${result.filesAnalyzed.length} file(s)${result.dropped.length ? ` (${result.dropped.map((d) => d.reason).join("; ")})` : ""}`),
  ];
  if (result.findings.length === 0) {
    lines.push(green("  ✓ no source-level findings"));
    return lines;
  }
  for (const f of result.findings) {
    const paint = f.severity === "high" ? red : f.severity === "medium" ? yellow : dim;
    lines.push(paint(`  • [${f.severity}] ${f.file}${f.line ? `:${f.line}` : ""} — ${f.summary}`));
  }
  return lines;
}

/**
 * `targate audit <package>`: read the package's ACTUAL source with the AI and
 * report security findings — WITHOUT installing or recording anything. The
 * source-audit counterpart of `targate approve` (approve records; audit only
 * reports). The named package is always audited; `--deep` also audits the
 * flagged packages in its transitive tree.
 */
export async function auditCommand(opts: AuditOptions): Promise<number> {
  const { name, version } = parsePackageSpec(opts.spec);

  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(dim(`\nAuditing ${bold(name)}${version ? `@${version}` : ""} source ...`));

  const session = await prepareAnalysisSession(opts.assess, { noCache: opts.noCache });
  const { policy } = session;
  const onStage = createAnalysisStageReporter(note, { failOnOsvError: opts.failOnOsvError });
  // Bound the transitive tree (when --deep) with the policy scope, defaulting to
  // "flagged"; the named package itself is always audited.
  const treeScope = resolveCodeAuditScope(true, policy?.policy.dependencyPolicy.codeAudit);

  let analysis;
  try {
    analysis = await analyzeRootPackage({ name, version }, session, {
      failOnOsvError: opts.failOnOsvError,
      noReputation: opts.noReputation,
      maintainerIntel: true,
      codeAudit: "all", // always audit the explicitly named package
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

  let deepResults: TransitiveResult[] | null = null;
  if (opts.deep) {
    const tree = await resolveTransitiveTree(metadata.name, metadata.version);
    if (tree.length > 0) {
      note(dim(`  … auditing flagged packages across ${tree.length} transitive dependencies (--deep)`));
      deepResults = await analyzeDependencyTree(tree, session, {
        json: opts.json,
        failOnOsvError: opts.failOnOsvError,
        concurrency: opts.concurrency,
        noAiBatch: opts.noAiBatch,
        noReputation: opts.noReputation,
        codeAudit: treeScope,
        renderResult: (r) => {
          const icon = ICON[r.assessment.decision] ?? "?";
          const paint = r.assessment.decision === "allow" ? dim : r.assessment.decision === "block" ? red : yellow;
          return paint(`    ${icon} ${r.name}@${r.version} → ${r.assessment.decision}`);
        },
      });
    }
    assessment = aggregateWithTransitive(assessment, deepResults ?? []);
  }

  if (!opts.json) {
    console.log(renderReport(metadata, signals, assessment, score, { deep: opts.deep }));
    console.log(bold("\nAI source-code audit"));
    for (const line of renderAuditFindings(analysis.sourceAudit)) console.log(line);
    console.log(
      cyan(
        `\nAudited ${metadata.name}@${metadata.version} — nothing installed or recorded. Use \`targate approve\` to record a decision.`,
      ),
    );
  } else {
    printJson("audit", {
      metadata,
      signals,
      assessment,
      score,
      deep: deepResults,
      ...(analysis.sourceAudit ? { sourceAudit: analysis.sourceAudit } : {}),
    });
  }

  // Informational exit code: 2 when the audit (or the tree) lands on a decision
  // a human must act on, 0 otherwise. Never installs or records regardless.
  return DECISION_SEVERITY[assessment.decision] >= DECISION_SEVERITY.require_approval ? 2 : 0;
}
