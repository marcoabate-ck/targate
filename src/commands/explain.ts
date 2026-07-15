import type { AssessOptions } from "../ai.js";
import { getApproval, loadApprovals } from "../approvals.js";
import {
  analyzeRootPackage,
  createAnalysisStageReporter,
  prepareAnalysisSession,
} from "../command-analysis.js";
import { printJson } from "../json-output.js";
import { LastRunError, readLastRun, type LastRunPackage } from "../last-run.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, dim, red, renderExplanation } from "../report.js";

export interface ExplainOptions {
  /** package[@version] — mutually exclusive with `last`. */
  spec?: string;
  /** Explain the recorded last add/approve run instead of analyzing fresh. */
  last: boolean;
  json: boolean;
  failOnOsvError?: boolean;
  /** Skip the external reputation lookups (npm downloads, GitHub). */
  noReputation?: boolean;
  /** Ignore cached AI assessments for this run. */
  noCache?: boolean;
  assess: AssessOptions;
}

/**
 * `targate explain` — why was (or would) a package (be) approved or blocked?
 * A pure lens: it never installs, never records an approval, never writes the
 * last-run file. Exit 0 on success regardless of the decision (the gate lives
 * in `add`/`install`/`ci`), 1 on operational errors. Never 2.
 */
export async function explainCommand(opts: ExplainOptions): Promise<number> {
  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  let packages: LastRunPackage[];
  let fromLastRun: { command: string; timestamp: string } | undefined;

  if (opts.last) {
    let record;
    try {
      record = await readLastRun();
    } catch (err) {
      if (err instanceof LastRunError) {
        console.error(red(err.message));
        return 1;
      }
      throw err;
    }
    packages = record.packages;
    fromLastRun = { command: record.command, timestamp: record.timestamp };
  } else {
    const { name, version } = parsePackageSpec(opts.spec!);
    note(dim(`\nAnalyzing ${bold(name)}${version ? `@${version}` : ""} to explain the verdict ...`));

    const session = await prepareAnalysisSession(opts.assess, { noCache: opts.noCache });
    const onStage = createAnalysisStageReporter(note, { failOnOsvError: opts.failOnOsvError });

    try {
      const { metadata, signals, assessment, score } = await analyzeRootPackage(
        { name, version },
        session,
        {
        failOnOsvError: opts.failOnOsvError,
        noReputation: opts.noReputation,
        maintainerIntel: true,
        onStage,
        },
      );
      packages = [{ metadata, signals, assessment, score }];
    } catch (err) {
      if (err instanceof PackageNotFoundError) {
        console.error(red(`\n${err.message}`));
        return 1;
      }
      throw err;
    }
  }

  // Read-only: mention a committed approval when one exists for this version.
  const approvals = await loadApprovals();

  if (opts.json) {
    printJson("explain", {
      source: fromLastRun ? "last-run" : "fresh",
      originCommand: fromLastRun?.command ?? null,
      analyzedAt: fromLastRun?.timestamp ?? new Date().toISOString(),
      packages,
    });
    return 0;
  }

  for (const pkg of packages) {
    const approval = getApproval(approvals, pkg.metadata.name, pkg.metadata.version);
    console.log(
      renderExplanation(pkg.metadata, pkg.signals, pkg.assessment, pkg.score, {
        approval,
        fromLastRun,
      }),
    );
  }
  return 0;
}
