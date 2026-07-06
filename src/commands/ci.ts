import type { AssessOptions } from "../ai.js";
import { initCiWorkflow, runCiCheck } from "../ci.js";
import { bold, dim, green, red, yellow } from "../report.js";

export interface CiCommandOptions {
  init: boolean;
  baseRef?: string;
  json: boolean;
  assess: AssessOptions;
}

const DECISION_ICON: Record<string, string> = {
  allow: "✓",
  allow_with_warnings: "⚠",
  require_approval: "✋",
  block: "✗",
};

/** Phase 5 — `bye ci`: analyze the dependencies a PR adds or updates. */
export async function ciCommand(opts: CiCommandOptions): Promise<number> {
  if (opts.init) {
    const file = await initCiWorkflow();
    if (file) {
      console.log(green(`Created ${file}`));
      console.log(dim("Commit it to run bye on every PR that touches dependencies."));
    } else {
      console.log(yellow(".github/workflows/bye.yml already exists — nothing written."));
    }
    return 0;
  }

  const report = await runCiCheck({
    baseRef: opts.baseRef,
    assess: opts.assess,
    log: (line) => console.log(dim(`  ${line}`)),
  });

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
    return report.exitCode;
  }

  if (report.changes.length === 0) {
    console.log(green(`\nNo dependency changes vs ${report.baseRef}.`));
    return 0;
  }

  console.log(bold(`\nDependency review vs ${report.baseRef} — ${report.results.length} package(s)`));
  for (const r of report.results) {
    const icon = DECISION_ICON[r.assessment.decision] ?? "?";
    const line = `${icon} ${r.name}@${r.version} (${r.change.kind}) → ${r.assessment.decision}${r.approved ? " [approved]" : ""}`;
    const paint =
      r.assessment.decision === "block"
        ? red
        : r.assessment.decision === "require_approval" && !r.approved
          ? yellow
          : r.assessment.decision === "allow"
            ? green
            : yellow;
    console.log("  " + paint(line));
    for (const reason of r.assessment.reasons.slice(0, 4)) {
      console.log(dim(`      - ${reason}`));
    }
  }

  if (report.exitCode === 2) {
    console.log(
      red(
        bold(
          "\nCI check failed: at least one dependency is blocked or requires an approval not present in .bye/approvals.json.",
        ),
      ),
    );
    console.log(dim("Approve locally with `bye add <pkg>` (the approval is recorded and committable)."));
  } else if (report.exitCode === 1) {
    console.log(yellow(bold("\nCI check finished with analysis errors — review the log.")));
  } else {
    console.log(green(bold("\nAll changed dependencies passed the pre-install review.")));
  }
  return report.exitCode;
}
