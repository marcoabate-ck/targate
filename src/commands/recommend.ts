import { printJson } from "../json-output.js";
import { loadPolicy } from "../policy.js";
import {
  recommendPackages,
  RecommendSearchError,
  type Recommendation,
} from "../recommend.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import type { Decision } from "../types.js";

export interface RecommendCommandOptions {
  query: string;
  limit?: number;
  json: boolean;
  noReputation?: boolean;
  failOnOsvError?: boolean;
}

const DECISION_PAINT: Record<Decision, (t: string) => string> = {
  allow: green,
  allow_with_warnings: yellow,
  require_approval: yellow,
  block: red,
};

function formatDownloads(weekly?: number): string | null {
  if (weekly === undefined) return null;
  const compact = new Intl.NumberFormat("en", { notation: "compact" }).format(weekly);
  return `${compact}/wk`;
}

/** Up to `max` deduction notes across categories — the "why not 100" lines. */
function topDeductions(r: Recommendation, max: number): string[] {
  return r.score.categories.flatMap((c) => c.notes ?? []).slice(0, max);
}

/**
 * `targate recommend "<need>"` — suggest packages for a need, safest first.
 * Candidates come from npm search; each is analyzed with the full
 * deterministic pipeline and ranked by security score (adoption breaks ties).
 */
export async function recommendCommand(opts: RecommendCommandOptions): Promise<number> {
  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(dim(`\nSearching npm for "${opts.query}" and analyzing the top candidates ...`));

  const policy = await loadPolicy();
  let report;
  try {
    report = await recommendPackages(opts.query, {
      limit: opts.limit,
      noReputation: opts.noReputation,
      failOnOsvError: opts.failOnOsvError,
      policy,
      onCandidate: (name, outcome, detail) => {
        if (outcome === "ok") note(dim(`  ✓ ${name} analyzed`));
        else note(yellow(`  ✗ ${name} excluded — ${detail}`));
      },
    });
  } catch (err) {
    if (err instanceof RecommendSearchError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }

  if (opts.json) {
    printJson("recommend", { ...report, exitCode: 0 });
    return 0;
  }

  if (report.analyzed === 0) {
    console.log(yellow(`\nnpm search returned no candidates for "${opts.query}".`));
    return 0;
  }

  console.log(
    bold(`\nRecommendations for "${opts.query}"`) +
      dim(
        ` — ${report.recommendations.length} of ${report.analyzed} candidates eligible, safest first`,
      ),
  );
  console.log("");

  report.recommendations.forEach((r, i) => {
    const meta = [
      `score ${r.score.total}/100`,
      formatDownloads(r.weeklyDownloads),
      DECISION_PAINT[r.assessment.decision](r.assessment.decision.replace(/_/g, " ")),
    ]
      .filter(Boolean)
      .join(dim("  ·  "));
    console.log(`  ${bold(`${i + 1}. ${r.name}@${r.version}`)}   ${meta}`);
    if (r.description) console.log(dim(`     ${r.description.slice(0, 100)}`));
    for (const deduction of topDeductions(r, 3)) console.log(dim(`       - ${deduction}`));
    console.log("");
  });

  if (report.rejected.length > 0) {
    console.log(bold("Excluded:"));
    for (const rej of report.rejected) {
      console.log(red(`  ✗ ${rej.name}${rej.version ? `@${rej.version}` : ""}`) + dim(` — ${rej.reason}`));
    }
    console.log("");
  }

  if (report.recommendations.length === 0) {
    console.log(yellow("No candidate survived the analysis — nothing to recommend."));
  } else {
    const winner = report.recommendations[0];
    console.log(
      dim("Candidates come from npm search relevance — targate ranks the safety of what search returned; it cannot know every package that could serve the need."),
    );
    console.log(cyan(`\nNext: targate add ${winner.name}`) + dim(" (gates the actual install)"));
  }
  return 0;
}
