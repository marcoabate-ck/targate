import type { SecurityScore } from "../score.js";
import { bold, dim, green, red, yellow } from "./colors.js";

/** The score block: total + per-category breakdown. Informational only. */
export function renderScoreLines(score: SecurityScore): string[] {
  const paint = score.total >= 80 ? green : score.total >= 50 ? yellow : red;
  const lines: string[] = [];
  lines.push(bold("Security score: ") + paint(bold(`${score.total}/100`)));
  if (score.floorReason) lines.push("  " + red(`✗ score floored: ${score.floorReason}`));
  const width = Math.max(...score.categories.map((category) => category.label.length));
  for (const category of score.categories) {
    const deduction = category.notes?.[0] ? `   (${category.notes[0]})` : "";
    lines.push(
      "  " +
        dim(
          `${category.label.padEnd(width)}  ${String(category.score).padStart(2)}/${category.max}${deduction}`,
        ),
    );
  }
  lines.push("  " + dim("(informational — does not affect the decision)"));
  return lines;
}
