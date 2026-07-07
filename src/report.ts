import type { Decision, PackageMetadata, RiskAssessment, Signals } from "./types.js";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: number, text: string) =>
  useColor ? `[${code}m${text}[0m` : text;

export const bold = (t: string) => c(1, t);
export const dim = (t: string) => c(2, t);
export const red = (t: string) => c(31, t);
export const green = (t: string) => c(32, t);
export const yellow = (t: string) => c(33, t);
export const cyan = (t: string) => c(36, t);

const DECISION_LABEL: Record<Decision, string> = {
  allow: "ALLOW",
  allow_with_warnings: "ALLOW WITH WARNINGS",
  require_approval: "REQUIRE MANUAL APPROVAL",
  block: "BLOCK",
};

function decisionColor(decision: Decision): (t: string) => string {
  switch (decision) {
    case "allow":
      return green;
    case "allow_with_warnings":
      return yellow;
    case "require_approval":
      return yellow;
    case "block":
      return red;
  }
}

const check = (flag: boolean, good: string, bad: string) =>
  flag ? yellow(`⚠ ${bad}`) : dim(`✓ ${good}`);

export function renderReport(
  metadata: PackageMetadata,
  signals: Signals,
  assessment: RiskAssessment,
): string {
  const lines: string[] = [];
  const color = decisionColor(assessment.decision);

  lines.push("");
  lines.push(bold(`Pre-install review — ${metadata.name}@${metadata.version}`));
  lines.push(dim("─".repeat(60)));

  if (metadata.description) lines.push(dim(metadata.description));
  lines.push(
    dim(
      [
        metadata.license ? `license: ${metadata.license}` : null,
        metadata.ageInDays !== undefined
          ? `published: ${metadata.ageInDays} days ago`
          : null,
        `deps: ${metadata.dependencyCount}`,
        metadata.repositoryUrl ? `repo: ${metadata.repositoryUrl}` : "repo: MISSING",
      ]
        .filter(Boolean)
        .join("  ·  "),
    ),
  );
  lines.push("");

  lines.push(bold("Analysis"));
  lines.push(
    "  " +
      check(
        signals.hasLifecycleScripts,
        "no lifecycle scripts",
        `lifecycle scripts: ${Object.keys(signals.lifecycleScripts).join(", ")}`,
      ),
  );
  lines.push(
    "  " +
      check(
        signals.knownMalicious,
        "no known malicious-package records (OSV/OpenSSF)",
        `KNOWN MALICIOUS: ${signals.maliciousRecords.map((r) => r.id).join(", ")}`,
      ),
  );
  lines.push(
    "  " +
      check(
        signals.nameSimilarity !== null,
        "no typosquatting suspicion",
        `name similar to "${signals.nameSimilarity?.similarTo}"`,
      ),
  );
  lines.push(
    "  " +
      check(
        signals.repositoryMissing,
        "repository metadata present",
        "repository metadata missing",
      ),
  );
  lines.push(
    "  " +
      (signals.osvUnavailable
        ? yellow("⚠ OSV/OpenSSF lookup unavailable — malicious-package status UNKNOWN")
        : dim("✓ OSV/OpenSSF lookup completed")),
  );
  for (const finding of signals.scriptCommandFindings) {
    lines.push("  " + red(`! ${finding}`));
  }
  lines.push(
    "  " +
      (signals.hasNativeCode
        ? cyan(
            `ℹ native code detected (${[
              signals.nativeSurface.hasIos ? "iOS" : null,
              signals.nativeSurface.hasAndroid ? "Android" : null,
              signals.nativeSurface.hasPodspec ? "Podspec" : null,
              signals.nativeSurface.hasGradle ? "Gradle" : null,
              signals.nativeSurface.hasCMake ? "CMake" : null,
            ]
              .filter(Boolean)
              .join(", ")})`,
          )
        : dim("✓ no native code")),
  );
  if (signals.nativeSurface.androidPermissions.length > 0) {
    const dangerous = new Set(signals.rnHardening.dangerousPermissions);
    const rendered = signals.nativeSurface.androidPermissions
      .map((p) => (dangerous.has(p) ? red(p) : p))
      .join(", ");
    lines.push("  " + yellow(`⚠ Android permissions: `) + rendered);
  }
  for (const finding of [
    ...signals.rnHardening.podspecFindings,
    ...signals.rnHardening.gradleFindings,
    ...signals.rnHardening.autolinkingFindings,
  ]) {
    lines.push("  " + yellow(`⚠ ${finding}`));
  }
  for (const note of signals.rnHardening.compatNotes) {
    lines.push("  " + cyan(`ℹ ${note}`));
  }
  if (signals.advisories.length > 0) {
    lines.push(
      "  " +
        yellow(
          `⚠ vulnerability advisories: ${signals.advisories.map((a) => a.id).join(", ")}`,
        ),
    );
  }
  if (signals.content.suspiciousFiles.length > 0) {
    lines.push("  " + dim("static findings:"));
    for (const f of signals.content.suspiciousFiles.slice(0, 8)) {
      lines.push("    " + dim(`- ${f}`));
    }
  }
  lines.push("");

  lines.push(
    bold("Decision: ") +
      color(bold(DECISION_LABEL[assessment.decision])) +
      dim(`   (risk: ${assessment.risk}, source: ${assessment.source})`),
  );
  lines.push("");
  lines.push(assessment.summary);
  lines.push("");
  lines.push(bold("Reasons"));
  for (const reason of assessment.reasons) {
    lines.push(`  • ${reason}`);
  }
  lines.push("");
  lines.push(bold("Recommendation"));
  lines.push(`  ${assessment.recommendedAction}`);
  if (assessment.suggestedAlternatives?.length) {
    lines.push("");
    lines.push(bold("Suggested alternatives"));
    for (const alt of assessment.suggestedAlternatives) {
      lines.push(`  • ${alt}`);
    }
  }
  lines.push("");

  return lines.join("\n");
}
