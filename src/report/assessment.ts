import type { SecurityScore } from "../score.js";
import type {
  Decision,
  PackageMetadata,
  RiskAssessment,
  Signals,
} from "../types.js";
import { bold, clean, cyan, dim, green, red, yellow } from "./colors.js";
import { renderScoreLines } from "./score.js";

export const DECISION_LABEL: Record<Decision, string> = {
  allow: "ALLOW",
  allow_with_warnings: "ALLOW WITH WARNINGS",
  require_approval: "REQUIRE MANUAL APPROVAL",
  block: "BLOCK",
};

export function decisionColor(decision: Decision): (text: string) => string {
  return decision === "allow" ? green : decision === "block" ? red : yellow;
}

const check = (flag: boolean, good: string, bad: string) =>
  flag ? yellow(`⚠ ${bad}`) : dim(`✓ ${good}`);

const daysAgo = (n: number): string => `${n} day${n === 1 ? "" : "s"} ago`;

export function renderReport(
  metadata: PackageMetadata,
  signals: Signals,
  assessment: RiskAssessment,
  score?: SecurityScore,
  opts: { deep?: boolean } = {},
): string {
  const lines: string[] = [];
  const paint = decisionColor(assessment.decision);
  // "published" is the ANALYZED VERSION's age (versionAgeDays). metadata.ageInDays
  // is the PACKAGE's first-publish age (time.created) — a different thing — used
  // only as a legacy fallback when a persisted run lacks the per-version value.
  const publishedAgeDays =
    signals.reputation.versionAgeDays ?? metadata.ageInDays;
  const analyzedIsLatest =
    signals.reputation.latestVersion === metadata.version;
  lines.push("");
  lines.push(
    bold(
      `Pre-install review — ${clean(metadata.name)}@${clean(metadata.version)}`,
    ),
  );
  lines.push(dim("─".repeat(60)));
  if (metadata.description) lines.push(dim(clean(metadata.description)));
  lines.push(
    dim(
      [
        metadata.license ? `license: ${clean(metadata.license)}` : null,
        publishedAgeDays !== undefined
          ? `published: ${daysAgo(publishedAgeDays)}${analyzedIsLatest ? " (latest)" : ""}`
          : null,
        // "last updated" = the package's latest release, shown when the analyzed
        // version is NOT the latest, so a stale pick vs an actively-maintained
        // package is visible. Informational; never drives the verdict.
        signals.reputation.latestVersionAgeDays !== undefined &&
        signals.reputation.latestVersion &&
        !analyzedIsLatest
          ? `last updated: ${daysAgo(signals.reputation.latestVersionAgeDays)} (latest ${clean(signals.reputation.latestVersion)})`
          : null,
        // Package maturity: how long the package has existed (time.created).
        // Shown only when it differs from this version's publish age, so the
        // very first release doesn't render a redundant duplicate line.
        metadata.ageInDays !== undefined &&
        metadata.ageInDays !== publishedAgeDays
          ? `first release: ${daysAgo(metadata.ageInDays)}`
          : null,
        `deps: ${metadata.dependencyCount}`,
        metadata.repositoryUrl
          ? `repo: ${clean(metadata.repositoryUrl)}`
          : "repo: MISSING",
        metadata.registrySource && metadata.registrySource !== "default"
          ? `registry: ${clean(metadata.registryUrl)} (${metadata.registrySource === "scope" ? "scoped" : "override"})`
          : null,
      ]
        .filter(Boolean)
        .join("  ·  "),
    ),
  );
  lines.push("");
  lines.push(bold("Analysis"));
  lines.push(...renderSignalLines(signals));
  lines.push("");
  if (score) {
    lines.push(...renderScoreLines(score));
    lines.push("");
  }
  lines.push(
    bold("Decision: ") +
      paint(bold(DECISION_LABEL[assessment.decision])) +
      dim(`   (risk: ${assessment.risk}, source: ${assessment.source})`),
  );
  const deterministic = assessment.deterministic;
  if (deterministic && assessment.source === "ai") {
    const line = `Deterministic verdict: ${DECISION_LABEL[deterministic.decision]} (rules) — the AI may only make this stricter`;
    lines.push(deterministic.decision === "block" ? red(line) : dim(line));
  }
  lines.push("", clean(assessment.summary), "", bold("Reasons"));
  for (const reason of assessment.reasons) lines.push(`  • ${clean(reason)}`);
  lines.push(
    "",
    bold("Recommendation"),
    `  ${clean(assessment.recommendedAction)}`,
  );
  if (assessment.suggestedAlternatives?.length) {
    lines.push("", bold("Suggested alternatives"));
    for (const alternative of assessment.suggestedAlternatives)
      lines.push(`  • ${clean(alternative)}`);
  }
  // Shallow runs analyze ONLY the named package — a clean verdict says nothing
  // about its transitive tree. Say so on the allow-ish paths so an ALLOW is not
  // read as "the whole install is safe". A --deep run vets the tree, so skip it.
  if (
    !opts.deep &&
    (assessment.decision === "allow" ||
      assessment.decision === "allow_with_warnings")
  ) {
    lines.push(
      "",
      dim(
        `Note: only ${clean(metadata.name)} was analyzed — its transitive dependencies were not. ` +
          "Re-run with --deep, or use `targate install`, to vet the whole tree.",
      ),
    );
  }
  lines.push("");
  return lines.join("\n");
}

/** The deterministic checklist shared by assessment and explanation views. */
export function renderSignalLines(signals: Signals): string[] {
  const lines: string[] = [];
  for (const reason of signals.analysisDegraded ?? []) {
    lines.push("  " + yellow(`⚠ analysis incomplete — UNKNOWN: ${reason}`));
  }
  const artifact = signals.artifact;
  if (artifact) {
    const artifactLine = `${artifact.trust} · ${artifact.digest === "unavailable" ? artifact.digest : artifact.digest.slice(0, 27) + "…"}`;
    lines.push(
      "  " +
        (artifact.trust === "mutated"
          ? red(`! artifact identity MISMATCH — ${artifactLine}`)
          : ["unverified", "public-unavailable", "private-only"].includes(
                artifact.trust,
              )
            ? yellow(`⚠ artifact identity: ${artifactLine}`)
            : dim(`✓ artifact identity: ${artifactLine}`)),
    );
  } else {
    lines.push(
      "  " + yellow("⚠ artifact identity unavailable (legacy saved run)"),
    );
  }
  lines.push(
    "  " +
      check(
        signals.hasLifecycleScripts,
        "no lifecycle scripts",
        `lifecycle scripts: ${clean(Object.keys(signals.lifecycleScripts).join(", "))}`,
      ),
  );
  lines.push(
    "  " +
      check(
        signals.knownMalicious,
        "no known malicious-package records (OSV/OpenSSF)",
        `KNOWN MALICIOUS: ${clean(signals.maliciousRecords.map((record) => record.id).join(", "))}`,
      ),
  );
  lines.push(
    "  " +
      check(
        signals.nameSimilarity !== null,
        "no typosquatting suspicion",
        `name similar to "${clean(signals.nameSimilarity?.similarTo ?? "")}"`,
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
      (signals.internalScope
        ? cyan(
            "ℹ internal scope — OSV, downloads and maintainer lookups skipped (policy internalScopes: the package name stays private; malicious-package status NOT externally checked)",
          )
        : signals.osvUnavailable
          ? yellow(
              "⚠ OSV/OpenSSF lookup unavailable — malicious-package status UNKNOWN",
            )
          : dim("✓ OSV/OpenSSF lookup completed")),
  );
  for (const finding of signals.scriptCommandFindings)
    lines.push("  " + red(`! ${clean(finding)}`));
  lines.push(
    "  " +
      (signals.analysisDegraded?.length
        ? yellow("⚠ native/content inspection incomplete — UNKNOWN")
        : signals.hasNativeCode
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
      .map((permission) =>
        dangerous.has(permission) ? red(clean(permission)) : clean(permission),
      )
      .join(", ");
    lines.push("  " + yellow("⚠ Android permissions: ") + rendered);
  }
  for (const finding of [
    ...signals.rnHardening.podspecFindings,
    ...signals.rnHardening.gradleFindings,
    ...signals.rnHardening.autolinkingFindings,
  ])
    lines.push("  " + yellow(`⚠ ${clean(finding)}`));
  for (const note of signals.rnHardening.compatNotes)
    lines.push("  " + cyan(`ℹ ${clean(note)}`));
  if (signals.advisories.length > 0) {
    lines.push(
      "  " +
        yellow(
          `⚠ vulnerability advisories: ${clean(signals.advisories.map((advisory) => advisory.id).join(", "))}`,
        ),
    );
  }
  lines.push(...renderReputationLines(signals.reputation, signals.package));
  if (signals.content.suspiciousFiles.length > 0) {
    lines.push("  " + dim("static findings:"));
    for (const finding of signals.content.suspiciousFiles.slice(0, 8)) {
      lines.push("    " + dim(`- ${clean(finding)}`));
    }
  }
  return lines;
}

function renderReputationLines(
  reputation: Signals["reputation"],
  packageName: string,
): string[] {
  const lines: string[] = [];
  const push = (line: string) => lines.push("  " + line);
  if (reputation.deprecated !== false)
    push(
      yellow(
        `⚠ version is DEPRECATED: "${clean(String(reputation.deprecated))}"`,
      ),
    );
  if (reputation.hasProvenance)
    push(dim("✓ npm provenance attestation present"));
  if (reputation.downloads.status === "ok") {
    const weekly = reputation.downloads.weeklyDownloads;
    if (reputation.downloads.trend === "spike")
      push(yellow(`⚠ download spike: ${reputation.downloads.trendDetail}`));
    else if (reputation.downloads.trend === "drop")
      push(yellow(`⚠ download drop: ${reputation.downloads.trendDetail}`));
    else if (weekly !== undefined && weekly < 100)
      push(yellow(`⚠ low adoption: ${weekly} weekly downloads`));
    else if (weekly !== undefined)
      push(dim(`✓ ~${weekly.toLocaleString("en-US")} weekly downloads`));
  } else if (reputation.downloads.status === "unavailable") {
    push(yellow("⚠ download stats unavailable — adoption UNKNOWN"));
  }
  if (reputation.repo.status === "ok" && reputation.repo.archived)
    push(yellow("⚠ GitHub repository is ARCHIVED"));
  else if (reputation.repo.status === "not-found")
    push(yellow("⚠ repository URL points to a missing/private GitHub repo"));
  else if (reputation.repo.status === "rate-limited")
    push(
      yellow(
        "⚠ GitHub lookup rate-limited — archived status UNKNOWN (set GITHUB_TOKEN to raise the limit)",
      ),
    );
  else if (reputation.repo.status === "unavailable")
    push(yellow("⚠ GitHub unreachable — archived status UNKNOWN"));
  if (reputation.maintainerChange?.changed) {
    push(
      yellow(
        `⚠ maintainer change since previous release: ${clean(reputation.maintainerChange.detail ?? "")}`,
      ),
    );
  }
  const intel = reputation.maintainerIntel;
  if (intel && intel.status !== "skipped") {
    if (intel.newMaintainerNoTrackRecord.length > 0) {
      push(
        red(
          `! new maintainer(s) with no other published packages: ${clean(intel.newMaintainerNoTrackRecord.join(", "))}`,
        ),
      );
    }
    if (intel.status === "unavailable")
      push(
        yellow(
          "⚠ maintainer portfolio lookup unavailable — track record UNKNOWN",
        ),
      );
    else {
      for (const maintainer of intel.maintainers) {
        if (maintainer.status !== "ok") continue;
        const notable = (maintainer.topPackages ?? [])
          .map((item) => item.name)
          .filter((name) => name !== packageName)
          .slice(0, 2)
          .join(", ");
        push(
          dim(
            `✓ maintainer ${clean(maintainer.name)}: ${maintainer.packageCount ?? "?"} package(s)${notable ? ` (notable: ${clean(notable)})` : ""}`,
          ),
        );
      }
    }
  }
  if (reputation.releaseGapAnomaly)
    push(
      yellow(
        `⚠ fresh release after ${reputation.releaseAfterInactivityDays} days of inactivity`,
      ),
    );
  if (reputation.repositoryMismatch)
    push(
      yellow(
        `⚠ repository mismatch: ${clean(reputation.repositoryMismatchDetail ?? "")}`,
      ),
    );
  return lines;
}
