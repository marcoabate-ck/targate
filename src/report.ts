import type { VersionDiff } from "./diff.js";
import type { SecurityScore } from "./score.js";
import type { Decision, PackageMetadata, RiskAssessment, RiskLevel, Signals } from "./types.js";

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
  score?: SecurityScore,
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
  lines.push(...renderSignalLines(signals));
  lines.push("");

  if (score) {
    lines.push(...renderScoreLines(score));
    lines.push("");
  }

  lines.push(
    bold("Decision: ") +
      color(bold(DECISION_LABEL[assessment.decision])) +
      dim(`   (risk: ${assessment.risk}, source: ${assessment.source})`),
  );
  const det = assessment.deterministic;
  if (det && assessment.source === "ai") {
    const line = `Deterministic verdict: ${DECISION_LABEL[det.decision]} (rules) — the AI may only make this stricter`;
    lines.push(det.decision === "block" ? red(line) : dim(line));
  }
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

/**
 * The "Analysis" checklist body — every deterministic signal as a ✓/⚠/ℹ line.
 * Shared by renderReport and renderExplanation.
 */
export function renderSignalLines(signals: Signals): string[] {
  const lines: string[] = [];
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
  lines.push(...renderReputationLines(signals.reputation, signals.package));
  if (signals.content.suspiciousFiles.length > 0) {
    lines.push("  " + dim("static findings:"));
    for (const f of signals.content.suspiciousFiles.slice(0, 8)) {
      lines.push("    " + dim(`- ${f}`));
    }
  }
  return lines;
}

/** Reputation lines: unknown states always SAY unknown — never imply clean. */
function renderReputationLines(rep: Signals["reputation"], packageName: string): string[] {
  const lines: string[] = [];
  const push = (line: string) => lines.push("  " + line);

  if (rep.deprecated !== false) push(yellow(`⚠ version is DEPRECATED: "${rep.deprecated}"`));

  if (rep.hasProvenance) push(dim("✓ npm provenance attestation present"));

  switch (rep.downloads.status) {
    case "ok": {
      const weekly = rep.downloads.weeklyDownloads;
      if (rep.downloads.trend === "spike") {
        push(yellow(`⚠ download spike: ${rep.downloads.trendDetail}`));
      } else if (rep.downloads.trend === "drop") {
        push(yellow(`⚠ download drop: ${rep.downloads.trendDetail}`));
      } else if (weekly !== undefined && weekly < 100) {
        push(yellow(`⚠ low adoption: ${weekly} weekly downloads`));
      } else if (weekly !== undefined) {
        push(dim(`✓ ~${weekly.toLocaleString("en-US")} weekly downloads`));
      }
      break;
    }
    case "unavailable":
      push(yellow("⚠ download stats unavailable — adoption UNKNOWN"));
      break;
    case "skipped":
      break;
  }

  switch (rep.repo.status) {
    case "ok":
      if (rep.repo.archived) push(yellow("⚠ GitHub repository is ARCHIVED"));
      break;
    case "not-found":
      push(yellow("⚠ repository URL points to a missing/private GitHub repo"));
      break;
    case "rate-limited":
      push(
        yellow(
          "⚠ GitHub lookup rate-limited — archived status UNKNOWN (set GITHUB_TOKEN to raise the limit)",
        ),
      );
      break;
    case "unavailable":
      push(yellow("⚠ GitHub unreachable — archived status UNKNOWN"));
      break;
    case "not-github":
    case "skipped":
      break;
  }

  if (rep.maintainerChange?.changed) {
    push(yellow(`⚠ maintainer change since previous release: ${rep.maintainerChange.detail ?? ""}`));
  }
  const intel = rep.maintainerIntel;
  if (intel && intel.status !== "skipped") {
    if (intel.newMaintainerNoTrackRecord.length > 0) {
      push(
        red(
          `! new maintainer(s) with no other published packages: ${intel.newMaintainerNoTrackRecord.join(", ")}`,
        ),
      );
    }
    if (intel.status === "unavailable") {
      push(yellow("⚠ maintainer portfolio lookup unavailable — track record UNKNOWN"));
    } else {
      for (const m of intel.maintainers) {
        if (m.status !== "ok") continue;
        const notable = (m.topPackages ?? [])
          .map((p) => p.name)
          .filter((n) => n !== packageName)
          .slice(0, 2)
          .join(", ");
        push(
          dim(
            `✓ maintainer ${m.name}: ${m.packageCount ?? "?"} package(s)${notable ? ` (notable: ${notable})` : ""}`,
          ),
        );
      }
    }
  }
  if (rep.releaseGapAnomaly) {
    push(yellow(`⚠ fresh release after ${rep.releaseAfterInactivityDays} days of inactivity`));
  }
  if (rep.repositoryMismatch) {
    push(yellow(`⚠ repository mismatch: ${rep.repositoryMismatchDetail ?? ""}`));
  }
  return lines;
}

/**
 * Risks that remain even on an allowed package — honest caveats for the
 * explanation view. Pure and exported for tests.
 */
export function residualRisks(signals: Signals): string[] {
  const risks: string[] = [];
  if (signals.hasNativeCode) {
    risks.push("native/compiled code cannot be fully vetted by static analysis");
  }
  if (signals.hasLifecycleScripts) {
    risks.push("lifecycle scripts will run on installs that allow them");
  }
  if (signals.osvUnavailable) {
    risks.push("the malicious-package status was UNKNOWN at analysis time (OSV unavailable)");
  }
  if (signals.content.hasMinifiedCode) {
    risks.push("minified/obfuscated code limits what static analysis can see");
  }
  if (signals.content.hasProcessEnvAccess && signals.content.hasNetworkCalls) {
    risks.push("code reads environment variables AND makes network calls — an exfiltration surface");
  }
  if (signals.recentPublish) {
    risks.push("recently published — little community exposure yet");
  }
  if (signals.reputation.repo.status === "rate-limited" || signals.reputation.repo.status === "unavailable") {
    risks.push("the repository's archived status could not be checked");
  }
  return risks;
}

export interface ExplanationOptions {
  /** A committed team approval for this exact version, when one exists. */
  approval?: { mode: string; approvedAt: string; approvedBy?: string } | null;
  /** Set when explaining a recorded run instead of a fresh analysis. */
  fromLastRun?: { command: string; timestamp: string };
}

/**
 * The `targate explain` view: decision first, then WHY — reasons partitioned
 * into the engine's own findings vs team/policy adjustments, the full
 * deterministic checklist, the AI's reasoning when one ran, residual risks,
 * and the score breakdown.
 */
export function renderExplanation(
  metadata: PackageMetadata,
  signals: Signals,
  assessment: RiskAssessment,
  score?: SecurityScore,
  opts: ExplanationOptions = {},
): string {
  const lines: string[] = [];
  const color = decisionColor(assessment.decision);

  // Reasons prefixed [policy]/[team] are escalations/clearings applied on top
  // of the engine verdict; the rest belong to the engine (rules or AI).
  const adjustments = assessment.reasons.filter((r) => /^\[(policy|team)\]/.test(r));
  const engineReasons = assessment.reasons.filter((r) => !/^\[(policy|team)\]/.test(r));

  lines.push("");
  lines.push(
    bold(`Why ${metadata.name}@${metadata.version} → `) +
      color(bold(DECISION_LABEL[assessment.decision])),
  );
  lines.push(
    dim(
      `(risk: ${assessment.risk} · source: ${assessment.source}${
        opts.fromLastRun ? ` · from last ${opts.fromLastRun.command} run, ${opts.fromLastRun.timestamp}` : ""
      })`,
    ),
  );
  lines.push(dim("─".repeat(60)));
  lines.push(assessment.summary);
  lines.push("");

  // For AI verdicts, show the rules engine's own conclusion FIRST — the split
  // between deterministic findings and the model's interpretation is the point.
  if (assessment.source === "ai" && assessment.deterministic) {
    const det = assessment.deterministic;
    lines.push(bold("Deterministic verdict (rules engine)"));
    lines.push(
      `  ${decisionColor(det.decision)(DECISION_LABEL[det.decision])}` + dim(` (risk: ${det.risk})`),
    );
    for (const reason of det.reasons) lines.push(dim(`  • ${reason}`));
    lines.push(dim("  The AI interprets these signals but can only make the verdict stricter."));
    lines.push("");
  }

  const reasonsTitle = assessment.source === "ai" ? "AI reasoning" : "Main reasons";
  lines.push(bold(reasonsTitle));
  if (engineReasons.length === 0) {
    lines.push(dim("  (no findings — nothing raised a flag)"));
  }
  engineReasons.forEach((reason, i) => lines.push(`  ${i + 1}. ${reason}`));
  lines.push("");

  if (adjustments.length > 0) {
    lines.push(bold("Team & policy adjustments"));
    for (const a of adjustments) lines.push(`  • ${a}`);
    lines.push("");
  }

  if (opts.approval) {
    lines.push(
      cyan(
        `ℹ a committed team approval exists for this exact version (${opts.approval.mode}, ${opts.approval.approvedAt.slice(0, 10)}${opts.approval.approvedBy ? `, by ${opts.approval.approvedBy}` : ""})`,
      ),
    );
    lines.push("");
  }

  lines.push(bold("Deterministic findings"));
  lines.push(...renderSignalLines(signals));
  lines.push("");

  const risks = residualRisks(signals);
  if (risks.length > 0) {
    lines.push(bold("Residual risks"));
    for (const risk of risks) lines.push(yellow(`  • ${risk}`));
    lines.push("");
  }

  if (score) {
    lines.push(...renderScoreLines(score));
    lines.push("");
  }

  lines.push(bold("Recommendation"));
  lines.push(`  ${assessment.recommendedAction}`);
  if (assessment.suggestedAlternatives?.length) {
    lines.push("");
    lines.push(bold("Suggested alternatives"));
    for (const alt of assessment.suggestedAlternatives) lines.push(`  • ${alt}`);
  }
  lines.push("");
  return lines.join("\n");
}

/** The score block: total + per-category breakdown. Informational only. */
export function renderScoreLines(score: SecurityScore): string[] {
  const paint = score.total >= 80 ? green : score.total >= 50 ? yellow : red;
  const lines: string[] = [];
  lines.push(bold("Security score: ") + paint(bold(`${score.total}/100`)));
  if (score.floorReason) {
    lines.push("  " + red(`✗ score floored: ${score.floorReason}`));
  }
  const width = Math.max(...score.categories.map((c) => c.label.length));
  for (const c of score.categories) {
    const deduction = c.notes?.[0] ? `   (${c.notes[0]})` : "";
    lines.push("  " + dim(`${c.label.padEnd(width)}  ${String(c.score).padStart(2)}/${c.max}${deduction}`));
  }
  lines.push("  " + dim("(informational — does not affect the decision)"));
  return lines;
}

const RISK_COLOR: Record<RiskLevel, (t: string) => string> = { low: green, medium: yellow, high: red };

/** Human-readable version-to-version diff — only sections that changed. */
export function renderVersionDiff(diff: VersionDiff): string {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);

  push("");
  push(bold(`Version diff — ${diff.package} ${diff.from.version} → ${diff.to.version}`) + dim(` (${diff.direction})`));
  const dates = [
    diff.from.publishDate ? `from: ${diff.from.publishDate.slice(0, 10)}` : null,
    diff.to.publishDate ? `to: ${diff.to.publishDate.slice(0, 10)}` : null,
  ].filter(Boolean);
  if (dates.length) push(dim(dates.join("  ·  ")));
  push(dim("─".repeat(60)));

  const ls = diff.lifecycleScripts;
  if (ls.added.length || ls.removed.length || ls.changed.length) {
    push(bold("Lifecycle scripts"));
    for (const s of ls.added) push(red(`  + ${s.hook}: ${s.after}`));
    for (const s of ls.changed) push(yellow(`  ~ ${s.hook}: ${s.before}  →  ${s.after}`));
    for (const s of ls.removed) push(dim(`  - ${s.hook}: ${s.before}`));
    push();
  }
  if (diff.newScriptFindings.length) {
    push(bold("New suspicious script commands"));
    for (const f of diff.newScriptFindings) push(red(`  ! ${f}`));
    push();
  }
  const dep = diff.dependencies;
  if (dep.added.length || dep.removed.length || dep.changed.length) {
    push(bold("Dependencies"));
    for (const d of dep.added) push((d.nonRegistrySpec ? red : green)(`  + ${d.name}${d.afterRange ? `@${d.afterRange}` : ""}`));
    for (const d of dep.changed) push((d.nonRegistrySpec ? red : yellow)(`  ~ ${d.name}: ${d.beforeRange}  →  ${d.afterRange}`));
    for (const d of dep.removed) push(dim(`  - ${d.name}${d.beforeRange ? `@${d.beforeRange}` : ""}`));
    push();
  }
  if (diff.maintainers.added.length || diff.maintainers.removed.length) {
    push(bold("Maintainers"));
    for (const m of diff.maintainers.added) push(yellow(`  + ${m}`));
    for (const m of diff.maintainers.removed) push(dim(`  - ${m}`));
    push();
  }
  if (diff.repositoryChanged) {
    push(bold("Repository"));
    push(yellow(`  ${diff.repositoryChanged.before ?? "(none)"}  →  ${diff.repositoryChanged.after ?? "(none)"}`));
    push();
  }
  const ns = diff.nativeSurface;
  if (ns.added.length || ns.newBinaries.length || ns.newAndroidPermissions.length) {
    push(bold("Native surface"));
    for (const l of ns.added) push(yellow(`  + ${l}`));
    for (const b of ns.newBinaries) push(red(`  + binary: ${b}`));
    for (const p of ns.newAndroidPermissions) push(red(`  + permission: ${p}`));
    push();
  }
  if (diff.advisories.added.length || diff.advisories.resolved.length) {
    push(bold("Advisories"));
    for (const a of diff.advisories.added) push(yellow(`  + ${a.id}${a.summary ? ` — ${a.summary}` : ""}`));
    for (const a of diff.advisories.resolved) push(green(`  - resolved: ${a.id}`));
    push();
  }
  if (diff.provenanceLost || diff.deprecatedAdded) {
    push(bold("Reputation"));
    if (diff.provenanceLost) push(yellow("  ! npm provenance attestation lost"));
    if (diff.deprecatedAdded) push(yellow(`  ! now deprecated: ${diff.deprecatedAdded}`));
    push();
  }
  if (diff.size && (diff.size.unpackedSizeDelta ?? 0) !== 0) {
    const kb = Math.round((diff.size.unpackedSizeDelta ?? 0) / 1024);
    push(bold("Size") + dim(`  unpacked ${kb >= 0 ? "+" : ""}${kb.toLocaleString("en-US")} kB` + (diff.size.fileCountDelta !== undefined ? `, ${diff.size.fileCountDelta >= 0 ? "+" : ""}${diff.size.fileCountDelta} files` : "")));
    push();
  }
  if (diff.score.delta !== 0) {
    const c = diff.score.delta < 0 ? red : green;
    push(bold("Security score") + dim(`  ${diff.score.before} → `) + c(`${diff.score.after}`) + dim(` (${diff.score.delta >= 0 ? "+" : ""}${diff.score.delta})`));
    push();
  }

  const anyChange =
    ls.added.length || ls.removed.length || ls.changed.length || diff.newScriptFindings.length ||
    dep.added.length || dep.removed.length || dep.changed.length || diff.maintainers.added.length ||
    diff.maintainers.removed.length || diff.repositoryChanged || ns.added.length || ns.newBinaries.length ||
    ns.newAndroidPermissions.length || diff.advisories.added.length || diff.advisories.resolved.length ||
    diff.provenanceLost || diff.deprecatedAdded || diff.score.delta !== 0;
  if (!anyChange) push(dim("No noteworthy changes between these versions."));

  push(bold("Diff risk: ") + RISK_COLOR[diff.diffRisk](bold(diff.diffRisk.toUpperCase())));
  for (const r of diff.riskReasons) push(`  • ${r.replace(/^\[(high|medium)\] /, "")}`);
  push();
  return lines.join("\n");
}
