import { isHardBlock } from "./rules.js";
import type { Signals } from "./types.js";

/**
 * Security Score — a 0–100 aggregation of the deterministic signals, with a
 * per-category breakdown.
 *
 * INFORMATIONAL ONLY. The score is a risk-signal aggregation, not a proof of
 * safety, and it is never consulted by evaluateRules, clampDecision, or
 * applyPolicy. That invariant is structural: this module imports rules.ts;
 * rules.ts (and policy.ts) never import this module.
 */

export interface ScoreCategory {
  /** Stable machine-readable id (part of the JSON contract). */
  name: string;
  /** Human label for the report. */
  label: string;
  /** Points awarded, integer, 0..max. */
  score: number;
  max: number;
  /** One entry per deduction actually applied. */
  notes?: string[];
}

export interface SecurityScore {
  /** 0..100. */
  total: number;
  categories: ScoreCategory[];
  /** Set when the hard floor fired (known-malicious / fetch-and-execute). */
  floorReason?: string;
}

// The rubric, one screen. Category maxes sum to 100.
const MAX = {
  vulnerabilities: 25,
  install_behavior: 20,
  content: 15,
  maturity: 10,
  maintainer_trust: 10,
  repository: 10,
  surface: 10,
} as const;

const FLOOR_KNOWN_MALICIOUS = 5;
const FLOOR_HARD_BLOCK = 10;

class Category {
  score: number;
  notes: string[] = [];
  constructor(
    readonly name: keyof typeof MAX,
    readonly label: string,
  ) {
    this.score = MAX[name];
  }
  deduct(points: number, note: string): void {
    this.score -= points;
    this.notes.push(note);
  }
  result(): ScoreCategory {
    return {
      name: this.name,
      label: this.label,
      score: Math.max(0, Math.round(this.score)),
      max: MAX[this.name],
      ...(this.notes.length > 0 ? { notes: this.notes } : {}),
    };
  }
}

/** Pure, deterministic scoring over the signals. */
export function computeSecurityScore(signals: Signals): SecurityScore {
  const rep = signals.reputation;

  // 1. Vulnerabilities & malicious records — 25
  const vulnerabilities = new Category("vulnerabilities", "Vulnerabilities & malicious records");
  if (signals.knownMalicious) {
    vulnerabilities.deduct(MAX.vulnerabilities, "known malicious-package record (OSV/OpenSSF)");
  } else {
    for (const advisory of signals.advisories) {
      vulnerabilities.deduct(8, `advisory: ${advisory.id}`);
    }
    if (signals.osvUnavailable) {
      vulnerabilities.deduct(10, "OSV lookup unavailable — vulnerability status unknown");
    }
    if (signals.internalScope) {
      // A deliberate policy skip, but the status is still unknown — a clean
      // 25/25 here would misread as "externally verified clean".
      vulnerabilities.deduct(5, "OSV lookup skipped (internal scope) — not externally checked");
    }
  }

  // 2. Install behavior — 20
  const install = new Category("install_behavior", "Install behavior");
  if (signals.hasLifecycleScripts) {
    install.deduct(8, `lifecycle scripts: ${Object.keys(signals.lifecycleScripts).join(", ")}`);
  }
  for (const finding of signals.scriptCommandFindings) {
    install.deduct(4, finding);
  }

  // 3. Package contents — 15
  const content = new Category("content", "Package contents");
  for (const finding of signals.content.installTimeFindings) {
    content.deduct(5, finding);
  }
  if (signals.content.hasEvalUsage) content.deduct(3, "eval/Function usage");
  if (signals.content.hasMinifiedCode) content.deduct(2, "minified/obfuscated code");
  const suspicious = signals.content.suspiciousFiles.length;
  if (suspicious > 0) {
    content.deduct(Math.min(6, suspicious * 2), `${suspicious} suspicious file(s)`);
  }

  // 4. Maturity — 10
  const maturity = new Category("maturity", "Maturity");
  const age = signals.ageInDays;
  const ageBand =
    age === undefined ? 5 : age < 30 ? 0 : age < 90 ? 4 : age < 365 ? 7 : 10;
  if (ageBand < MAX.maturity) {
    maturity.deduct(
      MAX.maturity - ageBand,
      age === undefined ? "package age unknown" : `package is ${age} days old`,
    );
  }
  if (rep.versionAgeDays !== undefined && rep.versionAgeDays < 7) {
    maturity.deduct(2, `this version is only ${rep.versionAgeDays} day(s) old`);
  }
  if (rep.releaseGapAnomaly) {
    maturity.deduct(3, `fresh release after ${rep.releaseAfterInactivityDays} days of inactivity`);
  }

  // 5. Maintainer trust — 10
  const trust = new Category("maintainer_trust", "Maintainer trust");
  if (rep.maintainerCount === 0) trust.deduct(4, "no maintainers listed");
  else if (rep.maintainerCount === 1) trust.deduct(2, "single maintainer");
  if (rep.maintainerChange?.changed) {
    trust.deduct(4, rep.maintainerChange.detail ?? "maintainer change since previous release");
  } else if (rep.maintainerChange === null) {
    trust.deduct(1, "maintainer history not derivable");
  }
  if (rep.downloads.status === "ok") {
    if (rep.downloads.weeklyDownloads !== undefined && rep.downloads.weeklyDownloads < 100) {
      trust.deduct(3, `low adoption: ${rep.downloads.weeklyDownloads} weekly downloads`);
    }
    if (rep.downloads.trend === "spike") {
      trust.deduct(2, rep.downloads.trendDetail ?? "download spike");
    } else if (rep.downloads.trend === "drop") {
      trust.deduct(2, rep.downloads.trendDetail ?? "download drop");
    }
  } else if (rep.downloads.status === "unavailable") {
    trust.deduct(1, "download stats unknown");
  }
  const intel = rep.maintainerIntel;
  if (intel) {
    if (intel.newMaintainerNoTrackRecord.length > 0) {
      trust.deduct(
        4,
        `new maintainer(s) with no other published packages: ${intel.newMaintainerNoTrackRecord.join(", ")}`,
      );
    } else if (
      intel.status === "ok" &&
      intel.maintainers.length > 0 &&
      intel.maintainers.every((m) => !m.hasEstablishedPackage && (m.packageCount ?? 0) <= 1)
    ) {
      trust.deduct(2, "no maintainer has an established package portfolio");
    } else if (intel.status === "unavailable") {
      trust.deduct(1, "maintainer portfolio unknown");
    }
  }

  // 6. Repository integrity — 10
  const repository = new Category("repository", "Repository integrity");
  if (signals.repositoryMissing) repository.deduct(6, "no repository metadata");
  if (rep.repositoryMismatch) {
    repository.deduct(4, rep.repositoryMismatchDetail ?? "repository mismatch");
  }
  if (rep.repo.status === "not-found") {
    repository.deduct(4, "repository URL points to a missing/private GitHub repo");
  } else if (rep.repo.status === "ok" && rep.repo.archived) {
    repository.deduct(3, "GitHub repository is archived");
  } else if (rep.repo.status === "rate-limited" || rep.repo.status === "unavailable") {
    repository.deduct(1, "archived status unknown");
  }
  if (rep.deprecated !== false) repository.deduct(4, `deprecated: ${rep.deprecated}`);
  if (!rep.hasProvenance) repository.deduct(2, "no npm provenance attestation");

  // 7. Native & dependency surface — 10
  const surface = new Category("surface", "Native & dependency surface");
  if (signals.hasNativeCode) surface.deduct(2, "native code present");
  if (signals.nativeSurface.binaryArtifacts.length > 0) {
    surface.deduct(2, `${signals.nativeSurface.binaryArtifacts.length} pre-built binary artifact(s)`);
  }
  const permissions = signals.rnHardening.dangerousPermissions.length;
  if (permissions > 0) {
    surface.deduct(Math.min(4, permissions * 2), `${permissions} dangerous Android permission(s)`);
  }
  if (signals.dependencyCount > 20) {
    surface.deduct(2, `${signals.dependencyCount} direct dependencies`);
  }
  const rnFindings =
    signals.rnHardening.podspecFindings.length +
    signals.rnHardening.gradleFindings.length +
    signals.rnHardening.autolinkingFindings.length;
  if (rnFindings > 0) {
    surface.deduct(Math.min(2, rnFindings), `${rnFindings} native build finding(s)`);
  }

  const categories = [
    vulnerabilities,
    install,
    content,
    maturity,
    trust,
    repository,
    surface,
  ].map((c) => c.result());

  let total = Math.min(
    100,
    Math.max(
      0,
      categories.reduce((sum, c) => sum + c.score, 0),
    ),
  );

  // Hard floor: a package the rules engine hard-blocks can never present a
  // reassuring number, whatever the other categories say.
  let floorReason: string | undefined;
  if (isHardBlock(signals)) {
    if (signals.knownMalicious) {
      floorReason = "known malicious-package record";
      total = Math.min(total, FLOOR_KNOWN_MALICIOUS);
    } else {
      floorReason = "lifecycle command downloads and executes remote code";
      total = Math.min(total, FLOOR_HARD_BLOCK);
    }
  }

  return { total, categories, ...(floorReason ? { floorReason } : {}) };
}
