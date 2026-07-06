import type { RiskAssessment, Signals } from "./types.js";

/**
 * Deterministic policy engine — used as a fallback when no Anthropic API key
 * is available, and as a hard floor for AI decisions (the AI can never be
 * more permissive than the BLOCK rules below).
 */
export function evaluateRules(signals: Signals): RiskAssessment {
  const reasons: string[] = [];

  // ---- BLOCK ----
  if (signals.knownMalicious) {
    return {
      risk: "high",
      decision: "block",
      summary: `${signals.package} is reported as a known malicious package.`,
      reasons: signals.maliciousRecords.map(
        (r) => `OSV malicious-package record: ${r.id}${r.summary ? ` — ${r.summary}` : ""}`,
      ),
      recommendedAction: "Do not install this package under any circumstances.",
      source: "rules",
    };
  }

  const scriptTouchesEnvAndNetwork =
    signals.hasLifecycleScripts &&
    signals.content.installTimeFindings.some((f) => f.includes("process.env")) &&
    signals.content.installTimeFindings.some((f) => f.includes("network"));

  if (signals.nameSimilarity && signals.recentPublish) {
    reasons.push(
      `Name is very similar to popular package "${signals.nameSimilarity.similarTo}" (edit distance ${signals.nameSimilarity.distance}) and was published recently — possible typosquatting.`,
    );
  }
  if (scriptTouchesEnvAndNetwork) {
    reasons.push(
      "Install-time code reads environment variables AND performs network calls — possible credential exfiltration.",
    );
  }
  if (signals.repositoryMissing && signals.recentPublish && signals.hasLifecycleScripts) {
    reasons.push(
      "Recently published package with lifecycle scripts and no repository metadata.",
    );
  }

  if (reasons.length > 0) {
    return {
      risk: "high",
      decision: "block",
      summary: `${signals.package} matches high-risk supply chain patterns.`,
      reasons,
      recommendedAction:
        "Do not install on the host machine. If you must evaluate it, use a disposable container.",
      suggestedAlternatives: signals.nameSimilarity
        ? [signals.nameSimilarity.similarTo]
        : undefined,
      source: "rules",
    };
  }

  // ---- REQUIRE APPROVAL ----
  if (signals.hasLifecycleScripts) {
    reasons.push(
      `Lifecycle scripts present: ${Object.keys(signals.lifecycleScripts).join(", ")}.`,
    );
  }
  if (signals.nameSimilarity) {
    reasons.push(
      `Name is similar to popular package "${signals.nameSimilarity.similarTo}" (edit distance ${signals.nameSimilarity.distance}).`,
    );
  }
  if (signals.recentPublish) {
    reasons.push(
      `Published very recently (${signals.ageInDays ?? "?"} days ago).`,
    );
  }
  if (signals.content.installTimeFindings.length > 0) {
    reasons.push(...signals.content.installTimeFindings);
  }

  if (reasons.length > 0) {
    return {
      risk: "medium",
      decision: "require_approval",
      summary: `${signals.package} has signals that need human review before installation.`,
      reasons,
      recommendedAction:
        "Install with scripts disabled (--ignore-scripts) or have a security reviewer approve the package.",
      source: "rules",
    };
  }

  // ---- ALLOW WITH WARNINGS ----
  if (signals.hasNativeCode) {
    reasons.push("Package contains native iOS/Android code.");
    if (signals.nativeSurface.androidPermissions.length > 0) {
      reasons.push(
        `Android permissions requested: ${signals.nativeSurface.androidPermissions.join(", ")}.`,
      );
    }
    if (signals.nativeSurface.binaryArtifacts.length > 0) {
      reasons.push(
        `Contains binary artifacts: ${signals.nativeSurface.binaryArtifacts.slice(0, 5).join(", ")}.`,
      );
    }
  }
  if (signals.repositoryMissing) {
    reasons.push("No repository metadata on npm.");
  }
  if (signals.advisories.length > 0) {
    reasons.push(
      `Known vulnerability advisories: ${signals.advisories.map((a) => a.id).join(", ")}.`,
    );
  }
  if (signals.dependencyCount > 20) {
    reasons.push(`Adds a large dependency tree (${signals.dependencyCount} direct dependencies).`);
  }

  if (reasons.length > 0) {
    return {
      risk: "medium",
      decision: "allow_with_warnings",
      summary: `${signals.package} looks legitimate but review the warnings below.`,
      reasons,
      recommendedAction:
        "Proceed if the native surface and warnings are expected for this package.",
      source: "rules",
    };
  }

  // ---- ALLOW ----
  return {
    risk: "low",
    decision: "allow",
    summary: `${signals.package} shows no high-risk install-time behavior.`,
    reasons: [
      "No lifecycle scripts, no known malicious records, repository metadata present.",
    ],
    recommendedAction: "Safe to install normally.",
    source: "rules",
  };
}

/**
 * Clamp an AI decision so it can never be more permissive than the
 * deterministic policy on hard signals.
 */
export function clampDecision(
  ai: RiskAssessment,
  signals: Signals,
): RiskAssessment {
  if (signals.knownMalicious && ai.decision !== "block") {
    return {
      ...ai,
      risk: "high",
      decision: "block",
      reasons: [
        "Overridden by policy: package has a known malicious-package record.",
        ...ai.reasons,
      ],
    };
  }
  return ai;
}
