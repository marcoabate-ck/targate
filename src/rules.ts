import { isInstallTimeScript } from "./analyze/scripts.js";
import { DECISION_SEVERITY, type RiskAssessment, type Signals } from "./types.js";

/** Partition detected lifecycle hooks into ones that run on a registry install
 *  and ones that only run at pack/publish (or git-install) time. */
function classifyLifecycleHooks(signals: Signals): {
  installTime: string[];
  packTime: string[];
} {
  const installTime: string[] = [];
  const packTime: string[] = [];
  for (const name of Object.keys(signals.lifecycleScripts)) {
    (isInstallTimeScript(name) ? installTime : packTime).push(name);
  }
  return { installTime, packTime };
}

/**
 * A lifecycle command that fetches from the network and pipes into a shell /
 * inline interpreter (curl … | bash, wget … | sh, node -e) — the canonical
 * remote-payload install attack.
 */
function fetchesAndExecutes(signals: Signals): boolean {
  const cmd = signals.scriptCommandFindings.join(" ");
  return (
    /downloads content from the network/.test(cmd) &&
    /(invokes a shell|runs inline node code|uses eval)/.test(cmd)
  );
}

/**
 * A "hard" block can NEVER be overridden — not by team policy, an approval,
 * or the AI: a known-malicious OSV record, or a lifecycle command that
 * downloads AND executes remote code.
 *
 * Artifact-identity mismatches are hard blocks too: approvals must never bless
 * bytes that differ from the reviewed lockfile/public/history evidence.
 * Every other deterministic block is "soft" (heuristic): a strong signal that
 * a human may deliberately clear for a specific package. The classic example
 * is a native-binary installer (esbuild, swc, sharp, playwright…) whose
 * install script legitimately reads process.env AND hits the network to fetch
 * its platform binary — indistinguishable by pattern from exfiltration, but
 * routinely legitimate. Soft blocks can be cleared by allowKnownPackages or a
 * committed version-pinned approval; hard blocks cannot.
 */
export function isHardBlock(signals: Signals): boolean {
  return signals.artifact.trust === "mutated" || signals.knownMalicious || fetchesAndExecutes(signals);
}

/**
 * Deterministic policy engine — used as a fallback when no Anthropic API key
 * is available, and as a hard floor for AI decisions (the AI can never be
 * more permissive than the BLOCK rules below).
 */
export function evaluateRules(signals: Signals): RiskAssessment {
  const reasons: string[] = [];
  const { installTime: installTimeHooks, packTime: packTimeHooks } =
    classifyLifecycleHooks(signals);
  const hasInstallTimeScripts = installTimeHooks.length > 0;

  // ---- BLOCK ----
  if (signals.artifact.trust === "mutated") {
    return {
      risk: "high",
      decision: "block",
      summary: `${signals.package}@${signals.version} does not match its trusted artifact identity.`,
      reasons: signals.artifact.reasons,
      recommendedAction:
        "Do not install this artifact. Investigate the registry, lockfile, and artifact history.",
      source: "rules",
    };
  }
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

  if (signals.analysisDegraded?.length) {
    return {
      risk: "medium",
      decision: "require_approval",
      summary: `${signals.package}@${signals.version} could not be fully analyzed within configured safety limits.`,
      reasons: signals.analysisDegraded.map((reason) => `[unknown] ${reason}`),
      recommendedAction:
        "Review the package manually or deliberately raise the relevant resource limit; do not treat this result as clean.",
      source: "rules",
    };
  }

  const scriptTouchesEnvAndNetwork =
    hasInstallTimeScripts &&
    signals.content.installTimeFindings.some((f) => f.includes("process.env")) &&
    signals.content.installTimeFindings.some((f) => f.includes("network"));

  const scriptFetchesAndExecutes = fetchesAndExecutes(signals);

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
  if (scriptFetchesAndExecutes) {
    reasons.push(
      `Lifecycle command downloads and executes remote code: ${signals.scriptCommandFindings.join("; ")}`,
    );
  }
  if (signals.repositoryMissing && signals.recentPublish && hasInstallTimeScripts) {
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
  if (hasInstallTimeScripts) {
    reasons.push(
      `Install-time lifecycle scripts present: ${installTimeHooks.join(", ")}.`,
    );
  }
  // Suspicious lifecycle command constructs that didn't rise to a BLOCK
  // (e.g. a shell invocation or credential-file reference on its own). Only
  // install-time hooks gate here — a suspicious construct in a pack/publish
  // hook does not run on a registry install (surfaced as a warning below).
  const packTimeCommandFindings = signals.scriptCommandFindings.filter((f) =>
    packTimeHooks.some((h) => f.startsWith(`${h} script `)),
  );
  reasons.push(
    ...signals.scriptCommandFindings.filter((f) => !packTimeCommandFindings.includes(f)),
  );
  // Build-time code execution declared in native build files is equivalent
  // to a lifecycle script: it runs on the developer machine.
  reasons.push(...signals.rnHardening.podspecFindings.filter((f) => /prepare_command|script_phase|downloads|remote/.test(f)));
  reasons.push(...signals.rnHardening.gradleFindings.filter((f) => /executes|remote|downloads/.test(f)));
  reasons.push(...signals.rnHardening.autolinkingFindings);
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
  if (signals.artifact.trust === "unverified" && signals.hasNativeCode) {
    reasons.push("Artifact has native code but no registry, lockfile, public, or historical checksum.");
  }
  if (signals.artifact.metadataDrift?.length) {
    // Bytes are checksum-verified but the registry packument disagrees with
    // the tarball manifest. Not tampering, but a reviewer should vouch that
    // the authentic tarball is the intended artifact.
    reasons.push(...signals.artifact.metadataDrift);
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
  if (packTimeHooks.length > 0) {
    reasons.push(
      `Pack/publish-time scripts present (${packTimeHooks.join(", ")}) — not executed when installing this package from the registry.`,
    );
    reasons.push(...packTimeCommandFindings);
  }
  if (signals.hasNativeCode) {
    reasons.push("Package contains native iOS/Android code.");
    if (signals.rnHardening.dangerousPermissions.length > 0) {
      reasons.push(
        `Dangerous Android permissions requested: ${signals.rnHardening.dangerousPermissions.join(", ")}.`,
      );
    } else if (signals.nativeSurface.androidPermissions.length > 0) {
      reasons.push(
        `Android permissions requested: ${signals.nativeSurface.androidPermissions.join(", ")}.`,
      );
    }
    if (signals.nativeSurface.binaryArtifacts.length > 0) {
      reasons.push(
        `Contains binary artifacts: ${signals.nativeSurface.binaryArtifacts.slice(0, 5).join(", ")}.`,
      );
    }
    if (signals.rnHardening.iosFrameworkFindings.length > 0) {
      reasons.push(
        `Ships pre-built iOS frameworks: ${signals.rnHardening.iosFrameworkFindings.join(", ")}.`,
      );
    }
    // Vendored/insecure-source notes that didn't rise to approval level
    reasons.push(...signals.rnHardening.podspecFindings.filter((f) => /vendored|insecure/.test(f)));
    reasons.push(...signals.rnHardening.gradleFindings.filter((f) => /Maven/.test(f)));
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
    reasons.push(
      `Adds ${signals.dependencyCount} direct dependencies (transitive dependencies are not analyzed).`,
    );
  }
  if (signals.osvUnavailable) {
    reasons.push(
      "OSV/OpenSSF lookup was unavailable — a known-malicious record could not be ruled out.",
    );
  }
  if (signals.artifact.trust === "unverified") {
    reasons.push("Artifact bytes have no registry, lockfile, public, or historical checksum.");
  } else if (signals.artifact.trust === "private-only") {
    reasons.push("Private artifact has no independently comparable public version.");
  } else if (signals.artifact.trust === "public-unavailable") {
    reasons.push("Public-registry comparison was unavailable; mirror equivalence is unknown.");
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
 * Escalate a decision when the OSV lookup was unavailable and the caller
 * asked to fail closed. Known-malicious detection is targate's strongest
 * deterministic guarantee; when it couldn't run, fail-closed callers (CI)
 * treat the package as requiring approval instead of silently trusting it.
 */
export function applyOsvFailurePolicy(
  assessment: RiskAssessment,
  signals: Signals,
  failClosed: boolean,
): RiskAssessment {
  if (!failClosed || !signals.osvUnavailable) return assessment;
  if (DECISION_SEVERITY[assessment.decision] >= DECISION_SEVERITY.require_approval) return assessment;
  return {
    ...assessment,
    decision: "require_approval",
    risk: assessment.risk === "low" ? "medium" : assessment.risk,
    reasons: [
      ...assessment.reasons,
      "[fail-closed] OSV lookup unavailable — cannot confirm the package is not known-malicious.",
    ],
  };
}

/**
 * Clamp an AI decision so it can never be more permissive than the
 * deterministic rules engine. DECISION_SEVERITY is the only ordering source.
 */
export function clampDecision(
  ai: RiskAssessment,
  signals: Signals,
): RiskAssessment {
  // Always compute the rules engine's own verdict and carry it on the result:
  // the output can then show "deterministic verdict" vs "AI interpretation",
  // and prove the AI never went below the floor.
  const floor = evaluateRules(signals);
  const deterministic = {
    decision: floor.decision,
    risk: floor.risk,
    reasons: floor.reasons,
  };

  if (DECISION_SEVERITY[ai.decision] >= DECISION_SEVERITY[floor.decision]) {
    return { ...ai, deterministic };
  }

  const reason = floor.decision === "block"
    ? "Overridden by policy: deterministic rules block this package; the AI cannot downgrade a hard BLOCK."
    : `Overridden by policy: deterministic rules require ${floor.decision}; the AI cannot downgrade it to ${ai.decision}.`;
  return {
    ...ai,
    risk: floor.risk,
    decision: floor.decision,
    recommendedAction: floor.recommendedAction,
    reasons: [reason, ...floor.reasons, ...ai.reasons],
    suggestedAlternatives: ai.suggestedAlternatives ?? floor.suggestedAlternatives,
    source: ai.source,
    deterministic,
  };
}
