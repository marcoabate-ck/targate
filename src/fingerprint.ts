import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { ContentFindings } from "./types.js";
import {
  INSTALL_TIME_SCRIPT_NAMES,
  referencedScriptFiles,
} from "./analyze/scripts.js";

/**
 * Behavior fingerprint — the load-bearing primitive behind "approve the
 * behavior, not the version" (see docs/design/trust-friction.md §5). It records
 * exactly what an attacker must change to execute code, so that a version bump
 * whose fingerprint is unchanged can be auto-passed while a bump that changes
 * behavior re-prompts.
 *
 * SECURITY: this module only *computes and compares* fingerprints. It changes
 * no decision on its own and can never clear a deterministic hard block — the
 * clamp/floor stays authoritative. A fingerprint match is, at most, a reason to
 * soften a *soft* signal, applied by a caller that still runs the floor.
 *
 * The empirical basis (§5.5) drives three properties encoded here:
 *  - referenced install-script files are hashed, not just the command string
 *    (esbuild keeps a byte-identical `postinstall: node install.js` while
 *    `install.js` changes every release — hashing the command alone is a bypass);
 *  - capabilities are tiered: only escalation into the *dangerous* set forces a
 *    re-prompt, so a benign `NODE_ENV` read (react-native-svg) does not nag;
 *  - only consumer-executed hooks (`preinstall`/`install`/`postinstall`) are
 *    fingerprinted — `prepare` never runs for an installed registry dependency.
 */

const HASH_LEN = 16;

function shortHash(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, HASH_LEN);
}

/** Sentinel recorded when a script references a file not present in the tarball. */
export const ABSENT_FILE = "(absent)";

export interface FingerprintScript {
  /** Install-time hook name. */
  name: string;
  /** sha256 (truncated) of the command string. */
  commandHash: string;
  /**
   * sha256 (truncated) of each first-party file the command references, keyed
   * by the referenced path. A missing file is recorded as ABSENT_FILE so that a
   * later appearance/disappearance counts as a change.
   */
  referencedFileHashes: Record<string, string>;
}

/** Dangerous capabilities — gaining any of these across a bump re-prompts. */
export const DANGEROUS_CAPABILITIES = [
  "network",
  "child_process",
  "eval",
] as const;
/** Low-risk capabilities — gaining these is noted but does not re-prompt. */
export const LOW_RISK_CAPABILITIES = ["env"] as const;

/**
 * Whether attestations exist for the artifact. NOTE: "present" means the
 * registry served an attestations object — it is NOT a cryptographic
 * verification that the provenance chains to the expected source repo (see
 * design §7.3). A downgrade present→none is still a meaningful red flag.
 */
export type ProvenanceState = "present" | "none";

export interface BehaviorFingerprint {
  schemaVersion: 1;
  /** "sha512-…" identity of the exact bytes, when available. Informational for
   *  cross-version comparison (it changes every release by definition); the
   *  behavioral fields below are what a comparison keys on. */
  artifactSha512?: string;
  /** Consumer-executed lifecycle scripts, sorted by name. */
  installScripts: FingerprintScript[];
  /** Subset of DANGEROUS_CAPABILITIES present anywhere in scanned code, sorted. */
  dangerousCapabilities: string[];
  /** Subset of LOW_RISK_CAPABILITIES present anywhere in scanned code, sorted. */
  lowRiskCapabilities: string[];
  provenanceState: ProvenanceState;
  /** False when the underlying file index was truncated — a partial fingerprint
   *  must never be treated as an unchanged match (§5.4, fail-closed). */
  complete: boolean;
}

export interface FingerprintInput {
  /** dist.integrity, e.g. "sha512-… [sha512-…]"; first token is used. */
  integrity?: string;
  /** Full scripts map from the tarball's package.json. */
  scripts?: Record<string, string>;
  /** Content findings already produced by analyzeContent. */
  content: ContentFindings;
  /** Whether the registry served provenance attestations. */
  hasProvenance: boolean;
  /** Extracted package root, for hashing referenced install-script files. Only
   *  the 0–2 files a lifecycle command names are read — no full directory walk. */
  packageDir: string;
  /** False when analysis was degraded/truncated — a partial fingerprint must
   *  never be treated as an unchanged match (§5.4, fail-closed). */
  complete: boolean;
}

function parseSha512(integrity: string | undefined): string | undefined {
  if (!integrity) return undefined;
  const token = integrity.split(/\s+/).find((t) => t.startsWith("sha512-"));
  return token;
}

/** Read a script-referenced file from inside the package root, guarding against
 *  path escape. Returns its content, or null when absent / outside the root. */
async function readReferenced(
  packageDir: string,
  ref: string,
): Promise<string | null> {
  const root = path.resolve(packageDir);
  const target = path.resolve(root, ref);
  const rel = path.relative(root, target);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null; // escapes the root
  return readFile(target, "utf8").catch(() => null);
}

export async function computeFingerprint(
  input: FingerprintInput,
): Promise<BehaviorFingerprint> {
  const scripts = input.scripts ?? {};
  const installScripts: FingerprintScript[] = [];

  for (const name of INSTALL_TIME_SCRIPT_NAMES) {
    const command = scripts[name];
    if (!command) continue;
    const referencedFileHashes: Record<string, string> = {};
    for (const ref of referencedScriptFiles(command)) {
      const key = path.posix.normalize(ref);
      const content = await readReferenced(input.packageDir, key);
      referencedFileHashes[key] =
        content === null ? ABSENT_FILE : shortHash(content);
    }
    installScripts.push({
      name,
      commandHash: shortHash(command),
      referencedFileHashes,
    });
  }
  installScripts.sort((a, b) => a.name.localeCompare(b.name));

  const dangerousCapabilities: string[] = [];
  if (input.content.hasNetworkCalls) dangerousCapabilities.push("network");
  if (input.content.hasChildProcessUsage)
    dangerousCapabilities.push("child_process");
  if (input.content.hasEvalUsage) dangerousCapabilities.push("eval");
  dangerousCapabilities.sort();

  const lowRiskCapabilities: string[] = [];
  if (input.content.hasProcessEnvAccess) lowRiskCapabilities.push("env");

  return {
    schemaVersion: 1,
    artifactSha512: parseSha512(input.integrity),
    installScripts,
    dangerousCapabilities,
    lowRiskCapabilities,
    provenanceState: input.hasProvenance ? "present" : "none",
    complete: input.complete,
  };
}

export interface FingerprintComparison {
  /** True when the new version is eligible for auto-pass (still under the floor). */
  matches: boolean;
  /** Human-readable reasons a re-prompt is required (empty when matches). */
  repromptReasons: string[];
  /** Low-risk changes observed that did NOT force a re-prompt. */
  autoPassNotes: string[];
}

function scriptByName(fp: BehaviorFingerprint): Map<string, FingerprintScript> {
  return new Map(fp.installScripts.map((s) => [s.name, s]));
}

/**
 * Compare an approved fingerprint against a new version's. A re-prompt is forced
 * on any install-script change (command OR referenced-file content), any
 * escalation into the dangerous capability set, a provenance downgrade, or an
 * incomplete fingerprint. Gaining only a low-risk capability is noted, not
 * re-prompted. Losing a capability is always fine (strictly safer).
 *
 * This never returns "clear a hard block" — it only reports whether the behavior
 * is unchanged enough to reuse a prior *soft* approval. The caller runs the
 * deterministic floor regardless.
 */
export function compareFingerprints(
  approved: BehaviorFingerprint,
  candidate: BehaviorFingerprint,
): FingerprintComparison {
  const repromptReasons: string[] = [];
  const autoPassNotes: string[] = [];

  // Fail closed on incompleteness — a partial fingerprint is never "unchanged".
  if (!approved.complete || !candidate.complete) {
    repromptReasons.push(
      "fingerprint incomplete (analysis truncated) — cannot prove unchanged",
    );
  }

  // Install scripts: any added/removed hook, changed command, or changed
  // referenced-file content forces a re-prompt.
  const approvedScripts = scriptByName(approved);
  const candidateScripts = scriptByName(candidate);
  const names = new Set([
    ...approvedScripts.keys(),
    ...candidateScripts.keys(),
  ]);
  for (const name of [...names].sort()) {
    const a = approvedScripts.get(name);
    const c = candidateScripts.get(name);
    if (!a || !c) {
      repromptReasons.push(
        `install script "${name}" ${a ? "removed" : "added"}`,
      );
      continue;
    }
    if (a.commandHash !== c.commandHash) {
      repromptReasons.push(`install script "${name}" command changed`);
      continue;
    }
    const refs = new Set([
      ...Object.keys(a.referencedFileHashes),
      ...Object.keys(c.referencedFileHashes),
    ]);
    for (const ref of [...refs].sort()) {
      if (a.referencedFileHashes[ref] !== c.referencedFileHashes[ref]) {
        repromptReasons.push(
          `install script "${name}" referenced file "${ref}" changed`,
        );
      }
    }
  }

  // Capabilities: dangerous escalation re-prompts; low-risk gain is a note.
  const dangerousAdded = candidate.dangerousCapabilities.filter(
    (cap) => !approved.dangerousCapabilities.includes(cap),
  );
  if (dangerousAdded.length > 0) {
    repromptReasons.push(
      `new dangerous capability: ${dangerousAdded.join(", ")}`,
    );
  }
  const lowRiskAdded = candidate.lowRiskCapabilities.filter(
    (cap) => !approved.lowRiskCapabilities.includes(cap),
  );
  if (lowRiskAdded.length > 0) {
    autoPassNotes.push(
      `low-risk capability added (no re-prompt): ${lowRiskAdded.join(", ")}`,
    );
  }

  // Provenance downgrade is a red flag; a gain is fine.
  if (
    approved.provenanceState === "present" &&
    candidate.provenanceState === "none"
  ) {
    repromptReasons.push("provenance downgraded (present → none)");
  }

  return {
    matches: repromptReasons.length === 0,
    repromptReasons,
    autoPassNotes,
  };
}
