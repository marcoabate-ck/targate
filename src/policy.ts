import { writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parse, stringify } from "yaml";
import { loadConfigFile } from "./config-loader.js";
import { evaluateRules } from "./rules.js";
import type { RiskAssessment, Signals } from "./types.js";

export const POLICY_BASENAME = "bye.policy";

/** Supported policy formats, in lookup order (first existing file wins). */
export const POLICY_FILENAMES = [
  `${POLICY_BASENAME}.ts`,
  `${POLICY_BASENAME}.js`,
  `${POLICY_BASENAME}.mjs`,
  `${POLICY_BASENAME}.cjs`,
  `${POLICY_BASENAME}.yaml`,
  `${POLICY_BASENAME}.yml`,
  `${POLICY_BASENAME}.json`,
] as const;

/** Team dependency policy — schema from the workshop proposal (§9 phase 6). */
export interface DependencyPolicy {
  blockRecentlyPublishedPackages?: boolean;
  minPackageAgeDays?: number;
  requireApprovalForNativeCode?: boolean;
  requireApprovalForLifecycleScripts?: boolean;
  blockMissingRepositoryForRuntimeDeps?: boolean;
  allowKnownPackages?: string[];
  blockPackages?: string[];
}

export interface PolicyFile {
  dependencyPolicy: DependencyPolicy;
}

const BOOLEAN_KEYS = [
  "blockRecentlyPublishedPackages",
  "requireApprovalForNativeCode",
  "requireApprovalForLifecycleScripts",
  "blockMissingRepositoryForRuntimeDeps",
] as const;

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

/** Validate an already-parsed policy document (any source format). */
export function validatePolicyObject(doc: unknown, sourceName = POLICY_BASENAME): PolicyFile {
  if (typeof doc !== "object" || doc === null || !("dependencyPolicy" in doc)) {
    throw new PolicyError(`${sourceName} must contain (or export) a "dependencyPolicy" key`);
  }
  const raw = (doc as { dependencyPolicy: unknown }).dependencyPolicy;
  if (typeof raw !== "object" || raw === null) {
    throw new PolicyError(`"dependencyPolicy" must be a mapping`);
  }
  const policy = raw as Record<string, unknown>;

  for (const key of BOOLEAN_KEYS) {
    if (key in policy && typeof policy[key] !== "boolean") {
      throw new PolicyError(`"dependencyPolicy.${key}" must be a boolean`);
    }
  }
  if ("minPackageAgeDays" in policy) {
    const v = policy.minPackageAgeDays;
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
      throw new PolicyError(`"dependencyPolicy.minPackageAgeDays" must be a non-negative number`);
    }
  }
  for (const listKey of ["allowKnownPackages", "blockPackages"] as const) {
    if (listKey in policy) {
      const v = policy[listKey];
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
        throw new PolicyError(`"dependencyPolicy.${listKey}" must be a list of package names`);
      }
    }
  }

  return { dependencyPolicy: policy as DependencyPolicy };
}

/** Parse a YAML/JSON policy source string (kept for tests and tooling). */
export function parsePolicy(source: string): PolicyFile {
  let doc: unknown;
  try {
    doc = parse(source);
  } catch (err) {
    throw new PolicyError(
      `Invalid YAML: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return validatePolicyObject(doc);
}

/** First bye.policy.* file found in the project root, or null. */
export function findPolicyFile(cwd: string = process.cwd()): string | null {
  for (const name of POLICY_FILENAMES) {
    const file = path.join(cwd, name);
    if (existsSync(file)) return file;
  }
  return null;
}

export interface LoadedPolicy {
  policy: PolicyFile;
  /** Absolute path of the file the policy came from. */
  file: string;
}

/**
 * Load the team policy from the project root; null when absent. Supported
 * formats, first match wins: .ts, .js, .mjs, .cjs (default export), .yaml,
 * .yml, .json.
 */
export async function loadPolicy(cwd: string = process.cwd()): Promise<LoadedPolicy | null> {
  const file = findPolicyFile(cwd);
  if (!file) return null;
  let doc: unknown;
  try {
    doc = await loadConfigFile(file);
  } catch (err) {
    if (err instanceof PolicyError) throw err;
    throw new PolicyError(
      `Failed to load ${path.basename(file)}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return { policy: validatePolicyObject(doc, path.basename(file)), file };
}

function escalate(
  assessment: RiskAssessment,
  to: "require_approval" | "block",
  reason: string,
): RiskAssessment {
  const order = { allow: 0, allow_with_warnings: 1, require_approval: 2, block: 3 } as const;
  if (order[assessment.decision] >= order[to]) {
    // Already at least as strict — just record the policy rule that fired.
    return { ...assessment, reasons: [...assessment.reasons, `[policy] ${reason}`] };
  }
  return {
    ...assessment,
    decision: to,
    risk: to === "block" ? "high" : assessment.risk === "low" ? "medium" : assessment.risk,
    reasons: [...assessment.reasons, `[policy] ${reason}`],
  };
}

/**
 * Apply the team policy on top of an AI/rules assessment.
 *
 * The policy is escalation-only, with one exception: allowKnownPackages can
 * downgrade to "allow" — but it can never cross a deterministic BLOCK. The
 * allow list is name-based (it trusts every future version of a package),
 * while the BLOCK rules describe the *current* version's behavior: a
 * compromised release of an allow-listed package that adds a `curl | bash`
 * postinstall must not be waved through. Known-malicious packages stay
 * blocked outright; any other deterministic BLOCK caps the downgrade at
 * require_approval, so a human reviews that specific version (and the
 * version-pinned approval cache — not the blanket allow list — records it).
 */
export function applyPolicy(
  assessment: RiskAssessment,
  signals: Signals,
  policyFile: PolicyFile,
): RiskAssessment {
  const p = policyFile.dependencyPolicy;
  let result = assessment;

  if (signals.knownMalicious) return result; // hard block already enforced upstream

  if (p.blockPackages?.includes(signals.package)) {
    return escalate(result, "block", `"${signals.package}" is on the team block list.`);
  }

  if (p.allowKnownPackages?.includes(signals.package)) {
    const floor = evaluateRules(signals);
    if (floor.decision === "block") {
      return {
        ...result,
        decision: "require_approval",
        risk: "high",
        reasons: [
          ...result.reasons,
          `[policy] "${signals.package}" is on the team allow list, but this version matches deterministic BLOCK rules — the allow list cannot override them. A human must approve this exact version.`,
          ...floor.reasons,
        ],
      };
    }
    return {
      ...result,
      decision: "allow",
      risk: "low",
      reasons: [
        ...result.reasons,
        `[policy] "${signals.package}" is on the team allow list — pre-approved.`,
      ],
    };
  }

  if (
    (p.blockRecentlyPublishedPackages || p.minPackageAgeDays !== undefined) &&
    signals.ageInDays !== undefined
  ) {
    const minAge = p.minPackageAgeDays ?? 7;
    if (signals.ageInDays < minAge) {
      const to = p.blockRecentlyPublishedPackages ? "block" : "require_approval";
      result = escalate(
        result,
        to,
        `Package is ${signals.ageInDays} days old, below the team minimum of ${minAge} days.`,
      );
    }
  }

  if (p.requireApprovalForNativeCode && signals.hasNativeCode) {
    result = escalate(result, "require_approval", "Team policy requires approval for native code.");
  }

  if (p.requireApprovalForLifecycleScripts && signals.hasLifecycleScripts) {
    result = escalate(
      result,
      "require_approval",
      "Team policy requires approval for lifecycle scripts.",
    );
  }

  if (p.blockMissingRepositoryForRuntimeDeps && signals.repositoryMissing) {
    result = escalate(result, "block", "Team policy blocks packages without repository metadata.");
  }

  return result;
}

const STARTER_POLICY: PolicyFile = {
  dependencyPolicy: {
    blockRecentlyPublishedPackages: false,
    minPackageAgeDays: 7,
    requireApprovalForNativeCode: false,
    requireApprovalForLifecycleScripts: true,
    blockMissingRepositoryForRuntimeDeps: false,
    allowKnownPackages: ["react", "react-native"],
    blockPackages: [],
  },
};

export type PolicyFormat = "yaml" | "json" | "js" | "ts";

const POLICY_COMMENT = [
  "bye team dependency policy — applied on top of the AI/rules assessment.",
  "The policy can only make decisions stricter, except allowKnownPackages",
  "(pre-approved packages; known-malicious packages are always blocked).",
];

const STARTER_BODY = JSON.stringify(STARTER_POLICY.dependencyPolicy, null, 2)
  // JSON -> JS object literal: unquote keys for the js/ts templates
  .replace(/"([a-zA-Z][\w]*)":/g, "$1:");

function policyTemplate(format: PolicyFormat): string {
  const hash = POLICY_COMMENT.map((l) => `# ${l}`).join("\n");
  const slash = POLICY_COMMENT.map((l) => `// ${l}`).join("\n");
  switch (format) {
    case "yaml":
      return `${hash}\n${stringify(STARTER_POLICY)}`;
    case "json":
      return JSON.stringify(STARTER_POLICY, null, 2) + "\n";
    case "js":
      return `${slash}\n/** @type {import("bye").PolicyFile} */\nexport default {\n  dependencyPolicy: ${STARTER_BODY.replace(/\n/g, "\n  ")},\n};\n`;
    case "ts":
      return `${slash}\nimport type { PolicyFile } from "bye";\n\nconst policy: PolicyFile = {\n  dependencyPolicy: ${STARTER_BODY.replace(/\n/g, "\n  ")},\n};\n\nexport default policy;\n`;
  }
}

/**
 * Scaffold a starter bye.policy.<format>. Returns the file path, or null
 * when a policy file (in ANY supported format) already exists.
 */
export async function initPolicy(
  cwd: string = process.cwd(),
  format: PolicyFormat = "yaml",
): Promise<string | null> {
  if (findPolicyFile(cwd)) return null;
  const file = path.join(cwd, `${POLICY_BASENAME}.${format}`);
  await writeFile(file, policyTemplate(format));
  return file;
}
