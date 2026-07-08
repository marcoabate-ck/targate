import { writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parse, stringify } from "yaml";
import type { AiCachePolicy } from "./ai-cache.js";
import { execConfigDisabled, isExecConfigFile, loadConfigFile } from "./config-loader.js";
import { isHardBlock } from "./rules.js";
import { DECISION_SEVERITY, type RiskAssessment, type Signals } from "./types.js";

export const POLICY_BASENAME = "targate.policy";

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
  /** AI response cache options — see AiCachePolicy (src/ai-cache.ts). */
  aiCache?: AiCachePolicy;
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

  return { dependencyPolicy: policy as DependencyPolicy, aiCache: validateAiCache(doc) };
}

/** Validate the optional aiCache section of a policy document. */
function validateAiCache(doc: object): AiCachePolicy | undefined {
  if (!("aiCache" in doc)) return undefined;
  const raw = (doc as { aiCache: unknown }).aiCache;
  if (typeof raw !== "object" || raw === null) {
    throw new PolicyError(`"aiCache" must be a mapping`);
  }
  const cache = raw as Record<string, unknown>;

  if ("enabled" in cache && typeof cache.enabled !== "boolean") {
    throw new PolicyError(`"aiCache.enabled" must be a boolean`);
  }
  if ("scope" in cache && cache.scope !== "user" && cache.scope !== "project") {
    throw new PolicyError(`"aiCache.scope" must be "user" or "project"`);
  }
  if ("ttlHours" in cache) {
    const v = cache.ttlHours;
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
      throw new PolicyError(`"aiCache.ttlHours" must be a positive number`);
    }
  }
  if ("exclude" in cache) {
    const v = cache.exclude;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      throw new PolicyError(`"aiCache.exclude" must be a list of package names`);
    }
  }
  return cache as AiCachePolicy;
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

/** First targate.policy.* file found in the project root, or null. */
export function findPolicyFile(cwd: string = process.cwd()): string | null {
  const noExec = execConfigDisabled();
  for (const name of POLICY_FILENAMES) {
    const file = path.join(cwd, name);
    if (!existsSync(file)) continue;
    if (noExec && isExecConfigFile(file)) {
      // stderr, so --json stdout stays clean; the skip must be visible because
      // it can remove strictness the repo's policy would otherwise add.
      console.error(
        `[targate] TARGATE_NO_EXEC_CONFIG is set — ignoring ${name} (executable config disabled). Use a .yaml/.json policy in untrusted repos.`,
      );
      continue;
    }
    return file;
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
  if (DECISION_SEVERITY[assessment.decision] >= DECISION_SEVERITY[to]) {
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
 * downgrade to "allow" — but never across a HARD block. A hard block
 * (known-malicious OSV record or a lifecycle command that downloads AND
 * executes remote code, see isHardBlock) can never be overridden. A soft
 * block (heuristics such as "install script reads env AND hits the network" —
 * exactly what native-binary installers like esbuild do) CAN be cleared by an
 * explicit, committed allow-list entry: that is a deliberate human decision to
 * trust the package. AI-only blocks (the rules engine didn't block) are soft
 * too — the AI is advisory.
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
    if (result.decision === "block" && isHardBlock(signals)) {
      // Hard block — the allow list cannot touch it. Leave it blocked.
      return {
        ...result,
        reasons: [
          ...result.reasons,
          `[policy] "${signals.package}" is on the allow list, but it matches a HARD block (known-malicious record or remote code execution) that the allow list cannot override.`,
        ],
      };
    }
    return {
      ...result,
      decision: "allow",
      risk: "low",
      reasons: [
        ...result.reasons,
        `[policy] "${signals.package}" is on the team allow list — pre-approved (heuristic findings acknowledged).`,
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
  aiCache: {
    enabled: true,
    scope: "user",
    ttlHours: 24,
    exclude: [],
  },
};

export type PolicyFormat = "yaml" | "json" | "js" | "ts";

const POLICY_COMMENT = [
  "targate team dependency policy — applied on top of the AI/rules assessment.",
  "The policy can only make decisions stricter, except allowKnownPackages",
  "(pre-approved packages; known-malicious packages are always blocked).",
  "aiCache controls reuse of AI assessments (never used in CI).",
];

// JSON -> JS object literal: unquote keys for the js/ts templates
const STARTER_BODY = JSON.stringify(STARTER_POLICY, null, 2).replace(
  /"([a-zA-Z][\w]*)":/g,
  "$1:",
);

function policyTemplate(format: PolicyFormat): string {
  const hash = POLICY_COMMENT.map((l) => `# ${l}`).join("\n");
  const slash = POLICY_COMMENT.map((l) => `// ${l}`).join("\n");
  switch (format) {
    case "yaml":
      return `${hash}\n${stringify(STARTER_POLICY)}`;
    case "json":
      return JSON.stringify(STARTER_POLICY, null, 2) + "\n";
    case "js":
      return `${slash}\n/** @type {import("targate").PolicyFile} */\nexport default ${STARTER_BODY};\n`;
    case "ts":
      return `${slash}\nimport type { PolicyFile } from "targate";\n\nconst policy: PolicyFile = ${STARTER_BODY};\n\nexport default policy;\n`;
  }
}

/**
 * Scaffold a starter targate.policy.<format>. Returns the file path, or null
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
