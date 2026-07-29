import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";

/**
 * Scaffolds agent-instruction files that make AI coding agents route npm
 * dependency installs through `targate` instead of the raw package manager.
 *
 * There is ONE canonical behavioral contract (AGENT_CONTRACT); each format is
 * that same contract wrapped for a specific agent ecosystem. Mirrors the
 * `initCiWorkflow` / `initPolicy` scaffolding pattern (compute path → skip if
 * it exists → mkdir -p → write).
 */

export type AgentFormat =
  "skill" | "agents" | "cursor" | "windsurf" | "copilot" | "cline";

export const AGENT_FORMATS: AgentFormat[] = [
  "skill",
  "agents",
  "cursor",
  "windsurf",
  "copilot",
  "cline",
];

/** Default when `--format` is omitted: the two canonical, widely-read files. */
export const DEFAULT_AGENT_FORMATS: AgentFormat[] = ["skill", "agents"];

const OUTPUT_PATH: Record<AgentFormat, string> = {
  skill: path.join("skills", "targate", "SKILL.md"),
  agents: "AGENTS.md",
  cursor: path.join(".cursor", "rules", "targate.mdc"),
  windsurf: path.join(".windsurf", "rules", "targate.md"),
  copilot: path.join(".github", "copilot-instructions.md"),
  cline: ".clinerules",
};

/**
 * One-line/one-paragraph rule carried by every file (standalone-safe).
 * Kept verbatim in the thin adapters so they work without AGENTS.md, and
 * embedded in the full body too.
 */
export const CORE_RULE =
  "Before adding or installing ANY npm dependency, run `targate add <package>[@version] --yes` instead of `npm install` / `pnpm add` / `yarn add`. If targate exits non-zero (2 = blocked or needs human approval), STOP and report its reasons to the user — never fall back to a raw package-manager install to get around it.";

/** The full contract, shared by SKILL.md and AGENTS.md. No leading H1. */
const AGENT_CONTRACT = `\`targate\` is an install-time supply-chain security gate for npm packages. Installing a package runs its install-time lifecycle scripts on this machine, so every new dependency must be analyzed by \`targate\` **before** it is installed.

## The rule

Whenever you would run \`npm install <pkg>\`, \`pnpm add <pkg>\`, or \`yarn add <pkg>\` — or the user asks you to add a package — run this instead:

\`\`\`bash
targate add <package>[@version] --yes
\`\`\`

- \`--yes\` lets targate install packages it rates \`allow\` / \`allow_with_warnings\` automatically, while it will **never** auto-install a package rated \`require_approval\` or \`block\` — those always require a human.
- Add \`--deep\` for production/runtime dependencies to also analyze the full transitive tree: \`targate add <pkg> --yes --deep\`.
- Add \`--json\` when you need to parse the verdict programmatically (prints \`{ schemaVersion, command, metadata, signals, assessment, score, deep, behaviorFingerprint, install }\`; the decision is \`assessment.decision\`, while \`install.status\` is the actual install outcome; new keys may be added within a schemaVersion — ignore unknown keys).
- Inspect \`signals.artifact.trust\` in JSON when artifact provenance matters. \`mutated\` is a non-overridable hard block; \`unverified\`, \`private-only\`, and \`public-unavailable\` are explicit weaker-trust states, never proof of authenticity.
- If \`signals.analysisDegraded\` is present, treat every listed item as **UNKNOWN**, not clean. Resource-limit results require human approval; do not raise limits or reinterpret placeholder \`false\` fields to make the install pass.
- Add \`--no-cache\` to force a fresh analysis, ignoring any cached verdict — e.g. when re-checking a package you suspect changed. Different tarball bytes always invalidate automatically because the SHA-512 artifact digest is part of the cache key.

To install **all** dependencies of a project (e.g. after cloning), run \`targate install\` instead. It reviews the exact committed lockfile and installs it immutably with scripts disabled by default. Use \`--update-lockfile\` only when you explicitly want targate to stage, review, and apply a lockfile update. It refuses (exit 2) if any package is blocked or needs approval. Same exit-code contract as below.

## Interpret the exit code

- **0** — proceed. The package was installed (or, with \`--dry-run\`, analyzed cleanly).
- **2** — STOP. The package is blocked or needs human approval. Surface \`assessment.reasons\` and any \`assessment.suggestedAlternatives\` to the user and let them decide. Do **not** install it.
- **1** — an error occurred (e.g. package not found). Report it; do not install.

## Read-only helpers

These analyze and report but never install and never record anything — use them to give the user context:

- \`targate recommend "<need>"\` — when the user asks for a library and hasn't named one ("add a date-formatting lib"), suggest candidates first: npm-search results plus AI-proposed names (hallucinated names are rejected on registry lookup), each analyzed with the full deterministic pipeline and ranked safest-first, with security scores and reasons. The AI only contributes candidate names — scoring and ranking are deterministic. Pick from the recommendations (or present them), then gate the actual install with \`targate add\`.
- \`targate diff <pkg>\` — before **upgrading** an existing dependency: what changed between the installed and latest version (lifecycle scripts, dependencies, maintainers, advisories, size) with an upgrade-risk rating. \`targate diff <pkg>@<from> <pkg>@<to>\` compares two explicit versions. Exit 2 means the diff risk is at/above \`--fail-on\` (default: high) — treat it like a gate: report, don't proceed.
- \`targate explain <pkg>\` — why a package would be allowed or blocked, in plain language (\`targate explain --last\` re-explains the run that just finished, offline).
- \`targate history <pkg>\` — the team's trust history: who approved which version, when, and under which policy/AI model. Useful when a gate stops you on a package the team has approved before at a different version.
- \`targate graph --why <pkg>\` — every dependency chain that pulls a package into the tree, risk-annotated ("why is this here?"). \`targate graph\` writes an interactive HTML risk graph of the whole tree when the user asks for an overview.
- \`targate audit <pkg>\` — an AI source-code audit: reads a bounded, risky subset of the package's actual source (install scripts, files touching env/child_process/network/eval, entry points) for obfuscated behavior the deterministic scanners miss. Findings only ever make the verdict **stricter** (escalation-only, clamped — never an approval). Add \`--audit-code\` to \`add\` / \`install\` to fold the same audit into a gated install. Needs an AI provider; without one it does not run.

## Hard guardrails

- **Never bypass a targate BLOCK** by calling \`npm\`/\`pnpm\`/\`yarn\` directly. If targate refuses a package, that decision stands until a human overrides it.
- **Do not run \`targate approve\` to get past a gate.** \`targate approve <pkg>\` records a human approval without installing — it is a **human** affordance for clearing a \`require_approval\` / soft block. When targate exits 2, surface the reasons and let a person decide; don't approve on their behalf.
- **Never manufacture trust.** Do not edit \`.targate/approvals.json\`, \`.targate/denials.json\`, \`.targate/artifacts.json\`, \`.targate/allowed-signers\`, the team policy, or \`.npmrc\` to change what passes the gate, and never run \`targate approve --sign\` — a signature asserts a **human** identity with that person's SSH key. Artifact-identity mismatches cannot be cleared with \`targate approve\`.
- **Do not disable analysis** (\`--no-ai\` only changes the reasoning layer; it does not weaken the deterministic security floor — but there is no flag that turns the gate off, and you should not try to find one).
- **Do not weaken the policy.** targate config is declarative only (\`.yaml\`/\`.yml\`/\`.json\`, parsed never executed — there is no code-execution path to enable). Don't relax \`targate.policy.*\`, add \`allowKnownPackages\` entries, or set \`dependencyPolicy.trustBehaviorFingerprint\` on the user's behalf to make a package pass — policy is a human/team decision.
- **Do not choose targate's AI provider.** Run \`targate\` with no \`--provider\` flag: it auto-detects a configured model from the environment, or falls back to its built-in deterministic rules engine. It works fully offline.

## In CI

Do not use \`targate add\` in CI pipelines. Use the CI check, which reviews the dependencies a change adds or updates and fails the build on a blocked/unapproved package:

\`\`\`bash
targate ci --fail-on-osv-error
\`\`\`

## Hardening a repo for agent installs

If the user asks to set up or tighten dependency policy for a repo where agents install packages, suggest \`targate policy init --preset ai-agent\` — a ready-made policy pack that stops the agent on anything needing human judgment (young packages, native code, lifecycle scripts, missing repos). Only scaffold it when the user asks; policy is a team decision.
`;

const POINTER =
  "The full contract lives in `AGENTS.md` at the repo root — follow it for all dependency installs.";

function skillFile(): string {
  const frontmatter = [
    "---",
    "name: targate",
    "description: >-",
    "  Gate npm dependency installs through the targate security CLI. Use whenever",
    "  installing, adding, or upgrading an npm/pnpm/yarn package (npm install,",
    "  pnpm add, yarn add) or when the user asks to add a dependency. Runs a",
    "  pre-install analysis and refuses malicious or high-risk packages.",
    "---",
    "",
  ].join("\n");
  return `${frontmatter}\n# Gate npm installs through targate\n\n${AGENT_CONTRACT}`;
}

function agentsFile(): string {
  return `# Dependency installs — use targate\n\n${AGENT_CONTRACT}`;
}

function cursorFile(): string {
  const frontmatter = [
    "---",
    "description: Gate npm dependency installs through the targate security CLI",
    "alwaysApply: true",
    "---",
    "",
  ].join("\n");
  return `${frontmatter}# Gate npm installs through targate\n\n${CORE_RULE}\n\n${POINTER}\n`;
}

function plainAdapter(title: string): string {
  return `# ${title}\n\n${CORE_RULE}\n\n${POINTER}\n`;
}

const RENDER: Record<AgentFormat, () => string> = {
  skill: skillFile,
  agents: agentsFile,
  cursor: cursorFile,
  windsurf: () => plainAdapter("Gate npm installs through targate"),
  copilot: () => plainAdapter("Gate npm installs through targate"),
  cline: () => plainAdapter("Gate npm installs through targate"),
};

/** Render the file content for a single format (used by scaffolder + drift test). */
export function renderAgentFile(format: AgentFormat): string {
  return RENDER[format]();
}

/** Absolute output path for a format under a project root. */
export function agentFilePath(
  format: AgentFormat,
  cwd: string = process.cwd(),
): string {
  return path.join(cwd, OUTPUT_PATH[format]);
}

/** Expand the special "all" keyword; otherwise validate each requested format. */
export function parseAgentFormats(raw: string): AgentFormat[] {
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.includes("all")) return [...AGENT_FORMATS];
  const invalid = parts.filter(
    (p) => !AGENT_FORMATS.includes(p as AgentFormat),
  );
  if (invalid.length > 0) {
    throw new Error(
      `Unknown agent format(s): ${invalid.join(", ")}. Valid: ${AGENT_FORMATS.join(", ")}, all`,
    );
  }
  return parts as AgentFormat[];
}

export interface InitAgentResult {
  /** Repo-relative paths written. */
  written: string[];
  /** Repo-relative paths left untouched because a file already existed. */
  skipped: string[];
}

/**
 * Scaffold the requested agent-instruction files. Never overwrites an
 * existing file (reports it under `skipped`) — the same protective behavior
 * as initCiWorkflow / initPolicy.
 */
export async function initAgentFiles(
  cwd: string = process.cwd(),
  formats: AgentFormat[] = DEFAULT_AGENT_FORMATS,
): Promise<InitAgentResult> {
  const written: string[] = [];
  const skipped: string[] = [];
  for (const format of formats) {
    const rel = OUTPUT_PATH[format];
    const file = path.join(cwd, rel);
    if (existsSync(file)) {
      skipped.push(rel);
      continue;
    }
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, renderAgentFile(format));
    written.push(rel);
  }
  return { written, skipped };
}
