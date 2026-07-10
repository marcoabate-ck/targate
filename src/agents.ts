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

export type AgentFormat = "skill" | "agents" | "cursor" | "windsurf" | "copilot" | "cline";

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
const AGENT_CONTRACT = `\`targate\` is a pre-install security gate for npm packages. Installing a package runs its install-time lifecycle scripts on this machine, so every new dependency must be analyzed by \`targate\` **before** it is installed.

## The rule

Whenever you would run \`npm install <pkg>\`, \`pnpm add <pkg>\`, or \`yarn add <pkg>\` — or the user asks you to add a package — run this instead:

\`\`\`bash
targate add <package>[@version] --yes
\`\`\`

- \`--yes\` lets targate install packages it rates \`allow\` / \`allow_with_warnings\` automatically, while it will **never** auto-install a package rated \`require_approval\` or \`block\` — those always require a human.
- Add \`--deep\` for production/runtime dependencies to also analyze the full transitive tree: \`targate add <pkg> --yes --deep\`.
- Add \`--json\` when you need to parse the verdict programmatically (prints \`{ schemaVersion, command, metadata, signals, assessment, score, deep }\`; the decision is \`assessment.decision\`, one of \`allow\`, \`allow_with_warnings\`, \`require_approval\`, \`block\`; new keys may be added within a schemaVersion — ignore unknown keys).
- Add \`--no-cache\` to force a fresh analysis, ignoring any cached verdict — e.g. when re-checking a package you suspect changed. (targate caches AI assessments between runs; it also invalidates automatically when a package's contents or the model change.)

To install **all** dependencies of a project (a plain \`npm install\` / \`pnpm install\` / \`yarn install\` — e.g. after cloning), run \`targate install\` instead. It vets the entire dependency tree before the install runs any lifecycle scripts, refuses (exit 2) if any package is blocked or needs approval, and otherwise installs with scripts disabled by default (\`--allow-scripts\` to run them). Same exit-code contract as below.

## Interpret the exit code

- **0** — proceed. The package was installed (or, with \`--dry-run\`, analyzed cleanly).
- **2** — STOP. The package is blocked or needs human approval. Surface \`assessment.reasons\` and any \`assessment.suggestedAlternatives\` to the user and let them decide. Do **not** install it.
- **1** — an error occurred (e.g. package not found). Report it; do not install.

## Hard guardrails

- **Never bypass a targate BLOCK** by calling \`npm\`/\`pnpm\`/\`yarn\` directly. If targate refuses a package, that decision stands until a human overrides it.
- **Do not run \`targate approve\` to get past a gate.** \`targate approve <pkg>\` records a human approval without installing — it is a **human** affordance for clearing a \`require_approval\` / soft block. When targate exits 2, surface the reasons and let a person decide; don't approve on their behalf.
- **Do not disable analysis** (\`--no-ai\` only changes the reasoning layer; it does not weaken the deterministic security floor — but there is no flag that turns the gate off, and you should not try to find one).
- **Do not choose targate's AI provider.** Run \`targate\` with no \`--provider\` flag: it auto-detects a configured model from the environment, or falls back to its built-in deterministic rules engine. It works fully offline.

## In CI

Do not use \`targate add\` in CI pipelines. Use the CI check, which reviews the dependencies a change adds or updates and fails the build on a blocked/unapproved package:

\`\`\`bash
targate ci --fail-on-osv-error
\`\`\`
`;

const POINTER = "The full contract lives in `AGENTS.md` at the repo root — follow it for all dependency installs.";

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
export function agentFilePath(format: AgentFormat, cwd: string = process.cwd()): string {
  return path.join(cwd, OUTPUT_PATH[format]);
}

/** Expand the special "all" keyword; otherwise validate each requested format. */
export function parseAgentFormats(raw: string): AgentFormat[] {
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.includes("all")) return [...AGENT_FORMATS];
  const invalid = parts.filter((p) => !AGENT_FORMATS.includes(p as AgentFormat));
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
