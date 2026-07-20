import type { ParseArgsConfig } from "node:util";
import { DEFAULT_AGENT_FORMATS, initAgentFiles, parseAgentFormats } from "./agents.js";
import { approveCommand } from "./commands/approve.js";
import { auditCommand } from "./commands/audit.js";
import { cacheCommand } from "./commands/cache.js";
import { checkCommand } from "./commands/check.js";
import { ciCommand } from "./commands/ci.js";
import { diffCommand } from "./commands/diff.js";
import { doctorCommand } from "./commands/doctor.js";
import { explainCommand } from "./commands/explain.js";
import { graphCommand } from "./commands/graph.js";
import { historyCommand } from "./commands/history.js";
import { installCommand } from "./commands/install.js";
import { monitorCommand } from "./commands/monitor.js";
import { recommendCommand } from "./commands/recommend.js";
import { sandboxCommand } from "./commands/sandbox.js";
import type { JsonCommand } from "./json-output.js";
import { initPolicy, POLICY_PRESETS, type PolicyFormat } from "./policy.js";
import type { ProviderName } from "./providers/index.js";
import { dim, green, red, yellow } from "./report.js";
import type { SandboxNetwork } from "./sandbox.js";

export type CommandValue = string | boolean | undefined;
export type CommandValues = Record<string, CommandValue>;

export interface OptionDefinition {
  name: string;
  type: "boolean" | "string";
  short?: string;
  valueName?: string;
  summary: string;
  default?: boolean | string;
  deprecated?: boolean;
}

export interface CommandContext {
  values: CommandValues;
  positionals: string[];
}

export type CommandHandler = (context: CommandContext) => Promise<number>;

export interface CommandDefinition {
  name: string;
  usage: string;
  summary: string;
  options: OptionDefinition[];
  examples: string[];
  jsonCommand?: JsonCommand;
  handler: CommandHandler;
}

const option = (
  name: string,
  type: OptionDefinition["type"],
  valueName: string | undefined,
  summary: string,
  extra: Pick<OptionDefinition, "short" | "default" | "deprecated"> = {},
): OptionDefinition => ({ name, type, valueName, summary, ...extra });

export const HELP_OPTION = option("help", "boolean", undefined, "Show help for this command.", {
  short: "h",
  default: false,
});

export const OPTION_DEFINITIONS = {
  packageManager: option("package-manager", "string", "pm", "Force pnpm, npm, or yarn (default: auto-detect)."),
  json: option("json", "boolean", undefined, "Print machine-readable JSON."),
  dryRun: option("dry-run", "boolean", undefined, "Analyze and report only; never prompt or install."),
  yes: option("yes", "boolean", undefined, "Skip confirmation only for decisions that may be automated."),
  noAi: option("no-ai", "boolean", undefined, "Skip AI reasoning and use deterministic rules only."),
  noCache: option("no-cache", "boolean", undefined, "Ignore cached AI assessments for this run."),
  provider: option("provider", "string", "name", "Use anthropic, deepseek, openai, ollama, or custom."),
  model: option("model", "string", "name", "Override the selected provider model."),
  baseUrl: option("base-url", "string", "url", "Set the API base URL (required for a custom provider)."),
  apiKey: option("api-key", "string", "key", "Set an API key (environment variables are preferred)."),
  reasoning: option("reasoning", "boolean", undefined, "Enable model reasoning where supported."),
  baseRef: option("base-ref", "string", "ref", "Git ref to compare against (default: origin/main)."),
  failOnOsvError: option("fail-on-osv-error", "boolean", undefined, "Require approval when OSV is unreachable."),
  deep: option("deep", "boolean", undefined, "Analyze the full transitive dependency tree."),
  codeAudit: option("audit-code", "boolean", undefined, "Run the AI source-code security audit (opt-in; expensive). Scope comes from the team policy's codeAudit (default: flagged packages)."),
  concurrency: option("concurrency", "string", "n", "Maximum parallel package analyses (default: 16)."),
  noAiBatch: option("no-ai-batch", "boolean", undefined, "Use one AI request per package instead of batching."),
  noReputation: option("no-reputation", "boolean", undefined, "Skip external reputation lookups."),
  updateLockfile: option("update-lockfile", "boolean", undefined, "Stage and review a lockfile update before installing."),
  frozenLockfile: option("frozen-lockfile", "boolean", undefined, "Deprecated no-op; immutable installs are the default.", { deprecated: true }),
  allowScripts: option("allow-scripts", "boolean", undefined, "Allow lifecycle scripts where the command supports it."),
  image: option("image", "string", "image", "Docker image (default: node:20-alpine)."),
  timeout: option("timeout", "string", "seconds", "Kill the sandbox after this many seconds (default: 300)."),
  network: option("network", "string", "mode", "Sandbox network mode: open or none."),
  format: option("format", "string", "format", "Select the output or scaffold format."),
  scope: option("scope", "string", "scope", "Cache scope: user or project."),
  ping: option("ping", "boolean", undefined, "Send a real provider completion during diagnostics."),
  last: option("last", "boolean", undefined, "Explain the most recent add or approve run offline."),
  failOn: option("fail-on", "string", "level", "Exit 2 at low, medium, or high diff risk (default: high)."),
  noCapture: option("no-capture", "boolean", undefined, "Disable sandbox network observation."),
  all: option("all", "boolean", undefined, "Include the complete lockfile dependency tree."),
  noUpdate: option("no-update", "boolean", undefined, "Report monitor events without advancing the baseline."),
  sign: option("sign", "boolean", undefined, "Sign an approval with the human operator's SSH key."),
  verify: option("verify", "boolean", undefined, "Verify approval signatures against allowed signers."),
  preset: option("preset", "string", "name", "Policy preset: default, strict, react-native, ci, or ai-agent."),
  limit: option("limit", "string", "n", "Maximum recommendation candidates (default: 5, maximum: 15)."),
  output: option("output", "string", "path", "Graph output path; use - for stdout."),
  only: option("only", "string", "filters", "Keep graph nodes matching comma-separated risk filters."),
  why: option("why", "string", "package", "Print every risk-annotated dependency chain to a package."),
  open: option("open", "boolean", undefined, "Open a written HTML or SVG graph in the browser."),
} as const satisfies Record<string, OptionDefinition>;

const O = OPTION_DEFINITIONS;
const AI_OPTIONS = [O.noAi, O.provider, O.model, O.baseUrl, O.apiKey, O.reasoning];
const ANALYSIS_OPTIONS = [...AI_OPTIONS, O.failOnOsvError, O.noReputation];

function stringValue(values: CommandValues, name: string): string | undefined {
  const value = values[name];
  return typeof value === "string" ? value : undefined;
}

function booleanValue(values: CommandValues, name: string): boolean {
  return values[name] === true;
}

const VALID_PROVIDERS: ProviderName[] = ["anthropic", "deepseek", "openai", "ollama", "custom"];

function assessmentOptions(values: CommandValues) {
  const provider = stringValue(values, "provider");
  return {
    useAi: !booleanValue(values, "no-ai"),
    provider: provider as ProviderName | undefined,
    model: stringValue(values, "model"),
    baseUrl: stringValue(values, "base-url"),
    apiKey: stringValue(values, "api-key"),
    reasoning: booleanValue(values, "reasoning"),
  };
}

function parseConcurrency(values: CommandValues): number | undefined {
  const raw = stringValue(values, "concurrency");
  const parsed = Number(raw);
  return raw !== undefined && Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function requireSingleSpec(context: CommandContext, usage: string): string | undefined {
  if (context.positionals.length !== 1) {
    console.error(red(`Usage: ${usage}`));
    return undefined;
  }
  return context.positionals[0];
}

const commands: CommandDefinition[] = [
  {
    name: "add",
    usage: "targate add <package>[@version]",
    summary: "Analyze one package, then gate its installation.",
    options: [O.packageManager, O.json, O.dryRun, O.yes, O.noCache, O.deep, O.codeAudit, O.concurrency, O.noAiBatch, ...ANALYSIS_OPTIONS],
    examples: ["targate add lodash", "targate add left-pad@1.3.0 --dry-run", "targate add esbuild --yes --deep"],
    jsonCommand: "add",
    handler: async (context) => {
      const spec = requireSingleSpec(context, "targate add <package>[@version]");
      if (!spec) return 1;
      const v = context.values;
      return checkCommand({
        spec,
        packageManager: stringValue(v, "package-manager"),
        json: booleanValue(v, "json"),
        dryRun: booleanValue(v, "dry-run"),
        assumeYes: booleanValue(v, "yes"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        deep: booleanValue(v, "deep"),
        codeAudit: booleanValue(v, "audit-code"),
        concurrency: parseConcurrency(v),
        noAiBatch: booleanValue(v, "no-ai-batch"),
        noReputation: booleanValue(v, "no-reputation"),
        noCache: booleanValue(v, "no-cache"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "approve",
    usage: "targate approve <package>[@version]",
    summary: "Record a committable human approval without installing.",
    options: [O.json, O.yes, O.allowScripts, O.sign, O.noCache, O.deep, O.codeAudit, ...ANALYSIS_OPTIONS],
    examples: ["targate approve esbuild@0.27.3", "targate approve esbuild@0.27.3 --sign"],
    jsonCommand: "approve",
    handler: async (context) => {
      const spec = requireSingleSpec(context, "targate approve <package>[@version]");
      if (!spec) return 1;
      const v = context.values;
      return approveCommand({
        spec,
        json: booleanValue(v, "json"),
        assumeYes: booleanValue(v, "yes"),
        allowScripts: booleanValue(v, "allow-scripts"),
        sign: booleanValue(v, "sign"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        deep: booleanValue(v, "deep"),
        codeAudit: booleanValue(v, "audit-code"),
        noReputation: booleanValue(v, "no-reputation"),
        noCache: booleanValue(v, "no-cache"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "audit",
    usage: "targate audit <package>[@version]",
    summary: "AI-read a package's source for security issues, without installing.",
    options: [O.json, O.deep, O.concurrency, O.noAiBatch, O.noCache, ...ANALYSIS_OPTIONS],
    examples: ["targate audit left-pad", "targate audit esbuild@0.27.3 --deep"],
    jsonCommand: "audit",
    handler: async (context) => {
      const spec = requireSingleSpec(context, "targate audit <package>[@version]");
      if (!spec) return 1;
      const v = context.values;
      return auditCommand({
        spec,
        json: booleanValue(v, "json"),
        deep: booleanValue(v, "deep"),
        concurrency: parseConcurrency(v),
        noAiBatch: booleanValue(v, "no-ai-batch"),
        noReputation: booleanValue(v, "no-reputation"),
        noCache: booleanValue(v, "no-cache"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "install",
    usage: "targate install",
    summary: "Vet the complete dependency tree, then gate a full install.",
    options: [O.packageManager, O.json, O.dryRun, O.yes, O.noCache, O.updateLockfile, O.frozenLockfile, O.allowScripts, O.codeAudit, O.concurrency, O.noAiBatch, ...ANALYSIS_OPTIONS],
    examples: ["targate install", "targate install --update-lockfile --dry-run"],
    jsonCommand: "install",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 0) {
        console.error(red("Usage: targate install"));
        return 1;
      }
      return installCommand({
        packageManager: stringValue(v, "package-manager"),
        json: booleanValue(v, "json"),
        dryRun: booleanValue(v, "dry-run"),
        assumeYes: booleanValue(v, "yes"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        updateLockfile: booleanValue(v, "update-lockfile"),
        allowScripts: booleanValue(v, "allow-scripts"),
        codeAudit: booleanValue(v, "audit-code"),
        concurrency: parseConcurrency(v),
        noAiBatch: booleanValue(v, "no-ai-batch"),
        noReputation: booleanValue(v, "no-reputation"),
        noCache: booleanValue(v, "no-cache"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "sandbox",
    usage: "targate sandbox <package>[@version]",
    summary: "Trial-install a package in a disposable Docker container.",
    options: [O.image, O.timeout, O.network, O.noCapture, O.json],
    examples: ["targate sandbox suspicious-package", "targate sandbox esbuild --network none"],
    jsonCommand: "sandbox",
    handler: async (context) => {
      const spec = requireSingleSpec(context, "targate sandbox <package>[@version]");
      if (!spec) return 1;
      const v = context.values;
      const network = (stringValue(v, "network") ?? "open") as SandboxNetwork;
      if (!(["open", "none"] as string[]).includes(network)) {
        console.error(red(`Unknown --network value: ${network}. Valid options: open, none`));
        return 1;
      }
      return sandboxCommand({
        spec,
        image: stringValue(v, "image"),
        timeoutMs: stringValue(v, "timeout") ? Number(stringValue(v, "timeout")) * 1000 : undefined,
        network,
        capture: !booleanValue(v, "no-capture"),
        json: booleanValue(v, "json"),
      });
    },
  },
  {
    name: "ci",
    usage: "targate ci [init]",
    summary: "Gate dependency changes against a Git ref or scaffold CI.",
    options: [O.baseRef, O.json, ...ANALYSIS_OPTIONS],
    examples: ["targate ci --base-ref origin/main --fail-on-osv-error", "targate ci init"],
    jsonCommand: "ci",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 1 || (positionals[0] !== undefined && positionals[0] !== "init")) {
        console.error(red("Usage: targate ci [init] [--base-ref <ref>]"));
        return 1;
      }
      return ciCommand({
        init: positionals[0] === "init",
        baseRef: stringValue(v, "base-ref"),
        json: booleanValue(v, "json"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        noReputation: booleanValue(v, "no-reputation"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "policy",
    usage: "targate policy init",
    summary: "Scaffold a declarative team policy from a preset.",
    options: [O.format, O.preset],
    examples: ["targate policy init", "targate policy init --preset ai-agent"],
    handler: async ({ values: v, positionals }) => {
      if (positionals.length !== 1 || positionals[0] !== "init") {
        console.error(red("Usage: targate policy init [--format yaml|json|js|ts] [--preset <name>]"));
        return 1;
      }
      const format = (stringValue(v, "format") ?? "yaml") as PolicyFormat;
      if (!(["yaml", "json", "js", "ts"] as string[]).includes(format)) {
        console.error(red(`Unknown policy format: ${format}. Valid options: yaml, json, js, ts`));
        return 1;
      }
      const preset = stringValue(v, "preset") ?? "default";
      if (!(preset in POLICY_PRESETS)) {
        console.error(red(`Unknown policy preset: ${preset}. Available presets:`));
        for (const [name, definition] of Object.entries(POLICY_PRESETS)) {
          console.error(`  ${name.padEnd(14)} ${dim(definition.description)}`);
        }
        return 1;
      }
      const file = await initPolicy(process.cwd(), format, preset);
      if (file) {
        console.log(green(`Created ${file} (preset: ${preset})`));
        console.log(dim("Edit the rules, then commit the file — it applies to every targate run in this repo."));
      } else {
        console.log(yellow("A targate.policy.* file already exists — nothing written."));
      }
      return 0;
    },
  },
  {
    name: "doctor",
    usage: "targate doctor",
    summary: "Diagnose the local security and provider environment.",
    options: [O.json, O.ping, ...AI_OPTIONS],
    examples: ["targate doctor", "targate doctor --ping"],
    jsonCommand: "doctor",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 0) {
        console.error(red("Usage: targate doctor [--ping]"));
        return 1;
      }
      return doctorCommand({ json: booleanValue(v, "json"), ping: booleanValue(v, "ping"), assess: assessmentOptions(v) });
    },
  },
  {
    name: "diff",
    usage: "targate diff <pkg>@<v1> [<pkg>[@<v2>]]",
    summary: "Compare package versions and rate the upgrade risk.",
    options: [O.packageManager, O.json, O.failOn, ...ANALYSIS_OPTIONS],
    examples: ["targate diff lodash@4.17.20 lodash@4.17.21", "targate diff lodash --fail-on medium"],
    jsonCommand: "diff",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length < 1 || positionals.length > 2) {
        console.error(red("Usage: targate diff <pkg>@<v1> [<pkg>[@<v2>]]"));
        return 1;
      }
      const failOn = (stringValue(v, "fail-on") ?? "high") as "low" | "medium" | "high";
      if (!(["low", "medium", "high"] as string[]).includes(failOn)) {
        console.error(red(`Unknown --fail-on level: ${failOn}. Valid options: low, medium, high`));
        return 1;
      }
      return diffCommand({
        specA: positionals[0],
        specB: positionals[1],
        packageManager: stringValue(v, "package-manager"),
        json: booleanValue(v, "json"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        noReputation: booleanValue(v, "no-reputation"),
        failOn,
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "monitor",
    usage: "targate monitor",
    summary: "Re-check trusted packages and report increased risk.",
    options: [O.packageManager, O.json, O.all, O.noUpdate, O.concurrency, ...ANALYSIS_OPTIONS],
    examples: ["targate monitor", "targate monitor --all --no-update"],
    jsonCommand: "monitor",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 0) {
        console.error(red("Usage: targate monitor [--all]"));
        return 1;
      }
      return monitorCommand({
        packageManager: stringValue(v, "package-manager"),
        json: booleanValue(v, "json"),
        all: booleanValue(v, "all"),
        noUpdate: booleanValue(v, "no-update"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        noReputation: booleanValue(v, "no-reputation"),
        concurrency: parseConcurrency(v),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "graph",
    usage: "targate graph [<package>[@version]]",
    summary: "Render a dependency risk graph or explain why a package is present.",
    options: [O.format, O.output, O.only, O.why, O.open, O.json, O.packageManager, O.noReputation, O.failOnOsvError, O.concurrency],
    examples: ["targate graph", "targate graph --only high-risk,scripts", "targate graph --why minimist"],
    jsonCommand: "graph",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 1) {
        console.error(red("Usage: targate graph [<package>[@version]]"));
        return 1;
      }
      return graphCommand({
        spec: positionals[0],
        format: stringValue(v, "format"),
        output: stringValue(v, "output"),
        only: stringValue(v, "only"),
        why: stringValue(v, "why"),
        open: booleanValue(v, "open"),
        json: booleanValue(v, "json"),
        packageManager: stringValue(v, "package-manager"),
        noReputation: booleanValue(v, "no-reputation"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        concurrency: parseConcurrency(v),
      });
    },
  },
  {
    name: "recommend",
    usage: 'targate recommend "<need>"',
    summary: "Recommend analyzed packages for a need, safest first.",
    options: [O.limit, O.json, ...ANALYSIS_OPTIONS],
    examples: ['targate recommend "date formatting"', 'targate recommend "immutable state" --limit 8 --json'],
    jsonCommand: "recommend",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length < 1) {
        console.error(red('Usage: targate recommend "<need>" [--limit <n>]'));
        return 1;
      }
      const rawLimit = stringValue(v, "limit");
      const limit = Number(rawLimit);
      if (rawLimit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
        console.error(red(`Invalid --limit: ${rawLimit}. Use a positive integer.`));
        return 1;
      }
      return recommendCommand({
        query: positionals.join(" "),
        limit: rawLimit !== undefined ? limit : undefined,
        json: booleanValue(v, "json"),
        noReputation: booleanValue(v, "no-reputation"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "history",
    usage: "targate history [<package>[@version]]",
    summary: "Show recorded trust decisions and optionally verify signatures.",
    options: [O.json, O.verify],
    examples: ["targate history", "targate history esbuild --verify"],
    jsonCommand: "history",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length > 1) {
        console.error(red("Usage: targate history [<package>[@version]]"));
        return 1;
      }
      return historyCommand({ spec: positionals[0], json: booleanValue(v, "json"), verify: booleanValue(v, "verify") });
    },
  },
  {
    name: "explain",
    usage: "targate explain <package>[@version] | --last",
    summary: "Explain a fresh or previously recorded decision without installing.",
    options: [O.last, O.json, O.noCache, ...ANALYSIS_OPTIONS],
    examples: ["targate explain left-pad@1.3.0", "targate explain --last"],
    jsonCommand: "explain",
    handler: async ({ values: v, positionals }) => {
      const last = booleanValue(v, "last");
      if (positionals.length > 1 || last === Boolean(positionals[0])) {
        console.error(red("Usage: targate explain <package>[@version] | targate explain --last"));
        return 1;
      }
      return explainCommand({
        spec: positionals[0],
        last,
        json: booleanValue(v, "json"),
        failOnOsvError: booleanValue(v, "fail-on-osv-error"),
        noReputation: booleanValue(v, "no-reputation"),
        noCache: booleanValue(v, "no-cache"),
        assess: assessmentOptions(v),
      });
    },
  },
  {
    name: "cache",
    usage: "targate cache <info|clear>",
    summary: "Inspect or clear the AI assessment cache.",
    options: [O.scope, O.json],
    examples: ["targate cache info", "targate cache clear --scope project"],
    jsonCommand: "cache",
    handler: async ({ values: v, positionals }) => {
      if (positionals.length !== 1) {
        console.error(red("Usage: targate cache <clear|info> [--scope user|project]"));
        return 1;
      }
      return cacheCommand({ action: positionals[0], scope: stringValue(v, "scope"), json: booleanValue(v, "json") });
    },
  },
  {
    name: "agents",
    usage: "targate agents init",
    summary: "Scaffold instructions that make coding agents use targate.",
    options: [O.format],
    examples: ["targate agents init", "targate agents init --format all"],
    handler: async ({ values: v, positionals }) => {
      if (positionals.length !== 1 || positionals[0] !== "init") {
        console.error(red("Usage: targate agents init [--format skill,agents,cursor,windsurf,copilot,cline|all]"));
        return 1;
      }
      let formats;
      try {
        const raw = stringValue(v, "format");
        formats = raw ? parseAgentFormats(raw) : DEFAULT_AGENT_FORMATS;
      } catch (error) {
        console.error(red(error instanceof Error ? error.message : String(error)));
        return 1;
      }
      const { written, skipped } = await initAgentFiles(process.cwd(), formats);
      for (const file of written) console.log(green(`Created ${file}`));
      for (const file of skipped) console.log(yellow(`${file} already exists — left unchanged.`));
      if (written.length > 0) {
        console.log(dim("Commit these so every agent working in this repo gates installs through targate."));
      }
      return 0;
    },
  },
];

export const COMMAND_DEFINITIONS: readonly CommandDefinition[] = commands;

export function findCommand(name: string): CommandDefinition | undefined {
  return COMMAND_DEFINITIONS.find((command) => command.name === name);
}

export function validateProvider(values: CommandValues): string | undefined {
  const provider = stringValue(values, "provider");
  if (provider && !VALID_PROVIDERS.includes(provider as ProviderName)) {
    return `Unknown provider: ${provider}. Valid options: ${VALID_PROVIDERS.join(", ")}`;
  }
  return undefined;
}

export function parseOptionsFor(command: CommandDefinition): NonNullable<ParseArgsConfig["options"]> {
  return Object.fromEntries(
    [...command.options, HELP_OPTION].map((definition) => [
      definition.name,
      {
        type: definition.type,
        ...(definition.short ? { short: definition.short } : {}),
        ...(definition.default !== undefined ? { default: definition.default } : {}),
      },
    ]),
  ) as NonNullable<ParseArgsConfig["options"]>;
}

function optionLabel(definition: OptionDefinition): string {
  return `--${definition.name}${definition.valueName ? ` <${definition.valueName}>` : ""}`;
}

export function renderGlobalHelp(): string {
  const commandLines = COMMAND_DEFINITIONS.map(
    (command) => `  ${command.usage.padEnd(47)} ${command.summary}`,
  ).join("\n");
  const uniqueOptions = new Map<string, OptionDefinition>();
  for (const command of COMMAND_DEFINITIONS) {
    for (const definition of command.options) uniqueOptions.set(definition.name, definition);
  }
  const optionLines = [...uniqueOptions.values()]
    .map((definition) => `  ${optionLabel(definition).padEnd(28)} ${definition.summary}`)
    .join("\n");
  return `targate — gate every dependency before it runs (AI-gated pre-install security)\n\nUsage:\n${commandLines}\n\nOptions:\n${optionLines}\n  -h, --help                  Show global or command-specific help.\n\nRun \`targate <command> --help\` for command-specific options and examples.`;
}

export function renderCommandHelp(command: CommandDefinition): string {
  const options = [...command.options, HELP_OPTION]
    .map((definition) => `  ${optionLabel(definition).padEnd(28)} ${definition.summary}`)
    .join("\n");
  const examples = command.examples.map((example) => `  ${example}`).join("\n");
  return `${command.summary}\n\nUsage:\n  ${command.usage}\n\nOptions:\n${options}\n\nExamples:\n${examples}`;
}

export function renderReadmeCommandTable(): string {
  const rows = COMMAND_DEFINITIONS.map(
    (command) => `| \`${command.usage.replaceAll("|", "\\|")}\` | ${command.summary} |`,
  ).join("\n");
  return `| Command | What it does |\n|---|---|\n${rows}`;
}

export function renderCliReference(): string {
  const rows = COMMAND_DEFINITIONS.map((command) => {
    const usage = command.usage.replaceAll("|", "\\|");
    const options = command.options.map((definition) => `\`${optionLabel(definition)}\``).join("<br>");
    const examples = command.examples.map((example) => `\`${example.replaceAll("|", "\\|")}\``).join("<br>");
    return `| \`${usage}\` | ${command.summary} | ${options || "—"} | ${examples} |`;
  }).join("\n");
  return `| Command | Summary | Supported options | Examples |\n|---|---|---|---|\n${rows}`;
}
