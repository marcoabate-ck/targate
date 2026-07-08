#!/usr/bin/env node
import { parseArgs } from "node:util";
import { DEFAULT_AGENT_FORMATS, initAgentFiles, parseAgentFormats } from "./agents.js";
import { approveCommand } from "./commands/approve.js";
import { checkCommand } from "./commands/check.js";
import { ciCommand } from "./commands/ci.js";
import { installCommand } from "./commands/install.js";
import { sandboxCommand } from "./commands/sandbox.js";
import { initPolicy, type PolicyFormat } from "./policy.js";
import type { SandboxNetwork } from "./sandbox.js";
import type { ProviderName } from "./providers/index.js";
import { dim, green, red, yellow } from "./report.js";

const VALID_PROVIDERS: ProviderName[] = ["anthropic", "deepseek", "openai", "ollama", "custom"];

const HELP = `
targate — gate every dependency before it runs (AI-gated pre-install security)

Usage:
  targate add <package>[@version]         Analyze a package, then gate the install
  targate approve <package>[@version]     Analyze a package and record a committable
                                      approval WITHOUT installing it (clears a
                                      require_approval / soft block ahead of time)
  targate install                         Vet the WHOLE dependency tree, then gate a
                                      full install (pnpm/npm/yarn install)
  targate sandbox <package>[@version]     Trial install in a disposable Docker container
  targate ci [--base-ref <ref>]           Analyze dependencies changed vs a git ref (for PRs)
  targate ci init                         Scaffold .github/workflows/targate.yml
  targate policy init [--format <fmt>]    Scaffold the team policy file
                                      (yaml default; also json, js, ts — typed)
  targate agents init [--format <list>]   Scaffold agent-instruction files so AI
                                      coding agents gate installs through targate
                                      (default skill,agents; also cursor,
                                      windsurf, copilot, cline, or all)

  (targate <package> without a subcommand is a shorthand for targate add <package>)

Options (add & ci):
  --package-manager <pm>  Force pnpm | npm | yarn (default: auto-detect)
  --json                  Print machine-readable JSON instead of the report
  --dry-run               Analyze and report only — never prompt, never install.
                          (To approve without installing, use targate approve.)
  --yes                   Skip confirmation for allow/allow-with-warnings
                          (approve: skip the lifecycle-scripts prompt)
  --no-ai                 Skip the AI reasoning layer, use rules only
  --provider <name>       anthropic | deepseek | openai | ollama | custom
                          (default: auto-detect from env vars, see below)
  --model <name>          Override the model for the selected provider
  --base-url <url>        API base URL (required for --provider custom)
  --api-key <key>         API key (prefer env vars below over this flag)
  --reasoning             Enable model reasoning where the provider supports it
  --fail-on-osv-error     Treat an unreachable OSV lookup as "unknown" and
                          escalate to require-approval (recommended in CI)
  --deep                  (add, approve) Also analyze the FULL transitive
                          dependency tree; the strictest verdict in the tree
                          gates it (slower; the AI cache softens repeat costs)
  --frozen-lockfile       (install) Immutable install (npm ci / --frozen-lockfile)
  --allow-scripts         (install) Run lifecycle scripts (default: disabled)
                          (approve) Record the approval as scripts-allowed
  --base-ref <ref>        (ci) Git ref to diff against (default: origin/main)

Options (sandbox):
  --image <image>         Docker image (default: node:20-alpine)
  --timeout <seconds>     Kill the sandbox after N seconds (default: 300)
  --network <mode>        open (default, full egress) | none (offline trial)

Provider auto-detection (first match wins):
  ANTHROPIC_API_KEY set        -> anthropic  (claude-opus-4-8)
  DEEPSEEK_API_KEY set         -> deepseek   (deepseek-chat)
  OPENAI_API_KEY set           -> openai     (gpt-4o-mini)
  OLLAMA_HOST / OLLAMA_MODEL   -> ollama     (local, default http://localhost:11434/v1)
  none of the above            -> deterministic rules engine (no AI)

Examples:
  targate add react-native-mmkv
  targate add left-pad@1.3.0 --dry-run
  targate approve esbuild@0.27.3
  targate sandbox suspicious-package
  targate ci --base-ref origin/main
  targate policy init
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      "package-manager": { type: "string" },
      json: { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      yes: { type: "boolean", default: false },
      "no-ai": { type: "boolean", default: false },
      provider: { type: "string" },
      model: { type: "string" },
      "base-url": { type: "string" },
      "api-key": { type: "string" },
      reasoning: { type: "boolean", default: false },
      "base-ref": { type: "string" },
      "fail-on-osv-error": { type: "boolean", default: false },
      deep: { type: "boolean", default: false },
      "frozen-lockfile": { type: "boolean", default: false },
      "allow-scripts": { type: "boolean", default: false },
      image: { type: "string" },
      timeout: { type: "string" },
      network: { type: "string" },
      format: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    console.log(HELP);
    return values.help ? 0 : 1;
  }

  if (values.provider && !VALID_PROVIDERS.includes(values.provider as ProviderName)) {
    console.error(
      red(`Unknown provider: ${values.provider}. Valid options: ${VALID_PROVIDERS.join(", ")}`),
    );
    return 1;
  }

  const assess = {
    useAi: !values["no-ai"],
    provider: values.provider as ProviderName | undefined,
    model: values.model,
    baseUrl: values["base-url"],
    apiKey: values["api-key"],
    reasoning: values.reasoning,
  };

  const [command, ...rest] = positionals;

  switch (command) {
    case "add": {
      if (!rest[0]) {
        console.error(red("Usage: targate add <package>[@version]"));
        return 1;
      }
      return checkCommand({
        spec: rest[0],
        packageManager: values["package-manager"],
        json: values.json,
        dryRun: values["dry-run"],
        assumeYes: values.yes,
        failOnOsvError: values["fail-on-osv-error"],
        deep: values.deep,
        assess,
      });
    }

    case "approve": {
      if (!rest[0]) {
        console.error(red("Usage: targate approve <package>[@version]"));
        return 1;
      }
      return approveCommand({
        spec: rest[0],
        json: values.json,
        assumeYes: values.yes,
        allowScripts: values["allow-scripts"],
        failOnOsvError: values["fail-on-osv-error"],
        deep: values.deep,
        assess,
      });
    }

    case "install": {
      return installCommand({
        packageManager: values["package-manager"],
        json: values.json,
        dryRun: values["dry-run"],
        assumeYes: values.yes,
        failOnOsvError: values["fail-on-osv-error"],
        frozenLockfile: values["frozen-lockfile"],
        allowScripts: values["allow-scripts"],
        assess,
      });
    }

    case "sandbox": {
      if (!rest[0]) {
        console.error(red("Usage: targate sandbox <package>[@version]"));
        return 1;
      }
      const network = (values.network ?? "open") as SandboxNetwork;
      if (!["open", "none"].includes(network)) {
        console.error(red(`Unknown --network value: ${values.network}. Valid options: open, none`));
        return 1;
      }
      return sandboxCommand({
        spec: rest[0],
        image: values.image,
        timeoutMs: values.timeout ? Number(values.timeout) * 1000 : undefined,
        network,
      });
    }

    case "ci": {
      return ciCommand({
        init: rest[0] === "init",
        baseRef: values["base-ref"],
        json: values.json,
        failOnOsvError: values["fail-on-osv-error"],
        assess,
      });
    }

    case "policy": {
      if (rest[0] !== "init") {
        console.error(red("Usage: targate policy init [--format yaml|json|js|ts]"));
        return 1;
      }
      const format = (values.format ?? "yaml") as PolicyFormat;
      if (!["yaml", "json", "js", "ts"].includes(format)) {
        console.error(red(`Unknown policy format: ${format}. Valid options: yaml, json, js, ts`));
        return 1;
      }
      const file = await initPolicy(process.cwd(), format);
      if (file) {
        console.log(green(`Created ${file}`));
        console.log(dim("Edit the rules, then commit the file — it applies to every targate run in this repo."));
      } else {
        console.log(yellow(`A targate.policy.* file already exists — nothing written.`));
      }
      return 0;
    }

    case "agents": {
      if (rest[0] !== "init") {
        console.error(red("Usage: targate agents init [--format skill,agents,cursor,windsurf,copilot,cline|all]"));
        return 1;
      }
      let formats;
      try {
        formats = values.format ? parseAgentFormats(values.format) : DEFAULT_AGENT_FORMATS;
      } catch (err) {
        console.error(red(err instanceof Error ? err.message : String(err)));
        return 1;
      }
      const { written, skipped } = await initAgentFiles(process.cwd(), formats);
      for (const f of written) console.log(green(`Created ${f}`));
      for (const f of skipped) console.log(yellow(`${f} already exists — left unchanged.`));
      if (written.length > 0) {
        console.log(dim("Commit these so every agent working in this repo gates installs through targate."));
      }
      return 0;
    }

    default:
      // Backward compatible shorthand: `targate <package>` behaves as `targate add`.
      // Suppressed in --json mode so stdout stays a single JSON document.
      if (!values.json) console.log(dim(`(shorthand for \`targate add ${command}\`)`));
      return checkCommand({
        spec: command,
        packageManager: values["package-manager"],
        json: values.json,
        dryRun: values["dry-run"],
        assumeYes: values.yes,
        failOnOsvError: values["fail-on-osv-error"],
        deep: values.deep,
        assess,
      });
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(red(`\ntargate failed: ${err instanceof Error ? err.message : String(err)}`));
    process.exit(1);
  });
