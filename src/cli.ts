#!/usr/bin/env node
import { parseArgs } from "node:util";
import { DEFAULT_AGENT_FORMATS, initAgentFiles, parseAgentFormats } from "./agents.js";
import { approveCommand } from "./commands/approve.js";
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
import { initPolicy, POLICY_PRESETS, type PolicyFormat } from "./policy.js";
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
                                      --preset default | strict | react-native |
                                      ci | ai-agent picks a ready-made policy pack
  targate diff <pkg>@<v1> [<pkg>[@<v2>]]  What changed between two versions (second
                                      spec/version omitted → latest; bare <pkg> →
                                      lockfile-installed version vs latest)
  targate explain <package>[@version]     Explain why a package would be allowed or
                                      blocked (analyzes fresh, installs nothing)
  targate explain --last                  Explain the most recent add/approve run
                                      (reads .targate/last-run.json, no network)
  targate recommend "<need>"              Suggest packages for a need, safest first:
                                      npm-search + AI-suggested candidates (names
                                      only, hallucinations rejected on registry
                                      lookup), each analyzed with the full
                                      deterministic pipeline and ranked by
                                      security score (adoption breaks ties).
                                      --no-ai → search-only discovery.
  targate graph [<package>[@version]]     The dependency tree as an interactive RISK
                                      GRAPH (project lockfile tree, or a package
                                      you are considering). Self-contained HTML
                                      by default; also svg, dot, mermaid, json.
                                      --why <pkg> prints every dependency chain
                                      that pulls a package in, risk-annotated.
  targate history [<package>[@version]]   Trust history: every recorded approval —
                                      who, when, verdict, policy, AI provider.
                                      --verify checks SSH signatures against
                                      .targate/allowed-signers (exit 2 on invalid)
  targate doctor [--ping]                 Check the environment (Node, package manager,
                                      registry, OSV, AI provider, GitHub, policy,
                                      cache dirs, CI mode); exit 1 on failure
  targate monitor [--all]                 Re-check monitored packages (approvals +
                                      direct deps, or --all for the whole tree)
                                      against .targate/monitor-baseline.json
  targate cache info                      Show the AI response cache location + size
  targate cache clear [--scope <s>]       Delete the AI response cache
                                      (--scope user | project; default: policy's)
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
  --no-cache              Ignore cached AI assessments for this run (recompute);
                          fresh results still refresh the cache
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
  --concurrency <n>       (add --deep, install) Packages analyzed in parallel
                          (default: 16). Lower it if a cloud AI provider
                          rate-limits you.
  --no-ai-batch           (add --deep, install) Assess each package in its own
                          AI request instead of batching several per request
                          (stricter per-package isolation; slower/costlier)
  --no-reputation         Skip the external reputation lookups (npm downloads,
                          GitHub repo status). Registry-derived reputation
                          signals are still computed.
  --frozen-lockfile       (install) Immutable install (npm ci / --frozen-lockfile)
  --allow-scripts         (install) Run lifecycle scripts (default: disabled)
                          (approve) Record the approval as scripts-allowed
  --limit <n>             (recommend) Candidates to analyze (default: 5, max: 15;
                          each costs a real tarball download + analysis)
  --format <fmt>          (graph) html (default) | svg | dot | mermaid | json
  --output <path>         (graph) Output file ("-" = stdout; defaults:
                          html/svg → targate-graph.<ext>, dot/mermaid → stdout)
  --only <filters>        (graph) Prune to matching nodes + their paths to root:
                          high-risk, scripts, native, deprecated, malicious,
                          no-provenance, risk-increased (comma-separated)
  --why <pkg>             (graph) Print every dependency chain from the root(s)
                          to <pkg>, each hop risk-annotated (like pnpm why,
                          but with verdicts)
  --open                  (graph) Open the written html/svg in the browser
  --sign                  (approve) Sign the approval entry with your SSH key
                          (TARGATE_SIGNING_KEY, git user.signingkey, or
                          ~/.ssh/id_*) so it verifies against the committed
                          .targate/allowed-signers file
  --verify                (history) Verify each entry's signature
  --base-ref <ref>        (ci) Git ref to diff against (default: origin/main)
  --fail-on <level>       (diff) Exit 2 at this diff-risk level or above
                          (low | medium | high; default: high)
  --all                   (monitor) Monitor the entire lockfile tree, not just
                          approvals + direct dependencies
  --no-update             (monitor) Report events without advancing the baseline

Options (doctor):
  --ping                  Send one real (paid) test completion to the resolved
                          AI provider to verify it end to end

Options (sandbox):
  --image <image>         Docker image (default: node:20-alpine)
  --timeout <seconds>     Kill the sandbox after N seconds (default: 300)
  --network <mode>        open (default, full egress) | none (offline trial)
  --no-capture            Do not observe network activity (DNS + HTTP(S) proxy).
                          Capture is on by default; inert with --network none.
  --json                  Machine-readable result (incl. observed network activity)

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
      "no-cache": { type: "boolean", default: false },
      provider: { type: "string" },
      model: { type: "string" },
      "base-url": { type: "string" },
      "api-key": { type: "string" },
      reasoning: { type: "boolean", default: false },
      "base-ref": { type: "string" },
      "fail-on-osv-error": { type: "boolean", default: false },
      deep: { type: "boolean", default: false },
      concurrency: { type: "string" },
      "no-ai-batch": { type: "boolean", default: false },
      "no-reputation": { type: "boolean", default: false },
      "frozen-lockfile": { type: "boolean", default: false },
      "allow-scripts": { type: "boolean", default: false },
      image: { type: "string" },
      timeout: { type: "string" },
      network: { type: "string" },
      format: { type: "string" },
      scope: { type: "string" },
      ping: { type: "boolean", default: false },
      last: { type: "boolean", default: false },
      "fail-on": { type: "string" },
      "no-capture": { type: "boolean", default: false },
      all: { type: "boolean", default: false },
      "no-update": { type: "boolean", default: false },
      sign: { type: "boolean", default: false },
      verify: { type: "boolean", default: false },
      preset: { type: "string" },
      limit: { type: "string" },
      output: { type: "string" },
      only: { type: "string" },
      why: { type: "string" },
      open: { type: "boolean", default: false },
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

  // Positive integer or undefined — an invalid/≤0 value falls back to the default.
  const parsedConcurrency = Number(values.concurrency);
  const concurrency =
    values.concurrency !== undefined && Number.isInteger(parsedConcurrency) && parsedConcurrency > 0
      ? parsedConcurrency
      : undefined;

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
        concurrency,
        noAiBatch: values["no-ai-batch"],
        noReputation: values["no-reputation"],
        noCache: values["no-cache"],
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
        sign: values.sign,
        failOnOsvError: values["fail-on-osv-error"],
        deep: values.deep,
        noReputation: values["no-reputation"],
        noCache: values["no-cache"],
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
        concurrency,
        noAiBatch: values["no-ai-batch"],
        noReputation: values["no-reputation"],
        noCache: values["no-cache"],
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
        capture: !values["no-capture"],
        json: values.json,
      });
    }

    case "ci": {
      return ciCommand({
        init: rest[0] === "init",
        baseRef: values["base-ref"],
        json: values.json,
        failOnOsvError: values["fail-on-osv-error"],
        noReputation: values["no-reputation"],
        assess,
      });
    }

    case "policy": {
      if (rest[0] !== "init") {
        console.error(red("Usage: targate policy init [--format yaml|json|js|ts] [--preset <name>]"));
        return 1;
      }
      const format = (values.format ?? "yaml") as PolicyFormat;
      if (!["yaml", "json", "js", "ts"].includes(format)) {
        console.error(red(`Unknown policy format: ${format}. Valid options: yaml, json, js, ts`));
        return 1;
      }
      const preset = values.preset ?? "default";
      if (!(preset in POLICY_PRESETS)) {
        console.error(
          red(`Unknown policy preset: ${preset}. Available presets:`),
        );
        for (const [name, def] of Object.entries(POLICY_PRESETS)) {
          console.error(`  ${name.padEnd(14)} ${dim(def.description)}`);
        }
        return 1;
      }
      const file = await initPolicy(process.cwd(), format, preset);
      if (file) {
        console.log(green(`Created ${file} (preset: ${preset})`));
        console.log(dim("Edit the rules, then commit the file — it applies to every targate run in this repo."));
      } else {
        console.log(yellow(`A targate.policy.* file already exists — nothing written.`));
      }
      return 0;
    }

    case "doctor": {
      return doctorCommand({ json: values.json, ping: values.ping, assess });
    }

    case "diff": {
      if (!rest[0]) {
        console.error(red("Usage: targate diff <pkg>@<v1> [<pkg>[@<v2>]]"));
        return 1;
      }
      const failOn = (values["fail-on"] ?? "high") as "low" | "medium" | "high";
      if (!["low", "medium", "high"].includes(failOn)) {
        console.error(red(`Unknown --fail-on level: ${failOn}. Valid options: low, medium, high`));
        return 1;
      }
      return diffCommand({
        specA: rest[0],
        specB: rest[1],
        packageManager: values["package-manager"],
        json: values.json,
        failOnOsvError: values["fail-on-osv-error"],
        noReputation: values["no-reputation"],
        failOn,
        assess,
      });
    }

    case "monitor": {
      return monitorCommand({
        packageManager: values["package-manager"],
        json: values.json,
        all: values.all,
        noUpdate: values["no-update"],
        failOnOsvError: values["fail-on-osv-error"],
        noReputation: values["no-reputation"],
        concurrency,
        assess,
      });
    }

    case "graph": {
      return graphCommand({
        spec: rest[0],
        format: values.format,
        output: values.output,
        only: values.only,
        why: values.why,
        open: values.open,
        json: values.json,
        packageManager: values["package-manager"],
        noReputation: values["no-reputation"],
        failOnOsvError: values["fail-on-osv-error"],
        concurrency,
      });
    }

    case "recommend": {
      if (!rest[0]) {
        console.error(red('Usage: targate recommend "<need>" [--limit <n>]'));
        return 1;
      }
      const parsedLimit = Number(values.limit);
      if (values.limit !== undefined && (!Number.isInteger(parsedLimit) || parsedLimit <= 0)) {
        console.error(red(`Invalid --limit: ${values.limit}. Use a positive integer.`));
        return 1;
      }
      return recommendCommand({
        // Unquoted multi-word needs arrive as several positionals — join them.
        query: rest.join(" "),
        limit: values.limit !== undefined ? parsedLimit : undefined,
        json: values.json,
        noReputation: values["no-reputation"],
        failOnOsvError: values["fail-on-osv-error"],
        assess,
      });
    }

    case "history": {
      return historyCommand({
        spec: rest[0],
        json: values.json,
        verify: values.verify,
      });
    }

    case "explain": {
      // Exactly one of <spec> / --last.
      if (values.last === Boolean(rest[0])) {
        console.error(red("Usage: targate explain <package>[@version] | targate explain --last"));
        return 1;
      }
      return explainCommand({
        spec: rest[0],
        last: values.last,
        json: values.json,
        failOnOsvError: values["fail-on-osv-error"],
        noReputation: values["no-reputation"],
        noCache: values["no-cache"],
        assess,
      });
    }

    case "cache": {
      return cacheCommand({
        action: rest[0],
        scope: values.scope,
        json: values.json,
      });
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
        concurrency,
        noAiBatch: values["no-ai-batch"],
        noReputation: values["no-reputation"],
        noCache: values["no-cache"],
        assess,
      });
  }
}

/**
 * process.exit() truncates stdout that hasn't drained to a pipe yet (the HELP
 * text alone now exceeds one 8KB pipe buffer). Queue the exit BEHIND every
 * pending stdout write: an empty write's callback fires only after the
 * stream has flushed everything queued before it.
 */
function exitFlushed(code: number): void {
  process.stdout.write("", () => process.exit(code));
}

main()
  .then((code) => exitFlushed(code))
  .catch((err) => {
    console.error(red(`\ntargate failed: ${err instanceof Error ? err.message : String(err)}`));
    exitFlushed(1);
  });
