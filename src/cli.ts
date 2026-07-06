#!/usr/bin/env node
import { parseArgs } from "node:util";
import { buildSignals } from "./analyze/index.js";
import { assessRisk } from "./ai.js";
import { detectPackageManager, gateInstall } from "./installer.js";
import { queryOsv, type OsvResult } from "./osv.js";
import { quarantineTarball } from "./quarantine.js";
import type { ProviderName } from "./providers/index.js";
import { fetchPackageMetadata, PackageNotFoundError, parsePackageSpec } from "./registry.js";
import { bold, dim, green, red, renderReport, yellow } from "./report.js";
import type { PackageManager } from "./types.js";

const VALID_PROVIDERS: ProviderName[] = ["anthropic", "deepseek", "openai", "ollama", "custom"];

const HELP = `
bye — AI-gated package installation

Usage:
  bye <package>[@version] [options]

Options:
  --package-manager <pm>  Force pnpm | npm | yarn (default: auto-detect)
  --json                  Print machine-readable JSON instead of the report
  --dry-run               Analyze and report only, never install
  --yes                   Skip confirmation for allow/allow-with-warnings
  --no-ai                 Skip the AI reasoning layer, use rules only
  --provider <name>       anthropic | deepseek | openai | ollama | custom
                          (default: auto-detect from env vars, see below)
  --model <name>          Override the model for the selected provider
  --base-url <url>        API base URL (required for --provider custom)
  --api-key <key>         API key (prefer env vars below over this flag)
  --reasoning             Enable model reasoning where the provider supports it
                          (anthropic reasons by default; openai: reasoning_effort;
                          deepseek: switches to deepseek-reasoner; ollama/custom:
                          use a reasoning model, <think> blocks are handled)
  -h, --help              Show this help

Provider auto-detection (first match wins):
  ANTHROPIC_API_KEY set        -> anthropic  (claude-opus-4-8)
  DEEPSEEK_API_KEY set         -> deepseek   (deepseek-chat)
  OPENAI_API_KEY set           -> openai     (gpt-4o-mini)
  OLLAMA_HOST / OLLAMA_MODEL   -> ollama     (local, default http://localhost:11434/v1)
  none of the above            -> deterministic rules engine (no AI)

Examples:
  bye react-native-mmkv
  bye left-pad@1.3.0 --dry-run
  bye some-package --package-manager npm --json
  bye some-package --provider ollama --model llama3.1
  bye some-package --provider custom --base-url http://localhost:1234/v1 --model local-model
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
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    console.log(HELP);
    return values.help ? 0 : 1;
  }

  const spec = positionals[0];
  const { name, version } = parsePackageSpec(spec);

  const pm = (values["package-manager"] as PackageManager) ?? detectPackageManager();
  if (!["pnpm", "npm", "yarn"].includes(pm)) {
    console.error(red(`Unknown package manager: ${pm}`));
    return 1;
  }

  if (values.provider && !VALID_PROVIDERS.includes(values.provider as ProviderName)) {
    console.error(
      red(`Unknown provider: ${values.provider}. Valid options: ${VALID_PROVIDERS.join(", ")}`),
    );
    return 1;
  }

  console.log(dim(`\nPre-install review started for ${bold(name)}${version ? `@${version}` : ""} ...`));

  // 1-2. Resolve metadata from npm
  let metadata;
  try {
    metadata = await fetchPackageMetadata(name, version);
  } catch (err) {
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }
  console.log(dim(`  ✓ npm metadata resolved (${metadata.name}@${metadata.version})`));

  // 3. Quarantine tarball (never executes scripts)
  const quarantine = await quarantineTarball(metadata.tarballUrl);
  console.log(dim(`  ✓ tarball downloaded to quarantine`));

  try {
    // 5-7. OSV lookup (non-fatal if offline)
    let osv: OsvResult;
    try {
      osv = await queryOsv(metadata.name, metadata.version);
      console.log(dim(`  ✓ OSV/OpenSSF malicious-package lookup done`));
    } catch {
      osv = { knownMalicious: false, maliciousRecords: [], advisories: [] };
      console.log(yellow(`  ⚠ OSV lookup failed — continuing without it`));
    }

    // 4-6. Static analysis of the extracted package
    const signals = await buildSignals(metadata, quarantine.packageDir, osv);
    console.log(dim(`  ✓ package contents inspected (scripts, native surface, static analysis)`));

    // 7. AI reasoning layer (falls back to deterministic rules)
    const assessment = await assessRisk(signals, {
      useAi: !values["no-ai"],
      provider: values.provider as ProviderName | undefined,
      model: values.model,
      baseUrl: values["base-url"],
      apiKey: values["api-key"],
      reasoning: values.reasoning,
    });
    console.log(dim(`  ✓ risk assessment complete (${assessment.source})`));

    if (values.json) {
      console.log(JSON.stringify({ metadata, signals, assessment }, null, 2));
    } else {
      console.log(renderReport(metadata, signals, assessment));
    }

    // 8. Gate the real install
    const result = await gateInstall(assessment.decision, pm, `${metadata.name}@${metadata.version}`, {
      assumeYes: values.yes,
      dryRun: values["dry-run"],
    });

    switch (result.mode) {
      case "blocked":
        console.log(red(bold("\nInstallation blocked. This package was not installed.")));
        return 2;
      case "skipped":
        if (values["dry-run"] && result.command) {
          console.log(dim(`\nDry run — recommended command: ${result.command.join(" ")}`));
        } else {
          console.log(dim("\nNothing installed."));
        }
        return 0;
      case "no-scripts":
        console.log(green("\nInstalled with lifecycle scripts disabled."));
        return 0;
      case "normal":
        console.log(green("\nInstalled."));
        return 0;
    }
  } finally {
    await quarantine.cleanup();
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(red(`\nbye failed: ${err instanceof Error ? err.message : String(err)}`));
    process.exit(1);
  });
