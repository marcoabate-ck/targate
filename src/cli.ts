#!/usr/bin/env node
import { parseArgs } from "node:util";
import {
  findCommand,
  parseOptionsFor,
  renderCommandHelp,
  renderGlobalHelp,
  validateProvider,
  type CommandValues,
} from "./command-registry.js";
import { red } from "./report.js";
import { TARGATE_VERSION } from "./version.js";

function unknownCommandMessage(name: string): string {
  const suggestion = name === "instal" ? " Did you mean `targate install`?" : "";
  return `Unknown command: ${name}.${suggestion} Run \`targate --help\` for usage.`;
}

export async function main(args: string[] = process.argv.slice(2)): Promise<number> {
  if (args.length === 0) {
    console.log(renderGlobalHelp());
    return 1;
  }
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    console.log(renderGlobalHelp());
    return 0;
  }
  if (args.length === 1 && (args[0] === "--version" || args[0] === "-v")) {
    console.log(TARGATE_VERSION);
    return 0;
  }

  const [commandName, ...commandArgs] = args;
  const command = findCommand(commandName);
  if (!command) {
    console.error(red(unknownCommandMessage(commandName)));
    return 1;
  }

  let parsed;
  try {
    parsed = parseArgs({
      args: commandArgs,
      allowPositionals: true,
      strict: true,
      options: parseOptionsFor(command),
    });
  } catch (error) {
    console.error(red(error instanceof Error ? error.message : String(error)));
    console.error(red(`Usage: ${command.usage}`));
    return 1;
  }

  const values = parsed.values as CommandValues;
  if (values.help) {
    console.log(renderCommandHelp(command));
    return 0;
  }

  const providerError = validateProvider(values);
  if (providerError) {
    console.error(red(providerError));
    return 1;
  }

  return command.handler({ values, positionals: parsed.positionals });
}

/** Flush pending stdout before exiting; large help output can exceed one pipe buffer. */
function exitFlushed(code: number): void {
  process.stdout.write("", () => process.exit(code));
}

main()
  .then((code) => exitFlushed(code))
  .catch((error) => {
    console.error(red(`\ntargate failed: ${error instanceof Error ? error.message : String(error)}`));
    exitFlushed(1);
  });
