import { existsSync } from "node:fs";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import {
  COMMAND_DEFINITIONS,
  findCommand,
  parseOptionsFor,
  renderCliReference,
  renderReadmeCommandTable,
} from "./command-registry.js";

/**
 * The single canonical product description (Milestone 6.1). Messaging in the
 * README, the docs index, and the package manifest must all contain this exact
 * sentence so positioning cannot drift; the docs check enforces it.
 */
export const PRODUCT_DESCRIPTION =
  "targate is install-time supply-chain security for npm — open source, AI-optional, and run from your terminal.";

export const README_COMMANDS_START = "<!-- targate:commands:start -->";
export const README_COMMANDS_END = "<!-- targate:commands:end -->";
export const CLI_REFERENCE_START = "<!-- targate:cli-reference:start -->";
export const CLI_REFERENCE_END = "<!-- targate:cli-reference:end -->";

function generatedBlock(start: string, content: string, end: string): string {
  return `${start}\n${content}\n${end}`;
}

function shellWords(input: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  for (const character of input) {
    if (quote) {
      if (character === quote) quote = undefined;
      else current += character;
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current) words.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  if (quote) throw new Error(`unclosed quote in example: ${input}`);
  if (current) words.push(current);
  return words;
}

async function markdownFiles(root: string): Promise<string[]> {
  const docsRoot = path.join(root, "docs");
  const files = [path.join(root, "README.md")];
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile() && entry.name.endsWith(".md")) files.push(file);
    }
  };
  await visit(docsRoot);
  return files;
}

function localMarkdownTargets(markdown: string): string[] {
  const targets: string[] = [];
  const links = markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/g);
  for (const match of links) {
    const raw = match[1].trim().replace(/^<|>$/g, "");
    const target = raw.split(/\s+["']/)[0];
    if (!target || target.startsWith("#") || /^[a-z][a-z+.-]*:/i.test(target)) continue;
    targets.push(decodeURIComponent(target.split("#")[0]));
  }
  return targets;
}

function replaceGeneratedBlock(source: string, start: string, end: string, content: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end);
  if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
    throw new Error(`generated block markers ${start} … ${end} not found`);
  }
  return `${source.slice(0, startIndex)}${generatedBlock(start, content, end)}${source.slice(endIndex + end.length)}`;
}

/**
 * Regenerate the command tables embedded in README.md and docs/cli-reference.md
 * from the command registry — the write counterpart of {@link checkDocumentation}.
 * Run after changing the command registry so the docs check stays green.
 */
export async function writeGeneratedDocs(root: string): Promise<void> {
  const readmeFile = path.join(root, "README.md");
  const readme = await readFile(readmeFile, "utf8");
  await writeFile(
    readmeFile,
    replaceGeneratedBlock(readme, README_COMMANDS_START, README_COMMANDS_END, renderReadmeCommandTable()),
  );

  const cliReferenceFile = path.join(root, "docs", "cli-reference.md");
  const cliReference = await readFile(cliReferenceFile, "utf8");
  await writeFile(
    cliReferenceFile,
    replaceGeneratedBlock(cliReference, CLI_REFERENCE_START, CLI_REFERENCE_END, renderCliReference()),
  );
}

export async function checkDocumentation(root: string): Promise<string[]> {
  const errors: string[] = [];
  const names = COMMAND_DEFINITIONS.map((command) => command.name);
  if (new Set(names).size !== names.length) errors.push("command registry contains duplicate commands");

  for (const command of COMMAND_DEFINITIONS) {
    const optionNames = command.options.map((definition) => definition.name);
    if (new Set(optionNames).size !== optionNames.length) {
      errors.push(`${command.name} contains duplicate options`);
    }
    for (const example of command.examples) {
      try {
        const words = shellWords(example);
        const [, commandName, ...args] = words;
        const exampleCommand = commandName ? findCommand(commandName) : undefined;
        if (words[0] !== "targate" || !exampleCommand) {
          errors.push(`invalid CLI example: ${example}`);
          continue;
        }
        parseArgs({ args, allowPositionals: true, strict: true, options: parseOptionsFor(exampleCommand) });
      } catch (error) {
        errors.push(`unparsable CLI example \`${example}\`: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  const readmeFile = path.join(root, "README.md");
  const readme = await readFile(readmeFile, "utf8");
  const expectedReadme = generatedBlock(README_COMMANDS_START, renderReadmeCommandTable(), README_COMMANDS_END);
  if (!readme.includes(expectedReadme)) errors.push("README command table is stale; regenerate it from the command registry");
  if (/\b\d+ tests\b/.test(readme)) errors.push("README contains a manual test count that can become stale");

  if (!readme.includes(PRODUCT_DESCRIPTION)) {
    errors.push(`README is missing the canonical product description: "${PRODUCT_DESCRIPTION}"`);
  }

  const docsIndexFile = path.join(root, "docs", "README.md");
  const docsIndex = await readFile(docsIndexFile, "utf8");
  if (!docsIndex.includes(PRODUCT_DESCRIPTION)) {
    errors.push(`docs/README.md is missing the canonical product description: "${PRODUCT_DESCRIPTION}"`);
  }

  const manifestFile = path.join(root, "package.json");
  const manifest = JSON.parse(await readFile(manifestFile, "utf8")) as { description?: string };
  if (!manifest.description?.includes(PRODUCT_DESCRIPTION)) {
    errors.push(`package.json description is missing the canonical product description: "${PRODUCT_DESCRIPTION}"`);
  }

  const cliReferenceFile = path.join(root, "docs", "cli-reference.md");
  const cliReference = await readFile(cliReferenceFile, "utf8");
  const expectedReference = generatedBlock(CLI_REFERENCE_START, renderCliReference(), CLI_REFERENCE_END);
  if (!cliReference.includes(expectedReference)) errors.push("CLI reference command/options table is stale; regenerate it from the command registry");

  for (const file of await markdownFiles(root)) {
    const markdown = await readFile(file, "utf8");
    for (const target of localMarkdownTargets(markdown)) {
      const absolute = path.resolve(path.dirname(file), target);
      if (!existsSync(absolute)) errors.push(`${path.relative(root, file)} links to missing ${target}`);
    }
  }
  return errors;
}
