import { readFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { describe, expect, it } from "vitest";
import {
  COMMAND_DEFINITIONS,
  findCommand,
  parseConcurrency,
  parseOptionsFor,
  renderCommandHelp,
  renderGlobalHelp,
} from "../src/command-registry.js";
import { PRODUCT_DESCRIPTION, checkDocumentation } from "../src/docs-consistency.js";

const repoRoot = path.resolve(__dirname, "..");

describe("declarative command registry", () => {
  it("defines every command and option only once per command", () => {
    const names = COMMAND_DEFINITIONS.map((command) => command.name);
    expect(new Set(names).size).toBe(names.length);
    for (const command of COMMAND_DEFINITIONS) {
      const options = command.options.map((definition) => definition.name);
      expect(new Set(options).size).toBe(options.length);
      expect(typeof command.handler).toBe("function");
    }
  });

  it("rejects a known flag when the selected command does not support it", () => {
    const doctor = findCommand("doctor");
    expect(doctor).toBeDefined();
    expect(() => parseArgs({ args: ["--deep"], strict: true, options: parseOptionsFor(doctor!) })).toThrow();
  });

  it("keeps global and per-command help under snapshots", () => {
    expect(renderGlobalHelp()).toMatchSnapshot("global help");
    for (const command of COMMAND_DEFINITIONS) {
      expect(renderCommandHelp(command)).toMatchSnapshot(`${command.name} help`);
    }
  });
});

// Offline, deterministic replacement for the old cli.test.ts case that spawned a
// real `targate add ... --concurrency 8` (which hit the npm registry). We assert
// the flag is accepted by the option parser and threaded through parseConcurrency
// — the exact contract the removed end-to-end run was standing in for.
describe("--concurrency parsing and threading", () => {
  const parse = (commandName: string, args: string[]) =>
    parseArgs({
      args,
      allowPositionals: true,
      strict: true,
      options: parseOptionsFor(findCommand(commandName)!),
    }).values as Record<string, unknown>;

  it("is a declared option on every command that runs the tree walker", () => {
    for (const name of ["add", "audit", "install", "monitor", "graph"]) {
      const command = findCommand(name);
      expect(command, name).toBeDefined();
      expect(command!.options.some((o) => o.name === "concurrency"), name).toBe(true);
    }
  });

  it("accepts --concurrency on `add` and parses it to a positive integer", () => {
    const values = parse("add", ["left-pad@1.3.0", "--no-ai", "--dry-run", "--concurrency", "8"]);
    expect(values.concurrency).toBe("8");
    expect(parseConcurrency(values)).toBe(8);
  });

  it("accepts --concurrency on `install` too", () => {
    expect(parseConcurrency(parse("install", ["--concurrency", "4"]))).toBe(4);
  });

  it("ignores an absent, non-numeric, or non-positive value (falls back to the default)", () => {
    expect(parseConcurrency(parse("add", ["left-pad"]))).toBeUndefined();
    expect(parseConcurrency(parse("add", ["left-pad", "--concurrency", "abc"]))).toBeUndefined();
    expect(parseConcurrency(parse("add", ["left-pad", "--concurrency", "0"]))).toBeUndefined();
    expect(parseConcurrency(parse("add", ["left-pad", "--concurrency=-3"]))).toBeUndefined();
  });
});

describe("documentation consistency", () => {
  it("keeps generated sections, examples, and local links valid", async () => {
    expect(await checkDocumentation(repoRoot)).toEqual([]);
  });
});

describe("product positioning (Milestone 6.1)", () => {
  it("keeps one canonical primary description", () => {
    expect(PRODUCT_DESCRIPTION).toBe(
      "targate is install-time supply-chain security for npm — open source, AI-optional, and run from your terminal.",
    );
  });

  it("uses that description consistently across the README, docs index, and manifest", () => {
    const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
    const docsIndex = readFileSync(path.join(repoRoot, "docs", "README.md"), "utf8");
    const manifest = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8")) as {
      description: string;
    };
    expect(readme).toContain(PRODUCT_DESCRIPTION);
    expect(docsIndex).toContain(PRODUCT_DESCRIPTION);
    expect(manifest.description).toContain(PRODUCT_DESCRIPTION);
  });

  it("leads with the supply-chain-security category and distinguishes it from app-sec", () => {
    const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
    // The H1 states the category up front, not an abstract "intelligence layer".
    expect(readme).toMatch(/^# targate — install-time supply-chain security for npm/m);
    expect(readme).toMatch(/supply-chain, not application security/i);
    // The honest roadmap section is kept.
    expect(readme).toContain("What's shipped today vs. the vision");
  });
});
