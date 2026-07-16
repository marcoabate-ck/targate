import { readFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { describe, expect, it } from "vitest";
import {
  COMMAND_DEFINITIONS,
  findCommand,
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

describe("documentation consistency", () => {
  it("keeps generated sections, examples, and local links valid", async () => {
    expect(await checkDocumentation(repoRoot)).toEqual([]);
  });
});

describe("product positioning (Milestone 6.1)", () => {
  it("keeps one canonical primary description", () => {
    expect(PRODUCT_DESCRIPTION).toBe(
      "targate is an AI-assisted dependency intelligence and decision layer for developers, teams, and coding agents.",
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

  it("keeps pre-install security framed as the first application, not the whole category", () => {
    const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
    expect(readme).toMatch(/first application/i);
    expect(readme).toContain("What's shipped today vs. the vision");
  });
});
