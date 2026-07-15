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
import { checkDocumentation } from "../src/docs-consistency.js";

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

