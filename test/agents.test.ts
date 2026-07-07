import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  AGENT_FORMATS,
  agentFilePath,
  DEFAULT_AGENT_FORMATS,
  initAgentFiles,
  parseAgentFormats,
  renderAgentFile,
  type AgentFormat,
} from "../src/agents.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("parseAgentFormats", () => {
  it("parses a comma list and trims", () => {
    expect(parseAgentFormats("skill, agents ,cursor")).toEqual(["skill", "agents", "cursor"]);
  });

  it("expands 'all' to every format", () => {
    expect(parseAgentFormats("all")).toEqual(AGENT_FORMATS);
  });

  it("throws on an unknown format", () => {
    expect(() => parseAgentFormats("skill,bogus")).toThrow(/Unknown agent format/);
  });
});

describe("renderAgentFile", () => {
  it("every format carries the core rule and the no-bypass guardrail", () => {
    for (const format of AGENT_FORMATS) {
      const content = renderAgentFile(format);
      // The action every agent must take.
      expect(content).toContain("bye add");
      // The critical guardrail: don't route around a refusal via a raw pm.
      expect(content.toLowerCase()).toMatch(/never (bypass|fall back)/);
    }
  });

  it("the skill file has valid frontmatter with name and a triggering description", () => {
    const skill = renderAgentFile("skill");
    expect(skill.startsWith("---\n")).toBe(true);
    const fm = skill.slice(4, skill.indexOf("\n---"));
    expect(fm).toContain("name: bye");
    expect(fm).toMatch(/description:/);
    expect(fm.toLowerCase()).toMatch(/install|add|dependency/);
  });
});

describe("initAgentFiles", () => {
  it("writes the default formats to their canonical paths", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-agents-"));
    const res = await initAgentFiles(dir);
    expect(res.written).toEqual([path.join("skills", "bye", "SKILL.md"), "AGENTS.md"]);
    expect(res.skipped).toEqual([]);
    for (const rel of res.written) {
      expect(await readFile(path.join(dir, rel), "utf8")).toContain("bye add");
    }
  });

  it("writes every format with 'all' and lands each at the right path", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-agents-"));
    await initAgentFiles(dir, parseAgentFormats("all"));
    const expected: Record<AgentFormat, string> = {
      skill: "skills/bye/SKILL.md",
      agents: "AGENTS.md",
      cursor: ".cursor/rules/bye.mdc",
      windsurf: ".windsurf/rules/bye.md",
      copilot: ".github/copilot-instructions.md",
      cline: ".clinerules",
    };
    for (const format of AGENT_FORMATS) {
      expect(agentFilePath(format, dir)).toBe(path.join(dir, expected[format]));
      expect(await readFile(agentFilePath(format, dir), "utf8")).toContain("bye add");
    }
  });

  it("never overwrites an existing file and reports it as skipped", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "bye-agents-"));
    await writeFile(path.join(dir, "AGENTS.md"), "MY EXISTING RULES\n");
    const res = await initAgentFiles(dir, ["agents", "cline"]);
    expect(res.written).toEqual([".clinerules"]);
    expect(res.skipped).toEqual(["AGENTS.md"]);
    // The pre-existing file is untouched.
    expect(await readFile(path.join(dir, "AGENTS.md"), "utf8")).toBe("MY EXISTING RULES\n");
  });

  it("defaults to skill + agents", () => {
    expect(DEFAULT_AGENT_FORMATS).toEqual(["skill", "agents"]);
  });
});

describe("committed canonical files match the generator (drift guard)", () => {
  it("skills/bye/SKILL.md is up to date", async () => {
    const committed = await readFile(path.join(repoRoot, "skills", "bye", "SKILL.md"), "utf8");
    expect(committed).toBe(renderAgentFile("skill"));
  });

  it("AGENTS.md is up to date", async () => {
    const committed = await readFile(path.join(repoRoot, "AGENTS.md"), "utf8");
    expect(committed).toBe(renderAgentFile("agents"));
  });
});
