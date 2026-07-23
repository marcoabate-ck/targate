import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import {
  buildClaudeArgs,
  buildGuardSettings,
  extractJsonObject,
  runWorker,
  type WorkerAssignment,
} from "../src/worker.js";
import { claudeWrapper, fakeSpawn, VALID_BODY } from "./helpers.js";

const config = defaultConfig();
let dir: string;
const now = () => new Date("2026-07-22T12:00:00.000Z");

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "la-worker-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function assignment(overrides: Partial<WorkerAssignment> = {}): WorkerAssignment {
  return {
    runId: "r1",
    workerId: "discovery-1",
    role: "discovery",
    task: "look around",
    cwd: dir,
    scopes: [dir],
    ...overrides,
  };
}

const base = () => ({ now, claudeBin: "claude", settingsPath: path.join(dir, "s.json"), parentEnv: { PATH: process.env.PATH ?? "" } });

describe("runWorker", () => {
  it("parses a valid worker body and captures runtime usage", async () => {
    const out = await runWorker(assignment(), config, {
      ...base(),
      spawnFn: fakeSpawn({ stdout: claudeWrapper(VALID_BODY), exitCode: 0 }),
    });
    expect(out.result.status).toBe("completed");
    expect(out.result.summary).toBe("did the thing");
    expect(out.result.usage?.source).toBe("runtime");
    expect(out.result.usage?.inputTokens).toBe(100);
    expect(out.transient).toBe(false);
  });

  it("treats a malformed body as a failure, not success", async () => {
    const out = await runWorker(assignment(), config, {
      ...base(),
      spawnFn: fakeSpawn({ stdout: claudeWrapper("I could not produce JSON, sorry."), exitCode: 0 }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.result.errors[0].kind).toBe("protocol");
  });

  it("fails on ENOENT (claude not installed) without marking it transient", async () => {
    const err = Object.assign(new Error("spawn claude ENOENT"), { code: "ENOENT" });
    const out = await runWorker(assignment(), config, {
      ...base(),
      spawnFn: fakeSpawn({ spawnError: err }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.result.errors[0].kind).toBe("spawn");
    expect(out.transient).toBe(false);
  });

  it("terminates and reports a timeout as transient", async () => {
    const out = await runWorker(assignment({ timeoutMs: 30 }), config, {
      ...base(),
      spawnFn: fakeSpawn({ hang: true }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.result.errors[0].kind).toBe("timeout");
    expect(out.transient).toBe(true);
  });

  it("classifies a connection error as transient", async () => {
    const out = await runWorker(assignment(), config, {
      ...base(),
      spawnFn: fakeSpawn({
        stdout: claudeWrapper("", { is_error: true, subtype: "error", result: "" }),
        stderr: "fetch failed: ECONNREFUSED 127.0.0.1:11434",
        exitCode: 1,
      }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.transient).toBe(true);
  });

  it("gives an explicit, actionable error when Ollama is unreachable", async () => {
    const out = await runWorker(assignment(), config, {
      ...base(),
      spawnFn: fakeSpawn({
        stdout: claudeWrapper("", { is_error: true, subtype: "error", result: "" }),
        stderr: "connect ECONNREFUSED 127.0.0.1:11434",
        exitCode: 1,
      }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.result.errors[0].kind).toBe("ollama-unreachable");
    expect(out.result.errors[0].message).toMatch(/ollama serve/);
    expect(out.transient).toBe(true);
  });

  it("flags a writer that changed files outside its scope", async () => {
    const body = { ...VALID_BODY, status: "completed", filesChanged: ["../../etc/evil"] };
    const out = await runWorker(assignment({ role: "implementer", workerId: "impl-1" }), config, {
      ...base(),
      spawnFn: fakeSpawn({ stdout: claudeWrapper(body), exitCode: 0 }),
    });
    expect(out.result.status).toBe("failed");
    expect(out.result.errors.some((e) => e.kind === "scope-violation")).toBe(true);
  });

  it("rejects an unknown role deterministically", async () => {
    const out = await runWorker(assignment({ role: "wizard" }), config, base());
    expect(out.result.status).toBe("failed");
    expect(out.transient).toBe(false);
  });
});

describe("buildClaudeArgs / buildGuardSettings", () => {
  it("emits the expected worker flags", () => {
    const args = buildClaudeArgs({
      systemPrompt: "sp",
      model: "m",
      allowedTools: ["Read", "Bash"],
      disallowedTools: ["Edit"],
      scopes: ["/a", "/b"],
      settingsPath: "/s.json",
      task: "t",
    });
    expect(args).toContain("-p");
    expect(args).toContain("--no-session-persistence");
    expect(args).toContain("--strict-mcp-config");
    expect(args[args.indexOf("--model") + 1]).toBe("m");
    expect(args[args.indexOf("--permission-mode") + 1]).toBe("bypassPermissions");
    expect(args.filter((a) => a === "--add-dir")).toHaveLength(2);
  });
  it("installs a PreToolUse hook", () => {
    const s = JSON.parse(buildGuardSettings("/x/hook-guard.ts"));
    expect(s.hooks.PreToolUse[0].hooks[0].command).toContain("hook-guard.ts");
  });
});

describe("extractJsonObject", () => {
  it("parses raw, fenced, and prose-wrapped JSON", () => {
    expect(extractJsonObject('{"a":1}')).toEqual({ a: 1 });
    expect(extractJsonObject('```json\n{"a":2}\n```')).toEqual({ a: 2 });
    expect(extractJsonObject('Here you go:\n{"a":3}\nDone.')).toEqual({ a: 3 });
    expect(extractJsonObject("no json here")).toBeNull();
  });
});
