/**
 * Opt-in integration test — runs a REAL local worker against Ollama.
 *
 * Skipped unless LOCAL_AGENT_INTEGRATION=1. Even then it checks prerequisites
 * (Ollama reachable, the model present, claude on PATH) and skips cleanly when
 * any are missing. It uses a throwaway temp fixture and never touches the real
 * repository. It DOES load the 35B model, so it is slow — hence opt-in.
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { orchestrateSingle } from "../src/orchestrator.js";

const exec = promisify(execFile);
const ENABLED = process.env.LOCAL_AGENT_INTEGRATION === "1";
const config = defaultConfig();

async function prereqsMet(): Promise<boolean> {
  try {
    await exec("claude", ["--version"], { timeout: 5_000 });
    const res = await fetch(`${config.runtime.baseUrl}/api/tags`, { signal: AbortSignal.timeout(3_000) });
    const body = (await res.json()) as { models?: { name?: string }[] };
    return (body.models ?? []).some((m) => m.name === config.runtime.model);
  } catch {
    return false;
  }
}

describe.skipIf(!ENABLED)("integration: real local worker", () => {
  let fixture: string;
  let ok = false;

  beforeAll(async () => {
    ok = await prereqsMet();
    if (!ok) return;
    fixture = await mkdtemp(path.join(tmpdir(), "la-integ-"));
    await writeFile(path.join(fixture, "AGENTS.md"), "# Fixture\nThis is a throwaway fixture repo.\n");
    await writeFile(path.join(fixture, "hello.ts"), "export const greet = () => 'hi';\n");
  });

  afterAll(async () => {
    if (fixture) await rm(fixture, { recursive: true, force: true });
  });

  it("runs a discovery worker end-to-end", async () => {
    if (!ok) {
      // eslint-disable-next-line no-console
      console.warn("integration prerequisites missing — skipping");
      return;
    }
    const { result } = await orchestrateSingle({
      cwd: fixture,
      role: "discovery",
      task: "List the TypeScript files in this repo and describe hello.ts in one sentence.",
      config,
      timeoutMs: 180_000,
    });
    expect(["completed", "partial"]).toContain(result.status);
    expect(result.summary.length).toBeGreaterThan(0);
  }, 200_000);
});
