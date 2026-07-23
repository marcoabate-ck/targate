import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import { DOCTOR_CHECKS, runDoctor, type DoctorContext } from "../src/doctor.js";

let cwd: string;
beforeEach(async () => {
  cwd = await mkdtemp(path.join(tmpdir(), "la-doctor-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

/** Stub fetch keyed by URL substring. */
function stub(map: Record<string, { status: number; body: string }>): typeof fetch {
  return (async (input: string | URL) => {
    const url = String(input);
    const key = Object.keys(map).find((k) => url.includes(k));
    const entry = key ? map[key] : { status: 200, body: "{}" };
    return { status: entry.status, text: async () => entry.body } as Response;
  }) as unknown as typeof fetch;
}

function ctx(fetchFn: typeof fetch, model = defaultConfig().runtime.model): DoctorContext {
  const config = defaultConfig();
  config.runtime.model = model;
  return { cwd, config, configFile: null, ping: false, fetchFn };
}

function pick(ids: string[]) {
  return DOCTOR_CHECKS.filter((c) => ids.includes(c.id));
}

describe("doctor", () => {
  it("passes the Anthropic-route probe on a 400 (route exists)", async () => {
    const report = await runDoctor(
      ctx(stub({ "/v1/messages": { status: 400, body: "" } })),
      pick(["anthropic-route"]),
    );
    expect(report.checks[0].status).toBe("pass");
  });

  it("fails the Anthropic-route probe on a 404 (route absent)", async () => {
    const report = await runDoctor(
      ctx(stub({ "/v1/messages": { status: 404, body: "not found" } })),
      pick(["anthropic-route"]),
    );
    expect(report.checks[0].status).toBe("fail");
    expect(report.exitCode).toBe(1);
  });

  it("passes model-present when the model is listed", async () => {
    const report = await runDoctor(
      ctx(stub({ "/api/tags": { status: 200, body: JSON.stringify({ models: [{ name: defaultConfig().runtime.model }] }) } })),
      pick(["model-present"]),
    );
    expect(report.checks[0].status).toBe("pass");
  });

  it("fails model-present with a pull hint when the model is missing", async () => {
    const report = await runDoctor(
      ctx(stub({ "/api/tags": { status: 200, body: JSON.stringify({ models: [{ name: "other" }] }) } })),
      pick(["model-present"]),
    );
    expect(report.checks[0].status).toBe("fail");
    expect(report.checks[0].message).toMatch(/ollama pull /);
  });

  it("fails when the Ollama server is unreachable", async () => {
    const failing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const report = await runDoctor(ctx(failing), pick(["ollama-server"]));
    expect(report.checks[0].status).toBe("fail");
  });

  it("confirms secret isolation and a writable run dir", async () => {
    const report = await runDoctor(ctx(stub({})), pick(["secret-isolation", "run-dir"]));
    expect(report.summary.fail).toBe(0);
    expect(report.checks.find((c) => c.id === "secret-isolation")?.status).toBe("pass");
  });
});
