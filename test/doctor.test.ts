import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { doctorCommand } from "../src/commands/doctor.js";
import {
  DOCTOR_CHECKS,
  runDoctor,
  type DoctorCheck,
  type DoctorContext,
} from "../src/doctor.js";

const ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "DEEPSEEK_API_KEY",
  "OPENAI_API_KEY",
  "OLLAMA_HOST",
  "OLLAMA_MODEL",
  "AI_API_KEY",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "CI",
];

let dir: string;
let cwd: string;
const saved: Record<string, string | undefined> = {};

function makeCtx(overrides: Partial<DoctorContext> = {}): DoctorContext {
  return {
    cwd: dir,
    env: process.env,
    networkTimeoutMs: 1_000,
    ping: false,
    provider: {},
    ...overrides,
  };
}

function check(id: string): DoctorCheck {
  return DOCTOR_CHECKS.find((c) => c.id === id)!;
}

/** fetch stub branching on URL; unlisted hosts resolve ok. */
function stubFetch(handler: (url: string) => Partial<Response> | undefined) {
  const mock = vi.fn(async (input: string | URL) => {
    const url = String(input);
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      json: async () => ({}),
      ...handler(url),
    } as Response;
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-doctor-"));
  process.chdir(dir);
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("individual checks", () => {
  it("node-version passes on the current runtime (≥20 required to run tests)", async () => {
    const r = await check("node-version").run(makeCtx());
    expect(r.status).toBe("pass");
  });

  it("ai-provider reports info when nothing is configured", async () => {
    const r = await check("ai-provider").run(makeCtx());
    expect(r.status).toBe("info");
    expect(r.message).toContain("rules engine");
  });

  it("ai-provider passes with a configured provider, naming the model", async () => {
    process.env.ANTHROPIC_API_KEY = "test-key";
    const r = await check("ai-provider").run(makeCtx());
    expect(r.status).toBe("pass");
    expect(r.message).toContain("anthropic");
  });

  it("ai-provider fails with resolveProvider's message when selected but misconfigured", async () => {
    const r = await check("ai-provider").run(makeCtx({ provider: { provider: "openai" } }));
    expect(r.status).toBe("fail");
    expect(r.message).toContain("OPENAI_API_KEY");
  });

  it("npm-registry passes on 2xx and fails on network errors", async () => {
    stubFetch(() => undefined);
    expect((await check("npm-registry").run(makeCtx())).status).toBe("pass");

    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("offline");
    }));
    expect((await check("npm-registry").run(makeCtx())).status).toBe("fail");
  });

  it("osv posts a query and warns on a non-2xx response", async () => {
    const mock = stubFetch((url) =>
      url.includes("osv.dev") ? ({ ok: false, status: 503 } as Partial<Response>) : undefined,
    );
    const r = await check("osv").run(makeCtx());
    expect(r.status).toBe("warn");
    expect(r.message).toContain("503");
    expect(mock).toHaveBeenCalledWith(
      expect.stringContaining("osv.dev"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("github-api: info without a token, pass with one, fail on 401 with one", async () => {
    stubFetch(() => ({ json: async () => ({ rate: { remaining: 55, limit: 60 } }) }) as Partial<Response>);
    let r = await check("github-api").run(makeCtx());
    expect(r.status).toBe("info");
    expect(r.message).toContain("GITHUB_TOKEN not set");

    process.env.GITHUB_TOKEN = "tok";
    stubFetch(() => ({ json: async () => ({ rate: { remaining: 4998, limit: 5000 } }) }) as Partial<Response>);
    r = await check("github-api").run(makeCtx());
    expect(r.status).toBe("pass");
    expect(r.message).toContain("4998/5000");

    stubFetch(() => ({ ok: false, status: 401 }) as Partial<Response>);
    r = await check("github-api").run(makeCtx());
    expect(r.status).toBe("fail");
  });

  it("policy: info when absent, pass when valid, fail with the PolicyError message", async () => {
    expect((await check("policy").run(makeCtx())).status).toBe("info");

    await writeFile(
      path.join(dir, "targate.policy.yaml"),
      "dependencyPolicy:\n  minPackageAgeDays: 7\n",
    );
    const ok = await check("policy").run(makeCtx());
    expect(ok.status).toBe("pass");
    expect(ok.message).toContain("targate.policy.yaml");

    await writeFile(path.join(dir, "targate.policy.yaml"), "dependencyPolicy:\n  minPackageAgeDays: -3\n");
    const bad = await check("policy").run(makeCtx());
    expect(bad.status).toBe("fail");
    expect(bad.message).toContain("minPackageAgeDays");
  });

  it("project-dir passes in a writable cwd", async () => {
    const r = await check("project-dir").run(makeCtx());
    expect(r.status).toBe("pass");
  });

  it("ci-mode reports CI when the env var is set", async () => {
    process.env.CI = "true";
    const r = await check("ci-mode").run(makeCtx());
    expect(r.status).toBe("info");
    expect(r.message).toContain("CI environment detected");
  });
});

describe("runDoctor", () => {
  const fake = (id: string, status: "pass" | "warn" | "fail" | "info", delay = 0): DoctorCheck => ({
    id,
    label: id,
    run: async () => {
      if (delay) await new Promise((r) => setTimeout(r, delay));
      return { status, message: id };
    },
  });

  it("preserves declaration order regardless of completion order", async () => {
    const report = await runDoctor(makeCtx(), [fake("slow", "pass", 30), fake("fast", "pass")]);
    expect(report.checks.map((c) => c.id)).toEqual(["slow", "fast"]);
  });

  it("turns a throwing check into a fail and sets exitCode 1", async () => {
    const boom: DoctorCheck = {
      id: "boom",
      label: "Boom",
      run: async () => {
        throw new Error("kaput");
      },
    };
    const report = await runDoctor(makeCtx(), [fake("ok", "pass"), boom]);
    expect(report.checks[1]).toMatchObject({ status: "fail", message: "kaput" });
    expect(report.summary).toMatchObject({ pass: 1, fail: 1 });
    expect(report.exitCode).toBe(1);
  });

  it("exitCode is 0 with warnings but no failures", async () => {
    const report = await runDoctor(makeCtx(), [fake("a", "warn"), fake("b", "info")]);
    expect(report.exitCode).toBe(0);
  });
});

describe("doctor --json purity", () => {
  it("emits exactly one JSON document with the envelope", async () => {
    stubFetch(() => ({ json: async () => ({ rate: { remaining: 60, limit: 60 } }) }) as Partial<Response>);
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.join(" "));
    });
    const code = await doctorCommand({ json: true, ping: false, assess: { useAi: false } });
    spy.mockRestore();

    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(Object.keys(parsed).sort()).toEqual([
      "checks",
      "command",
      "exitCode",
      "schemaVersion",
      "summary",
    ]);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.command).toBe("doctor");
    expect(code).toBe(parsed.exitCode);
  });
});
