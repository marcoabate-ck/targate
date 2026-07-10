import { afterEach, describe, expect, it, vi } from "vitest";
import { JSON_SCHEMA_VERSION, printJson, toJsonEnvelope } from "../src/json-output.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("toJsonEnvelope", () => {
  it("puts schemaVersion and command first and spreads the payload flat", () => {
    const env = toJsonEnvelope("add", { assessment: { decision: "allow" }, deep: null });
    expect(Object.keys(env)).toEqual(["schemaVersion", "command", "assessment", "deep"]);
    expect(env.schemaVersion).toBe(JSON_SCHEMA_VERSION);
    expect(env.command).toBe("add");
    expect(env.assessment).toEqual({ decision: "allow" });
  });

  it("leaves the payload values untouched", () => {
    const payload = { nested: { a: [1, 2, 3] }, s: "x" };
    const env = toJsonEnvelope("cache", payload);
    expect(env.nested).toBe(payload.nested);
    expect(env.s).toBe("x");
  });
});

describe("printJson", () => {
  it("emits exactly one console.log call with parseable JSON", () => {
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: string) => {
      lines.push(line);
    });

    printJson("doctor", { checks: [], exitCode: 0 });

    expect(spy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.schemaVersion).toBe(JSON_SCHEMA_VERSION);
    expect(parsed.command).toBe("doctor");
    expect(parsed.checks).toEqual([]);
  });
});
