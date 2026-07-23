import { describe, expect, it } from "vitest";
import {
  failureResult,
  maxSeverity,
  normalizeWorkerResult,
  ProtocolError,
  type NormalizeContext,
} from "../src/protocol.js";

const ctx: NormalizeContext = {
  runId: "r1",
  workerId: "w1",
  role: "discovery",
  startedAt: "2026-07-22T00:00:00.000Z",
  completedAt: "2026-07-22T00:01:00.000Z",
};

describe("normalizeWorkerResult", () => {
  it("normalizes a valid body", () => {
    const r = normalizeWorkerResult(
      {
        status: "completed",
        summary: "  ok  ",
        filesRead: ["a", 1, "b"],
        filesChanged: ["c"],
        findings: [{ severity: "high", summary: "bug", file: "x.ts", line: 3 }],
        questions: ["q?"],
        errors: ["boom"],
      },
      ctx,
    );
    expect(r.status).toBe("completed");
    expect(r.summary).toBe("ok");
    expect(r.filesRead).toEqual(["a", "b"]); // non-strings dropped
    expect(r.findings[0].severity).toBe("high");
    expect(r.errors[0].message).toBe("boom");
    expect(r.protocolVersion).toBe(1);
  });

  it("throws on a non-object body", () => {
    expect(() => normalizeWorkerResult("nope", ctx)).toThrow(ProtocolError);
    expect(() => normalizeWorkerResult(null, ctx)).toThrow(ProtocolError);
  });

  it("throws on an unknown status (malformed is not success)", () => {
    expect(() => normalizeWorkerResult({ status: "done" }, ctx)).toThrow(/unknown status/);
    expect(() => normalizeWorkerResult({ summary: "x" }, ctx)).toThrow(/unknown status/);
  });

  it("merges observed commands with reported ones", () => {
    const r = normalizeWorkerResult(
      { status: "completed", commandsExecuted: [{ command: "git diff", exitCode: 0 }] },
      { ...ctx, observedCommands: [{ command: "git status", exitCode: 0 }] },
    );
    const cmds = r.commandsExecuted.map((c) => c.command).sort();
    expect(cmds).toEqual(["git diff", "git status"]);
  });

  it("coerces unknown finding severities to info", () => {
    const r = normalizeWorkerResult(
      { status: "partial", findings: [{ severity: "spicy", summary: "x" }] },
      ctx,
    );
    expect(r.findings[0].severity).toBe("info");
  });
});

describe("failureResult / maxSeverity", () => {
  it("builds a failed result", () => {
    const r = failureResult(ctx, { message: "timeout", kind: "timeout" });
    expect(r.status).toBe("failed");
    expect(r.errors[0].kind).toBe("timeout");
  });
  it("finds the worst severity", () => {
    expect(maxSeverity([{ severity: "low", summary: "" }, { severity: "critical", summary: "" }])).toBe("critical");
    expect(maxSeverity([])).toBeNull();
  });
});
