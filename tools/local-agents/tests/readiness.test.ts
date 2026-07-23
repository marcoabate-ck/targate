import { describe, expect, it } from "vitest";
import { isConnectionError, probeOllama } from "../src/readiness.js";

function stubStatus(status: number): typeof fetch {
  return (async () => ({ status }) as Response) as unknown as typeof fetch;
}
const stubThrow = (async () => {
  throw new Error("connect ECONNREFUSED 127.0.0.1:11434");
}) as unknown as typeof fetch;

describe("probeOllama", () => {
  it("reports reachable on HTTP 200", async () => {
    const r = await probeOllama("http://localhost:11434", { fetchFn: stubStatus(200) });
    expect(r.ok).toBe(true);
  });
  it("reports not-ok with an actionable message on a connection error", async () => {
    const r = await probeOllama("http://localhost:11434", { fetchFn: stubThrow });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/ollama serve/);
    expect(r.message).toMatch(/not reachable/);
  });
  it("reports not-ok on a non-200 status", async () => {
    const r = await probeOllama("http://localhost:11434", { fetchFn: stubStatus(500) });
    expect(r.ok).toBe(false);
    expect(r.message).toMatch(/HTTP 500/);
  });
});

describe("isConnectionError", () => {
  it("recognises common connection failures", () => {
    expect(isConnectionError("connect ECONNREFUSED 127.0.0.1:11434")).toBe(true);
    expect(isConnectionError("fetch failed")).toBe(true);
    expect(isConnectionError("some unrelated error")).toBe(false);
  });
});
