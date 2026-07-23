import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listRuns, makeRunId, RunStore, type RunMetadata } from "../src/run-store.js";
import { failureResult } from "../src/protocol.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), "la-runs-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function meta(runId: string): RunMetadata {
  return {
    runId,
    createdAt: "2026-07-22T00:00:00.000Z",
    updatedAt: "2026-07-22T00:00:00.000Z",
    cwd: root,
    status: "created",
    task: "t",
    model: "m",
    maxConcurrency: 1,
    plannedFlow: ["discovery"],
    approval: { required: false },
    workers: [],
  };
}

describe("makeRunId", () => {
  it("builds a sortable id with a slug", () => {
    const id = makeRunId("2026-07-22T14:30:00.000Z", "Implement Feature X!");
    expect(id).toMatch(/^20260722143000-implement-feature-x$/);
  });
  it("falls back to 'task' for an empty slug", () => {
    expect(makeRunId("2026-07-22T14:30:00.000Z", "!!!")).toMatch(/-task$/);
  });
});

describe("RunStore", () => {
  it("persists metadata, events, and worker results, and can be re-read", async () => {
    const id = makeRunId("2026-07-22T00:00:00.000Z", "demo");
    const store = new RunStore(root, id);
    await store.init(meta(id));
    expect(store.exists()).toBe(true);

    await store.appendEvent({ at: "2026-07-22T00:00:01.000Z", kind: "test", message: "hello" });
    await store.appendEvent({ at: "2026-07-22T00:00:02.000Z", kind: "test", message: "world" });
    const events = await store.readEvents();
    expect(events).toHaveLength(2);
    expect(events[1].message).toBe("world");

    const result = failureResult(
      { runId: id, workerId: "w1", role: "discovery", startedAt: "a", completedAt: "b" },
      { message: "x" },
    );
    const rel = await store.writeWorkerResult(result);
    expect(rel).toContain("w1.json");

    const reread = await store.readMetadata();
    expect(reread.runId).toBe(id);
  });

  it("upserts a worker from running to done without duplicating it", async () => {
    const id = makeRunId("2026-07-22T00:00:00.000Z", "up");
    const store = new RunStore(root, id);
    await store.init(meta(id));

    await store.upsertWorker({ workerId: "discovery-1", role: "discovery", state: "running" }, "2026-07-22T00:00:01.000Z");
    let m = await store.readMetadata();
    expect(m.workers).toHaveLength(1);
    expect(m.workers[0].state).toBe("running");
    expect(m.workers[0].status).toBeUndefined();

    await store.upsertWorker(
      { workerId: "discovery-1", role: "discovery", state: "done", status: "completed", resultFile: "workers/discovery-1.json" },
      "2026-07-22T00:00:02.000Z",
    );
    m = await store.readMetadata();
    expect(m.workers).toHaveLength(1); // merged, not duplicated
    expect(m.workers[0].state).toBe("done");
    expect(m.workers[0].status).toBe("completed");
  });

  it("lists runs newest-first", async () => {
    for (const t of ["2026-07-22T00:00:00.000Z", "2026-07-22T01:00:00.000Z"]) {
      const id = makeRunId(t, "x");
      await new RunStore(root, id).init(meta(id));
    }
    const runs = await listRuns(root);
    expect(runs).toHaveLength(2);
    expect(runs[0] > runs[1]).toBe(true);
  });
});
