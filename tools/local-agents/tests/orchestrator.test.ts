import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultConfig } from "../src/config.js";
import {
  orchestrateSingle,
  resumeWorkflow,
  startWorkflow,
} from "../src/orchestrator.js";
import { RunStore } from "../src/run-store.js";
import type { Finding, WorkerResult } from "../src/protocol.js";
import type { RunWorkerOutcome, WorkerAssignment } from "../src/worker.js";

let cwd: string;
beforeEach(async () => {
  cwd = await mkdtemp(path.join(tmpdir(), "la-orch-"));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

function result(a: WorkerAssignment, status: WorkerResult["status"], findings: Finding[] = []): WorkerResult {
  return {
    protocolVersion: 1,
    runId: a.runId,
    workerId: a.workerId,
    role: a.role,
    status,
    summary: `${a.role} summary`,
    filesRead: [],
    filesChanged: [],
    commandsExecuted: [],
    findings,
    artifacts: [],
    questions: [],
    errors: [],
    startedAt: "a",
    completedAt: "b",
  };
}

function outcome(r: WorkerResult, transient = false): RunWorkerOutcome {
  return { result: r, raw: { stdout: "{}", stderr: "", exitCode: 0, killedByTimeout: false }, transient };
}

const config = defaultConfig();

describe("orchestrateSingle", () => {
  it("runs one role, persists artifacts, and returns the result", async () => {
    const { runId, result: res, runDir } = await orchestrateSingle({
      cwd,
      role: "discovery",
      task: "map the code",
      config,
      deps: { runWorkerFn: async (a) => outcome(result(a, "completed")) },
    });
    expect(res.status).toBe("completed");
    const store = new RunStore(path.join(cwd, config.orchestration.runDirectory), runId);
    const meta = await store.readMetadata();
    expect(meta.status).toBe("completed");
    expect(meta.workers).toHaveLength(1);
    expect(runDir).toContain(runId);
  });
});

describe("startWorkflow — approval gate", () => {
  it("runs read-only discovery, then pauses before the first writer when approval is required", async () => {
    const roles: string[] = [];
    const wf = await startWorkflow({
      cwd,
      task: "add auth",
      config,
      signals: { securitySensitive: true },
      deps: {
        runWorkerFn: async (a) => {
          roles.push(a.role);
          return outcome(result(a, "completed"));
        },
      },
    });
    expect(wf.decision.approvalRequired).toBe(true);
    expect(wf.status).toBe("awaiting-approval");
    expect(roles).toEqual(["discovery"]); // stopped before implementer
  });

  it("resumes after approval and runs the remaining writer roles", async () => {
    const wf = await startWorkflow({
      cwd,
      task: "add auth",
      config,
      signals: { securitySensitive: true },
      deps: { runWorkerFn: async (a) => outcome(result(a, "completed")) },
    });
    const resumed = await resumeWorkflow(cwd, wf.runId, config, {
      approvedBy: "marco",
      signals: { securitySensitive: true },
      deps: { runWorkerFn: async (a) => outcome(result(a, "completed")) },
    });
    expect(resumed.status).toBe("completed");
    const store = new RunStore(path.join(cwd, config.orchestration.runDirectory), wf.runId);
    const meta = await store.readMetadata();
    expect(meta.approval.approvedBy).toBe("marco");
    const roles = meta.workers.map((w) => w.role);
    // Review is the lead's job → reviewer is not in the default flow.
    expect(roles).toEqual(expect.arrayContaining(["discovery", "implementer", "tester"]));
    expect(roles).not.toContain("reviewer");
  });
});

describe("startWorkflow — small task, no approval", () => {
  it("runs implementer then reviewer to completion", async () => {
    const wf = await startWorkflow({
      cwd,
      task: "fix typo",
      config,
      signals: { likelyFiles: 1 },
      deps: { runWorkerFn: async (a) => outcome(result(a, "completed")) },
    });
    expect(wf.decision.approvalRequired).toBe(false);
    expect(wf.status).toBe("completed");
    // Default small flow is implementer only; the lead reviews.
    expect(wf.results.map((r) => r.role)).toEqual(["implementer"]);
  });
});

describe("correction loop", () => {
  it("drives a bounded implementer→reviewer loop on critical findings and resolves", async () => {
    let reviewerSeen = 0;
    const wf = await startWorkflow({
      cwd,
      task: "risky change",
      config,
      signals: { likelyFiles: 1 },
      approval: { approvedBy: "auto" },
      flowOverride: ["implementer", "reviewer"], // opt the reviewer worker in
      deps: {
        runWorkerFn: async (a) => {
          if (a.role === "reviewer" && a.workerId === "reviewer-1") {
            reviewerSeen++;
            return outcome(result(a, "completed", [{ severity: "critical", summary: "bug" }]));
          }
          // recheck reviewers find nothing
          return outcome(result(a, "completed"));
        },
      },
    });
    // Initial reviewer found critical → correction cycle ran → recheck clean.
    expect(reviewerSeen).toBe(1);
    const store = new RunStore(path.join(cwd, config.orchestration.runDirectory), wf.runId);
    const meta = await store.readMetadata();
    expect(meta.workers.some((w) => w.workerId.startsWith("implementer-fix"))).toBe(true);
    expect(meta.workers.some((w) => w.workerId.startsWith("reviewer-recheck"))).toBe(true);
    expect(wf.status).toBe("completed");
  });

  it("marks the run failed when critical findings persist past the cycle cap", async () => {
    const wf = await startWorkflow({
      cwd,
      task: "stubborn bug",
      config: { ...config, orchestration: { ...config.orchestration, maxCorrectionCycles: 1 } },
      signals: { likelyFiles: 1 },
      approval: { approvedBy: "auto" },
      flowOverride: ["implementer", "reviewer"], // opt the reviewer worker in
      deps: {
        runWorkerFn: async (a) =>
          a.role === "reviewer"
            ? outcome(result(a, "completed", [{ severity: "critical", summary: "still broken" }]))
            : outcome(result(a, "completed")),
      },
    });
    expect(wf.status).toBe("failed");
  });
});

describe("bounded transient retries", () => {
  it("retries a transient failure then succeeds", async () => {
    const attempts: Record<string, number> = {};
    const wf = await startWorkflow({
      cwd,
      task: "fix typo",
      config,
      signals: { likelyFiles: 1 },
      deps: {
        runWorkerFn: async (a) => {
          attempts[a.workerId] = (attempts[a.workerId] ?? 0) + 1;
          if (a.role === "implementer" && attempts[a.workerId] === 1) {
            return outcome(result(a, "failed"), true); // transient
          }
          return outcome(result(a, "completed"));
        },
      },
    });
    expect(attempts["implementer-1"]).toBe(2);
    expect(wf.status).toBe("completed");
  });

  it("does not retry a deterministic failure", async () => {
    const attempts: Record<string, number> = {};
    await startWorkflow({
      cwd,
      task: "fix typo",
      config,
      signals: { likelyFiles: 1 },
      deps: {
        runWorkerFn: async (a) => {
          attempts[a.workerId] = (attempts[a.workerId] ?? 0) + 1;
          return outcome(result(a, "failed"), false); // not transient
        },
      },
    });
    expect(attempts["implementer-1"]).toBe(1);
  });
});
