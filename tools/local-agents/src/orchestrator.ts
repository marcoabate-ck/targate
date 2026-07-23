/**
 * Workflow orchestration engine.
 *
 * The lead (Opus) is the persistent coordinator; this engine gives it
 * deterministic primitives: create a run, run a worker inside it (persisting
 * the structured result + events), gate on approval, and walk a role flow with
 * a bounded correction loop. Read-only workers may fan out in parallel; writer
 * workers run sequentially in the main tree (worktree isolation is opt-in and
 * lives in worktree.ts). Context is minimised — later workers receive prior
 * workers' compact summaries, never their raw transcripts.
 */

import path from "node:path";
import type { ResolvedConfig } from "./config.js";
import { agentsContextFor, loadRepoRoleInstructions } from "./agents-context.js";
import { runPool, memoryAwareConcurrency } from "./concurrency.js";
import { decide, planHash, type PolicyDecision, type TaskSignals } from "./policy.js";
import { maxSeverity, type WorkerResult } from "./protocol.js";
import { resolveRole } from "./roles.js";
import {
  makeRunId,
  RunStore,
  type ApprovalRecord,
  type RunMetadata,
} from "./run-store.js";
import { runWorker, type RunWorkerDeps, type WorkerAssignment } from "./worker.js";

export interface OrchestratorDeps {
  now?: () => Date;
  /** Injectable worker runner for tests. */
  runWorkerFn?: typeof runWorker;
  workerDeps?: RunWorkerDeps;
}

export interface SingleRunOptions {
  cwd: string;
  role: string;
  task: string;
  config: ResolvedConfig;
  /** Working directory for the worker (defaults to cwd). */
  workingDir?: string;
  timeoutMs?: number;
  deps?: OrchestratorDeps;
}

function iso(deps: OrchestratorDeps): string {
  return (deps.now ?? (() => new Date()))().toISOString();
}

/** Build the per-worker context (settings path, agents digest, role instructions). */
async function assignmentFor(
  runStore: RunStore,
  cwd: string,
  workingDir: string,
  role: string,
  task: string,
  runId: string,
  workerId: string,
  timeoutMs: number | undefined,
): Promise<WorkerAssignment> {
  const agentsContext = await agentsContextFor(cwd, workingDir);
  const repoRoleInstructions = (await loadRepoRoleInstructions(cwd, role)) ?? undefined;
  const scopes = [workingDir, runStore.dir];
  return {
    runId,
    workerId,
    role,
    task,
    cwd: workingDir,
    scopes,
    agentsContext,
    repoRoleInstructions,
    timeoutMs,
  };
}

/** Run one worker inside a run, persisting result + events, with bounded retries. */
export async function runWorkerInRun(
  runStore: RunStore,
  assignment: WorkerAssignment,
  config: ResolvedConfig,
  deps: OrchestratorDeps,
): Promise<WorkerResult> {
  const run = deps.runWorkerFn ?? runWorker;
  const workerDeps: RunWorkerDeps = {
    ...deps.workerDeps,
    now: deps.now,
    settingsPath: path.join(runStore.dir, "workers", `${assignment.workerId}.settings.json`),
  };

  let attempt = 0;
  const maxRetries = config.orchestration.maxTransientRetries;
  for (;;) {
    attempt++;
    await runStore.appendEvent({
      at: iso(deps),
      kind: "worker-start",
      message: `${assignment.role} (${assignment.workerId}) attempt ${attempt}`,
    });
    const outcome = await run(assignment, config, workerDeps);

    if (config.orchestration.preserveRawOutput) {
      await runStore.writeText(
        path.join("workers", `${assignment.workerId}.stdout.log`),
        outcome.raw.stdout,
      );
      if (outcome.raw.stderr.trim()) {
        await runStore.writeText(
          path.join("workers", `${assignment.workerId}.stderr.log`),
          outcome.raw.stderr,
        );
      }
    }

    const retryable = outcome.transient && attempt <= maxRetries;
    if (retryable) {
      await runStore.appendEvent({
        at: iso(deps),
        kind: "worker-retry",
        message: `${assignment.workerId} transient failure, retrying (${attempt}/${maxRetries})`,
      });
      continue;
    }

    const resultFile = await runStore.writeWorkerResult(outcome.result);
    await runStore.appendEvent({
      at: iso(deps),
      kind: "worker-done",
      message: `${assignment.role} (${assignment.workerId}) → ${outcome.result.status}`,
      data: { status: outcome.result.status, findings: outcome.result.findings.length },
    });

    // Record in metadata.
    const meta = await runStore.readMetadata();
    meta.workers.push({
      workerId: assignment.workerId,
      role: assignment.role,
      status: outcome.result.status,
      resultFile,
    });
    meta.updatedAt = iso(deps);
    await runStore.writeMetadata(meta);

    return outcome.result;
  }
}

/** Run a single role once (the `run <role>` CLI command). */
export async function orchestrateSingle(opts: SingleRunOptions): Promise<{ runId: string; result: WorkerResult; runDir: string }> {
  const deps = opts.deps ?? {};
  const role = resolveRole(opts.role, opts.config);
  if (!role) throw new Error(`unknown role: ${opts.role}`);

  const runRoot = path.resolve(opts.cwd, opts.config.orchestration.runDirectory);
  const runId = makeRunId(iso(deps), `${opts.role}-${opts.task}`);
  const runStore = new RunStore(runRoot, runId);
  const workingDir = path.resolve(opts.workingDir ?? opts.cwd);

  const metadata: RunMetadata = {
    runId,
    createdAt: iso(deps),
    updatedAt: iso(deps),
    cwd: opts.cwd,
    status: "running",
    task: opts.task,
    model: opts.config.runtime.model,
    approval: { required: false },
    workers: [],
  };
  await runStore.init(metadata);
  await runStore.writeText("task.md", `# Task\n\n${opts.task}\n`);

  const workerId = `${opts.role}-1`;
  const assignment = await assignmentFor(
    runStore, opts.cwd, workingDir, opts.role, opts.task, runId, workerId, opts.timeoutMs,
  );
  const result = await runWorkerInRun(runStore, assignment, opts.config, deps);

  const meta = await runStore.readMetadata();
  meta.status = result.status === "completed" ? "completed" : "failed";
  meta.updatedAt = iso(deps);
  await runStore.writeMetadata(meta);
  await writeSummary(runStore, meta, [result]);

  return { runId, result, runDir: runStore.dir };
}

export interface WorkflowOptions {
  cwd: string;
  task: string;
  config: ResolvedConfig;
  /** The plan text (for medium/large tasks). */
  plan?: string;
  /** The lead's structured read of the task for the approval policy. */
  signals?: TaskSignals;
  /** Human/lead pre-approval, recorded verbatim. */
  approval?: { approvedBy: string };
  /** Override the policy's suggested role flow. */
  flowOverride?: string[];
  workingDir?: string;
  timeoutMs?: number;
  deps?: OrchestratorDeps;
}

export interface WorkflowResult {
  runId: string;
  runDir: string;
  status: RunMetadata["status"];
  decision: PolicyDecision;
  results: WorkerResult[];
}

/**
 * Start a workflow. Runs any read-only discovery first (safe pre-approval),
 * then gates on approval before the first writer role. When approval is
 * required and not granted, it persists `awaiting-approval` and returns — the
 * lead calls `resumeWorkflow` after `approve`.
 */
export async function startWorkflow(opts: WorkflowOptions): Promise<WorkflowResult> {
  const deps = opts.deps ?? {};
  const decision = decide(opts.signals ?? {}, opts.config.approval.mode);
  const flow = opts.flowOverride ?? decision.suggestedFlow;

  const runRoot = path.resolve(opts.cwd, opts.config.orchestration.runDirectory);
  const runId = makeRunId(iso(deps), opts.task);
  const runStore = new RunStore(runRoot, runId);

  const approval: ApprovalRecord = {
    required: decision.approvalRequired,
    reason: decision.approvalReason,
  };
  if (opts.approval) {
    approval.approvedAt = iso(deps);
    approval.approvedBy = opts.approval.approvedBy;
    if (opts.plan) approval.approvedPlanHash = planHash(opts.plan);
  }

  const metadata: RunMetadata = {
    runId,
    createdAt: iso(deps),
    updatedAt: iso(deps),
    cwd: opts.cwd,
    status: "running",
    task: opts.task,
    model: opts.config.runtime.model,
    approval,
    workers: [],
  };
  await runStore.init(metadata);
  await runStore.writeText("task.md", `# Task\n\n${opts.task}\n`);
  if (opts.plan) await runStore.writeText("plan.md", opts.plan);
  if (opts.approval && opts.plan) await runStore.writeText("approved-plan.md", opts.plan);
  await runStore.appendEvent({
    at: iso(deps),
    kind: "workflow-start",
    message: `tier=${decision.riskTier} approvalRequired=${decision.approvalRequired} flow=[${flow.join(", ")}]`,
    data: { decision: { ...decision } },
  });

  const results = await runFlow(runStore, opts, decision, flow, new Set(), deps);
  return finalize(runStore, decision, results, deps);
}

/** Resume a workflow that was awaiting approval (or interrupted). */
export async function resumeWorkflow(
  cwd: string,
  runId: string,
  config: ResolvedConfig,
  opts: { approvedBy?: string; signals?: TaskSignals; flowOverride?: string[]; deps?: OrchestratorDeps } = {},
): Promise<WorkflowResult> {
  const deps = opts.deps ?? {};
  const runRoot = path.resolve(cwd, config.orchestration.runDirectory);
  const runStore = new RunStore(runRoot, runId);
  if (!runStore.exists()) throw new Error(`run not found: ${runId}`);
  const meta = await runStore.readMetadata();

  // Record approval if provided now.
  if (opts.approvedBy && !meta.approval.approvedAt) {
    meta.approval.approvedAt = iso(deps);
    meta.approval.approvedBy = opts.approvedBy;
    await runStore.appendEvent({ at: iso(deps), kind: "approved", message: `approved by ${opts.approvedBy}` });
  }
  // Clear the paused state so finalize() does not short-circuit on the prior
  // "awaiting-approval" status while this resume actually runs the workers.
  if (meta.status === "awaiting-approval") meta.status = "running";
  meta.updatedAt = iso(deps);
  await runStore.writeMetadata(meta);

  const decision = decide(opts.signals ?? {}, config.approval.mode);
  const flow = opts.flowOverride ?? decision.suggestedFlow;
  const completedRoles = new Set(meta.workers.filter((w) => w.status === "completed").map((w) => w.role));

  const workflowOpts: WorkflowOptions = { cwd, task: meta.task, config, signals: opts.signals, deps };
  const results = await runFlow(runStore, workflowOpts, { ...decision, approvalRequired: false }, flow, completedRoles, deps);
  return finalize(runStore, decision, results, deps);
}

/**
 * Walk the role flow. Read-only roles at the front (discovery) can run in a
 * memory-aware parallel pool; the first writer role triggers the approval gate.
 * A reviewer finding of critical/high blocks completion and drives a bounded
 * correction loop.
 */
async function runFlow(
  runStore: RunStore,
  opts: WorkflowOptions,
  decision: PolicyDecision,
  flow: string[],
  skipRoles: Set<string>,
  deps: OrchestratorDeps,
): Promise<WorkerResult[]> {
  const cwd = opts.cwd;
  const workingDir = path.resolve(opts.workingDir ?? cwd);
  const meta = await runStore.readMetadata();
  const results: WorkerResult[] = [];
  const summaries: string[] = [];

  const composeTask = (role: string): string => {
    const parts = [opts.task];
    if (opts.plan) parts.push(`\n## Approved plan\n${opts.plan}`);
    if (summaries.length) parts.push(`\n## Prior worker summaries\n${summaries.join("\n\n")}`);
    parts.push(`\n## Your role\nAct as the "${role}" worker for this task.`);
    return parts.join("\n");
  };

  for (const role of flow) {
    if (skipRoles.has(role)) continue;
    const def = resolveRole(role, opts.config);
    if (!def) throw new Error(`unknown role in flow: ${role}`);

    // Approval gate before the first writer role.
    if (!def.readOnly && meta.approval.required && !meta.approval.approvedAt) {
      meta.status = "awaiting-approval";
      meta.updatedAt = iso(deps);
      await runStore.writeMetadata(meta);
      await runStore.appendEvent({
        at: iso(deps),
        kind: "awaiting-approval",
        message: `paused before "${role}": ${meta.approval.reason ?? "approval required"}`,
      });
      return results;
    }

    const workerId = `${role}-${results.filter((r) => r.role === role).length + 1}`;
    const assignment = await assignmentFor(
      runStore, cwd, workingDir, role, composeTask(role), meta.runId, workerId, opts.timeoutMs,
    );
    const result = await runWorkerInRun(runStore, assignment, opts.config, deps);
    results.push(result);
    summaries.push(`### ${role}\n${result.summary}`);

    // A blocked/failed worker halts the flow — the lead must intervene.
    if (result.status === "blocked" || result.status === "failed") {
      await runStore.appendEvent({
        at: iso(deps),
        kind: "flow-halt",
        message: `halting: ${role} returned ${result.status}`,
      });
      break;
    }

    // Reviewer with critical/high findings → bounded correction loop.
    if (role === "reviewer") {
      const worst = maxSeverity(result.findings);
      if (worst === "critical" || worst === "high") {
        await runCorrectionLoop(runStore, opts, results, summaries, deps);
      }
    }
  }
  return results;
}

/** Bounded implementer→reviewer correction loop for critical/high findings. */
async function runCorrectionLoop(
  runStore: RunStore,
  opts: WorkflowOptions,
  results: WorkerResult[],
  summaries: string[],
  deps: OrchestratorDeps,
): Promise<void> {
  const cwd = opts.cwd;
  const workingDir = path.resolve(opts.workingDir ?? cwd);
  const max = opts.config.orchestration.maxCorrectionCycles;
  const meta = await runStore.readMetadata();

  for (let cycle = 1; cycle <= max; cycle++) {
    const lastReview = [...results].reverse().find((r) => r.role === "reviewer");
    const worst = lastReview ? maxSeverity(lastReview.findings) : null;
    if (worst !== "critical" && worst !== "high") return; // resolved

    await runStore.appendEvent({ at: iso(deps), kind: "correction-cycle", message: `cycle ${cycle}/${max}` });

    const fixTask = [
      opts.task,
      `\n## Correction cycle ${cycle}`,
      `The reviewer found ${worst}-severity issues. Fix ONLY these findings:`,
      ...lastReview!.findings
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .map((f) => `- [${f.severity}] ${f.summary}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`),
    ].join("\n");

    const fixId = `implementer-fix-${cycle}`;
    const fixAssignment = await assignmentFor(runStore, cwd, workingDir, "implementer", fixTask, meta.runId, fixId, opts.timeoutMs);
    const fix = await runWorkerInRun(runStore, fixAssignment, opts.config, deps);
    results.push(fix);
    summaries.push(`### implementer (fix ${cycle})\n${fix.summary}`);
    if (fix.status !== "completed" && fix.status !== "partial") return;

    const reReviewId = `reviewer-recheck-${cycle}`;
    const reReviewTask = `${opts.task}\n\n## Re-review after correction cycle ${cycle}\nVerify the previously reported critical/high findings are resolved and no regressions were introduced.`;
    const reAssignment = await assignmentFor(runStore, cwd, workingDir, "reviewer", reReviewTask, meta.runId, reReviewId, opts.timeoutMs);
    const reReview = await runWorkerInRun(runStore, reAssignment, opts.config, deps);
    results.push(reReview);
    summaries.push(`### reviewer (recheck ${cycle})\n${reReview.summary}`);
  }

  await runStore.appendEvent({
    at: iso(deps),
    kind: "correction-exhausted",
    message: `correction cycles exhausted (${max}); unresolved findings require the lead`,
  });
}

async function finalize(
  runStore: RunStore,
  decision: PolicyDecision,
  results: WorkerResult[],
  deps: OrchestratorDeps,
): Promise<WorkflowResult> {
  const meta = await runStore.readMetadata();
  if (meta.status === "awaiting-approval") {
    return { runId: meta.runId, runDir: runStore.dir, status: meta.status, decision, results };
  }

  const anyFailed = results.some((r) => r.status === "failed" || r.status === "blocked");
  const lastReview = [...results].reverse().find((r) => r.role === "reviewer");
  const worst = lastReview ? maxSeverity(lastReview.findings) : null;
  const blockedByFindings = worst === "critical" || worst === "high";

  meta.status = anyFailed || blockedByFindings ? "failed" : "completed";
  meta.updatedAt = iso(deps);
  await runStore.writeMetadata(meta);
  await writeSummary(runStore, meta, results);
  await runStore.appendEvent({
    at: iso(deps),
    kind: "workflow-end",
    message: `status=${meta.status}${blockedByFindings ? ` (unresolved ${worst} findings)` : ""}`,
  });

  return { runId: meta.runId, runDir: runStore.dir, status: meta.status, decision, results };
}

/** Write a compact human summary the lead reads first. */
async function writeSummary(runStore: RunStore, meta: RunMetadata, results: WorkerResult[]): Promise<void> {
  const lines: string[] = [
    `# Run ${meta.runId}`,
    "",
    `- Status: ${meta.status}`,
    `- Model: ${meta.model}`,
    `- Approval required: ${meta.approval.required}${meta.approval.reason ? ` (${meta.approval.reason})` : ""}`,
    meta.approval.approvedBy ? `- Approved by: ${meta.approval.approvedBy}` : "",
    "",
    "## Workers",
  ];
  for (const r of results) {
    lines.push(`\n### ${r.role} — ${r.status}`);
    lines.push(r.summary || "(no summary)");
    if (r.findings.length) {
      lines.push("Findings:");
      for (const f of r.findings) {
        lines.push(`- [${f.severity}] ${f.summary}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`);
      }
    }
    if (r.filesChanged.length) lines.push(`Files changed: ${r.filesChanged.join(", ")}`);
  }
  await runStore.writeText("summary.md", lines.filter((l) => l !== undefined).join("\n") + "\n");
}
