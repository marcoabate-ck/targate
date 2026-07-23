/**
 * Public API for the local-agent orchestration engine.
 *
 * Reusable across repositories: nothing here imports repo-specific code. The
 * repository contributes only DATA — a `local-agents.config.{yaml,json}`, an
 * `AGENTS.md` hierarchy, and optional `.claude/local-agents/roles/*.md` — never
 * changes to this engine.
 */

export * from "./config.js";
export * from "./protocol.js";
export * from "./env.js";
export * from "./roles.js";
export * from "./permissions.js";
export * from "./command-guard.js";
export * from "./paths.js";
export * from "./concurrency.js";
export * from "./readiness.js";
export * from "./policy.js";
export * from "./run-store.js";
export * from "./worktree.js";
export {
  runWorker,
  buildClaudeArgs,
  buildGuardSettings,
  extractJsonObject,
  type WorkerAssignment,
  type RunWorkerOutcome,
  type RunWorkerDeps,
} from "./worker.js";
export {
  orchestrateSingle,
  startWorkflow,
  resumeWorkflow,
  runWorkerInRun,
  type WorkflowOptions,
  type WorkflowResult,
  type SingleRunOptions,
  type OrchestratorDeps,
} from "./orchestrator.js";
export {
  runDoctor,
  doctorForCwd,
  DOCTOR_CHECKS,
  type DoctorReport,
  type DoctorContext,
  type DoctorCheck,
} from "./doctor.js";
