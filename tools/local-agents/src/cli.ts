#!/usr/bin/env node
/**
 * local-agents CLI.
 *
 * Works both manually (a developer runs a role or a workflow) and as the
 * concise, machine-readable interface the lead (Opus) drives with `--json`.
 * Exit codes: 0 success · 1 error · 2 needs-human (awaiting approval, a blocked
 * worker, or unresolved critical/high findings).
 */

import { parseArgs } from "node:util";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "./config.js";
import { availableRoles, resolveRole, assembleSystemPrompt } from "./roles.js";
import { resolvePermissions } from "./permissions.js";
import { decide, type TaskSignals } from "./policy.js";
import { orchestrateSingle, startWorkflow, resumeWorkflow } from "./orchestrator.js";
import { doctorForCwd } from "./doctor.js";
import { probeOllama } from "./readiness.js";
import { RunStore, listRuns, makeRunId } from "./run-store.js";
import { cleanupWorktrees, type WorktreeInfo } from "./worktree.js";
import { agentsContextFor } from "./agents-context.js";
import type { WorkflowResult } from "./orchestrator.js";

const USAGE = `local-agents — local Claude Code worker orchestration

Usage:
  local-agents doctor [--ping] [--json]
  local-agents run <role> --task "<text>" | --task-file <f> [options]
  local-agents workflow start --task "<text>" | --task-file <f> [signal flags] [options]
  local-agents workflow status <run-id> [--json]
  local-agents workflow resume <run-id> [--approve <name>] [options]
  local-agents workflow cancel <run-id>
  local-agents worktree cleanup <run-id>
  local-agents roles

Options:
  --task <text>          Inline task text
  --task-file <path>     Read task text from a file
  --role <name>          Role (for run): discovery|implementer|tester|reviewer|<custom>
  --model <name>         Override the Ollama model
  --base-url <url>       Override the Ollama base URL
  --cwd <path>           Repository root (default: process cwd)
  --working-dir <path>   Worker working directory (default: cwd)
  --timeout <ms>         Per-worker timeout in milliseconds
  --concurrency <n>      Max parallel workers
  --flow <a,b,c>         Override the role flow for a workflow
  --approve <name>       Record human approval by <name>
  --json                 Machine-readable JSON output
  --dry-run              Show what would run; spawn nothing
  --verbose              Extra diagnostics

Workflow signal flags (feed the adaptive approval policy):
  --files <n>  --architectural  --security  --dependency  --public-api-breaking
  --destructive  --affects-ci  --uncertain  --explanatory`;

interface Opts {
  values: Record<string, string | boolean | undefined>;
  positionals: string[];
}

const OPTION_CONFIG = {
  task: { type: "string" },
  "task-file": { type: "string" },
  role: { type: "string" },
  model: { type: "string" },
  "base-url": { type: "string" },
  cwd: { type: "string" },
  "working-dir": { type: "string" },
  timeout: { type: "string" },
  concurrency: { type: "string" },
  flow: { type: "string" },
  approve: { type: "string" },
  json: { type: "boolean" },
  "dry-run": { type: "boolean" },
  verbose: { type: "boolean" },
  ping: { type: "boolean" },
  "no-preflight": { type: "boolean" },
  files: { type: "string" },
  architectural: { type: "boolean" },
  security: { type: "boolean" },
  dependency: { type: "boolean" },
  "public-api-breaking": { type: "boolean" },
  destructive: { type: "boolean" },
  "affects-ci": { type: "boolean" },
  uncertain: { type: "boolean" },
  explanatory: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

function str(o: Opts, name: string): string | undefined {
  const v = o.values[name];
  return typeof v === "string" ? v : undefined;
}
function bool(o: Opts, name: string): boolean {
  return o.values[name] === true;
}

async function taskText(o: Opts): Promise<string | null> {
  const inline = str(o, "task");
  if (inline) return inline;
  const file = str(o, "task-file");
  if (file) return (await readFile(path.resolve(file), "utf8")).trim();
  return null;
}

function signalsFrom(o: Opts): TaskSignals {
  const s: TaskSignals = {};
  const files = str(o, "files");
  if (files) s.likelyFiles = Number(files);
  if (bool(o, "architectural")) s.architectural = true;
  if (bool(o, "security")) s.securitySensitive = true;
  if (bool(o, "dependency")) s.dependencyChange = true;
  if (bool(o, "public-api-breaking")) s.publicApiBreaking = true;
  if (bool(o, "destructive")) s.destructive = true;
  if (bool(o, "affects-ci")) s.affectsCiOrRelease = true;
  if (bool(o, "uncertain")) s.highUncertainty = true;
  if (bool(o, "explanatory")) s.explanatoryOnly = true;
  return s;
}

async function resolvedConfig(o: Opts, cwd: string) {
  const { config, file } = await loadConfig(cwd);
  if (str(o, "model")) config.runtime.model = str(o, "model")!;
  if (str(o, "base-url")) config.runtime.baseUrl = str(o, "base-url")!.replace(/\/+$/, "");
  if (str(o, "concurrency")) config.orchestration.maxConcurrency = Number(str(o, "concurrency"));
  return { config, file };
}

function print(o: Opts, human: string, json: unknown): void {
  if (bool(o, "json")) console.log(JSON.stringify(json, null, 2));
  else console.log(human);
}

function workflowExit(result: WorkflowResult): number {
  if (result.status === "awaiting-approval") return 2;
  if (result.status === "failed") return 2;
  return 0;
}

async function cmdDoctor(o: Opts, cwd: string): Promise<number> {
  const report = await doctorForCwd(cwd, bool(o, "ping"));
  if (bool(o, "json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const glyph: Record<string, string> = { pass: "✓", warn: "!", fail: "✗", info: "·" };
    for (const c of report.checks) console.log(`  ${glyph[c.status]} ${c.label}: ${c.message}`);
    console.log(`\n  ${report.summary.pass} pass · ${report.summary.warn} warn · ${report.summary.fail} fail`);
  }
  return report.exitCode;
}

async function cmdRun(o: Opts, cwd: string): Promise<number> {
  const role = str(o, "role") ?? o.positionals[0];
  if (!role) return fail("run requires a role, e.g. `local-agents run discovery --task \"...\"`");
  const task = await taskText(o);
  if (!task) return fail("run requires --task or --task-file");
  const { config } = await resolvedConfig(o, cwd);
  const def = resolveRole(role, config);
  if (!def) return fail(`unknown role: ${role}. Available: ${availableRoles(config).join(", ")}`);

  if (bool(o, "dry-run")) {
    const perms = resolvePermissions(config.roles[role] ?? { readOnly: def.readOnly });
    const agents = await agentsContextFor(cwd, path.resolve(str(o, "working-dir") ?? cwd));
    const prompt = assembleSystemPrompt({ role: def, agentsContext: agents });
    print(o, `DRY RUN — ${role}\nmodel: ${config.runtime.model}\nreadOnly: ${def.readOnly}\nallowedTools: ${perms.allowedTools.join(",")}\ndisallowedTools: ${perms.disallowedTools.join(",")}\nsystem prompt bytes: ${prompt.length}`, {
      role, model: config.runtime.model, readOnly: def.readOnly, permissions: perms, systemPromptBytes: prompt.length,
    });
    return 0;
  }

  const gate = await preflight(o, config.runtime.baseUrl);
  if (gate !== null) return gate;

  const timeout = str(o, "timeout") ? Number(str(o, "timeout")) : undefined;
  const { runId, result, runDir } = await orchestrateSingle({
    cwd, role, task, config, workingDir: str(o, "working-dir"), timeoutMs: timeout,
  });
  print(o, `Run ${runId} → ${result.status}\n${result.summary}\nArtifacts: ${path.relative(cwd, runDir)}`, { runId, result, runDir });
  return result.status === "completed" ? 0 : 2;
}

async function cmdWorkflowStart(o: Opts, cwd: string): Promise<number> {
  const task = await taskText(o);
  if (!task) return fail("workflow start requires --task or --task-file");
  const { config } = await resolvedConfig(o, cwd);
  const signals = signalsFrom(o);
  const flow = str(o, "flow")?.split(",").map((s) => s.trim()).filter(Boolean);

  if (bool(o, "dry-run")) {
    const decision = decide(signals, config.approval.mode);
    print(o, `DRY RUN — tier=${decision.riskTier} approvalRequired=${decision.approvalRequired}${decision.approvalReason ? ` (${decision.approvalReason})` : ""}\nflow: ${(flow ?? decision.suggestedFlow).join(" → ") || "(lead handles directly)"}`, { decision, flow: flow ?? decision.suggestedFlow });
    return decision.approvalRequired ? 2 : 0;
  }

  const gate = await preflight(o, config.runtime.baseUrl);
  if (gate !== null) return gate;

  const result = await startWorkflow({
    cwd, task, config, signals, flowOverride: flow,
    workingDir: str(o, "working-dir"),
    timeoutMs: str(o, "timeout") ? Number(str(o, "timeout")) : undefined,
    approval: str(o, "approve") ? { approvedBy: str(o, "approve")! } : undefined,
  });
  print(o, renderWorkflow(result, cwd), result);
  return workflowExit(result);
}

async function cmdWorkflowStatus(o: Opts, cwd: string): Promise<number> {
  const runId = o.positionals[0];
  if (!runId) return fail("workflow status requires a run-id");
  const { config } = await loadConfig(cwd);
  const store = new RunStore(path.resolve(cwd, config.orchestration.runDirectory), runId);
  if (!store.exists()) return fail(`run not found: ${runId}`);
  const meta = await store.readMetadata();
  if (bool(o, "json")) {
    console.log(JSON.stringify(meta, null, 2));
  } else {
    console.log(`Run: ${meta.runId}`);
    console.log(`Status: ${meta.status}`);
    console.log(`Approval: ${meta.approval.required ? `required${meta.approval.approvedAt ? " (approved)" : " — PENDING"}` : "not required"}`);

    // Per-role view: show every worker that started/finished, then any planned
    // role that has not started yet as "queued".
    const started = new Set(meta.workers.map((w) => w.role));
    const label = (w: (typeof meta.workers)[number]) => (w.state === "running" ? "running" : (w.status ?? "done"));
    const width = Math.max(0, ...meta.plannedFlow.concat(meta.workers.map((w) => w.role)).map((r) => r.length));
    for (const w of meta.workers) {
      console.log(`  ${w.role.padEnd(width)}  ${label(w)}${w.workerId.endsWith("-1") ? "" : ` (${w.workerId})`}`);
    }
    for (const role of meta.plannedFlow) {
      if (!started.has(role)) console.log(`  ${role.padEnd(width)}  queued`);
    }

    const active = meta.workers.filter((w) => w.state === "running").length;
    console.log(`Local concurrency: ${active}/${meta.maxConcurrency}`);
  }
  return meta.status === "awaiting-approval" || meta.status === "failed" ? 2 : 0;
}

async function cmdWorkflowResume(o: Opts, cwd: string): Promise<number> {
  const runId = o.positionals[0];
  if (!runId) return fail("workflow resume requires a run-id");
  const { config } = await resolvedConfig(o, cwd);
  const flow = str(o, "flow")?.split(",").map((s) => s.trim()).filter(Boolean);
  const result = await resumeWorkflow(cwd, runId, config, {
    approvedBy: str(o, "approve"),
    signals: signalsFrom(o),
    flowOverride: flow,
  });
  print(o, renderWorkflow(result, cwd), result);
  return workflowExit(result);
}

async function cmdWorkflowCancel(o: Opts, cwd: string): Promise<number> {
  const runId = o.positionals[0];
  if (!runId) return fail("workflow cancel requires a run-id");
  const { config } = await loadConfig(cwd);
  const store = new RunStore(path.resolve(cwd, config.orchestration.runDirectory), runId);
  if (!store.exists()) return fail(`run not found: ${runId}`);
  const meta = await store.readMetadata();
  meta.status = "cancelled";
  meta.updatedAt = new Date().toISOString();
  await store.writeMetadata(meta);
  console.log(`Run ${runId} marked cancelled. Worktrees (if any) are preserved — run \`worktree cleanup ${runId}\`.`);
  return 0;
}

async function cmdWorktreeCleanup(o: Opts, cwd: string): Promise<number> {
  const runId = o.positionals[0];
  if (!runId) return fail("worktree cleanup requires a run-id");
  const { config } = await loadConfig(cwd);
  const store = new RunStore(path.resolve(cwd, config.orchestration.runDirectory), runId);
  if (!store.exists()) return fail(`run not found: ${runId}`);
  const meta = await store.readMetadata() as unknown as { worktrees?: WorktreeInfo[] };
  const worktrees = meta.worktrees ?? [];
  if (worktrees.length === 0) {
    console.log("No worktrees recorded for this run.");
    return 0;
  }
  const result = await cleanupWorktrees(cwd, worktrees);
  console.log(`Removed ${result.removed.length} worktree(s).`);
  if (result.skippedDirty.length) {
    console.log(`Skipped ${result.skippedDirty.length} with uncommitted changes (preserved):`);
    for (const w of result.skippedDirty) console.log(`  ${w.path} (${w.branch})`);
  }
  return 0;
}

function renderWorkflow(result: WorkflowResult, cwd: string): string {
  const lines = [
    `Run: ${result.runId}`,
    `Status: ${result.status}`,
    `Risk tier: ${result.decision.riskTier}`,
  ];
  if (result.status === "awaiting-approval") {
    lines.push(`APPROVAL REQUIRED: ${result.decision.approvalReason ?? "policy"}`);
    lines.push(`Approve and continue: local-agents workflow resume ${result.runId} --approve <name>`);
  }
  for (const r of result.results) lines.push(`  ${r.role}: ${r.status} — ${r.summary.slice(0, 100)}`);
  lines.push(`Artifacts: ${path.relative(cwd, result.runDir)}`);
  return lines.join("\n");
}

function fail(message: string): number {
  console.error(`error: ${message}`);
  return 1;
}

/** Fast-fail before spawning any worker when Ollama is unreachable. */
async function preflight(o: Opts, baseUrl: string): Promise<number | null> {
  if (bool(o, "no-preflight") || bool(o, "dry-run")) return null;
  const r = await probeOllama(baseUrl);
  if (!r.ok) return fail(r.message);
  return null;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    console.log(USAGE);
    return argv.length === 0 ? 1 : 0;
  }

  const [command, sub, ...rest] = argv;
  // Group tokens for parseArgs depending on command shape.
  const isWorkflow = command === "workflow";
  const isWorktree = command === "worktree";
  const parseArgsInput = isWorkflow || isWorktree ? rest : [sub, ...rest].filter((v) => v !== undefined);

  let parsed;
  try {
    parsed = parseArgs({ args: parseArgsInput as string[], options: OPTION_CONFIG, allowPositionals: true, strict: true });
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
  const o: Opts = { values: parsed.values, positionals: parsed.positionals };
  if (bool(o, "help")) {
    console.log(USAGE);
    return 0;
  }
  const cwd = path.resolve(str(o, "cwd") ?? process.cwd());

  try {
    switch (command) {
      case "doctor":
        return await cmdDoctor(o, cwd);
      case "run":
        return await cmdRun(o, cwd);
      case "roles": {
        const { config } = await loadConfig(cwd);
        console.log(availableRoles(config).join("\n"));
        return 0;
      }
      case "workflow":
        switch (sub) {
          case "start":
            return await cmdWorkflowStart(o, cwd);
          case "status":
            return await cmdWorkflowStatus(o, cwd);
          case "resume":
            return await cmdWorkflowResume(o, cwd);
          case "cancel":
            return await cmdWorkflowCancel(o, cwd);
          default:
            return fail(`unknown workflow subcommand: ${sub ?? "(none)"}`);
        }
      case "worktree":
        if (sub === "cleanup") return await cmdWorktreeCleanup(o, cwd);
        return fail(`unknown worktree subcommand: ${sub ?? "(none)"}`);
      default:
        return fail(`unknown command: ${command}. Run \`local-agents --help\`.`);
    }
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
}

// Only run when invoked directly (not when imported by tests).
const invokedDirectly = process.argv[1] && /(?:^|\/)cli\.(?:ts|js)$/.test(process.argv[1]);
if (invokedDirectly) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err instanceof Error ? err.stack ?? err.message : String(err));
      process.exit(1);
    });
}

// makeRunId is re-exported so scripts can predict a run id if needed.
export { makeRunId };
