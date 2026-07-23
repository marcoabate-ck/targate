/**
 * Disposable Claude Code worker runner.
 *
 * Spawns a single `claude -p` child process pointed at the local Ollama server,
 * scoped to one bounded assignment, then terminates it. No session is
 * persisted; no conversational history is shared. The child receives a filtered
 * environment (no parent secrets), a per-role tool set, a PreToolUse command
 * guard, and a system prompt carrying its role, the in-scope AGENTS.md, and the
 * prompt-injection defense. The worker's only trusted output is the JSON body
 * it emits, normalised into a {@link WorkerResult}.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import type { ResolvedConfig } from "./config.js";
import { buildWorkerEnv, assertNoSecrets } from "./env.js";
import { resolveRole } from "./roles.js";
import { assembleSystemPrompt } from "./roles.js";
import { resolvePermissions } from "./permissions.js";
import { violatingPaths } from "./paths.js";
import { isConnectionError } from "./readiness.js";
import {
  failureResult,
  normalizeWorkerResult,
  type NormalizeContext,
  type UsageMetrics,
  type WorkerResult,
  ProtocolError,
} from "./protocol.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** The PreToolUse guard script, run via tsx (repo convention). */
export const HOOK_GUARD_PATH = path.join(HERE, "hook-guard.ts");

export interface WorkerAssignment {
  runId: string;
  workerId: string;
  role: string;
  /** The bounded task text (already includes plan section / constraints). */
  task: string;
  /** Working directory the worker runs in (repo root or an isolated worktree). */
  cwd: string;
  /** Scope roots the worker may write within (defaults to [cwd] + runDir). */
  scopes?: string[];
  /** In-scope AGENTS.md digest for the working directory. */
  agentsContext?: string;
  /** Optional repo-specific per-role instructions (data). */
  repoRoleInstructions?: string;
  /** Overrides the config default. */
  timeoutMs?: number;
}

export interface RunWorkerDeps {
  /** Injectable spawn for tests. */
  spawnFn?: typeof spawn;
  /** Injectable clock for deterministic timestamps. */
  now?: () => Date;
  /** Claude binary (default "claude"). */
  claudeBin?: string;
  /** Where to write the per-worker settings file (default: OS temp via caller). */
  settingsPath?: string;
  parentEnv?: NodeJS.ProcessEnv;
}

export interface RunWorkerOutcome {
  result: WorkerResult;
  raw: { stdout: string; stderr: string; exitCode: number | null; killedByTimeout: boolean };
  /** True when a transient failure suggests a retry is worthwhile. */
  transient: boolean;
}

/** Kill grace before SIGKILL after a SIGTERM. */
const KILL_GRACE_MS = 5_000;
/** Cap captured output so a runaway worker cannot exhaust memory. */
const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

/** Build the argument list for `claude -p`. Exported for testing. */
export function buildClaudeArgs(opts: {
  systemPrompt: string;
  model: string;
  allowedTools: string[];
  disallowedTools: string[];
  scopes: string[];
  settingsPath: string;
  task: string;
}): string[] {
  return [
    "-p",
    opts.task,
    "--output-format",
    "json",
    "--no-session-persistence",
    "--model",
    opts.model,
    // The command guard hook is the security gate; bypass the interactive
    // permission prompts that a non-interactive worker could never answer.
    "--permission-mode",
    "bypassPermissions",
    "--allowedTools",
    opts.allowedTools.join(","),
    "--disallowedTools",
    opts.disallowedTools.join(","),
    // No MCP servers in a worker unless one is explicitly injected.
    "--strict-mcp-config",
    "--settings",
    opts.settingsPath,
    "--append-system-prompt",
    opts.systemPrompt,
    ...opts.scopes.flatMap((dir) => ["--add-dir", dir]),
  ];
}

/** Settings JSON that installs the PreToolUse command guard hook. */
export function buildGuardSettings(hookGuardPath: string): string {
  return JSON.stringify(
    {
      hooks: {
        PreToolUse: [
          {
            matcher: "*",
            hooks: [
              {
                type: "command",
                command: `node --import tsx ${JSON.stringify(hookGuardPath)}`,
              },
            ],
          },
        ],
      },
    },
    null,
    2,
  );
}

/**
 * Extract the first balanced top-level JSON object from arbitrary text, so a
 * worker that wraps its result in prose or code fences is still parseable.
 * Returns null when no object is found.
 */
export function extractJsonObject(text: string): unknown | null {
  const trimmed = text.trim();
  // Fast path: the whole thing is JSON.
  try {
    return JSON.parse(trimmed);
  } catch {
    /* fall through */
  }
  const fenceless = trimmed.replace(/```(?:json)?/gi, "");
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < fenceless.length; i++) {
    const ch = fenceless[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        const candidate = fenceless.slice(start, i + 1);
        try {
          return JSON.parse(candidate);
        } catch {
          start = -1;
        }
      }
    }
  }
  return null;
}

interface ClaudeWrapper {
  result?: string;
  is_error?: boolean;
  subtype?: string;
  num_turns?: number;
  total_cost_usd?: number;
  usage?: { input_tokens?: number; output_tokens?: number };
}

function usageFrom(wrapper: ClaudeWrapper | null): UsageMetrics | undefined {
  if (!wrapper) return undefined;
  const u: UsageMetrics = { source: "runtime" };
  if (typeof wrapper.usage?.input_tokens === "number") u.inputTokens = wrapper.usage.input_tokens;
  if (typeof wrapper.usage?.output_tokens === "number") u.outputTokens = wrapper.usage.output_tokens;
  if (u.inputTokens !== undefined || u.outputTokens !== undefined) {
    u.totalTokens = (u.inputTokens ?? 0) + (u.outputTokens ?? 0);
  }
  if (typeof wrapper.total_cost_usd === "number") u.costUsd = wrapper.total_cost_usd;
  if (typeof wrapper.num_turns === "number") u.numTurns = wrapper.num_turns;
  return u;
}

/** Heuristic: does stderr/subtype indicate a transient (retryable) failure? */
function looksTransient(stderr: string, subtype?: string): boolean {
  const s = stderr.toLowerCase();
  if (/econnrefused|connection refused|connection reset|econnreset|socket hang up|network|timeout|502|503|504|model .*load|loading model/.test(s)) {
    return true;
  }
  if (subtype && /overloaded|unavailable/.test(subtype)) return true;
  return false;
}

/**
 * Run one worker to completion. Never throws for a worker-level problem — it
 * returns a `failed` WorkerResult with the error attached (so the orchestrator
 * records it) and a `transient` flag the caller uses to decide on a retry.
 */
export async function runWorker(
  assignment: WorkerAssignment,
  config: ResolvedConfig,
  deps: RunWorkerDeps = {},
): Promise<RunWorkerOutcome> {
  const now = deps.now ?? (() => new Date());
  const spawnFn = deps.spawnFn ?? spawn;
  const claudeBin = deps.claudeBin ?? "claude";
  const startedAt = now().toISOString();

  const role = resolveRole(assignment.role, config);
  const scopes = assignment.scopes ?? [assignment.cwd];

  const baseCtx: NormalizeContext = {
    runId: assignment.runId,
    workerId: assignment.workerId,
    role: assignment.role,
    startedAt,
    completedAt: startedAt,
  };

  if (!role) {
    return {
      result: failureResult(
        { ...baseCtx, completedAt: now().toISOString() },
        { message: `unknown role: ${assignment.role}`, kind: "config" },
      ),
      raw: { stdout: "", stderr: "", exitCode: null, killedByTimeout: false },
      transient: false,
    };
  }

  const permissions = resolvePermissions(config.roles[assignment.role] ?? { readOnly: role.readOnly });
  const systemPrompt = assembleSystemPrompt({
    role,
    agentsContext: assignment.agentsContext,
    repoRoleInstructions: assignment.repoRoleInstructions,
  });

  const settingsPath = deps.settingsPath ?? path.join(assignment.cwd, `.la-worker-${assignment.workerId}.settings.json`);

  const built = buildWorkerEnv({
    runtime: config.runtime,
    parentEnv: deps.parentEnv,
    allowExtra: config.orchestration.envAllowlist,
  });
  const env: Record<string, string> = {
    ...built.env,
    LOCAL_AGENT_ROLE: assignment.role,
    LOCAL_AGENT_READONLY: role.readOnly ? "1" : "0",
    LOCAL_AGENT_SCOPES: scopes.join(path.delimiter),
  };
  // Guarantee no secret slipped into the child environment.
  assertNoSecrets(env);

  const args = buildClaudeArgs({
    systemPrompt,
    model: config.runtime.model,
    allowedTools: permissions.allowedTools,
    disallowedTools: permissions.disallowedTools,
    scopes,
    settingsPath,
    task: assignment.task,
  });

  const timeoutMs = assignment.timeoutMs ?? config.orchestration.defaultTimeoutMs;

  // Write the guard settings file before spawning.
  const { writeFile, rm } = await import("node:fs/promises");
  await writeFile(settingsPath, buildGuardSettings(HOOK_GUARD_PATH));

  let stdout = "";
  let stderr = "";
  let killedByTimeout = false;
  let child: ChildProcess | null = null;

  const exitCode: number | null = await new Promise<number | null>((resolve) => {
    child = spawnFn(claudeBin, args, {
      cwd: assignment.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const termTimer = setTimeout(() => {
      killedByTimeout = true;
      child?.kill("SIGTERM");
      // Escalate to SIGKILL if it ignores SIGTERM.
      setTimeout(() => child?.kill("SIGKILL"), KILL_GRACE_MS).unref?.();
    }, timeoutMs);
    termTimer.unref?.();

    child.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length < MAX_CAPTURE_BYTES) stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_CAPTURE_BYTES) stderr += chunk.toString("utf8");
    });
    child.on("error", (err: Error) => {
      clearTimeout(termTimer);
      stderr += `\n[spawn error] ${err.message}`;
      resolve(null);
    });
    child.on("close", (code) => {
      clearTimeout(termTimer);
      resolve(code);
    });
  });

  const completedAt = now().toISOString();
  await rm(settingsPath, { force: true }).catch(() => {});
  const ctx: NormalizeContext = { ...baseCtx, completedAt };

  // Spawn failure (e.g. claude not installed): deterministic, do not retry.
  if (exitCode === null && /spawn error/.test(stderr)) {
    const missing = /ENOENT/.test(stderr);
    return {
      result: failureResult(ctx, {
        message: missing
          ? `Claude Code binary "${claudeBin}" not found on PATH`
          : `failed to spawn worker: ${stderr.trim()}`,
        kind: "spawn",
      }),
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient: false,
    };
  }

  if (killedByTimeout) {
    return {
      result: failureResult(ctx, { message: `worker exceeded ${timeoutMs}ms and was terminated`, kind: "timeout" }),
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient: true,
    };
  }

  // Parse the Claude Code JSON wrapper, then the worker's JSON body.
  let wrapper: ClaudeWrapper | null = null;
  const parsedWrapper = extractJsonObject(stdout);
  if (parsedWrapper && typeof parsedWrapper === "object") wrapper = parsedWrapper as ClaudeWrapper;

  const usage = usageFrom(wrapper);
  ctx.usage = usage;

  const bodyText = typeof wrapper?.result === "string" ? wrapper.result : stdout;
  const body = extractJsonObject(bodyText);

  // A connection error to the local endpoint is the "Ollama is down" case:
  // give it an explicit, actionable message rather than a generic one.
  if ((wrapper === null || wrapper?.is_error) && body === null && isConnectionError(stderr)) {
    return {
      result: failureResult(ctx, {
        message: `Ollama unreachable at ${config.runtime.baseUrl} — is \`ollama serve\` running? (run \`local-agents doctor\`)`,
        kind: "ollama-unreachable",
      }),
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient: true,
    };
  }

  if (wrapper?.is_error && body === null) {
    const transient = looksTransient(stderr + " " + (wrapper.subtype ?? ""), wrapper.subtype);
    return {
      result: failureResult(ctx, {
        message: `worker reported an error (${wrapper.subtype ?? "unknown"})`,
        kind: transient ? "transient" : "worker-error",
      }),
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient,
    };
  }

  try {
    const result = normalizeWorkerResult(body, ctx);
    // Post-hoc scope enforcement: a writer that claims to have changed files
    // outside its scope is a failure regardless of what it reported.
    const violations = violatingPaths(scopes, result.filesChanged.map((f) => path.resolve(assignment.cwd, f)));
    if (violations.length > 0) {
      result.status = "failed";
      result.errors.push({
        message: `worker reported changes outside its scope: ${violations.join(", ")}`,
        kind: "scope-violation",
      });
    }
    return {
      result,
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient: false,
    };
  } catch (error) {
    const transient = looksTransient(stderr, wrapper?.subtype);
    const message = error instanceof ProtocolError ? error.message : `failed to parse worker output: ${String(error)}`;
    return {
      result: failureResult(ctx, { message, kind: "protocol" }),
      raw: { stdout, stderr, exitCode, killedByTimeout },
      transient,
    };
  }
}
