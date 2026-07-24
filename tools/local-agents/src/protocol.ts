/**
 * Versioned worker-result protocol.
 *
 * A worker is a disposable Claude Code process. Its ONLY trustworthy output is
 * a JSON object matching {@link WorkerResult}. Free-form stdout is kept for
 * diagnostics but never treated as the result. `normalizeWorkerResult` parses
 * whatever the worker emitted and either returns a valid, fully-populated
 * result or throws — malformed output must never be mistaken for success.
 */

export const PROTOCOL_VERSION = 1 as const;

export type WorkerStatus = "completed" | "blocked" | "failed" | "partial";

export const WORKER_STATUSES: readonly WorkerStatus[] = [
  "completed",
  "blocked",
  "failed",
  "partial",
];

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export const FINDING_SEVERITIES: readonly FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export interface CommandExecution {
  command: string;
  exitCode: number | null;
  /** True when the wrapper (not the model) refused the command. */
  denied?: boolean;
}

export interface Finding {
  severity: FindingSeverity;
  summary: string;
  file?: string;
  line?: number;
}

export interface ArtifactReference {
  /** Stable key, e.g. "raw-stdout", "diff", "plan". */
  kind: string;
  /** Path relative to the run directory. */
  path: string;
  description?: string;
}

export interface WorkerError {
  message: string;
  /** Machine-readable class, e.g. "timeout", "spawn", "protocol". */
  kind?: string;
}

/**
 * Token / timing metrics. Every field is optional and MUST be omitted rather
 * than guessed — an absent field means "the runtime did not expose it", which
 * is different from zero. `source` records provenance so a report never
 * presents an estimate as an exact measurement.
 */
export interface UsageMetrics {
  source: "runtime" | "estimate";
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  costUsd?: number;
  numTurns?: number;
  modelLoadMs?: number;
}

export interface WorkerResult {
  protocolVersion: typeof PROTOCOL_VERSION;
  runId: string;
  workerId: string;
  role: string;
  status: WorkerStatus;
  summary: string;
  filesRead: string[];
  filesChanged: string[];
  commandsExecuted: CommandExecution[];
  findings: Finding[];
  artifacts: ArtifactReference[];
  questions: string[];
  errors: WorkerError[];
  usage?: UsageMetrics;
  startedAt: string;
  completedAt: string;
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}

function asSeverity(value: unknown): FindingSeverity {
  return FINDING_SEVERITIES.includes(value as FindingSeverity)
    ? (value as FindingSeverity)
    : "info";
}

function asFindings(value: unknown): Finding[] {
  if (!Array.isArray(value)) return [];
  const out: Finding[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) continue;
    const summary = typeof raw.summary === "string" ? raw.summary : undefined;
    if (!summary) continue;
    const finding: Finding = { severity: asSeverity(raw.severity), summary };
    if (typeof raw.file === "string") finding.file = raw.file;
    if (typeof raw.line === "number" && Number.isFinite(raw.line)) finding.line = raw.line;
    out.push(finding);
  }
  return out;
}

function asCommands(value: unknown): CommandExecution[] {
  if (!Array.isArray(value)) return [];
  const out: CommandExecution[] = [];
  for (const raw of value) {
    if (!isRecord(raw)) continue;
    const command = typeof raw.command === "string" ? raw.command : undefined;
    if (!command) continue;
    const exitCode =
      typeof raw.exitCode === "number" && Number.isFinite(raw.exitCode) ? raw.exitCode : null;
    const entry: CommandExecution = { command, exitCode };
    if (raw.denied === true) entry.denied = true;
    out.push(entry);
  }
  return out;
}

function asErrors(value: unknown): WorkerError[] {
  if (!Array.isArray(value)) return [];
  const out: WorkerError[] = [];
  for (const raw of value) {
    if (typeof raw === "string") {
      out.push({ message: raw });
    } else if (isRecord(raw) && typeof raw.message === "string") {
      const err: WorkerError = { message: raw.message };
      if (typeof raw.kind === "string") err.kind = raw.kind;
      out.push(err);
    }
  }
  return out;
}

/**
 * The JSON body a worker is instructed to emit. This is the subset the model
 * controls; the runner injects `runId`, `workerId`, `role`, timestamps, and
 * merges observed data (commands the wrapper saw, raw-output artifacts).
 */
export interface WorkerReportedBody {
  status?: unknown;
  summary?: unknown;
  filesRead?: unknown;
  filesChanged?: unknown;
  commandsExecuted?: unknown;
  findings?: unknown;
  questions?: unknown;
  errors?: unknown;
}

/**
 * JSON Schema for the model-controlled worker body, passed to Claude Code via
 * `--json-schema` so the CLI enforces the output SHAPE instead of relying only
 * on a prompt instruction (small local models routinely answer in prose). The
 * runner still parses and normalises the result, so this is enforcement, not a
 * replacement for validation.
 */
export const WORKER_BODY_JSON_SCHEMA = {
  type: "object",
  properties: {
    status: { type: "string", enum: [...WORKER_STATUSES] },
    summary: { type: "string" },
    filesRead: { type: "array", items: { type: "string" } },
    filesChanged: { type: "array", items: { type: "string" } },
    commandsExecuted: {
      type: "array",
      items: {
        type: "object",
        properties: {
          command: { type: "string" },
          exitCode: { type: ["integer", "null"] },
        },
        required: ["command"],
      },
    },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          severity: { type: "string", enum: [...FINDING_SEVERITIES] },
          summary: { type: "string" },
          file: { type: "string" },
          line: { type: "integer" },
        },
        required: ["severity", "summary"],
      },
    },
    questions: { type: "array", items: { type: "string" } },
    errors: {
      type: "array",
      items: {
        type: "object",
        properties: { message: { type: "string" }, kind: { type: "string" } },
        required: ["message"],
      },
    },
  },
  required: ["status", "summary"],
  additionalProperties: true,
} as const;

export interface NormalizeContext {
  runId: string;
  workerId: string;
  role: string;
  startedAt: string;
  completedAt: string;
  /** Commands the wrapper observed, merged with anything the model reported. */
  observedCommands?: CommandExecution[];
  artifacts?: ArtifactReference[];
  usage?: UsageMetrics;
}

/**
 * Parse and validate a worker's reported JSON body into a WorkerResult.
 * Throws {@link ProtocolError} when the body is not an object or lacks a
 * recognisable status — a malformed body is a failure, not a silent success.
 */
export function normalizeWorkerResult(
  body: unknown,
  ctx: NormalizeContext,
): WorkerResult {
  if (!isRecord(body)) {
    throw new ProtocolError("worker body is not a JSON object");
  }

  const rawStatus = body.status;
  if (!WORKER_STATUSES.includes(rawStatus as WorkerStatus)) {
    throw new ProtocolError(
      `worker reported an unknown status: ${JSON.stringify(rawStatus)}`,
    );
  }
  const status = rawStatus as WorkerStatus;

  const summary = typeof body.summary === "string" ? body.summary.trim() : "";

  const reportedCommands = asCommands(body.commandsExecuted);
  const commandsExecuted = mergeCommands(ctx.observedCommands ?? [], reportedCommands);

  const result: WorkerResult = {
    protocolVersion: PROTOCOL_VERSION,
    runId: ctx.runId,
    workerId: ctx.workerId,
    role: ctx.role,
    status,
    summary,
    filesRead: asStringArray(body.filesRead),
    filesChanged: asStringArray(body.filesChanged),
    commandsExecuted,
    findings: asFindings(body.findings),
    artifacts: ctx.artifacts ?? [],
    questions: asStringArray(body.questions),
    errors: asErrors(body.errors),
    startedAt: ctx.startedAt,
    completedAt: ctx.completedAt,
  };
  if (ctx.usage) result.usage = ctx.usage;
  return result;
}

/** Union observed + reported commands, de-duplicated by command string. */
function mergeCommands(
  observed: CommandExecution[],
  reported: CommandExecution[],
): CommandExecution[] {
  const byCommand = new Map<string, CommandExecution>();
  for (const c of observed) byCommand.set(c.command, c);
  for (const c of reported) {
    if (!byCommand.has(c.command)) byCommand.set(c.command, c);
  }
  return [...byCommand.values()];
}

/** Build a synthetic failure result (spawn error, timeout, protocol error). */
export function failureResult(
  ctx: NormalizeContext,
  error: WorkerError,
  summary = "worker did not produce a valid result",
): WorkerResult {
  return {
    protocolVersion: PROTOCOL_VERSION,
    runId: ctx.runId,
    workerId: ctx.workerId,
    role: ctx.role,
    status: "failed",
    summary,
    filesRead: [],
    filesChanged: [],
    commandsExecuted: ctx.observedCommands ?? [],
    findings: [],
    artifacts: ctx.artifacts ?? [],
    questions: [],
    errors: [error],
    ...(ctx.usage ? { usage: ctx.usage } : {}),
    startedAt: ctx.startedAt,
    completedAt: ctx.completedAt,
  };
}

/** The highest-severity finding present, or null. */
export function maxSeverity(findings: Finding[]): FindingSeverity | null {
  for (const sev of FINDING_SEVERITIES) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return null;
}
