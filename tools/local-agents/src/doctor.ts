/**
 * `local-agents doctor` — preflight diagnostics.
 *
 * Each check is independent, time-bounded, and reports pass/warn/fail/info.
 * The command exits non-zero iff at least one check FAILED. Never auto-pulls
 * the model, never mutates anything, never prints secrets.
 */

import { execFile } from "node:child_process";
import { access, mkdir, rm, writeFile } from "node:fs/promises";
import { constants as FS } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { loadConfig, type ResolvedConfig } from "./config.js";
import { buildWorkerEnv } from "./env.js";

const execFileAsync = promisify(execFile);

export type DoctorStatus = "pass" | "warn" | "fail" | "info";

export interface DoctorCheckResult {
  id: string;
  label: string;
  status: DoctorStatus;
  message: string;
  durationMs: number;
}

export interface DoctorContext {
  cwd: string;
  config: ResolvedConfig;
  configFile: string | null;
  /** --ping: fire one real (local) completion through a worker dry run. */
  ping: boolean;
  /** Injectable HTTP for tests. */
  fetchFn?: typeof fetch;
  now?: () => number;
}

export interface DoctorCheck {
  id: string;
  label: string;
  run(ctx: DoctorContext): Promise<{ status: DoctorStatus; message: string }>;
}

async function httpText(
  ctx: DoctorContext,
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<{ status: number; body: string } | { error: string }> {
  const f = ctx.fetchFn ?? fetch;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), init.timeoutMs ?? 3_000);
  try {
    const res = await f(url, { ...init, signal: ac.signal });
    const body = await res.text();
    return { status: res.status, body };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export const DOCTOR_CHECKS: DoctorCheck[] = [
  {
    id: "claude-cli",
    label: "Claude Code CLI",
    async run() {
      try {
        const { stdout } = await execFileAsync("claude", ["--version"], { timeout: 5_000 });
        return { status: "pass", message: `found ${stdout.trim()}` };
      } catch {
        return { status: "fail", message: "`claude` not found on PATH — install Claude Code" };
      }
    },
  },
  {
    id: "ollama-cli",
    label: "Ollama CLI",
    async run() {
      try {
        const { stdout } = await execFileAsync("ollama", ["--version"], { timeout: 5_000 });
        return { status: "pass", message: stdout.trim() || "installed" };
      } catch {
        return { status: "fail", message: "`ollama` not found on PATH — install Ollama" };
      }
    },
  },
  {
    id: "ollama-server",
    label: "Ollama server reachable",
    async run(ctx) {
      const res = await httpText(ctx, `${ctx.config.runtime.baseUrl}/api/version`);
      if ("error" in res) {
        return { status: "fail", message: `cannot reach ${ctx.config.runtime.baseUrl}: ${res.error}` };
      }
      return { status: res.status === 200 ? "pass" : "warn", message: `HTTP ${res.status} from /api/version` };
    },
  },
  {
    id: "anthropic-route",
    label: "Ollama Anthropic-compatible route",
    async run(ctx) {
      // Empty body → 400 means /v1/messages exists; 404 means it does not.
      const res = await httpText(ctx, `${ctx.config.runtime.baseUrl}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
        timeoutMs: 4_000,
      });
      if ("error" in res) return { status: "fail", message: `route probe failed: ${res.error}` };
      if (res.status === 404) {
        return { status: "fail", message: "/v1/messages not found — this Ollama build lacks the Anthropic-compatible API" };
      }
      return { status: "pass", message: `/v1/messages present (probe HTTP ${res.status})` };
    },
  },
  {
    id: "model-present",
    label: "Configured model available",
    async run(ctx) {
      const res = await httpText(ctx, `${ctx.config.runtime.baseUrl}/api/tags`);
      if ("error" in res) return { status: "fail", message: `cannot list models: ${res.error}` };
      let names: string[] = [];
      try {
        const parsed = JSON.parse(res.body) as { models?: { name?: string }[] };
        names = (parsed.models ?? []).map((m) => m.name ?? "").filter(Boolean);
      } catch {
        return { status: "warn", message: "could not parse /api/tags response" };
      }
      const model = ctx.config.runtime.model;
      if (names.includes(model)) return { status: "pass", message: `${model} is present` };
      return {
        status: "fail",
        message: `model "${model}" not found locally. Pull it manually:\n    ollama pull ${model}`,
      };
    },
  },
  {
    id: "repo",
    label: "Git repository accessible",
    async run(ctx) {
      try {
        await execFileAsync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: ctx.cwd, timeout: 5_000 });
        return { status: "pass", message: "inside a git work tree" };
      } catch {
        return { status: "warn", message: "not a git repository — worktree isolation will be unavailable" };
      }
    },
  },
  {
    id: "worktree",
    label: "Git worktree capability",
    async run(ctx) {
      try {
        await execFileAsync("git", ["worktree", "list"], { cwd: ctx.cwd, timeout: 5_000 });
        return { status: "pass", message: "git worktree is available" };
      } catch {
        return { status: "warn", message: "git worktree unavailable — parallel writers must run sequentially" };
      }
    },
  },
  {
    id: "run-dir",
    label: "Run directory writable",
    async run(ctx) {
      const dir = path.resolve(ctx.cwd, ctx.config.orchestration.runDirectory);
      try {
        await mkdir(dir, { recursive: true });
        await access(dir, FS.W_OK);
        const probe = path.join(dir, ".doctor-probe");
        await writeFile(probe, "ok");
        await rm(probe, { force: true });
        return { status: "pass", message: `writable: ${ctx.config.orchestration.runDirectory}` };
      } catch (err) {
        return { status: "fail", message: `cannot write run directory: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  },
  {
    id: "config",
    label: "Configuration valid",
    async run(ctx) {
      // loadConfig already validated; report the source + key values.
      const where = ctx.configFile ? path.relative(ctx.cwd, ctx.configFile) : "built-in defaults";
      return {
        status: "info",
        message: `${where} — model=${ctx.config.runtime.model}, maxConcurrency=${ctx.config.orchestration.maxConcurrency}, approval=${ctx.config.approval.mode}`,
      };
    },
  },
  {
    id: "secret-isolation",
    label: "Worker environment secret isolation",
    async run(ctx) {
      const built = buildWorkerEnv({ runtime: ctx.config.runtime });
      const leaked = Object.keys(built.env).filter(
        (k) => /API_KEY|TOKEN|SECRET/.test(k) && k !== "ANTHROPIC_AUTH_TOKEN" && !(k === "ANTHROPIC_API_KEY" && built.env[k] === ""),
      );
      if (leaked.length > 0) return { status: "fail", message: `secret variables reached the worker env: ${leaked.join(", ")}` };
      const dropped = built.droppedSecrets.length;
      return { status: "pass", message: `no secrets forwarded (${dropped} dropped from parent env)` };
    },
  },
  {
    id: "ping",
    label: "Live worker dry run (--ping)",
    async run(ctx) {
      if (!ctx.ping) return { status: "info", message: "skipped (pass --ping to fire one real local completion)" };
      const model = ctx.config.runtime.model;
      const env = {
        ...buildWorkerEnv({ runtime: ctx.config.runtime }).env,
      };
      try {
        // Minimal prompt, tools disabled, short cap. This DOES load the model.
        const { stdout } = await execFileAsync(
          "claude",
          ["-p", 'Reply with the single word: ok', "--output-format", "json", "--no-session-persistence", "--model", model, "--tools", "", "--permission-mode", "bypassPermissions"],
          { cwd: ctx.cwd, env, timeout: 120_000 },
        );
        const ok = /"result"|"type"\s*:\s*"result"/.test(stdout);
        return ok
          ? { status: "pass", message: "worker produced a completion against the local model" }
          : { status: "warn", message: "worker ran but produced no recognisable result" };
      } catch (err) {
        return { status: "fail", message: `live worker failed: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  },
];

export interface DoctorReport {
  checks: DoctorCheckResult[];
  summary: { pass: number; warn: number; fail: number; info: number };
  exitCode: 0 | 1;
}

export async function runDoctor(ctx: DoctorContext, checks: DoctorCheck[] = DOCTOR_CHECKS): Promise<DoctorReport> {
  const clock = ctx.now ?? (() => Date.now());
  const results: DoctorCheckResult[] = [];
  for (const check of checks) {
    const start = clock();
    let outcome: { status: DoctorStatus; message: string };
    try {
      outcome = await check.run(ctx);
    } catch (err) {
      outcome = { status: "fail", message: err instanceof Error ? err.message : String(err) };
    }
    results.push({ id: check.id, label: check.label, ...outcome, durationMs: clock() - start });
  }
  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const r of results) summary[r.status]++;
  return { checks: results, summary, exitCode: summary.fail > 0 ? 1 : 0 };
}

/** Convenience: load config for `cwd` and run the doctor. */
export async function doctorForCwd(cwd: string, ping: boolean): Promise<DoctorReport> {
  const { config, file } = await loadConfig(cwd);
  return runDoctor({ cwd, config, configFile: file, ping });
}
