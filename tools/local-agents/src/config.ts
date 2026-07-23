/**
 * Configuration: load, validate, and resolve the orchestration config.
 *
 * Config is declarative only (YAML or JSON) — the orchestrator never executes
 * repository-controlled code to obtain its settings, mirroring targate's
 * "declarative config is the safe default" stance. Environment variables
 * override individual fields for one-off runs.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";

export const CONFIG_FILENAMES = [
  "local-agents.config.yaml",
  "local-agents.config.yml",
  "local-agents.config.json",
] as const;

export const BUILTIN_ROLE_NAMES = ["discovery", "implementer", "tester", "reviewer"] as const;
export type BuiltinRoleName = (typeof BUILTIN_ROLE_NAMES)[number];

export type ApprovalMode = "adaptive" | "always" | "never";

/** A role as declared in config (built-in defaults live in roles.ts). */
export interface RoleConfig {
  /** false → worker may not modify files (Discovery, Reviewer). */
  readOnly: boolean;
  /** Extra tool names to allow on top of the role's built-in set. */
  allowTools?: string[];
  /** Extra tool names to deny. */
  denyTools?: string[];
  /** Human description, used in the role's system prompt. */
  description?: string;
}

export interface RuntimeConfig {
  provider: "ollama";
  baseUrl: string;
  authToken: string;
  model: string;
}

export interface OrchestrationConfig {
  maxConcurrency: number;
  defaultTimeoutMs: number;
  preserveRawOutput: boolean;
  runDirectory: string;
  /** Max implementer→reviewer correction cycles before Opus must intervene. */
  maxCorrectionCycles: number;
  /** Bounded retries for transient (not deterministic) worker failures. */
  maxTransientRetries: number;
  /** Extra parent env var names workers may inherit (never secrets). */
  envAllowlist: string[];
}

export interface ResolvedConfig {
  version: 1;
  runtime: RuntimeConfig;
  orchestration: OrchestrationConfig;
  roles: Record<string, RoleConfig>;
  approval: { mode: ApprovalMode };
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export const DEFAULT_MODEL = "qwen3.6:35b-a3b-coding-nvfp4";
export const DEFAULT_BASE_URL = "http://localhost:11434";

/** Conservative default: one 35B/21GB worker at a time. */
export const DEFAULT_MAX_CONCURRENCY = 1;
export const DEFAULT_TIMEOUT_MS = 900_000;

export function defaultConfig(): ResolvedConfig {
  return {
    version: 1,
    runtime: {
      provider: "ollama",
      baseUrl: DEFAULT_BASE_URL,
      authToken: "ollama",
      model: DEFAULT_MODEL,
    },
    orchestration: {
      maxConcurrency: DEFAULT_MAX_CONCURRENCY,
      defaultTimeoutMs: DEFAULT_TIMEOUT_MS,
      preserveRawOutput: true,
      runDirectory: ".local-agent-runs",
      maxCorrectionCycles: 2,
      maxTransientRetries: 2,
      envAllowlist: [],
    },
    roles: {
      discovery: { readOnly: true },
      implementer: { readOnly: false },
      tester: { readOnly: false },
      reviewer: { readOnly: true },
    },
    approval: { mode: "adaptive" },
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function num(value: unknown, field: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ConfigError(`${field} must be a finite number`);
  }
  if (value < min || value > max) {
    throw new ConfigError(`${field} must be between ${min} and ${max} (got ${value})`);
  }
  return value;
}

function validateBaseUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ConfigError("runtime.baseUrl must be a non-empty string");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`runtime.baseUrl is not a valid URL: ${value}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError(`runtime.baseUrl must be http(s): ${value}`);
  }
  // Claude Code appends /v1/messages; strip any trailing slash to avoid //.
  return value.replace(/\/+$/, "");
}

function validateRoles(raw: unknown): Record<string, RoleConfig> {
  const roles: Record<string, RoleConfig> = {};
  if (raw === undefined) return roles;
  if (!isRecord(raw)) throw new ConfigError("roles must be an object");
  for (const [name, value] of Object.entries(raw)) {
    if (!/^[a-z][a-z0-9-]*$/.test(name)) {
      throw new ConfigError(`invalid role name "${name}" (use lower-kebab-case)`);
    }
    if (!isRecord(value)) throw new ConfigError(`role "${name}" must be an object`);
    if (typeof value.readOnly !== "boolean") {
      throw new ConfigError(`role "${name}" requires a boolean readOnly`);
    }
    const role: RoleConfig = { readOnly: value.readOnly };
    if (value.allowTools !== undefined) {
      if (!Array.isArray(value.allowTools) || value.allowTools.some((t) => typeof t !== "string")) {
        throw new ConfigError(`role "${name}" allowTools must be a string array`);
      }
      role.allowTools = value.allowTools as string[];
    }
    if (value.denyTools !== undefined) {
      if (!Array.isArray(value.denyTools) || value.denyTools.some((t) => typeof t !== "string")) {
        throw new ConfigError(`role "${name}" denyTools must be a string array`);
      }
      role.denyTools = value.denyTools as string[];
    }
    // A read-only role that also grants write tools is a conflicting permission.
    if (role.readOnly && role.allowTools?.some((t) => /^(Edit|Write|NotebookEdit)\b/.test(t))) {
      throw new ConfigError(
        `role "${name}" is readOnly but allowTools grants a write tool (conflicting permissions)`,
      );
    }
    if (typeof value.description === "string") role.description = value.description;
    roles[name] = role;
  }
  return roles;
}

/** Merge a parsed config object over the defaults, validating every field. */
export function resolveConfig(raw: unknown): ResolvedConfig {
  const base = defaultConfig();
  if (raw === undefined || raw === null) return base;
  if (!isRecord(raw)) throw new ConfigError("config root must be an object");

  if (raw.version !== undefined && raw.version !== 1) {
    throw new ConfigError(`unsupported config version: ${JSON.stringify(raw.version)} (expected 1)`);
  }

  const runtime = { ...base.runtime };
  if (raw.runtime !== undefined) {
    if (!isRecord(raw.runtime)) throw new ConfigError("runtime must be an object");
    const r = raw.runtime;
    if (r.provider !== undefined && r.provider !== "ollama") {
      throw new ConfigError(`runtime.provider must be "ollama" (got ${JSON.stringify(r.provider)})`);
    }
    if (r.baseUrl !== undefined) runtime.baseUrl = validateBaseUrl(r.baseUrl);
    if (r.authToken !== undefined) {
      if (typeof r.authToken !== "string" || r.authToken.length === 0) {
        throw new ConfigError("runtime.authToken must be a non-empty string");
      }
      runtime.authToken = r.authToken;
    }
    if (r.model !== undefined) {
      if (typeof r.model !== "string" || r.model.length === 0) {
        throw new ConfigError("runtime.model must be a non-empty string");
      }
      runtime.model = r.model;
    }
  }

  const orch = { ...base.orchestration };
  if (raw.orchestration !== undefined) {
    if (!isRecord(raw.orchestration)) throw new ConfigError("orchestration must be an object");
    const o = raw.orchestration;
    if (o.maxConcurrency !== undefined) {
      orch.maxConcurrency = num(o.maxConcurrency, "orchestration.maxConcurrency", 1, 32);
    }
    if (o.defaultTimeoutMs !== undefined) {
      orch.defaultTimeoutMs = num(o.defaultTimeoutMs, "orchestration.defaultTimeoutMs", 1_000, 3_600_000);
    }
    if (o.preserveRawOutput !== undefined) {
      if (typeof o.preserveRawOutput !== "boolean") {
        throw new ConfigError("orchestration.preserveRawOutput must be a boolean");
      }
      orch.preserveRawOutput = o.preserveRawOutput;
    }
    if (o.runDirectory !== undefined) {
      if (typeof o.runDirectory !== "string" || o.runDirectory.length === 0) {
        throw new ConfigError("orchestration.runDirectory must be a non-empty string");
      }
      if (path.isAbsolute(o.runDirectory)) {
        throw new ConfigError("orchestration.runDirectory must be repo-relative, not absolute");
      }
      orch.runDirectory = o.runDirectory;
    }
    if (o.maxCorrectionCycles !== undefined) {
      orch.maxCorrectionCycles = num(o.maxCorrectionCycles, "orchestration.maxCorrectionCycles", 0, 10);
    }
    if (o.maxTransientRetries !== undefined) {
      orch.maxTransientRetries = num(o.maxTransientRetries, "orchestration.maxTransientRetries", 0, 5);
    }
    if (o.envAllowlist !== undefined) {
      if (!Array.isArray(o.envAllowlist) || o.envAllowlist.some((v) => typeof v !== "string")) {
        throw new ConfigError("orchestration.envAllowlist must be a string array");
      }
      orch.envAllowlist = o.envAllowlist as string[];
    }
  }

  const roles = { ...base.roles, ...validateRoles(raw.roles) };

  let approvalMode: ApprovalMode = base.approval.mode;
  if (raw.approval !== undefined) {
    if (!isRecord(raw.approval)) throw new ConfigError("approval must be an object");
    const m = raw.approval.mode;
    if (m !== undefined) {
      if (m !== "adaptive" && m !== "always" && m !== "never") {
        throw new ConfigError(`approval.mode must be adaptive|always|never (got ${JSON.stringify(m)})`);
      }
      approvalMode = m;
    }
  }

  return { version: 1, runtime, orchestration: orch, roles, approval: { mode: approvalMode } };
}

/** Apply environment-variable overrides after file resolution. */
export function applyEnvOverrides(
  config: ResolvedConfig,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedConfig {
  const next: ResolvedConfig = {
    ...config,
    runtime: { ...config.runtime },
    orchestration: { ...config.orchestration },
  };
  if (env.LOCAL_AGENT_MODEL) next.runtime.model = env.LOCAL_AGENT_MODEL;
  if (env.LOCAL_AGENT_BASE_URL) next.runtime.baseUrl = validateBaseUrl(env.LOCAL_AGENT_BASE_URL);
  if (env.LOCAL_AGENT_AUTH_TOKEN) next.runtime.authToken = env.LOCAL_AGENT_AUTH_TOKEN;
  if (env.LOCAL_AGENT_MAX_CONCURRENCY) {
    const parsed = Number(env.LOCAL_AGENT_MAX_CONCURRENCY);
    next.orchestration.maxConcurrency = num(parsed, "LOCAL_AGENT_MAX_CONCURRENCY", 1, 32);
  }
  if (env.LOCAL_AGENT_TIMEOUT_MS) {
    const parsed = Number(env.LOCAL_AGENT_TIMEOUT_MS);
    next.orchestration.defaultTimeoutMs = num(parsed, "LOCAL_AGENT_TIMEOUT_MS", 1_000, 3_600_000);
  }
  return next;
}

/** Locate a config file at `cwd`, or null when none exists. */
export function findConfigFile(cwd: string): string | null {
  for (const name of CONFIG_FILENAMES) {
    const file = path.join(cwd, name);
    if (existsSync(file)) return file;
  }
  return null;
}

async function parseConfigFile(file: string): Promise<unknown> {
  const text = await readFile(file, "utf8");
  const ext = path.extname(file);
  if (ext === ".json") return JSON.parse(text);
  return parseYaml(text);
}

/**
 * Load, validate, and env-override the config for a working directory. When no
 * file exists, returns validated defaults (with env overrides still applied).
 */
export async function loadConfig(
  cwd: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ config: ResolvedConfig; file: string | null }> {
  const file = findConfigFile(cwd);
  const raw = file ? await parseConfigFile(file) : undefined;
  const config = applyEnvOverrides(resolveConfig(raw), env);
  return { config, file };
}
