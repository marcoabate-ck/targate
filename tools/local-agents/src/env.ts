/**
 * Child-process environment isolation.
 *
 * A local worker is a Claude Code process pointed at a local Ollama server. It
 * must NEVER see the parent's Anthropic credentials (or any other secret), and
 * the parent's own environment must never be mutated. `buildWorkerEnv` returns
 * a fresh environment built by allowlist — start from nothing, copy only what a
 * CLI genuinely needs, drop anything matching a secret pattern, then set the
 * Ollama routing variables.
 */

/** Runtime routing config for the local (Ollama-backed) worker. */
export interface RuntimeEnvConfig {
  /** e.g. http://localhost:11434 — Claude Code appends /v1/messages. */
  baseUrl: string;
  /** Bearer token the local server ignores but the SDK requires. */
  authToken: string;
  /** Ollama model tag, surfaced to the worker as LOCAL_AGENT_MODEL. */
  model: string;
}

/**
 * Base variables safe to forward verbatim. Deliberately small: a coding CLI
 * needs PATH/HOME/shell/locale and little else. Everything outside this list is
 * dropped unless the caller adds it to `allowExtra`.
 */
const BASE_ALLOWLIST: readonly string[] = [
  "PATH",
  "HOME",
  "SHELL",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "TMPDIR",
  "TZ",
  "NODE_EXTRA_CA_CERTS",
  "COLORTERM",
  // Ollama server discovery, when a non-default host is configured.
  "OLLAMA_HOST",
];

/**
 * Names that must never reach a worker even if a repo adds them to its extra
 * allowlist. Exact names plus prefix families. This is a hard deny that wins
 * over every allow.
 */
const SECRET_EXACT: readonly string[] = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "CLAUDE_CODE_OAUTH_TOKEN",
  "OPENAI_API_KEY",
  "DEEPSEEK_API_KEY",
  "AI_API_KEY",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "HF_TOKEN",
  "HUGGING_FACE_HUB_TOKEN",
];

const SECRET_PREFIXES: readonly string[] = [
  "AWS_",
  "GOOGLE_",
  "GCP_",
  "AZURE_",
  "CLOUDFLARE_",
  "VERCEL_",
  "STRIPE_",
  "SLACK_",
  "NPM_CONFIG__AUTH",
];

/** Substrings that mark a variable as sensitive regardless of prefix. */
const SECRET_SUBSTRINGS: readonly string[] = [
  "SECRET",
  "PASSWORD",
  "PASSWD",
  "PRIVATE_KEY",
  "ACCESS_KEY",
  "SESSION_TOKEN",
  "CREDENTIALS",
];

/** True when a variable name must be excluded from any worker environment. */
export function isSecretName(name: string): boolean {
  const upper = name.toUpperCase();
  if (SECRET_EXACT.includes(upper)) return true;
  if (SECRET_PREFIXES.some((p) => upper.startsWith(p))) return true;
  if (SECRET_SUBSTRINGS.some((s) => upper.includes(s))) return true;
  // Generic *_TOKEN / *_KEY families, but keep the harmless PUBLIC_ ones.
  if ((upper.endsWith("_TOKEN") || upper.endsWith("_KEY")) && !upper.startsWith("PUBLIC_")) {
    return true;
  }
  return false;
}

export interface BuildWorkerEnvOptions {
  /** Runtime routing (base URL, token, model). */
  runtime: RuntimeEnvConfig;
  /** The parent environment to filter (defaults to process.env). */
  parentEnv?: NodeJS.ProcessEnv;
  /**
   * Extra variable names a repository explicitly allows through. Each is still
   * checked against the secret filter — a repo cannot allowlist a secret.
   */
  allowExtra?: readonly string[];
}

export interface BuiltWorkerEnv {
  env: Record<string, string>;
  /** Names dropped because they matched the secret filter (for diagnostics). */
  droppedSecrets: string[];
  /** Names forwarded from the parent (for diagnostics). */
  forwarded: string[];
}

/**
 * Build a fresh worker environment. Never mutates `parentEnv`. Returns the
 * env plus a breakdown of what was forwarded and what was dropped so a doctor
 * or verbose run can prove no secret leaked.
 */
export function buildWorkerEnv(options: BuildWorkerEnvOptions): BuiltWorkerEnv {
  const parent = options.parentEnv ?? process.env;
  const allow = new Set<string>([...BASE_ALLOWLIST, ...(options.allowExtra ?? [])]);

  const env: Record<string, string> = {};
  const forwarded: string[] = [];
  const droppedSecrets: string[] = [];

  for (const name of allow) {
    const value = parent[name];
    if (value === undefined) continue;
    if (isSecretName(name)) {
      droppedSecrets.push(name);
      continue;
    }
    env[name] = value;
    forwarded.push(name);
  }

  // Any secret that happened to be in the parent env is reported as dropped
  // (it was never in `allow`, but surfacing it makes the guarantee auditable).
  for (const name of Object.keys(parent)) {
    if (!allow.has(name) && isSecretName(name)) droppedSecrets.push(name);
  }

  // Ollama routing — set LAST so it can never be overridden by a forwarded var.
  env.ANTHROPIC_BASE_URL = options.runtime.baseUrl;
  env.ANTHROPIC_AUTH_TOKEN = options.runtime.authToken;
  // Explicit empty string: ensures Claude Code does not fall back to a
  // parent ANTHROPIC_API_KEY that slipped through some other path.
  env.ANTHROPIC_API_KEY = "";
  env.LOCAL_AGENT_MODEL = options.runtime.model;
  // Disposable workers never persist or read a prior session.
  env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1";

  return { env, droppedSecrets: [...new Set(droppedSecrets)].sort(), forwarded: forwarded.sort() };
}

/** Assert an env object carries no secret values (used by tests and doctor). */
export function assertNoSecrets(env: Record<string, string>): void {
  for (const name of Object.keys(env)) {
    // ANTHROPIC_AUTH_TOKEN is intentionally set to the Ollama placeholder.
    if (name === "ANTHROPIC_AUTH_TOKEN") continue;
    if (name === "ANTHROPIC_API_KEY" && env[name] === "") continue;
    if (isSecretName(name) && env[name] !== "") {
      throw new Error(`worker environment leaked a secret variable: ${name}`);
    }
  }
}
