import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

/**
 * Private-registry support: .npmrc resolution.
 *
 * targate reads the same configuration npm does — the user ~/.npmrc and the
 * project .npmrc (project wins) — to decide WHICH registry serves a package
 * (per-scope `@acme:registry=` rules, a global `registry=` override, or the
 * npmjs default) and WHICH credentials authenticate the request (nerf-darted
 * `//host/path/:_authToken=` entries, npm's own format). Tokens are used as
 * request headers only; they are never logged, printed, or persisted.
 *
 * Out of scope on purpose: npm's full config surface (proxies, strict-ssl,
 * certfiles). This module answers exactly two questions — "where do I fetch
 * this package?" and "with which Authorization header?".
 */

export const DEFAULT_REGISTRY = "https://registry.npmjs.org";

export interface NpmrcConfig {
  /** Merged key→value map, project entries overriding user entries. */
  entries: Record<string, string>;
  /** The .npmrc files that were actually read (for doctor). */
  files: string[];
}

/**
 * Parse .npmrc content (ini-lite, the subset npm uses for registry+auth):
 * `key=value` lines, `#`/`;` comments, quoted values, and `${VAR}` environment
 * expansion. An entry referencing an UNSET env var is dropped — npm would
 * error there; for analysis we degrade to "no credential" (the registry then
 * answers 401 visibly) rather than sending a literal "${NPM_TOKEN}".
 */
export function parseNpmrc(
  content: string,
  env: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    let missingEnv = false;
    value = value.replace(/\$\{([^}]+)\}/g, (_, name: string) => {
      const v = env[name];
      if (v === undefined) missingEnv = true;
      return v ?? "";
    });
    if (missingEnv) continue;
    entries[key] = value;
  }
  return entries;
}

/** Read + merge ~/.npmrc and <cwd>/.npmrc (project wins). Never throws. */
export function loadNpmrc(
  cwd: string = process.cwd(),
  env: NodeJS.ProcessEnv = process.env,
): NpmrcConfig {
  const entries: Record<string, string> = {};
  const files: string[] = [];
  for (const file of [path.join(homedir(), ".npmrc"), path.join(cwd, ".npmrc")]) {
    try {
      Object.assign(entries, parseNpmrc(readFileSync(file, "utf8"), env));
      files.push(file);
    } catch {
      /* absent or unreadable — npm behaves the same way */
    }
  }
  return { entries, files };
}

// Per-process memo: every analysis in a run sees the same config, and tests
// reset it. Keyed by cwd so tools embedding targate across projects stay correct.
const npmrcMemo = new Map<string, NpmrcConfig>();

export function getNpmrc(cwd: string = process.cwd()): NpmrcConfig {
  let config = npmrcMemo.get(cwd);
  if (!config) {
    config = loadNpmrc(cwd);
    npmrcMemo.set(cwd, config);
  }
  return config;
}

export function resetNpmrcCacheForTests(): void {
  npmrcMemo.clear();
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export interface RegistryResolution {
  /** Registry base URL, no trailing slash. */
  url: string;
  /** How it was chosen: a per-scope rule, a global registry= override, or the npmjs default. */
  source: "scope" | "global" | "default";
  /** The scope that matched, when source is "scope". */
  scope?: string;
}

/** Which registry serves this package, per npm's resolution rules. */
export function resolveRegistry(name: string, config: NpmrcConfig): RegistryResolution {
  if (name.startsWith("@")) {
    const scope = name.slice(0, name.indexOf("/"));
    const scoped = config.entries[`${scope}:registry`];
    if (scoped) return { url: stripTrailingSlash(scoped), source: "scope", scope };
  }
  const global = config.entries.registry;
  if (global && stripTrailingSlash(global) !== DEFAULT_REGISTRY) {
    return { url: stripTrailingSlash(global), source: "global" };
  }
  return { url: DEFAULT_REGISTRY, source: "default" };
}

/**
 * The Authorization header for a URL, from nerf-darted .npmrc credentials —
 * npm's own scheme: `//host/path/:_authToken=…` entries are matched against
 * the URL's host+path, most-specific path first, so a tarball URL under the
 * registry path picks up the registry's token. Supports `_authToken`
 * (Bearer), `_auth` (pre-encoded Basic), and `username`+`_password`
 * (base64-encoded password, per npm).
 */
export function authHeaderForUrl(url: string, config: NpmrcConfig): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  // Candidate nerf-dart prefixes, most specific first:
  //   //host/a/b/ → //host/a/ → //host/
  const segments = parsed.pathname.split("/").filter(Boolean);
  const prefixes: string[] = [];
  for (let i = segments.length; i >= 0; i--) {
    const p = segments.slice(0, i).join("/");
    prefixes.push(`//${parsed.host}/${p ? `${p}/` : ""}`);
  }
  for (const prefix of prefixes) {
    const token = config.entries[`${prefix}:_authToken`];
    if (token) return `Bearer ${token}`;
    const basic = config.entries[`${prefix}:_auth`];
    if (basic) return `Basic ${basic}`;
    const username = config.entries[`${prefix}:username`];
    const password = config.entries[`${prefix}:_password`];
    if (username && password) {
      const decoded = Buffer.from(password, "base64").toString("utf8");
      return `Basic ${Buffer.from(`${username}:${decoded}`).toString("base64")}`;
    }
  }
  return undefined;
}

/** True when `name` belongs to one of the policy's internal scopes. */
export function isInternalScope(name: string, internalScopes?: string[]): boolean {
  if (!internalScopes?.length || !name.startsWith("@")) return false;
  const scope = name.slice(0, name.indexOf("/"));
  return internalScopes.includes(scope);
}
