import { execFile } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { isCiEnvironment } from "./approvals.js";
import { execConfigDisabled } from "./config-loader.js";
import { detectPackageManager } from "./installer.js";
import { loadPolicy, PolicyError } from "./policy.js";
import { resolveProvider, type ProviderSelection } from "./providers/index.js";
import { authHeaderForUrl, DEFAULT_REGISTRY, loadNpmrc } from "./npmrc.js";
import type { Signals } from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * `targate doctor` — environment diagnostics. Each check is independent,
 * time-bounded, and reports pass/warn/fail/info; the command exits 1 iff at
 * least one check FAILED.
 */

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
  env: NodeJS.ProcessEnv;
  /** Per network check. */
  networkTimeoutMs: number;
  /** --ping: one real (paid) completion against the resolved AI provider. */
  ping: boolean;
  provider: ProviderSelection;
}

export interface DoctorCheck {
  id: string;
  label: string;
  run(ctx: DoctorContext): Promise<{ status: DoctorStatus; message: string }>;
}

export interface DoctorReport {
  checks: DoctorCheckResult[];
  summary: { pass: number; warn: number; fail: number; info: number };
  exitCode: 0 | 1;
}

export const MIN_NODE_MAJOR = 20; // mirrors package.json "engines"

const REGISTRY_PING = "https://registry.npmjs.org/-/ping";
const OSV_QUERY = "https://api.osv.dev/v1/query";
const GITHUB_RATE_LIMIT = "https://api.github.com/rate_limit";

/** Benign synthetic signals for the --ping live completion. */
function pingSignals(): Signals {
  return {
    package: "targate-doctor-ping",
    version: "1.0.0",
    lifecycleScripts: {},
    hasLifecycleScripts: false,
    scriptCommandFindings: [],
    hasNativeCode: false,
    nativeSurface: {
      hasIos: false,
      hasAndroid: false,
      hasPodspec: false,
      hasGradle: false,
      hasCMake: false,
      hasRnConfig: false,
      binaryArtifacts: [],
      androidPermissions: [],
    },
    rnHardening: {
      podspecFindings: [],
      gradleFindings: [],
      dangerousPermissions: [],
      iosFrameworkFindings: [],
      autolinkingFindings: [],
      compatNotes: [],
    },
    content: {
      hasProcessEnvAccess: false,
      hasChildProcessUsage: false,
      hasNetworkCalls: false,
      hasEvalUsage: false,
      hasMinifiedCode: false,
      suspiciousFiles: [],
      installTimeFindings: [],
    },
    knownMalicious: false,
    maliciousRecords: [],
    advisories: [],
    osvUnavailable: false,
    repositoryMissing: false,
    recentPublish: false,
    ageInDays: 1000,
    nameSimilarity: null,
    dependencyCount: 0,
    directDependencies: [],
    reputation: {
      releaseGapAnomaly: false,
      maintainerCount: 1,
      maintainerChange: null,
      repositoryMismatch: false,
      hasProvenance: false,
      deprecated: false,
      downloads: { status: "skipped" },
      repo: { status: "skipped" },
    },
  };
}

async function probeWritable(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  const probe = path.join(dir, `.doctor-${randomUUID()}.tmp`);
  await writeFile(probe, "ok");
  await rm(probe, { force: true });
}

export const DOCTOR_CHECKS: DoctorCheck[] = [
  {
    id: "node-version",
    label: "Node version",
    async run() {
      const version = process.versions.node;
      const major = Number(version.split(".")[0]);
      return major >= MIN_NODE_MAJOR
        ? { status: "pass", message: `Node v${version} (>=${MIN_NODE_MAJOR} required)` }
        : { status: "fail", message: `Node v${version} — targate requires Node >=${MIN_NODE_MAJOR}` };
    },
  },
  {
    id: "package-manager",
    label: "Package manager",
    async run(ctx) {
      const pm = detectPackageManager(ctx.cwd);
      const lockfiles: Record<string, string> = {
        pnpm: "pnpm-lock.yaml",
        yarn: "yarn.lock",
        npm: "package-lock.json",
      };
      const hasLockfile = existsSync(path.join(ctx.cwd, lockfiles[pm]));
      let binaryVersion: string | null = null;
      try {
        const { stdout } = await execFileAsync(pm, ["--version"], {
          timeout: ctx.networkTimeoutMs,
        });
        binaryVersion = stdout.trim();
      } catch {
        binaryVersion = null;
      }
      if (hasLockfile && binaryVersion) {
        return { status: "pass", message: `${pm} ${binaryVersion} (${lockfiles[pm]})` };
      }
      if (!hasLockfile && binaryVersion) {
        return { status: "info", message: `no lockfile — defaulting to ${pm} ${binaryVersion}` };
      }
      if (hasLockfile) {
        return {
          status: "fail",
          message: `${lockfiles[pm]} found but \`${pm} --version\` failed (not on PATH, or the binary errors on this Node)`,
        };
      }
      return { status: "warn", message: `no lockfile and \`${pm} --version\` failed` };
    },
  },
  {
    id: "npm-registry",
    label: "npm registry",
    async run(ctx) {
      const started = Date.now();
      try {
        const res = await fetch(REGISTRY_PING, {
          signal: AbortSignal.timeout(ctx.networkTimeoutMs),
        });
        return res.ok
          ? { status: "pass", message: `registry.npmjs.org reachable (${Date.now() - started}ms)` }
          : { status: "warn", message: `registry.npmjs.org responded with HTTP ${res.status}` };
      } catch {
        return {
          status: "fail",
          message: `registry.npmjs.org unreachable (timeout ${ctx.networkTimeoutMs}ms) — metadata and tarball fetches will fail`,
        };
      }
    },
  },
  {
    id: "npmrc",
    label: "Registry configuration (.npmrc)",
    async run(ctx) {
      const config = loadNpmrc(ctx.cwd, ctx.env);
      const scoped = Object.entries(config.entries)
        .filter(([k]) => k.startsWith("@") && k.endsWith(":registry"))
        .map(([k, v]) => {
          const url = v.replace(/\/+$/, "");
          const auth = authHeaderForUrl(`${url}/`, config) !== undefined;
          return `${k.slice(0, -":registry".length)} → ${url}${auth ? " (auth configured)" : " (no auth)"}`;
        });
      const globalOverride = config.entries.registry?.replace(/\/+$/, "");
      const parts: string[] = [];
      if (globalOverride && globalOverride !== DEFAULT_REGISTRY) {
        const auth = authHeaderForUrl(`${globalOverride}/`, config) !== undefined;
        parts.push(`default registry override: ${globalOverride}${auth ? " (auth configured)" : ""}`);
      }
      parts.push(...scoped);
      if (parts.length === 0) {
        return {
          status: "pass",
          message: config.files.length
            ? "default registry (registry.npmjs.org), no scoped registries"
            : "no .npmrc found — default registry (registry.npmjs.org)",
        };
      }
      // Informational pass: token VALUES are never printed, only presence.
      return { status: "pass", message: parts.join("; ") };
    },
  },
  {
    id: "osv",
    label: "OSV / OpenSSF",
    async run(ctx) {
      const started = Date.now();
      try {
        const res = await fetch(OSV_QUERY, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            package: { name: "left-pad", ecosystem: "npm" },
            version: "1.3.0",
          }),
          signal: AbortSignal.timeout(ctx.networkTimeoutMs),
        });
        return res.ok
          ? { status: "pass", message: `api.osv.dev reachable (${Date.now() - started}ms)` }
          : { status: "warn", message: `api.osv.dev responded with HTTP ${res.status}` };
      } catch {
        return {
          status: "fail",
          message: `api.osv.dev unreachable — malicious-package status will be UNKNOWN on every run (consider --fail-on-osv-error in CI)`,
        };
      }
    },
  },
  {
    id: "ai-provider",
    label: "AI provider",
    async run(ctx) {
      let provider;
      try {
        provider = resolveProvider(ctx.provider);
      } catch (err) {
        return { status: "fail", message: err instanceof Error ? err.message : String(err) };
      }
      if (!provider) {
        return {
          status: "info",
          message: "no AI provider configured — deterministic rules engine only",
        };
      }
      if (!ctx.ping) {
        return { status: "pass", message: `${provider.name} (${provider.model})` };
      }
      const started = Date.now();
      try {
        const assessment = await Promise.race([
          provider.assess(pingSignals()),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("ping timed out after 30s")), 30_000),
          ),
        ]);
        return assessment && typeof assessment.decision === "string"
          ? {
              status: "pass",
              message: `${provider.name} (${provider.model}) — live completion OK (${((Date.now() - started) / 1000).toFixed(1)}s)`,
            }
          : { status: "fail", message: `${provider.name} returned an invalid assessment` };
      } catch (err) {
        return {
          status: "fail",
          message: `${provider.name} ping failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  },
  {
    id: "github-api",
    label: "GitHub API",
    async run(ctx) {
      const token = ctx.env.GITHUB_TOKEN ?? ctx.env.GH_TOKEN;
      try {
        const res = await fetch(GITHUB_RATE_LIMIT, {
          headers: {
            accept: "application/vnd.github+json",
            "user-agent": "targate",
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
          signal: AbortSignal.timeout(ctx.networkTimeoutMs),
        });
        if (res.status === 401 && token) {
          return { status: "fail", message: "GITHUB_TOKEN rejected (HTTP 401) — fix or unset it" };
        }
        if (!res.ok) {
          return { status: "warn", message: `api.github.com responded with HTTP ${res.status}` };
        }
        const body = (await res.json()) as { rate?: { remaining?: number; limit?: number } };
        const rate = body.rate;
        if (token) {
          return {
            status: "pass",
            message: `authenticated — ${rate?.remaining ?? "?"}/${rate?.limit ?? "?"} requests remaining`,
          };
        }
        return {
          status: "info",
          message: `GITHUB_TOKEN not set — ${rate?.remaining ?? "?"}/${rate?.limit ?? "?"} unauthenticated requests/h (used by reputation signals)`,
        };
      } catch {
        return {
          status: "warn",
          message: "api.github.com unreachable — repo reputation signals will be UNKNOWN",
        };
      }
    },
  },
  {
    id: "policy",
    label: "Team policy",
    async run(ctx) {
      try {
        const loaded = await loadPolicy(ctx.cwd);
        return loaded
          ? { status: "pass", message: `${path.basename(loaded.file)} valid` }
          : { status: "info", message: "no policy file — defaults apply (targate policy init)" };
      } catch (err) {
        return {
          status: "fail",
          message: err instanceof PolicyError ? err.message : String(err),
        };
      }
    },
  },
  {
    id: "exec-config",
    label: "Executable config",
    async run(ctx) {
      return execConfigDisabled(ctx.env)
        ? {
            status: "info",
            message: "TARGATE_NO_EXEC_CONFIG set — .ts/.js policy & approvals sources are ignored",
          }
        : { status: "pass", message: "executable config enabled (default)" };
    },
  },
  {
    id: "project-dir",
    label: "Project .targate/",
    async run(ctx) {
      try {
        await probeWritable(path.join(ctx.cwd, ".targate"));
        return { status: "pass", message: `${path.join(ctx.cwd, ".targate")} writable` };
      } catch (err) {
        return {
          status: "fail",
          message: `cannot write ${path.join(ctx.cwd, ".targate")} — approvals and last-run records cannot be recorded (${err instanceof Error ? err.message : String(err)})`,
        };
      }
    },
  },
  {
    id: "user-cache-dir",
    label: "User cache dir",
    async run(ctx) {
      const dir = path.join(ctx.env.HOME ?? homedir(), ".targate");
      try {
        await probeWritable(dir);
        return { status: "pass", message: `${dir} writable` };
      } catch {
        return { status: "warn", message: `cannot write ${dir} — the AI response cache is disabled` };
      }
    },
  },
  {
    id: "ci-mode",
    label: "CI mode",
    async run(ctx) {
      return isCiEnvironment(ctx.env)
        ? {
            status: "info",
            message: "CI environment detected — prompts and `targate approve` are disabled",
          }
        : { status: "info", message: "not running in CI" };
    },
  },
];

/** Run every check concurrently; report results in declaration order. */
export async function runDoctor(
  ctx: DoctorContext,
  checks: DoctorCheck[] = DOCTOR_CHECKS,
): Promise<DoctorReport> {
  const results = await Promise.all(
    checks.map(async (check): Promise<DoctorCheckResult> => {
      const started = Date.now();
      try {
        const { status, message } = await check.run(ctx);
        return { id: check.id, label: check.label, status, message, durationMs: Date.now() - started };
      } catch (err) {
        return {
          id: check.id,
          label: check.label,
          status: "fail",
          message: err instanceof Error ? err.message : String(err),
          durationMs: Date.now() - started,
        };
      }
    }),
  );

  const summary = { pass: 0, warn: 0, fail: 0, info: 0 };
  for (const r of results) summary[r.status]++;
  return { checks: results, summary, exitCode: summary.fail > 0 ? 1 : 0 };
}
