import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

/**
 * Daemon state for the registry proxy. The proxy runs as a detached background
 * process; its state file lets `stop` / `status` / `ensure` find it across CLI
 * invocations. Machine-scoped under ~/.targate (the same home npm-style config
 * root the AI cache uses) — one proxy per machine.
 */
export interface ProxyState {
  pid: number;
  port: number;
  host: string;
  upstream: string;
  /** "http" or "https" — the proxy serves TLS after `setup`. */
  scheme: "http" | "https";
  /** Shared secret for the local control API (approve/deny). */
  controlToken?: string;
  /** epoch ms; passed in by the caller (Date is intentionally injected). */
  startedAt: number;
}

export function proxyStateDir(): string {
  return path.join(homedir(), ".targate");
}

export function proxyStateFile(): string {
  return path.join(proxyStateDir(), "proxy.json");
}

export function proxyLogFile(): string {
  return path.join(proxyStateDir(), "proxy.log");
}

export function readProxyState(): ProxyState | null {
  const file = proxyStateFile();
  if (!existsSync(file)) return null;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<ProxyState>;
    if (typeof parsed.pid === "number" && typeof parsed.port === "number") {
      return {
        pid: parsed.pid,
        port: parsed.port,
        host: parsed.host ?? "127.0.0.1",
        upstream: parsed.upstream ?? "https://registry.npmjs.org",
        scheme: parsed.scheme === "https" ? "https" : "http",
        controlToken: typeof parsed.controlToken === "string" ? parsed.controlToken : undefined,
        startedAt: parsed.startedAt ?? 0,
      };
    }
  } catch {
    // corrupt state file — treat as no daemon
  }
  return null;
}

export function writeProxyState(state: ProxyState): void {
  mkdirSync(proxyStateDir(), { recursive: true });
  // Holds the control-API token — restrict to the owner.
  writeFileSync(proxyStateFile(), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

export function clearProxyState(): void {
  try {
    rmSync(proxyStateFile(), { force: true });
  } catch {
    // best-effort
  }
}

/** True when a process with this pid exists and is signalable by this user. */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // ESRCH = gone; EPERM = alive but not ours (still "running")
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** State only if the recorded process is actually still alive; clears stale files. */
export function liveProxyState(): ProxyState | null {
  const state = readProxyState();
  if (!state) return null;
  if (isProcessAlive(state.pid)) return state;
  clearProxyState();
  return null;
}
