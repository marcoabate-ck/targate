import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { CAPTURE_SCRIPT } from "./sandbox-capture.js";

const DEFAULT_IMAGE = "node:22-alpine";
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Network policy for the trial install:
 * - "open" (default): full egress via docker's bridge network. npm can
 *   fetch the package and its dependencies; a malicious script can also
 *   reach the internet. This is an OBSERVATION sandbox, not a network jail.
 * - "none": no network at all (`--network=none`). Only works when the
 *   package and its dependencies are already cached in the image; useful
 *   for confirming a script does NOT need the network, since a phone-home
 *   attempt fails loudly. A normal cold install cannot fetch and will fail.
 */
export type SandboxNetwork = "open" | "none";

export interface SandboxOptions {
  image?: string;
  timeoutMs?: number;
  network?: SandboxNetwork;
  /** Observe DNS + HTTP(S) proxy traffic during the install (default: true).
   *  Forced off when network is "none". */
  capture?: boolean;
  /** Where to echo the live container log (default: "stdout"; "stderr" keeps
   *  --json stdout clean). */
  echo?: "stdout" | "stderr" | "none";
  /** Container name (`docker run --name`). runSandbox always sets one so the
   *  timeout can stop the CONTAINER, not just the attached client. */
  containerName?: string;
}

export interface DnsQuery {
  name: string;
  type: string;
  count: number;
}
export interface NetConnection {
  host: string;
  port: number;
  count: number;
  sentBytes: number;
  recvBytes: number;
  /** Host is on the expected-during-install allowlist (registry, git hosts…). */
  expected: boolean;
}
export interface HttpRequest {
  method: string;
  url: string;
  host: string;
  expected: boolean;
}
export interface NetworkActivity {
  /** The shim reported "ready" — capture was actually running. */
  captureActive: boolean;
  dnsQueries: DnsQuery[];
  connections: NetConnection[];
  httpRequests: HttpRequest[];
  /** Non-fatal shim errors surfaced from "[targate-net] error …". */
  errors: string[];
}

export interface SandboxResult {
  exitCode: number;
  timedOut: boolean;
  /** Combined stdout+stderr of the containerized install (script log). */
  log: string;
  /** Lines from the log that deserve attention. */
  suspiciousLines: string[];
  /** Observed network activity, or null when capture was off. */
  network: NetworkActivity | null;
  command: string[];
}

/** Hosts a cold `npm install` legitimately contacts (dot-boundary suffix match). */
export const EXPECTED_NETWORK_HOSTS = [
  "registry.npmjs.org",
  "npmjs.org",
  "npmjs.com",
  "github.com",
  "githubusercontent.com",
  "gitlab.com",
  "bitbucket.org",
  "nodejs.org",
  "localhost",
  "127.0.0.1",
  "::1",
];

function isExpectedHost(host: string): boolean {
  const h = host.toLowerCase();
  return EXPECTED_NETWORK_HOSTS.some((e) => h === e || h.endsWith("." + e));
}

/**
 * Shell script executed INSIDE the disposable container. The package spec
 * is passed via the TARGATE_SPEC environment variable (NOT interpolated into the
 * script text), so a hostile spec string cannot break out of the quoting and
 * inject shell commands. The install runs with --foreground-scripts so every
 * lifecycle script's output lands in the log, then we snapshot what the
 * install left on the filesystem outside its own project directory.
 */
/**
 * The shell script run INSIDE the container. With capture off it is the
 * original script (plus a robustness fix: the install no longer aborts the
 * whole script under `set -e`, so the filesystem-writes report always runs).
 * With capture on it additionally boots the network-observation shim (delivered
 * via the TARGATE_CAPTURE_SRC env var, never a heredoc), points resolv.conf and
 * the proxy env at it, and flushes it after the install. Capture failure is
 * loud but never fatal — the install proceeds either way.
 */
export function buildContainerScript(capture: boolean): string {
  const lines = ["set -e", "mkdir -p /sandbox/project && cd /sandbox/project", "npm init -y > /dev/null 2>&1"];

  if (capture) {
    lines.push(
      // Deliver the shim via env (printf), not a heredoc — BusyBox-safe.
      "printf '%s' \"$TARGATE_CAPTURE_SRC\" > /tmp/targate-capture.mjs",
      "unset TARGATE_CAPTURE_SRC",
      "node /tmp/targate-capture.mjs & CAPTURE_PID=$!",
      'i=0; while [ ! -f /tmp/targate-capture.ready ] && [ "$i" -lt 20 ]; do sleep 0.1; i=$((i+1)); done',
      // DNS is pointed at the shim via docker --dns 127.0.0.1 (set on the
      // container, since a non-root / read-only container cannot rewrite
      // /etc/resolv.conf). Here we only route npm/HTTP(S) through the proxy.
      "if [ -f /tmp/targate-capture.ready ]; then",
      "  export HTTP_PROXY=http://127.0.0.1:8888 HTTPS_PROXY=http://127.0.0.1:8888",
      "  export http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888",
      "  export npm_config_proxy=http://127.0.0.1:8888 npm_config_https_proxy=http://127.0.0.1:8888",
      "else",
      '  echo "[targate-net] error capture-not-ready (proceeding WITHOUT network capture)"',
      "fi",
    );
  }

  lines.push(
    "find / -path /proc -prune -o -newer /sandbox -type f -print 2>/dev/null > /tmp/before.txt || true",
    'echo "--- targate sandbox: installing $TARGATE_SPEC ---"',
    // NOT `; STATUS=$?` — under set -e that aborts the script on a failed
    // install, skipping the reports below. `|| STATUS=$?` keeps them running.
    "STATUS=0",
    'npm install "$TARGATE_SPEC" --foreground-scripts --loglevel info || STATUS=$?',
  );

  if (capture) {
    lines.push(
      "echo '--- targate sandbox: network activity ---'",
      'kill -TERM "$CAPTURE_PID" 2>/dev/null || true',
      'wait "$CAPTURE_PID" 2>/dev/null || true',
    );
  }

  lines.push(
    "echo '--- targate sandbox: filesystem writes outside the project ---'",
    "find /root /home /etc /usr/local -type f -newer /tmp/before.txt 2>/dev/null | grep -v -E '^/root/.npm|^/sandbox' || echo '(none)'",
    "exit $STATUS",
  );
  return lines.join("\n");
}

/**
 * Build the docker invocation for a quarantined trial install (phase 4).
 * Isolation properties actually enforced:
 * - disposable container (--rm), nothing mounted from the host;
 * - no host environment variables, SSH agent, npm/GitHub tokens (docker
 *   passes none of them unless explicitly asked to — and we don't);
 * - runs as a NON-ROOT user (uid 1000) on a READ-ONLY root filesystem; the
 *   only writable space is two tmpfs work dirs (/sandbox, /tmp), so a hostile
 *   script cannot persist into the image or write outside them;
 * - CPU/memory/pid caps, all capabilities dropped, no privilege escalation;
 * - the package spec is passed as an env var, never interpolated into the
 *   shell script, and is rejected if it starts with "-".
 *
 * NETWORK: by default the container uses docker's bridge network with FULL
 * egress — npm needs it to fetch packages, and so a malicious install script
 * can also reach the internet. This is an observation sandbox, not a network
 * jail. Pass network: "none" for a fully offline trial. There is no per-host
 * network allowlist.
 */
export function buildSandboxCommand(spec: string, opts: SandboxOptions = {}): string[] {
  // A spec beginning with "-" would be read by npm inside the container as a
  // flag, not a package. Reject it (mirrors installer.ts / install-plan.ts).
  if (spec.startsWith("-")) {
    throw new Error(`refusing a package spec that starts with "-": ${spec}`);
  }
  const network = opts.network ?? "open";
  // Capture needs the network; it is meaningless (and its port-53 bind would
  // fail) under --network=none.
  const capture = (opts.capture ?? true) && network !== "none";
  return [
    "docker",
    "run",
    "--rm",
    "--pull=missing",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
    // Run the untrusted install as a NON-ROOT user on a READ-ONLY root
    // filesystem: a hostile lifecycle script cannot escalate, persist into the
    // image, or write anywhere outside the two tmpfs work dirs below. uid 1000
    // is the image's own `node` user. Validated end-to-end (non-root +
    // read-only + capture + a real install) before shipping.
    "--user",
    "1000:1000",
    "--read-only",
    "--tmpfs",
    "/sandbox:exec,mode=1777",
    "--tmpfs",
    "/tmp:exec,mode=1777",
    // HOME and the npm cache must live on a writable tmpfs (the rootfs is
    // read-only and the default /root/.npm is not writable as a non-root user).
    "--env",
    "HOME=/sandbox",
    "--env",
    "npm_config_cache=/sandbox/.npm",
    "--memory=1g",
    "--cpus=1",
    // Cap process count so a fork bomb in a lifecycle script can't exhaust
    // host PIDs before the memory limit bites.
    "--pids-limit=512",
    // Named so runSandbox's timeout can `docker kill` the container itself;
    // killing the attached client alone would orphan it (miner/beacon keeps
    // running with egress open past the deadline).
    ...(opts.containerName ? ["--name", opts.containerName] : []),
    // Let the shim bind 127.0.0.1:53 without any capability — this keeps
    // --cap-drop=ALL fully intact (a strictly better story than --cap-add).
    // The sysctl is namespaced, affecting only this container.
    ...(capture ? ["--sysctl", "net.ipv4.ip_unprivileged_port_start=0"] : []),
    // As a non-root / read-only container the shell can't rewrite
    // /etc/resolv.conf to point resolution at the in-container DNS shim, so
    // direct docker's resolver at it here (docker writes resolv.conf at
    // creation, before the rootfs is read-only). The shim on 127.0.0.1:53
    // logs each query name and forwards it upstream.
    ...(capture ? ["--dns", "127.0.0.1"] : []),
    ...(network === "none" ? ["--network=none"] : []),
    "--env",
    "npm_config_fund=false",
    "--env",
    "npm_config_audit=false",
    // Spec passed as data via env, not interpolated into the shell script.
    "--env",
    `TARGATE_SPEC=${spec}`,
    // Capture shim source travels as data too — a static constant, never
    // interpolated, so it can't affect the injection-safety of the spec.
    ...(capture ? ["--env", `TARGATE_CAPTURE_SRC=${CAPTURE_SCRIPT}`] : []),
    opts.image ?? DEFAULT_IMAGE,
    "sh",
    "-c",
    buildContainerScript(capture),
  ];
}

const SUSPICIOUS_LOG_PATTERNS: Array<[RegExp, string]> = [
  [/(curl|wget)\s/i, "network download during install"],
  [/\.ssh|id_rsa/i, "SSH material referenced"],
  [/\.npmrc|NPM_TOKEN|GITHUB_TOKEN|AWS_/, "credential names referenced"],
  [/\/etc\/passwd|\/etc\/shadow/, "system credential files referenced"],
  [/base64\s+(-d|--decode)/, "base64 decoding during install"],
  [/nc\s+-|\bncat\b|\/dev\/tcp\//, "raw network connection attempted"],
];

export function findSuspiciousLogLines(log: string): string[] {
  const findings: string[] = [];
  for (const line of log.split("\n")) {
    // Our own capture-shim output is not install activity — never match it.
    if (line.includes("[targate-net] ")) continue;
    for (const [pattern, label] of SUSPICIOUS_LOG_PATTERNS) {
      if (pattern.test(line)) {
        findings.push(`${label}: ${line.trim().slice(0, 160)}`);
        break;
      }
    }
  }
  return findings.slice(0, 30);
}

/**
 * Parse the capture shim's `[targate-net] …` lines into structured activity.
 * null when capture was off (no shim lines at all); captureActive is false
 * when lines exist but the shim never reported "ready".
 */
export function extractNetworkActivity(log: string): NetworkActivity | null {
  const lines = log.split("\n").filter((l) => l.includes("[targate-net] "));
  if (lines.length === 0) return null;

  let captureActive = false;
  const errors: string[] = [];
  const dns = new Map<string, DnsQuery>();
  const conns = new Map<string, NetConnection>();
  const https = new Map<string, HttpRequest>();

  for (const raw of lines) {
    const rest = raw.slice(raw.indexOf("[targate-net] ") + "[targate-net] ".length).trim();
    const parts = rest.split(/\s+/);
    const kind = parts[0];
    if (kind === "ready") captureActive = true;
    else if (kind === "error") errors.push(rest.slice("error".length).trim());
    else if (kind === "dns" && parts[1]) {
      const key = `${parts[1]} ${parts[2] ?? ""}`;
      const e = dns.get(key) ?? { name: parts[1], type: parts[2] ?? "?", count: 0 };
      e.count++;
      dns.set(key, e);
    } else if (kind === "connect" && parts[1]) {
      const host = parts[1];
      const port = Number(parts[2]) || 0;
      const key = `${host}:${port}`;
      const e = conns.get(key) ?? { host, port, count: 0, sentBytes: 0, recvBytes: 0, expected: isExpectedHost(host) };
      e.count++;
      conns.set(key, e);
    } else if (kind === "http" && parts[2]) {
      const method = parts[1];
      const url = parts[2];
      let host = "";
      try {
        host = new URL(url).hostname;
      } catch {
        /* leave blank */
      }
      https.set(`${method} ${url}`, { method, url, host, expected: isExpectedHost(host) });
    } else if (kind === "close" && parts[1]) {
      const host = parts[1];
      const port = Number(parts[2]) || 0;
      const key = `${host}:${port}`;
      const sent = Number(/sent=(\d+)/.exec(rest)?.[1] ?? 0);
      const recv = Number(/recv=(\d+)/.exec(rest)?.[1] ?? 0);
      const e = conns.get(key) ?? { host, port, count: 0, sentBytes: 0, recvBytes: 0, expected: isExpectedHost(host) };
      e.sentBytes += sent;
      e.recvBytes += recv;
      conns.set(key, e);
    }
  }

  return {
    captureActive,
    dnsQueries: [...dns.values()],
    connections: [...conns.values()],
    httpRequests: [...https.values()],
    errors,
  };
}

/** Unexpected destinations, as human suspicious-line strings (deduped, capped). */
function networkSuspicions(network: NetworkActivity | null): string[] {
  if (!network) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (host: string, extra = "") => {
    if (!host || isExpectedHost(host) || seen.has(host)) return;
    seen.add(host);
    out.push(`unexpected network destination during install: ${host}${extra}`);
  };
  for (const c of network.connections) {
    if (c.expected) continue;
    add(c.host, `:${c.port}${c.sentBytes > 0 ? ` sent=${c.sentBytes}B` : ""}`);
  }
  for (const r of network.httpRequests) if (!r.expected) add(r.host);
  for (const q of network.dnsQueries) add(q.name);
  return out.slice(0, 10);
}

export async function isDockerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn("docker", ["version", "--format", "{{.Server.Version}}"], {
      stdio: "ignore",
    });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}

/** Run the trial install in a disposable container and capture the log. */
export function runSandbox(spec: string, opts: SandboxOptions = {}): Promise<SandboxResult> {
  const containerName = opts.containerName ?? `targate-sandbox-${randomUUID()}`;
  const command = buildSandboxCommand(spec, { ...opts, containerName });
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const echo = opts.echo ?? "stdout";

  return new Promise((resolve, reject) => {
    const [bin, ...args] = command;
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      // Stop the CONTAINER, not just the attached `docker run` client. A
      // SIGKILL'd client cannot forward a stop, so without this a background
      // process spawned by a lifecycle script keeps running (with egress) in
      // the orphaned container past the deadline. `--rm` reaps it on kill.
      const killer = spawn("docker", ["kill", containerName], { stdio: "ignore" });
      killer.on("error", () => {
        /* docker gone / already exited — the client kill below is the fallback */
      });
      child.kill("SIGKILL");
    }, timeoutMs);

    const sink = echo === "stderr" ? process.stderr : process.stdout;
    child.stdout.on("data", (chunk) => {
      log += chunk;
      if (echo !== "none") sink.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      log += chunk;
      if (echo !== "none") sink.write(chunk);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      const network = extractNetworkActivity(log);
      const suspiciousLines = [...findSuspiciousLogLines(log), ...networkSuspicions(network)].slice(0, 30);
      resolve({
        exitCode: code ?? 1,
        timedOut,
        log,
        suspiciousLines,
        network,
        command,
      });
    });
  });
}
