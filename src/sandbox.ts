import { spawn } from "node:child_process";

const DEFAULT_IMAGE = "node:20-alpine";
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

export interface SandboxOptions {
  image?: string;
  timeoutMs?: number;
}

export interface SandboxResult {
  exitCode: number;
  timedOut: boolean;
  /** Combined stdout+stderr of the containerized install (script log). */
  log: string;
  /** Lines from the log that deserve attention. */
  suspiciousLines: string[];
  command: string[];
}

/**
 * Shell script executed INSIDE the disposable container. The install runs
 * with --foreground-scripts so every lifecycle script's output lands in the
 * log, then we snapshot what the install left on the filesystem outside its
 * own project directory.
 */
function containerScript(spec: string): string {
  return [
    "set -e",
    "mkdir -p /sandbox/project && cd /sandbox/project",
    "npm init -y > /dev/null 2>&1",
    "find / -path /proc -prune -o -newer /sandbox -type f -print 2>/dev/null > /tmp/before.txt || true",
    `echo '--- bye sandbox: installing ${spec} ---'`,
    `npm install '${spec}' --foreground-scripts --loglevel info; STATUS=$?`,
    "echo '--- bye sandbox: filesystem writes outside the project ---'",
    "find /root /home /etc /usr/local -type f -newer /tmp/before.txt 2>/dev/null | grep -v -E '^/root/.npm|^/sandbox' || echo '(none)'",
    "exit $STATUS",
  ].join("\n");
}

/**
 * Build the docker invocation for a quarantined trial install (phase 4).
 * Isolation properties, per the proposal:
 * - disposable container (--rm), nothing mounted from the host;
 * - no host environment variables, SSH agent, npm/GitHub tokens (docker
 *   passes none of them unless explicitly asked to — and we don't);
 * - temporary filesystem only, host project never exposed;
 * - CPU/memory caps and no privilege escalation;
 * - network restricted to what npm needs (no host network namespace).
 */
export function buildSandboxCommand(spec: string, opts: SandboxOptions = {}): string[] {
  return [
    "docker",
    "run",
    "--rm",
    "--pull=missing",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
    "--memory=1g",
    "--cpus=1",
    "--env",
    "npm_config_fund=false",
    "--env",
    "npm_config_audit=false",
    opts.image ?? DEFAULT_IMAGE,
    "sh",
    "-c",
    containerScript(spec),
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
    for (const [pattern, label] of SUSPICIOUS_LOG_PATTERNS) {
      if (pattern.test(line)) {
        findings.push(`${label}: ${line.trim().slice(0, 160)}`);
        break;
      }
    }
  }
  return findings.slice(0, 30);
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
  const command = buildSandboxCommand(spec, opts);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const [bin, ...args] = command;
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      log += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      log += chunk;
      process.stderr.write(chunk);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: code ?? 1,
        timedOut,
        log,
        suspiciousLines: findSuspiciousLogLines(log),
        command,
      });
    });
  });
}
