import { spawn } from "node:child_process";

const DEFAULT_IMAGE = "node:20-alpine";
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
 * Shell script executed INSIDE the disposable container. The package spec
 * is passed via the BYE_SPEC environment variable (NOT interpolated into the
 * script text), so a hostile spec string cannot break out of the quoting and
 * inject shell commands. The install runs with --foreground-scripts so every
 * lifecycle script's output lands in the log, then we snapshot what the
 * install left on the filesystem outside its own project directory.
 */
const CONTAINER_SCRIPT = [
  "set -e",
  "mkdir -p /sandbox/project && cd /sandbox/project",
  "npm init -y > /dev/null 2>&1",
  "find / -path /proc -prune -o -newer /sandbox -type f -print 2>/dev/null > /tmp/before.txt || true",
  'echo "--- bye sandbox: installing $BYE_SPEC ---"',
  'npm install "$BYE_SPEC" --foreground-scripts --loglevel info; STATUS=$?',
  "echo '--- bye sandbox: filesystem writes outside the project ---'",
  "find /root /home /etc /usr/local -type f -newer /tmp/before.txt 2>/dev/null | grep -v -E '^/root/.npm|^/sandbox' || echo '(none)'",
  "exit $STATUS",
].join("\n");

/**
 * Build the docker invocation for a quarantined trial install (phase 4).
 * Isolation properties actually enforced:
 * - disposable container (--rm), nothing mounted from the host;
 * - no host environment variables, SSH agent, npm/GitHub tokens (docker
 *   passes none of them unless explicitly asked to — and we don't);
 * - temporary container filesystem only, host project never exposed;
 * - CPU/memory caps, all capabilities dropped, no privilege escalation;
 * - the package spec is passed as an env var, never interpolated into the
 *   shell script.
 *
 * NETWORK: by default the container uses docker's bridge network with FULL
 * egress — npm needs it to fetch packages, and so a malicious install script
 * can also reach the internet. This is an observation sandbox, not a network
 * jail. Pass network: "none" for a fully offline trial. There is no per-host
 * network allowlist.
 */
export function buildSandboxCommand(spec: string, opts: SandboxOptions = {}): string[] {
  const network = opts.network ?? "open";
  return [
    "docker",
    "run",
    "--rm",
    "--pull=missing",
    "--security-opt=no-new-privileges",
    "--cap-drop=ALL",
    "--memory=1g",
    "--cpus=1",
    ...(network === "none" ? ["--network=none"] : []),
    "--env",
    "npm_config_fund=false",
    "--env",
    "npm_config_audit=false",
    // Spec passed as data via env, not interpolated into the shell script.
    "--env",
    `BYE_SPEC=${spec}`,
    opts.image ?? DEFAULT_IMAGE,
    "sh",
    "-c",
    CONTAINER_SCRIPT,
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
