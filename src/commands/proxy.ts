import { spawn } from "node:child_process";
import { existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { startProxy, type ProxyEvent } from "../proxy.js";
import {
  clearProxyState,
  liveProxyState,
  proxyLogFile,
  proxyStateDir,
  proxyStateFile,
  writeProxyState,
} from "../proxy-daemon.js";
import { ProxyVerdictCache } from "../proxy-cache.js";
import { readProxyUplinks } from "../proxy-uplinks.js";
import { ensureTlsMaterial, loadTlsMaterial, removeTlsMaterial } from "../proxy-tls.js";
import { dim, green, red, yellow } from "../report.js";

const DEFAULT_PORT = 4873;
const NPMRC_BEGIN = "# >>> targate proxy (managed — `targate proxy teardown` removes this)";
const NPMRC_END = "# <<< targate proxy";

export interface ProxyOptions {
  port?: string;
  upstream?: string;
  host?: string;
  /** Run the server in this process instead of spawning a detached daemon. */
  foreground?: boolean;
  /** Serve HTTPS with a locally generated CA/cert. */
  tls?: boolean;
}

function resolvePort(raw: string | undefined): number | null {
  if (raw === undefined) return DEFAULT_PORT;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 && parsed < 65536 ? parsed : null;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function printEvent(event: ProxyEvent): void {
  switch (event.kind) {
    case "listening":
      console.log(green(`targate proxy listening on ${event.url}`));
      console.log(dim(`  upstream: ${event.upstream}`));
      break;
    case "decision": {
      const tag =
        event.decision === "allow" || event.decision === "allow_with_warnings"
          ? green("ALLOW")
          : red("BLOCK");
      const detail = event.cached ? dim(" (cached)") : dim(` (${event.ms}ms)`);
      console.log(`${tag} ${event.name}@${event.version}${detail}  ${dim(event.reason ?? "")}`);
      break;
    }
    case "error":
      console.error(yellow(`proxy: ${event.detail}`));
      break;
    case "packument":
      break;
  }
}

/** Reconstruct this CLI's own invocation so the daemon child re-runs targate. */
function selfInvocation(extraArgs: string[]): { command: string; args: string[] } {
  const entry = process.argv[1];
  const base = [...process.execArgv, ...(entry ? [entry] : [])];
  return { command: process.execPath, args: [...base, "proxy", "start", "--foreground", ...extraArgs] };
}

async function runForeground(port: number, options: ProxyOptions): Promise<number> {
  const tls = options.tls ? (loadTlsMaterial() ?? undefined) : undefined;
  if (options.tls && !tls) {
    console.error(red("TLS requested but no certificate material found — run `targate proxy setup` first."));
    return 1;
  }
  // The analysis pipeline resolves the upstream registry from process.cwd()'s
  // .npmrc. The invoking project's .npmrc now points at THIS proxy, so run the
  // daemon from a neutral directory to avoid the proxy fetching from itself.
  mkdirSync(proxyStateDir(), { recursive: true });
  process.chdir(proxyStateDir());
  const handle = await startProxy({
    port,
    host: options.host,
    upstream: options.upstream,
    uplinks: readProxyUplinks(),
    tls,
    cwd: proxyStateDir(),
    onEvent: printEvent,
  });
  const address = handle.server.address();
  const boundPort = typeof address === "object" && address ? address.port : port;
  writeProxyState({
    pid: process.pid,
    port: boundPort,
    host: options.host ?? "127.0.0.1",
    upstream: options.upstream ?? "https://registry.npmjs.org",
    scheme: tls ? "https" : "http",
    startedAt: Date.now(),
  });
  return await new Promise<number>((resolve) => {
    const shutdown = (): void => {
      clearProxyState();
      handle.server.close(() => resolve(0));
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}

function daemonExtraArgs(port: number, options: ProxyOptions): string[] {
  const extra: string[] = ["--port", String(port)];
  if (options.upstream) extra.push("--upstream", options.upstream);
  if (options.host) extra.push("--host", options.host);
  if (options.tls) extra.push("--tls");
  return extra;
}

async function startDaemon(port: number, options: ProxyOptions): Promise<number> {
  const running = liveProxyState();
  if (running) {
    console.log(yellow(`targate proxy already running (pid ${running.pid}) on ${running.scheme}://${running.host}:${running.port}`));
    return 0;
  }

  const { command, args } = selfInvocation(daemonExtraArgs(port, options));
  mkdirSync(proxyStateDir(), { recursive: true });
  const log = openSync(proxyLogFile(), "a");
  const child = spawn(command, args, { detached: true, stdio: ["ignore", log, log] });
  child.unref();

  for (let i = 0; i < 50; i++) {
    const state = liveProxyState();
    if (state) {
      const url = `${state.scheme}://${state.host}:${state.port}`;
      console.log(green(`targate proxy started (pid ${state.pid}) on ${url}`));
      console.log(dim(`  upstream: ${state.upstream}`));
      console.log(dim(`  logs: ${proxyLogFile()}`));
      console.log(dim(`  point your client at it:  npm config set registry ${url}`));
      console.log(dim("  (npm ≥ 9 keeps replace-registry-host=npmjs by default — do not set it to 'never')"));
      console.log(dim("  stop with:  targate proxy stop"));
      return 0;
    }
    await sleep(100);
  }
  console.error(red(`targate proxy failed to start within 5s — see ${proxyLogFile()}`));
  return 1;
}

async function stopDaemon(): Promise<number> {
  const state = liveProxyState();
  if (!state) {
    console.log(dim("targate proxy is not running."));
    return 0;
  }
  try {
    process.kill(state.pid, "SIGTERM");
  } catch {
    // already gone
  }
  for (let i = 0; i < 30; i++) {
    if (!liveProxyState()) {
      clearProxyState();
      console.log(green(`targate proxy stopped (was pid ${state.pid}).`));
      return 0;
    }
    await sleep(100);
  }
  console.error(yellow(`targate proxy (pid ${state.pid}) did not stop within 3s; leaving state file ${proxyStateFile()}`));
  return 1;
}

function statusDaemon(): number {
  const state = liveProxyState();
  if (!state) {
    console.log(dim("targate proxy: not running."));
    return 0;
  }
  const uptimeS = state.startedAt ? Math.round((Date.now() - state.startedAt) / 1000) : undefined;
  console.log(green(`targate proxy: running`));
  console.log(`  pid:      ${state.pid}`);
  console.log(`  address:  ${state.scheme}://${state.host}:${state.port}`);
  console.log(`  upstream: ${state.upstream}`);
  if (uptimeS !== undefined) console.log(`  uptime:   ${uptimeS}s`);
  console.log(`  verdicts: ${new ProxyVerdictCache().size} cached`);
  console.log(dim(`  logs:     ${proxyLogFile()}`));
  return 0;
}

/** Insert or replace the managed block in the project .npmrc. */
function writeNpmrcBlock(cwd: string, registryUrl: string): string {
  const file = path.join(cwd, ".npmrc");
  const block = [NPMRC_BEGIN, `registry=${registryUrl}`, "replace-registry-host=npmjs", NPMRC_END, ""].join("\n");
  const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  const stripped = removeNpmrcBlock(existing);
  writeFileSync(file, stripped ? `${stripped.replace(/\n*$/, "\n")}${block}` : block);
  return file;
}

/** Remove the managed block, returning the remaining .npmrc text. Exported for tests. */
export function removeNpmrcBlock(content: string): string {
  const begin = content.indexOf(NPMRC_BEGIN);
  if (begin === -1) return content;
  const endMarker = content.indexOf(NPMRC_END, begin);
  const end = endMarker === -1 ? content.length : endMarker + NPMRC_END.length;
  return `${content.slice(0, begin)}${content.slice(end)}`.replace(/\n{3,}/g, "\n\n");
}

function caTrustHint(caPath: string, host: string, port: number): void {
  console.log(dim("  Trust the CA once so the client accepts the proxy's TLS:"));
  console.log(dim(`    • CI / one shell:  export NODE_EXTRA_CA_CERTS=${caPath}`));
  if (process.platform === "darwin") {
    console.log(dim(`    • macOS keychain:  security add-trusted-cert -k ~/Library/Keychains/login.keychain-db ${caPath}`));
  } else if (process.platform === "win32") {
    console.log(dim(`    • Windows:         certutil -addstore -user Root ${caPath}`));
  } else {
    console.log(dim(`    • Linux (Debian):  sudo cp ${caPath} /usr/local/share/ca-certificates/targate-ca.crt && sudo update-ca-certificates`));
  }
  console.log(dim(`    (registry: https://${host}:${port})`));
}

async function setupProxy(port: number, options: ProxyOptions): Promise<number> {
  const host = options.host ?? "127.0.0.1";
  const cwd = process.cwd();
  console.log(dim("Generating local CA + certificate…"));
  let caPath: string;
  try {
    ({ caPath } = ensureTlsMaterial(host));
  } catch (error) {
    console.error(red(`Could not generate TLS material (is openssl installed?): ${error instanceof Error ? error.message : String(error)}`));
    return 1;
  }

  const code = await startDaemon(port, { ...options, tls: true });
  if (code !== 0) return code;

  const registryUrl = `https://${host}:${port}`;
  const npmrc = writeNpmrcBlock(cwd, registryUrl);
  console.log(green(`Configured ${npmrc} to use the proxy.`));
  console.log(yellow("  Note: this .npmrc points at a local proxy — add it to .gitignore; do not commit it."));
  caTrustHint(caPath, host, port);
  return 0;
}

async function teardownProxy(): Promise<number> {
  await stopDaemon();
  const file = path.join(process.cwd(), ".npmrc");
  if (existsSync(file)) {
    const cleaned = removeNpmrcBlock(readFileSync(file, "utf8"));
    writeFileSync(file, cleaned);
    console.log(green(`Removed the targate block from ${file}.`));
  }
  removeTlsMaterial();
  console.log(green("Removed local TLS material."));
  return 0;
}

function certCommand(action: string | undefined): number {
  const { caPath } = ensureTlsMaterial();
  switch (action) {
    case undefined:
    case "path":
      console.log(caPath);
      return 0;
    case "export":
      console.log(`export NODE_EXTRA_CA_CERTS=${caPath}`);
      return 0;
    default:
      console.error(red(`Unknown cert action: ${action}. Use: targate proxy cert [path|export]`));
      return 1;
  }
}

const USAGE =
  "Usage: targate proxy <start|stop|status|ensure|setup|teardown|cert> [--port <n>] [--upstream <url>] [--host <addr>] [--tls]";

/** `targate proxy <subcommand> [action]` — lifecycle + setup for the registry proxy. */
export async function proxyCommand(positionals: string[], options: ProxyOptions): Promise<number> {
  const [subcommand, action] = positionals;
  const port = resolvePort(options.port);
  if (port === null) {
    console.error(red(`Invalid --port: ${options.port}. Expected an integer 1–65535.`));
    return 1;
  }

  switch (subcommand) {
    case "start":
      return options.foreground ? runForeground(port, options) : startDaemon(port, options);
    case "ensure":
      return liveProxyState() ? statusDaemon() : startDaemon(port, options);
    case "stop":
      return stopDaemon();
    case "status":
      return statusDaemon();
    case "setup":
      return setupProxy(port, options);
    case "teardown":
      return teardownProxy();
    case "cert":
      return certCommand(action);
    default:
      console.error(red(USAGE));
      if (subcommand) console.error(red(`Unknown proxy subcommand: ${subcommand}`));
      return 1;
  }
}
