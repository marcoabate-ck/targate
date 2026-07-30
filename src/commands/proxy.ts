import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { startProxy, type ProxyEvent } from "../proxy.js";
import {
  clearProxyState,
  liveProxyState,
  proxyLogFile,
  proxyStateDir,
  proxyStateFile,
  writeProxyState,
  type ProxyState,
} from "../proxy-daemon.js";
import { authHeaderForUrl, DEFAULT_REGISTRY, loadNpmrc } from "../npmrc.js";
import { ProxyVerdictCache } from "../proxy-cache.js";
import { readProxyUplinks, removeProxyUplinks, writeProxyUplinks, type ProxyUplink } from "../proxy-uplinks.js";
import {
  caInstallCommand,
  caUninstallCommand,
  ensureTlsMaterial,
  loadTlsMaterial,
  removeTlsMaterial,
  tlsMaterialPaths,
  type TrustCommand,
} from "../proxy-tls.js";
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
  /** Print what would happen without changing anything (cert install/uninstall). */
  dryRun?: boolean;
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
    case "pending":
      console.log(yellow(`HOLD  ${event.name}@${event.version} needs approval — \`targate proxy approve ${event.name}@${event.version}\` (or deny)`));
      break;
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
  const controlToken = randomUUID();
  const handle = await startProxy({
    port,
    host: options.host,
    upstream: options.upstream,
    uplinks: readProxyUplinks(),
    tls,
    controlToken,
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
    controlToken,
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
function writeNpmrcBlock(cwd: string, registryUrl: string, scopes: string[] = []): string {
  const file = path.join(cwd, ".npmrc");
  const lines = [NPMRC_BEGIN, `registry=${registryUrl}`, "replace-registry-host=npmjs"];
  // Route each migrated private scope through the proxy too (the proxy holds the
  // real upstream + credential, so no per-scope token is needed here).
  for (const scope of scopes) lines.push(`${scope}:registry=${registryUrl}`);
  lines.push(NPMRC_END, "");
  const block = lines.join("\n");
  const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  const stripped = removeNpmrcBlock(existing);
  writeFileSync(file, stripped ? `${stripped.replace(/\n*$/, "\n")}${block}` : block);
  return file;
}

/**
 * Read the project .npmrc and turn its private per-scope registries into proxy
 * uplinks: `@acme:registry=https://real` becomes an uplink to that registry with
 * the scope's credential captured pass-forward. npmjs, the proxy itself, and
 * loopback/local hosts are skipped.
 */
export function migrateScopes(cwd: string, proxyOrigin: string): ProxyUplink[] {
  const config = loadNpmrc(cwd);
  const uplinks: ProxyUplink[] = [];
  for (const [key, value] of Object.entries(config.entries)) {
    if (!key.startsWith("@") || !key.endsWith(":registry")) continue;
    const upstream = value.replace(/\/+$/, "");
    let host = "";
    try {
      host = new URL(upstream).hostname;
    } catch {
      continue;
    }
    const isNpmjs = upstream === DEFAULT_REGISTRY;
    const isLocal = host === "localhost" || host === "127.0.0.1" || host === "::1" || proxyOrigin.includes(host);
    if (isNpmjs || isLocal) continue;
    const scope = key.slice(0, -":registry".length);
    const auth = authHeaderForUrl(`${upstream}/`, config);
    uplinks.push({ scope, upstream, ...(auth ? { auth } : {}) });
  }
  return uplinks;
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
  console.log(dim(`    • system trust:    targate proxy cert install`));
  console.log(dim(`    • CI / one shell:  export NODE_EXTRA_CA_CERTS=${caPath}`));
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

  const registryUrl = `https://${host}:${port}`;
  // Capture private per-scope registries + credentials BEFORE the daemon starts
  // (it reads the uplinks at boot) and before we rewrite the .npmrc.
  const uplinks = migrateScopes(cwd, registryUrl);
  writeProxyUplinks(uplinks);

  const code = await startDaemon(port, { ...options, tls: true });
  if (code !== 0) return code;

  const npmrc = writeNpmrcBlock(cwd, registryUrl, uplinks.map((u) => u.scope));
  console.log(green(`Configured ${npmrc} to use the proxy.`));
  if (uplinks.length > 0) {
    console.log(green(`Routed ${uplinks.length} private scope(s) through the proxy: ${uplinks.map((u) => u.scope).join(", ")}`));
    console.log(dim("  their credentials were copied into ~/.targate/proxy-uplinks.json (0600) — the proxy authenticates upstream."));
  }
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
  removeProxyUplinks();
  removeTlsMaterial();
  console.log(green("Removed local TLS material and uplinks."));
  return 0;
}

function runTrust(plan: TrustCommand, verb: string, dryRun: boolean): number {
  if (dryRun) {
    console.log(dim(`would run: ${plan.manual}`));
    return 0;
  }
  if (plan.sudo) {
    // Needs root and is distro-specific — print it for the user to run.
    console.log(yellow(`This step needs root. Run:\n  ${plan.manual}`));
    return 0;
  }
  try {
    execFileSync(plan.command, plan.args, { stdio: ["ignore", "ignore", "inherit"] });
    console.log(green(`CA ${verb} in the system trust store.`));
    return 0;
  } catch (error) {
    console.error(red(`Could not ${verb} the CA automatically (${error instanceof Error ? error.message : String(error)}). Run manually:`));
    console.error(`  ${plan.manual}`);
    return 1;
  }
}

function certCommand(action: string | undefined, options: ProxyOptions): number {
  const { caPath } = ensureTlsMaterial();
  switch (action) {
    case undefined:
    case "path":
      console.log(caPath);
      return 0;
    case "export":
      console.log(`export NODE_EXTRA_CA_CERTS=${caPath}`);
      return 0;
    case "install":
      return runTrust(caInstallCommand(caPath), "trusted", options.dryRun ?? false);
    case "uninstall":
      return runTrust(caUninstallCommand(caPath), "untrusted", options.dryRun ?? false);
    default:
      console.error(red(`Unknown cert action: ${action}. Use: targate proxy cert [path|export|install|uninstall]`));
      return 1;
  }
}

/** Call the running daemon's local control API. */
function controlRequest(
  state: ProxyState,
  method: "GET" | "POST",
  pathname: string,
  body?: unknown,
): Promise<{ status: number; json: unknown }> {
  return new Promise((resolve, reject) => {
    const mod = state.scheme === "https" ? https : http;
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = mod.request(
      {
        host: state.host,
        port: state.port,
        method,
        path: pathname,
        headers: {
          "x-targate-control": state.controlToken ?? "",
          ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}),
        },
        // loopback to our own daemon — the control token, not TLS identity, authenticates
        ...(state.scheme === "https" ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") });
          } catch {
            resolve({ status: res.statusCode ?? 0, json: {} });
          }
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Split "name@version" (handles scoped @scope/name@version). Exported for tests. */
export function parseSpec(spec: string | undefined): { name: string; version: string } | null {
  if (!spec) return null;
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null; // need a version, and a leading @ alone is not enough
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

async function approvalsCommand(): Promise<number> {
  const state = liveProxyState();
  if (!state) {
    console.log(dim("targate proxy is not running."));
    return 0;
  }
  const { status, json } = await controlRequest(state, "GET", "/-/targate/pending");
  if (status !== 200) {
    console.error(red(`control API error (${status})`));
    return 1;
  }
  const pending = (json as { pending?: Array<{ name: string; version: string }> }).pending ?? [];
  if (pending.length === 0) {
    console.log(dim("No packages are awaiting approval."));
    return 0;
  }
  console.log(`${pending.length} awaiting approval:`);
  for (const p of pending) console.log(`  ${p.name}@${p.version}`);
  console.log(dim("Approve with `targate proxy approve <pkg>@<version>` (or deny)."));
  return 0;
}

async function decideCommand(spec: string | undefined, decision: "approve" | "deny"): Promise<number> {
  const parsed = parseSpec(spec);
  if (!parsed) {
    console.error(red(`Usage: targate proxy ${decision} <package>@<version>`));
    return 1;
  }
  const state = liveProxyState();
  if (!state) {
    console.log(dim("targate proxy is not running."));
    return 1;
  }
  const { status, json } = await controlRequest(state, "POST", "/-/targate/decide", { ...parsed, decision });
  if (status !== 200) {
    console.error(red(`control API error (${status})`));
    return 1;
  }
  const resolved = (json as { resolved?: number }).resolved ?? 0;
  if (resolved === 0) {
    console.log(yellow(`No held request matched ${parsed.name}@${parsed.version} (already resolved or never pending).`));
    return 0;
  }
  console.log(green(`${decision === "approve" ? "Approved" : "Denied"} ${parsed.name}@${parsed.version} (${resolved} request(s) released).`));
  return 0;
}

const USAGE =
  "Usage: targate proxy <start|stop|status|ensure|setup|teardown|cert|approvals|approve|deny> [--port <n>] [--upstream <url>] [--host <addr>] [--tls]";

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
      return certCommand(action, options);
    case "approvals":
      return approvalsCommand();
    case "approve":
      return decideCommand(action, "approve");
    case "deny":
      return decideCommand(action, "deny");
    default:
      console.error(red(USAGE));
      if (subcommand) console.error(red(`Unknown proxy subcommand: ${subcommand}`));
      return 1;
  }
}
