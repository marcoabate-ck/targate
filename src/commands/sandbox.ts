import { printJson } from "../json-output.js";
import {
  isDockerAvailable,
  runSandbox,
  type NetworkActivity,
  type SandboxNetwork,
} from "../sandbox.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";

export interface SandboxCommandOptions {
  spec: string;
  image?: string;
  timeoutMs?: number;
  network?: SandboxNetwork;
  /** Observe DNS + proxy traffic during the install (default: true). */
  capture?: boolean;
  json: boolean;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function renderNetwork(network: NetworkActivity): void {
  console.log(bold("\nNetwork activity"));
  if (!network.captureActive) {
    console.log(yellow("  ⚠ network capture failed to start — see [targate-net] error lines above (install was unaffected)"));
    for (const e of network.errors) console.log(dim(`    ${e}`));
    return;
  }
  if (
    network.dnsQueries.length === 0 &&
    network.connections.length === 0 &&
    network.httpRequests.length === 0
  ) {
    console.log(dim("  (no DNS or proxied traffic observed during the install)"));
  }
  for (const c of network.connections) {
    const bytes = `sent ${fmtBytes(c.sentBytes)} / recv ${fmtBytes(c.recvBytes)}`;
    const line = `  ${c.host}:${c.port} ×${c.count}  ${bytes}`;
    console.log(c.expected ? dim(line) : red(`! ${line.trim()}`));
  }
  for (const r of network.httpRequests) {
    const line = `  ${r.method} ${r.url}`;
    console.log(r.expected ? dim(line) : red(`! ${line.trim()}`));
  }
  for (const q of network.dnsQueries) {
    console.log(dim(`  dns ${q.name} ${q.type}${q.count > 1 ? ` ×${q.count}` : ""}`));
  }
  console.log(
    dim(
      "  Observation only: traffic to hardcoded IPs or ignoring the proxy is NOT captured; a hostile script can disable it.",
    ),
  );
}

/** Phase 4 — `targate sandbox <pkg>`: trial install in a disposable container. */
export async function sandboxCommand(opts: SandboxCommandOptions): Promise<number> {
  if (!(await isDockerAvailable())) {
    console.error(
      red("Docker is required for sandboxed installs but was not found (or the daemon is not running)."),
    );
    console.error(dim("Install Docker Desktop / colima, or use `targate <pkg> --dry-run` for static analysis only."));
    return 1;
  }

  const network = opts.network ?? "open";
  const capture = (opts.capture ?? true) && network !== "none";
  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  note(bold(`\nSandboxed trial install of ${opts.spec}`));
  note(
    dim(
      "Disposable container: no host env vars, no SSH agent, no npm/GitHub tokens,\n" +
        "no host filesystem, capabilities dropped, 1 CPU / 1 GB memory cap.\n" +
        (network === "none"
          ? "Network: DISABLED (--network none) — offline trial.\n"
          : capture
            ? "Network: full egress, OBSERVED — DNS queries and HTTP(S) proxy traffic are logged.\n" +
              "Traffic to hardcoded IPs or ignoring the proxy is NOT captured.\n"
            : "Network: FULL egress (npm needs it; a malicious script can use it too).\n"),
    ),
  );

  const result = await runSandbox(opts.spec, {
    image: opts.image,
    timeoutMs: opts.timeoutMs,
    network,
    capture,
    echo: opts.json ? "stderr" : "stdout",
  });

  if (opts.json) {
    printJson("sandbox", {
      spec: opts.spec,
      image: opts.image ?? null,
      networkMode: network,
      captureRequested: capture,
      exitCode: result.timedOut ? 2 : result.suspiciousLines.length > 0 ? 2 : result.exitCode === 0 ? 0 : 1,
      timedOut: result.timedOut,
      suspicious: result.suspiciousLines,
      network: result.network,
      log: result.log,
    });
    return result.timedOut ? 2 : result.suspiciousLines.length > 0 ? 2 : result.exitCode === 0 ? 0 : 1;
  }

  console.log("");
  if (result.timedOut) {
    console.log(red(bold("Sandbox timed out — the install did not finish in time.")));
    console.log(yellow("A hanging install can itself be a signal (waiting on a network hole-punch, mining, …)."));
    return 2;
  }

  if (result.exitCode !== 0) {
    console.log(yellow(bold(`Sandbox install exited with code ${result.exitCode}.`)));
  } else {
    console.log(green(bold("Sandbox install completed.")));
  }

  if (result.network) renderNetwork(result.network);

  if (result.suspiciousLines.length > 0) {
    console.log(red(bold("\nSuspicious lines in the script execution log:")));
    for (const line of result.suspiciousLines) console.log(red(`  ! ${line}`));
    console.log(
      yellow("\nReview the full log above before deciding to install this package on your machine."),
    );
    return 2;
  }

  console.log(cyan("\nNo suspicious activity spotted in the script log."));
  console.log(
    dim("Note: the sandbox observes install-time behavior only — runtime behavior still needs code review."),
  );
  return result.exitCode === 0 ? 0 : 1;
}
