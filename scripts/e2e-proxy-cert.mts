/**
 * End-to-end verification of the registry proxy's TLS + system-trust path, for
 * the CI matrix (macOS / Windows / Linux). NOT part of the unit suite — it
 * starts a daemon, touches the system trust store, and needs network.
 *
 * Flow: setup (local CA + HTTPS daemon + .npmrc) → trust the CA the way that OS
 * expects → `npm install` over HTTPS WITHOUT NODE_EXTRA_CA_CERTS (proving the CA
 * is really trusted) → untrust → teardown.
 *
 * Run:  node --import tsx scripts/e2e-proxy-cert.mts
 * Exit: 0 on success, non-zero on the first failed assertion.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import path from "node:path";

const REPO = process.cwd();
const CLI = ["--import", "tsx", path.join(REPO, "src", "cli.ts")];
const PORT = 4873;
const HOST = "127.0.0.1";

function cli(args: string[], opts: { cwd?: string } = {}): { status: number; out: string } {
  const r = spawnSync(process.execPath, [...CLI, "proxy", ...args], {
    cwd: opts.cwd ?? REPO,
    encoding: "utf8",
    env: process.env,
  });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  // best-effort cleanup
  cli(["cert", "uninstall"]);
  cli(["teardown"], { cwd: project });
  process.exit(1);
}

const project = mkdtempSync(path.join(tmpdir(), "targate-cert-e2e-"));
writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "e2e", version: "1.0.0", dependencies: { "is-odd": "3.0.1" } }));

console.log(`platform=${platform()} project=${project}`);

// 1) setup: generate CA, start HTTPS daemon, write .npmrc
const setup = cli(["setup", "--port", String(PORT)], { cwd: project });
if (setup.status !== 0) fail(`setup exited ${setup.status}: ${setup.out}`);

// 2) trust the CA. macOS/Windows: `cert install` executes; Linux: it prints the
//    root command, which this script runs (the CI runner has sudo).
if (platform() === "linux") {
  const caPath = cli(["cert", "path"]).out.trim().split("\n").pop() ?? "";
  if (!existsSync(caPath)) fail(`cert path did not resolve: ${caPath}`);
  const r = spawnSync("sh", ["-c", `sudo cp ${caPath} /usr/local/share/ca-certificates/targate-e2e.crt && sudo update-ca-certificates`], { encoding: "utf8" });
  if ((r.status ?? 1) !== 0) fail(`linux trust failed: ${r.stdout}${r.stderr}`);
} else {
  const inst = cli(["cert", "install"]);
  if (inst.status !== 0) fail(`cert install exited ${inst.status}: ${inst.out}`);
}

// 3) install over HTTPS WITHOUT NODE_EXTRA_CA_CERTS — success proves the CA is trusted
const cache = path.join(project, ".npmcache");
const env = { ...process.env };
delete env.NODE_EXTRA_CA_CERTS;
const install = spawnSync("npm", ["install", "--no-audit", "--no-fund", "--cache", cache, "--registry", `https://${HOST}:${PORT}`], {
  cwd: project,
  encoding: "utf8",
  env,
});
const installed = existsSync(path.join(project, "node_modules", "is-odd", "package.json"));
if ((install.status ?? 1) !== 0 || !installed) {
  fail(`npm install over HTTPS failed (status ${install.status}, installed=${installed}): ${install.stdout}${install.stderr}`);
}
console.log("OK: HTTPS install succeeded with the system-trusted CA (no NODE_EXTRA_CA_CERTS)");

// 4) untrust + teardown
if (platform() === "linux") {
  spawnSync("sh", ["-c", "sudo rm -f /usr/local/share/ca-certificates/targate-e2e.crt && sudo update-ca-certificates --fresh"], { encoding: "utf8" });
} else {
  cli(["cert", "uninstall"]);
}
cli(["teardown"], { cwd: project });
try {
  rmSync(project, { recursive: true, force: true });
} catch {
  // best-effort
}
console.log("PASS: proxy TLS + system-trust e2e");
