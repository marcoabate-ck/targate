/**
 * End-to-end verification of the registry proxy's TLS trust path, for the CI
 * matrix (macOS / Windows / Linux). NOT part of the unit suite — it starts a
 * daemon, touches the system trust store, and needs network.
 *
 * Node does NOT read the OS trust store by default (no `--use-system-ca` before
 * Node 22.15), so the mechanism that actually makes npm/pnpm/yarn accept the
 * proxy is `NODE_EXTRA_CA_CERTS`. This test therefore:
 *   1. hard-asserts an HTTPS install works with NODE_EXTRA_CA_CERTS (the real,
 *      cross-platform trust path for the package managers), and
 *   2. best-effort checks that `cert install` places the CA in the OS store
 *      (for browsers / curl / Node ≥ 22.15 `--use-system-ca`), then removes it.
 *
 * Run:  node --import tsx scripts/e2e-proxy-cert.mts
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir, platform } from "node:os";
import path from "node:path";

const REPO = process.cwd();
// Absolute tsx path so the CLI (and the daemon it re-spawns) load it from any cwd.
const TSX = createRequire(import.meta.url).resolve("tsx");
const CLI = ["--import", TSX, path.join(REPO, "src", "cli.ts")];
const PORT = 4873;
const HOST = "127.0.0.1";

function cli(args: string[], cwd = REPO): { status: number; out: string } {
  const r = spawnSync(process.execPath, [...CLI, "proxy", ...args], { cwd, encoding: "utf8", env: process.env });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

const project = mkdtempSync(path.join(tmpdir(), "targate-cert-e2e-"));
writeFileSync(
  path.join(project, "package.json"),
  JSON.stringify({ name: "e2e", version: "1.0.0", dependencies: { "is-odd": "3.0.1" } }),
);
console.log(`platform=${platform()} project=${project}`);

function cleanup(): void {
  cli(["cert", "uninstall"]);
  cli(["teardown"], project);
  try {
    rmSync(project, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}
function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  cleanup();
  process.exit(1);
}

// setup: local CA + HTTPS daemon + project .npmrc
const setup = cli(["setup", "--port", String(PORT)], project);
if (setup.status !== 0) fail(`setup exited ${setup.status}: ${setup.out}`);
const caPath = cli(["cert", "path"]).out.trim().split(/\r?\n/).pop() ?? "";
if (!existsSync(caPath)) fail(`cert path did not resolve: ${caPath}`);

// (1) HARD: NODE_EXTRA_CA_CERTS makes an HTTPS install work — the real trust path.
const install = spawnSync(
  "npm",
  ["install", "--no-audit", "--no-fund", "--cache", path.join(project, ".npmcache"), "--registry", `https://${HOST}:${PORT}`],
  { cwd: project, encoding: "utf8", env: { ...process.env, NODE_EXTRA_CA_CERTS: caPath } },
);
const installed = existsSync(path.join(project, "node_modules", "is-odd", "package.json"));
if ((install.status ?? 1) !== 0 || !installed) {
  fail(`HTTPS install with NODE_EXTRA_CA_CERTS failed (status ${install.status}, installed=${installed}): ${install.stdout}${install.stderr}`);
}
console.log("OK: HTTPS install works with NODE_EXTRA_CA_CERTS (the package-manager trust path)");

// (2) BEST-EFFORT: cert install places the CA in the OS store, uninstall removes
//     it. Opt-in (TARGATE_TEST_SYSTEM_TRUST=1) because on macOS/Windows it
//     touches the real trust store and can prompt for keychain access.
if (process.env.TARGATE_TEST_SYSTEM_TRUST !== "1") {
  console.log("INFO: skipping system-store install (set TARGATE_TEST_SYSTEM_TRUST=1 to include it).");
} else if (platform() === "linux") {
  console.log("INFO: on Linux `cert install` prints a sudo step; skipping the store check here.");
} else {
  const inst = cli(["cert", "install"]);
  console.log(`cert install → status ${inst.status}`);
  const present = spawnSync(
    platform() === "darwin" ? "security" : "certutil",
    platform() === "darwin" ? ["find-certificate", "-c", "targate local CA"] : ["-user", "-store", "Root", "targate local CA"],
    { encoding: "utf8" },
  );
  console.log(`store check after install: ${(present.status ?? 1) === 0 ? "CA present ✓" : "CA NOT found (see note)"}`);
  cli(["cert", "uninstall"]);
}

cli(["teardown"], project);
try {
  rmSync(project, { recursive: true, force: true });
} catch {
  /* best-effort */
}
console.log("PASS: proxy TLS trust e2e (NODE_EXTRA_CA_CERTS verified; system-store install best-effort)");
