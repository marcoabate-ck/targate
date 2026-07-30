/**
 * End-to-end verification of the registry proxy against a REAL private registry
 * — GitHub Packages (npm.pkg.github.com), a non-loopback HTTPS host, so no SSRF
 * exception is needed. Proves the private-scope path (uplink routing, credential
 * relay, dist.tarball rewrite, metadata override, and quarantine of the private
 * tarball) end to end.
 *
 * You run this locally; it is not part of CI (needs your token + a package you
 * can read).
 *
 * Prerequisites:
 *   - A GitHub token with `read:packages`  →  export GITHUB_TOKEN=ghp_...
 *   - A scoped package published to GitHub Packages that the token can read:
 *       export GH_PKG_SPEC=@your-scope/your-package@1.2.3
 *
 * Run:  node --import tsx scripts/e2e-proxy-github-packages.mts
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

const REPO = process.cwd();
// Absolute tsx path so the daemon (spawned from a temp project) can load it.
const TSX = createRequire(import.meta.url).resolve("tsx");
const CLI = ["--import", TSX, path.join(REPO, "src", "cli.ts")];
const PORT = 4874;

const token = process.env.GITHUB_TOKEN;
const spec = process.env.GH_PKG_SPEC;
if (!token || !spec) {
  console.error("Set GITHUB_TOKEN (read:packages) and GH_PKG_SPEC (@scope/pkg@version). See the header of this file.");
  process.exit(2);
}
const at = spec.lastIndexOf("@");
if (at <= 0) {
  console.error(`GH_PKG_SPEC must be @scope/name@version, got: ${spec}`);
  process.exit(2);
}
const name = spec.slice(0, at);
const version = spec.slice(at + 1);
const scope = name.slice(0, name.indexOf("/"));

function cli(args: string[], cwd = REPO): { status: number; out: string } {
  const r = spawnSync(process.execPath, [...CLI, "proxy", ...args], { cwd, encoding: "utf8", env: process.env });
  return { status: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

const project = mkdtempSync(path.join(tmpdir(), "targate-ghpkg-e2e-"));
writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "e2e", version: "1.0.0", dependencies: { [name]: version } }));
// The ORIGINAL .npmrc a GitHub Packages consumer would have — setup migrates it.
writeFileSync(
  path.join(project, ".npmrc"),
  [`${scope}:registry=https://npm.pkg.github.com`, `//npm.pkg.github.com/:_authToken=${token}`, ""].join("\n"),
);

console.log(`scope=${scope} spec=${spec} project=${project}`);

const setup = cli(["setup", "--port", String(PORT)], project);
console.log(setup.out.trim());
if (setup.status !== 0) {
  console.error("setup failed");
  process.exit(1);
}

const install = spawnSync("npm", ["install", "--no-audit", "--no-fund", "--cache", path.join(project, ".npmcache"), "--loglevel", "error"], {
  cwd: project,
  encoding: "utf8",
  env: process.env,
});
const installed = existsSync(path.join(project, "node_modules", ...name.split("/"), "package.json"));

// Confirm the private package actually went THROUGH the proxy (a decision was logged).
const logPath = path.join(homedir(), ".targate", "proxy.log");
const log = existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
const routed = log.includes(`${name}@${version}`);

cli(["teardown"], project);
try {
  rmSync(project, { recursive: true, force: true });
} catch {
  // best-effort
}

console.log(`installed=${installed} routedThroughProxy=${routed} npmExit=${install.status}`);
if (!installed || !routed) {
  console.error(`FAIL — installed=${installed}, routed=${routed}. npm output:\n${install.stdout}${install.stderr}`);
  process.exit(1);
}
console.log("PASS: private GitHub Packages install routed through and vetted by the proxy");
