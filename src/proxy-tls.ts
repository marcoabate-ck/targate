import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { homedir } from "node:os";
import path from "node:path";
import { proxyStateDir } from "./proxy-daemon.js";

/** The CA's certificate common name — used to remove it from a trust store by name. */
export const CA_COMMON_NAME = "targate local CA";

/**
 * Local TLS material for the registry proxy. npm only sends registry auth over
 * https and refuses http registries for authenticated scopes, so the proxy must
 * speak TLS. We mint a local CA and a leaf certificate for it with `openssl`
 * (the mkcert pattern, minus the trust step): the CA can be trusted once — via
 * the system store (`cert install`) or `NODE_EXTRA_CA_CERTS` in CI — and every
 * regenerated leaf stays valid under it.
 *
 * Nothing here touches the system trust store; that is an explicit, separate,
 * privileged step (see the `cert install` command).
 */

export interface TlsMaterial {
  caPath: string;
  caKeyPath: string;
  certPath: string;
  certKeyPath: string;
}

export function tlsDir(): string {
  return path.join(proxyStateDir(), "proxy-tls");
}

export function tlsMaterialPaths(): TlsMaterial {
  const dir = tlsDir();
  return {
    caPath: path.join(dir, "ca.pem"),
    caKeyPath: path.join(dir, "ca-key.pem"),
    certPath: path.join(dir, "cert.pem"),
    certKeyPath: path.join(dir, "cert-key.pem"),
  };
}

export function tlsMaterialExists(): boolean {
  const p = tlsMaterialPaths();
  return existsSync(p.caPath) && existsSync(p.certPath) && existsSync(p.certKeyPath);
}

/** subjectAltName entries: always localhost + 127.0.0.1, plus an extra host. */
function subjectAltName(host?: string): string {
  const dns = new Set(["localhost"]);
  const ip = new Set(["127.0.0.1", "::1"]);
  if (host && host !== "localhost" && host !== "127.0.0.1") {
    if (net.isIP(host)) ip.add(host);
    else dns.add(host);
  }
  return [...[...dns].map((d) => `DNS:${d}`), ...[...ip].map((i) => `IP:${i}`)].join(",");
}

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"] });
}

/**
 * Generate the CA + leaf certificate if they are not already present.
 * Idempotent: an existing CA and leaf are reused so the trusted CA keeps working.
 */
export function ensureTlsMaterial(host?: string): TlsMaterial {
  const paths = tlsMaterialPaths();
  if (tlsMaterialExists()) return paths;

  const dir = tlsDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  // 1) self-signed CA
  openssl([
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", paths.caKeyPath, "-out", paths.caPath,
    "-days", "3650", "-subj", "/CN=targate local CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ]);

  // 2) leaf key + CSR
  const csrPath = path.join(dir, "cert.csr");
  openssl([
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", paths.certKeyPath, "-out", csrPath, "-subj", "/CN=localhost",
  ]);

  // 3) sign the leaf with the CA, carrying the SANs + server-auth EKU
  const extPath = path.join(dir, "leaf.ext");
  writeFileSync(
    extPath,
    [
      `subjectAltName=${subjectAltName(host)}`,
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      "",
    ].join("\n"),
  );
  openssl([
    "x509", "-req", "-in", csrPath,
    "-CA", paths.caPath, "-CAkey", paths.caKeyPath, "-CAcreateserial",
    "-out", paths.certPath, "-days", "825", "-extfile", extPath,
  ]);

  // cleanup transient files
  for (const f of [csrPath, extPath, path.join(dir, "ca.srl")]) rmSync(f, { force: true });
  // Private keys must not be world/group-readable — a readable CA key lets any
  // local user mint certs trusted by this proxy (MITM).
  for (const key of [paths.caKeyPath, paths.certKeyPath]) {
    try {
      chmodSync(key, 0o600);
    } catch {
      // best-effort (e.g. Windows ACLs)
    }
  }
  return paths;
}

/** Load key+cert PEMs for https.createServer. Returns null when material is absent. */
export function loadTlsMaterial(): { key: Buffer; cert: Buffer } | null {
  if (!tlsMaterialExists()) return null;
  const paths = tlsMaterialPaths();
  return { key: readFileSync(paths.certKeyPath), cert: readFileSync(paths.certPath) };
}

/** Remove all generated TLS material (used by teardown). */
export function removeTlsMaterial(): void {
  rmSync(tlsDir(), { recursive: true, force: true });
}

/**
 * A trust-store command for the current platform. `sudo` marks the ones that
 * need root (Linux) — those are printed for the user to run rather than executed,
 * since auto-elevating is surprising and distro-specific. macOS (login keychain)
 * and Windows (per-user Root store) do not need root and can be run directly.
 */
export interface TrustCommand {
  command: string;
  args: string[];
  sudo: boolean;
  /** Copy-pasteable form for --dry-run and failure messages. */
  manual: string;
}

function manualForm(command: string, args: string[], sudo: boolean): string {
  const quote = (a: string): string => (/\s/.test(a) ? `"${a}"` : a);
  return `${sudo ? "sudo " : ""}${command} ${args.map(quote).join(" ")}`;
}

function trustCommand(command: string, args: string[], sudo: boolean): TrustCommand {
  return { command, args, sudo, manual: manualForm(command, args, sudo) };
}

/** Command that trusts the local CA in the current platform's trust store. */
export function caInstallCommand(caPath = tlsMaterialPaths().caPath): TrustCommand {
  if (process.platform === "darwin") {
    const keychain = path.join(homedir(), "Library", "Keychains", "login.keychain-db");
    return trustCommand("security", ["add-trusted-cert", "-r", "trustRoot", "-k", keychain, caPath], false);
  }
  if (process.platform === "win32") {
    return trustCommand("certutil", ["-addstore", "-user", "Root", caPath], false);
  }
  // Linux (Debian/Ubuntu family); needs root, so it is printed, not auto-run.
  return trustCommand(
    "sh",
    ["-c", `cp ${caPath} /usr/local/share/ca-certificates/targate-local-ca.crt && update-ca-certificates`],
    true,
  );
}

/** Command that removes the local CA from the current platform's trust store. */
export function caUninstallCommand(caPath = tlsMaterialPaths().caPath): TrustCommand {
  if (process.platform === "darwin") {
    return trustCommand("security", ["delete-certificate", "-c", CA_COMMON_NAME], false);
  }
  if (process.platform === "win32") {
    return trustCommand("certutil", ["-delstore", "-user", "Root", CA_COMMON_NAME], false);
  }
  return trustCommand("sh", ["-c", "rm -f /usr/local/share/ca-certificates/targate-local-ca.crt && update-ca-certificates --fresh"], true);
}
