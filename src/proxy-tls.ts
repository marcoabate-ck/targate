import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { proxyStateDir } from "./proxy-daemon.js";

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
  mkdirSync(dir, { recursive: true });

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
