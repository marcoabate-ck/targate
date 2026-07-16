import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  artifactLedgerKey,
  loadArtifactLedger,
  recordArtifactObservations,
} from "../src/artifact-ledger.js";
import { resetNpmrcCacheForTests } from "../src/npmrc.js";
import { buildPackageSignals } from "../src/pipeline.js";
import { verifyArtifactIdentity } from "../src/quarantine.js";
import { evaluateRules, isHardBlock } from "../src/rules.js";

const bytes = Buffer.from("private mirror artifact");
const sri = (value: Buffer) =>
  `sha512-${createHash("sha512").update(value).digest("base64")}`;

describe("artifact identity verification", () => {
  it("establishes public equivalence from an independent checksum", () => {
    const artifact = verifyArtifactIdentity(bytes, "https://mirror/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://mirror",
      registry: { integrity: sri(bytes) },
      publicArtifact: {
        status: "available",
        registryUrl: "https://registry.npmjs.org",
        checksums: { integrity: sri(bytes) },
      },
    });
    expect(artifact.trust).toBe("public-equivalent");
    expect(artifact.digest).toBe(sri(bytes));
  });

  it("marks a private tarball and metadata replaced together as mutated", () => {
    const artifact = verifyArtifactIdentity(bytes, "https://mirror/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://mirror",
      registry: { integrity: sri(bytes) },
      publicArtifact: {
        status: "available",
        registryUrl: "https://registry.npmjs.org",
        checksums: { integrity: sri(Buffer.from("original public artifact")) },
      },
    });
    expect(artifact.trust).toBe("mutated");
    expect(artifact.reasons.join(" ")).toContain("public registry checksum mismatch");
  });

  it("reports checksum-free first contact without blocking by itself", () => {
    const artifact = verifyArtifactIdentity(bytes, "https://private/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://private",
      registry: {},
    });
    expect(artifact.trust).toBe("unverified");
  });

  it("does not treat a freshly resolved lockfile as an independent trust source", () => {
    const fresh = verifyArtifactIdentity(bytes, "https://mirror/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://mirror",
      registry: { integrity: sri(bytes) },
      lockfile: { integrity: sri(bytes) },
      lockfileTrusted: false,
      publicArtifact: {
        status: "unavailable",
        registryUrl: "https://registry.npmjs.org",
        reason: "offline",
      },
    });
    expect(fresh.trust).toBe("public-unavailable");

    const committed = verifyArtifactIdentity(bytes, "https://mirror/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://mirror",
      registry: { integrity: sri(bytes) },
      lockfile: { integrity: sri(bytes) },
      lockfileTrusted: true,
    });
    expect(committed.trust).toBe("lockfile-verified");
  });
});

describe("artifact ledger", () => {
  let dir = "";
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("records successful observations and refuses historical replacement", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-artifacts-"));
    const artifact = verifyArtifactIdentity(bytes, "https://private/pkg.tgz", {
      packageName: "pkg",
      version: "1.0.0",
      registryUrl: "https://private",
      registry: { integrity: sri(bytes) },
    });
    await recordArtifactObservations([{ name: "pkg", version: "1.0.0", artifact }], dir);
    const ledger = await loadArtifactLedger(dir);
    expect(ledger[artifactLedgerKey("https://private", "pkg", "1.0.0")].digest).toBe(sri(bytes));

    await expect(
      recordArtifactObservations([
        {
          name: "pkg",
          version: "1.0.0",
          artifact: { ...artifact, digest: sri(Buffer.from("changed")) },
        },
      ], dir),
    ).rejects.toThrow("Refusing to replace historical artifact identity");
  });

  it("ignores malformed records with a visible warning", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-artifacts-invalid-"));
    await mkdir(path.join(dir, ".targate"));
    await writeFile(
      path.join(dir, ".targate", "artifacts.json"),
      JSON.stringify({ schemaVersion: 1, artifacts: { bad: { digest: 42 } } }),
    );
    const warnings: string[] = [];
    expect(await loadArtifactLedger(dir, (warning) => warnings.push(warning))).toEqual({});
    expect(warnings[0]).toContain("invalid artifact record");
  });
});

describe("compromised npm mirror", () => {
  let dir = "";
  let cwd = "";

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    if (cwd) process.chdir(cwd);
    resetNpmrcCacheForTests();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  async function tarball(scripts: Record<string, string> = {}): Promise<Buffer> {
    const work = await mkdtemp(path.join(tmpdir(), "targate-mirror-tar-"));
    try {
      await mkdir(path.join(work, "package"));
      await writeFile(
        path.join(work, "package", "package.json"),
        JSON.stringify({ name: "public-pkg", version: "1.0.0", scripts }),
      );
      const file = path.join(work, "package.tgz");
      await tar.c({ gzip: true, cwd: work, file }, ["package"]);
      return await readFile(file);
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  }

  it("hard-blocks when a private mirror rewrites tarball and metadata", async () => {
    cwd = process.cwd();
    dir = await mkdtemp(path.join(tmpdir(), "targate-mirror-"));
    await writeFile(path.join(dir, ".npmrc"), "registry=https://mirror.example/\n");
    process.chdir(dir);
    resetNpmrcCacheForTests();
    const privateBytes = await tarball();
    const publicIntegrity = sri(Buffer.from("original public bytes"));

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => privateBytes };
      }
      const integrity = url.startsWith("https://registry.npmjs.org")
        ? publicIntegrity
        : sri(privateBytes);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "public-pkg",
              repository: { url: "https://github.com/example/public-pkg" },
              dist: { tarball: "https://mirror.example/public-pkg.tgz", integrity },
              scripts: {},
              dependencies: {},
            },
          },
          time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
        }),
      };
    }));

    const { signals } = await buildPackageSignals("public-pkg", "1.0.0", {
      noReputation: true,
      osv: { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      cwd: dir,
    });
    expect(signals.artifact.trust).toBe("mutated");
    expect(isHardBlock(signals)).toBe(true);
    expect(evaluateRules(signals).decision).toBe("block");
  });

  it("hard-blocks a mirror packument that hides a tarball lifecycle script", async () => {
    cwd = process.cwd();
    dir = await mkdtemp(path.join(tmpdir(), "targate-mirror-scripts-"));
    await writeFile(path.join(dir, ".npmrc"), "registry=https://mirror.example/\n");
    process.chdir(dir);
    resetNpmrcCacheForTests();
    const privateBytes = await tarball({ postinstall: "node install.js" });
    const integrity = sri(privateBytes);

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => privateBytes };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "public-pkg",
              repository: { url: "https://github.com/example/public-pkg" },
              dist: { tarball: "https://mirror.example/public-pkg.tgz", integrity },
              scripts: {}, // compromised mirror hides the tarball's postinstall
              dependencies: {},
            },
          },
          time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
        }),
      };
    }));

    const { signals } = await buildPackageSignals("public-pkg", "1.0.0", {
      noReputation: true,
      osv: { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      cwd: dir,
    });
    expect(signals.lifecycleScripts).toEqual({ postinstall: "node install.js" });
    expect(signals.artifact.trust).toBe("mutated");
    expect(evaluateRules(signals).decision).toBe("block");
  });

  it("keeps a checksum-verified tarball approvable when the packument over-declares a script it drops", async () => {
    // fsevents-shaped drift: the registry packument keeps an `install` entry
    // the authentic tarball has removed. Nothing extra runs, the bytes match
    // the declared checksum, so this is an approvable drift — not a mutated
    // hard block (which would make the package uninstallable forever).
    cwd = process.cwd();
    dir = await mkdtemp(path.join(tmpdir(), "targate-mirror-overdeclare-"));
    await writeFile(path.join(dir, ".npmrc"), "registry=https://mirror.example/\n");
    process.chdir(dir);
    resetNpmrcCacheForTests();
    const privateBytes = await tarball({}); // tarball declares no scripts
    const integrity = sri(privateBytes);

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith(".tgz")) {
        return { ok: true, status: 200, arrayBuffer: async () => privateBytes };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "public-pkg",
              repository: { url: "https://github.com/example/public-pkg" },
              dist: { tarball: "https://mirror.example/public-pkg.tgz", integrity },
              scripts: { install: "node-gyp rebuild" }, // packument over-declares
              dependencies: {},
            },
          },
          time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
        }),
      };
    }));

    const { signals } = await buildPackageSignals("public-pkg", "1.0.0", {
      noReputation: true,
      osv: { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      cwd: dir,
    });
    expect(signals.lifecycleScripts).toEqual({}); // tarball is authoritative — nothing runs
    expect(signals.artifact.trust).not.toBe("mutated");
    expect(signals.artifact.metadataDrift?.length).toBeGreaterThan(0);
    expect(isHardBlock(signals)).toBe(false);
    expect(evaluateRules(signals).decision).toBe("require_approval");
  });
});
