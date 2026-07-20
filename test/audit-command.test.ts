import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { auditCommand } from "../src/commands/audit.js";
import { applySourceAudit, buildPackageSignals } from "../src/pipeline.js";
import { evaluateRules } from "../src/rules.js";
import type { AiProvider } from "../src/providers/types.js";
import type { SourceAuditFinding } from "../src/types.js";
import { archetypes, buildPackageTarball, registryFetchStub } from "./fixtures/malicious-packages.js";

let dir = "";
let cwd = "";

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-audit-cmd-"));
  process.chdir(dir);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (cwd) process.chdir(cwd);
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = "";
  cwd = "";
});

async function stub(pkg: Parameters<typeof registryFetchStub>[0]): Promise<void> {
  const bytes = await buildPackageTarball(pkg);
  vi.stubGlobal("fetch", vi.fn(registryFetchStub(pkg, bytes)));
}

function runAuditJson(spec: string): Promise<{ code: number; report: any }> {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
  return auditCommand({ spec, json: true, noReputation: true, assess: { useAi: false } }).then((code) => {
    spy.mockRestore();
    return { code, report: JSON.parse(lines[lines.length - 1]) };
  });
}

describe("targate audit (end-to-end, network stubbed)", () => {
  it("blocks a curl|bash postinstall and exits 2", async () => {
    const pkg = archetypes.curlBashPostinstall();
    await stub(pkg);
    const { code, report } = await runAuditJson(pkg.name);
    expect(code).toBe(2);
    expect(report.command).toBe("audit");
    expect(report.assessment.decision).toBe("block");
  });

  it("blocks an env+network exfiltration install script and exits 2", async () => {
    const pkg = archetypes.envNetworkExfil();
    await stub(pkg);
    const { code, report } = await runAuditJson(pkg.name);
    expect(code).toBe(2);
    expect(report.assessment.decision).toBe("block");
  });

  it("passes a clean package and exits 0", async () => {
    const pkg = archetypes.clean();
    await stub(pkg);
    const { code, report } = await runAuditJson(pkg.name);
    expect(code).toBe(0);
    expect(report.assessment.decision).toBe("allow");
  });

  it("reports that the AI audit did not run without a provider", async () => {
    const pkg = archetypes.curlBashPostinstall();
    await stub(pkg);
    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((...a) => lines.push(a.join(" ")));
    await auditCommand({ spec: pkg.name, json: false, noReputation: true, assess: { useAi: false } });
    spy.mockRestore();
    expect(lines.join("\n")).toContain("AI source-code audit did not run");
  });
});

// The payoff case: obfuscated exfiltration the regex scanners miss, which only
// reading the source catches. targate audit forces scope "all", so the file is
// selected even though the deterministic pass never flags it.
describe("obfuscated exfiltration — AI audit catches what the regex misses", () => {
  it("deterministic scan misses it, but the audit escalates it to block", async () => {
    const pkg = archetypes.obfuscatedExfil();
    const bytes = await buildPackageTarball(pkg);
    vi.stubGlobal("fetch", vi.fn(registryFetchStub(pkg, bytes)));

    const built = await buildPackageSignals(pkg.name, "1.0.0", {
      noReputation: true,
      osv: { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
      cwd: dir,
      codeAudit: "all",
    });

    // The regex heuristics did NOT fire (obfuscated), so the deterministic
    // verdict is clean — this is exactly the gap the audit closes.
    expect(built.signals.content.hasProcessEnvAccess).toBe(false);
    expect(built.signals.content.hasNetworkCalls).toBe(false);
    expect(evaluateRules(built.signals).decision).toBe("allow");

    // But scope "all" still selected the file for the audit.
    expect(built.audit?.input.files.map((f) => f.relPath)).toContain("index.js");

    // A provider that reads the code reports the exfiltration → escalates to block.
    const finding: SourceAuditFinding = {
      severity: "high",
      file: "index.js",
      summary: "assembles process.env.NPM_TOKEN via string-splitting and ships it to evil.example",
    };
    const provider: AiProvider = {
      name: "fake",
      model: "m",
      assess: async () => {
        throw new Error("unused");
      },
      assessBatch: async () => [],
      analyzeSource: async () => [finding],
    };
    const out = await applySourceAudit(
      provider,
      built.audit,
      evaluateRules(built.signals),
      built.signals,
      { cache: undefined, cwd: dir },
    );
    expect(out.assessment.decision).toBe("block");
    expect(out.result?.findings).toEqual([finding]);
  });
});
