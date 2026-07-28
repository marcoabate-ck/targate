import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  ABSENT_FILE,
  BehaviorFingerprint,
  compareFingerprints,
  computeFingerprint,
} from "../src/fingerprint.js";
import type { ContentFindings } from "../src/types.js";

const tmpDirs: string[] = [];

async function makePackage(files: Record<string, string>) {
  const dir = await mkdtemp(path.join(tmpdir(), "targate-fp-"));
  tmpDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

function content(overrides: Partial<ContentFindings> = {}): ContentFindings {
  return {
    hasProcessEnvAccess: false,
    hasChildProcessUsage: false,
    hasNetworkCalls: false,
    hasEvalUsage: false,
    hasMinifiedCode: false,
    suspiciousFiles: [],
    installTimeFindings: [],
    ...overrides,
  };
}

afterAll(async () => {
  await Promise.all(
    tmpDirs.map((d) => rm(d, { recursive: true, force: true })),
  );
});

describe("computeFingerprint", () => {
  it("hashes install-script referenced files, not just the command string", async () => {
    const dir = await makePackage({ "install.js": "console.log('v1')" });
    const fp = await computeFingerprint({
      integrity: "sha512-abc==",
      scripts: { postinstall: "node install.js", prepare: "bob build" },
      content: content(),
      hasProvenance: true,
      packageDir: dir,
      complete: true,
    });
    // prepare is pack-time — excluded; only postinstall is fingerprinted.
    expect(fp.installScripts).toHaveLength(1);
    expect(fp.installScripts[0].name).toBe("postinstall");
    expect(fp.installScripts[0].referencedFileHashes["install.js"]).toMatch(
      /^[0-9a-f]{16}$/,
    );
    expect(fp.artifactSha512).toBe("sha512-abc==");
    expect(fp.provenanceState).toBe("present");
    expect(fp.complete).toBe(true);
  });

  it("records ABSENT_FILE when a referenced script file is missing from the tarball", async () => {
    const dir = await makePackage({ "index.js": "module.exports = 1" });
    const fp = await computeFingerprint({
      scripts: { postinstall: "node install.js" },
      content: content(),
      hasProvenance: false,
      packageDir: dir,
      complete: true,
    });
    expect(fp.installScripts[0].referencedFileHashes["install.js"]).toBe(
      ABSENT_FILE,
    );
    expect(fp.provenanceState).toBe("none");
  });

  it("treats a referenced file that escapes the package root as absent", async () => {
    const dir = await makePackage({ "index.js": "x" });
    const fp = await computeFingerprint({
      scripts: { postinstall: "node ../../etc/evil.js" },
      content: content(),
      hasProvenance: false,
      packageDir: dir,
      complete: true,
    });
    expect(fp.installScripts[0].referencedFileHashes["../../etc/evil.js"]).toBe(
      ABSENT_FILE,
    );
  });

  it("tiers capabilities from content findings", async () => {
    const dir = await makePackage({ "index.js": "x" });
    const fp = await computeFingerprint({
      content: content({
        hasNetworkCalls: true,
        hasChildProcessUsage: true,
        hasEvalUsage: true,
        hasProcessEnvAccess: true,
      }),
      hasProvenance: false,
      packageDir: dir,
      complete: true,
    });
    expect(fp.dangerousCapabilities).toEqual([
      "child_process",
      "eval",
      "network",
    ]);
    expect(fp.lowRiskCapabilities).toEqual(["env"]);
  });
});

describe("compareFingerprints", () => {
  const base: BehaviorFingerprint = {
    schemaVersion: 1,
    installScripts: [],
    dangerousCapabilities: [],
    lowRiskCapabilities: [],
    provenanceState: "none",
    complete: true,
  };

  it("matches an identical fingerprint", () => {
    const cmp = compareFingerprints(base, { ...base });
    expect(cmp.matches).toBe(true);
    expect(cmp.repromptReasons).toEqual([]);
  });

  it("re-prompts when an install script's referenced file content changes (esbuild case)", () => {
    // esbuild keeps a byte-identical `node install.js` across releases while
    // install.js itself changes every release. The command hash matches; the
    // referenced-file hash does not -> re-prompt. (Auto-pass for esbuild comes
    // from the provenance layer, not the fingerprint — see design §5.5.)
    const approved: BehaviorFingerprint = {
      ...base,
      installScripts: [
        {
          name: "postinstall",
          commandHash: "aaaa",
          referencedFileHashes: { "install.js": "v1hash0000000000" },
        },
      ],
    };
    const candidate: BehaviorFingerprint = {
      ...base,
      installScripts: [
        {
          name: "postinstall",
          commandHash: "aaaa",
          referencedFileHashes: { "install.js": "v2hash0000000000" },
        },
      ],
    };
    const cmp = compareFingerprints(approved, candidate);
    expect(cmp.matches).toBe(false);
    expect(cmp.repromptReasons).toContain(
      'install script "postinstall" referenced file "install.js" changed',
    );
  });

  it("auto-passes a benign low-risk capability gain (react-native-svg NODE_ENV case)", () => {
    // svg 15.15.5 added `process.env.NODE_ENV` — env flips on, nothing else.
    const approved: BehaviorFingerprint = {
      ...base,
      dangerousCapabilities: ["network"],
    };
    const candidate: BehaviorFingerprint = {
      ...base,
      dangerousCapabilities: ["network"],
      lowRiskCapabilities: ["env"],
    };
    const cmp = compareFingerprints(approved, candidate);
    expect(cmp.matches).toBe(true);
    expect(cmp.repromptReasons).toEqual([]);
    expect(cmp.autoPassNotes).toContain(
      "low-risk capability added (no re-prompt): env",
    );
  });

  it("re-prompts on escalation into the dangerous capability set", () => {
    const approved: BehaviorFingerprint = {
      ...base,
      lowRiskCapabilities: ["env"],
    };
    const candidate: BehaviorFingerprint = {
      ...base,
      lowRiskCapabilities: ["env"],
      dangerousCapabilities: ["network"],
    };
    const cmp = compareFingerprints(approved, candidate);
    expect(cmp.matches).toBe(false);
    expect(cmp.repromptReasons).toContain("new dangerous capability: network");
  });

  it("does not re-prompt when a capability is removed (strictly safer)", () => {
    const approved: BehaviorFingerprint = {
      ...base,
      dangerousCapabilities: ["network", "child_process"],
    };
    const candidate: BehaviorFingerprint = {
      ...base,
      dangerousCapabilities: ["network"],
    };
    expect(compareFingerprints(approved, candidate).matches).toBe(true);
  });

  it("re-prompts on a provenance downgrade", () => {
    const approved: BehaviorFingerprint = {
      ...base,
      provenanceState: "present",
    };
    const candidate: BehaviorFingerprint = { ...base, provenanceState: "none" };
    const cmp = compareFingerprints(approved, candidate);
    expect(cmp.matches).toBe(false);
    expect(cmp.repromptReasons).toContain(
      "provenance downgraded (present → none)",
    );
  });

  it("does not re-prompt on a provenance gain", () => {
    const approved: BehaviorFingerprint = { ...base, provenanceState: "none" };
    const candidate: BehaviorFingerprint = {
      ...base,
      provenanceState: "present",
    };
    expect(compareFingerprints(approved, candidate).matches).toBe(true);
  });

  it("re-prompts when a new install script appears", () => {
    const candidate: BehaviorFingerprint = {
      ...base,
      installScripts: [
        { name: "postinstall", commandHash: "bbbb", referencedFileHashes: {} },
      ],
    };
    const cmp = compareFingerprints(base, candidate);
    expect(cmp.matches).toBe(false);
    expect(cmp.repromptReasons).toContain('install script "postinstall" added');
  });

  it("fails closed when either fingerprint is incomplete", () => {
    const incomplete: BehaviorFingerprint = { ...base, complete: false };
    const cmp = compareFingerprints(base, incomplete);
    expect(cmp.matches).toBe(false);
    expect(cmp.repromptReasons[0]).toMatch(/incomplete/);
  });
});
