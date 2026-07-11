import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildApprovalContext,
  loadApprovals,
  recordApproval,
  type ApprovalRecord,
} from "../src/approvals.js";
import { historyCommand } from "../src/commands/history.js";
import {
  applySignedApprovalsPolicy,
  approvalSigner,
  canonicalApprovalPayload,
  enforceSignedApprovals,
  resolveSigningKey,
  verifyApprovalSignature,
  SIGNING_NAMESPACE,
} from "../src/signing.js";
import { TARGATE_VERSION } from "../src/version.js";
import type { RiskAssessment } from "../src/types.js";

const execFileAsync = promisify(execFile);

let dir: string;
let cwd: string;

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-trust-"));
  process.chdir(dir);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

const assessment: RiskAssessment = {
  risk: "medium",
  decision: "require_approval",
  summary: "install script",
  reasons: ["r1", "r2", "r3", "r4", "r5", "r6", "r7"],
  recommendedAction: "review",
  source: "rules",
};

describe("trust history — approval context", () => {
  it("buildApprovalContext records the tool version, verdict, and caps reasons", () => {
    const ctx = buildApprovalContext({
      assessment,
      score: 61,
      policyFile: "targate.policy.yaml",
      policyHash: "abc123",
      aiProvider: "anthropic",
      aiModel: "claude-opus-4-8",
    });
    expect(ctx.targateVersion).toBe(TARGATE_VERSION);
    expect(ctx.decision).toBe("require_approval");
    expect(ctx.risk).toBe("medium");
    expect(ctx.source).toBe("rules");
    expect(ctx.score).toBe(61);
    expect(ctx.policyFile).toBe("targate.policy.yaml");
    expect(ctx.policyHash).toBe("abc123");
    expect(ctx.aiProvider).toBe("anthropic");
    expect(ctx.aiModel).toBe("claude-opus-4-8");
    expect(ctx.reasons).toHaveLength(5); // capped
  });

  it("buildApprovalContext with nothing at hand still stamps the version", () => {
    const ctx = buildApprovalContext({});
    expect(ctx.targateVersion).toBe(TARGATE_VERSION);
    expect(ctx.decision).toBeUndefined();
    expect(ctx.policyFile).toBeUndefined();
  });

  it("recordApproval persists the context and returns the record as written", async () => {
    const record = await recordApproval("esbuild", "0.27.3", "no-scripts", dir, {
      context: buildApprovalContext({ assessment, score: 61 }),
    });
    expect(record.context?.decision).toBe("require_approval");
    const approvals = await loadApprovals(dir);
    expect(approvals["esbuild@0.27.3"].context?.score).toBe(61);
    expect(approvals["esbuild@0.27.3"].context?.targateVersion).toBe(TARGATE_VERSION);
  });

  it("old-format approvals (no context) still load", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "approvals.json"),
      JSON.stringify({ "legacy@1.0.0": { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" } }),
    );
    const approvals = await loadApprovals(dir);
    expect(approvals["legacy@1.0.0"].mode).toBe("no-scripts");
    expect(approvals["legacy@1.0.0"].context).toBeUndefined();
  });
});

describe("canonical approval payload", () => {
  const record: ApprovalRecord = {
    mode: "no-scripts",
    approvedAt: "2026-07-10T00:00:00Z",
    approvedBy: "alice",
    context: { targateVersion: "0.1.0", decision: "require_approval" },
  };

  it("is independent of key insertion order and excludes the signature", () => {
    const reordered = {
      approvedBy: "alice",
      approvedAt: "2026-07-10T00:00:00Z",
      context: { decision: "require_approval", targateVersion: "0.1.0" },
      mode: "no-scripts",
      signature: { format: "ssh", signer: "x", signature: "y" },
    } as unknown as ApprovalRecord;
    expect(canonicalApprovalPayload("a@1.0.0", record)).toBe(
      canonicalApprovalPayload("a@1.0.0", reordered),
    );
  });

  it("changes when any covered field is tampered with", () => {
    const base = canonicalApprovalPayload("a@1.0.0", record);
    expect(canonicalApprovalPayload("a@1.0.1", record)).not.toBe(base);
    expect(canonicalApprovalPayload("a@1.0.0", { ...record, mode: "normal" })).not.toBe(base);
    expect(
      canonicalApprovalPayload("a@1.0.0", { ...record, approvedBy: "mallory" }),
    ).not.toBe(base);
  });
});

describe("signed approvals (ssh-keygen)", () => {
  async function makeKeyAndSigners(identity: string): Promise<string> {
    const keyPath = path.join(dir, "testkey");
    await execFileAsync("ssh-keygen", ["-t", "ed25519", "-f", keyPath, "-N", "", "-C", identity, "-q"]);
    const pub = await readFile(`${keyPath}.pub`, "utf8");
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "allowed-signers"),
      `${identity} namespaces="${SIGNING_NAMESPACE}" ${pub}`,
    );
    return keyPath;
  }

  /** git identity so signerIdentity() is deterministic in the temp repo. */
  async function gitIdentity(identity: string): Promise<void> {
    await execFileAsync("git", ["init", "-q", "."], { cwd: dir });
    await execFileAsync("git", ["config", "user.email", identity], { cwd: dir });
  }

  it("signs on record and verifies against allowed-signers; tampering invalidates", async () => {
    const keyPath = await makeKeyAndSigners("alice@example.com");
    await gitIdentity("alice@example.com");
    vi.stubEnv("TARGATE_SIGNING_KEY", keyPath);

    const record = await recordApproval("esbuild", "0.27.3", "no-scripts", dir, {
      context: buildApprovalContext({ assessment }),
      sign: approvalSigner(dir),
    });
    expect(record.signature?.format).toBe("ssh");
    expect(record.signature?.signer).toBe("alice@example.com");
    expect(record.signature?.signature).toContain("BEGIN SSH SIGNATURE");

    expect((await verifyApprovalSignature("esbuild@0.27.3", record, dir)).status).toBe("valid");
    // Tamper with a covered field → invalid.
    const tampered = { ...record, mode: "normal" as const };
    expect((await verifyApprovalSignature("esbuild@0.27.3", tampered, dir)).status).toBe("invalid");
    // Wrong key (different version string means different payload) → invalid.
    expect((await verifyApprovalSignature("esbuild@0.27.4", record, dir)).status).toBe("invalid");
  });

  it("reports unsigned and no-allowed-signers distinctly", async () => {
    const unsigned: ApprovalRecord = { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" };
    expect((await verifyApprovalSignature("a@1.0.0", unsigned, dir)).status).toBe("unsigned");

    const signed: ApprovalRecord = {
      ...unsigned,
      signature: { format: "ssh", signer: "alice@example.com", signature: "not-a-real-sig" },
    };
    // No .targate/allowed-signers in this repo yet.
    expect((await verifyApprovalSignature("a@1.0.0", signed, dir)).status).toBe(
      "no-allowed-signers",
    );
  });

  it("resolveSigningKey honors TARGATE_SIGNING_KEY and fails loudly on a bad path", async () => {
    vi.stubEnv("TARGATE_SIGNING_KEY", path.join(dir, "missing-key"));
    await expect(resolveSigningKey(dir)).rejects.toThrow(/does not exist/);
  });

  it("enforceSignedApprovals keeps only verified entries; policy off is a no-op", async () => {
    const keyPath = await makeKeyAndSigners("alice@example.com");
    await gitIdentity("alice@example.com");
    vi.stubEnv("TARGATE_SIGNING_KEY", keyPath);

    const good = await recordApproval("good", "1.0.0", "no-scripts", dir, {
      sign: approvalSigner(dir),
    });
    const approvals = {
      "good@1.0.0": good,
      "unsigned@1.0.0": { mode: "no-scripts", approvedAt: "2026-01-01T00:00:00Z" },
      "tampered@1.0.0": { ...good, mode: "normal" },
    } as Record<string, ApprovalRecord>;

    const { kept, dropped } = await enforceSignedApprovals(approvals, dir);
    expect(Object.keys(kept)).toEqual(["good@1.0.0"]);
    expect(dropped.map((d) => d.key).sort()).toEqual(["tampered@1.0.0", "unsigned@1.0.0"]);

    // Policy off → untouched, no verification runs.
    const untouched = await applySignedApprovalsPolicy(approvals, undefined, dir);
    expect(untouched).toBe(approvals);

    // Policy on → stderr explains each dropped entry.
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    const filtered = await applySignedApprovalsPolicy(approvals, true, dir);
    expect(Object.keys(filtered)).toEqual(["good@1.0.0"]);
    expect(errors.join("\n")).toContain("unsigned@1.0.0");
    expect(errors.join("\n")).toContain("requireSignedApprovals");
  });
});

describe("targate history", () => {
  it("lists approvals newest-first with context, as JSON with the envelope", async () => {
    await recordApproval("b-pkg", "2.0.0", "normal", dir, {
      context: buildApprovalContext({ assessment, score: 55 }),
    });
    await recordApproval("a-pkg", "1.0.0", "no-scripts", dir);

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const code = await historyCommand({ json: true, verify: false });
    expect(code).toBe(0);
    const doc = JSON.parse(logs.join("\n"));
    expect(doc.schemaVersion).toBe(1);
    expect(doc.command).toBe("history");
    expect(doc.total).toBe(2);
    expect(doc.entries[0].key).toBe("a-pkg@1.0.0"); // recorded last → newest first
    expect(doc.entries.find((e: { key: string }) => e.key === "b-pkg@2.0.0").context.score).toBe(55);
  });

  it("filters by package and by exact version", async () => {
    await recordApproval("a-pkg", "1.0.0", "no-scripts", dir);
    await recordApproval("a-pkg", "1.1.0", "no-scripts", dir);
    await recordApproval("other", "9.0.0", "no-scripts", dir);

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    await historyCommand({ spec: "a-pkg", json: true, verify: false });
    const doc = JSON.parse(logs.join("\n"));
    expect(doc.total).toBe(2);

    logs.length = 0;
    await historyCommand({ spec: "a-pkg@1.1.0", json: true, verify: false });
    expect(JSON.parse(logs.join("\n")).total).toBe(1);
  });

  it("--verify exits 2 when a signature is invalid", async () => {
    const keyPath = path.join(dir, "testkey");
    await execFileAsync("ssh-keygen", ["-t", "ed25519", "-f", keyPath, "-N", "", "-q"]);
    const pub = await readFile(`${keyPath}.pub`, "utf8");
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "allowed-signers"),
      `alice@example.com namespaces="${SIGNING_NAMESPACE}" ${pub}`,
    );
    await execFileAsync("git", ["init", "-q", "."], { cwd: dir });
    await execFileAsync("git", ["config", "user.email", "alice@example.com"], { cwd: dir });
    vi.stubEnv("TARGATE_SIGNING_KEY", keyPath);

    await recordApproval("signed-pkg", "1.0.0", "no-scripts", dir, { sign: approvalSigner(dir) });
    // Tamper on disk.
    const file = path.join(dir, ".targate", "approvals.json");
    const doc = JSON.parse(await readFile(file, "utf8"));
    doc["signed-pkg@1.0.0"].mode = "normal";
    await writeFile(file, JSON.stringify(doc, null, 2));

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const code = await historyCommand({ json: true, verify: true });
    expect(code).toBe(2);
    const out = JSON.parse(logs.join("\n"));
    expect(out.entries[0].verification.status).toBe("invalid");
  });
});
