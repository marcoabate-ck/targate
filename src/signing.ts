import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ApprovalRecord, ApprovalSignature, ApprovalsMap } from "./approvals.js";

const execFileAsync = promisify(execFile);

/** Run a command feeding `input` on stdin (execFileAsync cannot). */
function execWithInput(
  cmd: string,
  args: string[],
  input: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(cmd, args, { timeout: 15_000 }, (err, stdout, stderr) => {
      if (err) {
        (err as NodeJS.ErrnoException & { stderr?: string }).stderr = stderr;
        reject(err);
      } else resolve({ stdout, stderr });
    });
    child.stdin?.end(input);
  });
}

/**
 * Signed approvals — SSH signatures over approval entries.
 *
 * The mechanism is OpenSSH's lightweight signature scheme (`ssh-keygen -Y`),
 * the same one git uses for SSH commit signing: developers already have the
 * keys, no extra tooling is required, and verification has a first-class
 * trust model — a committed ALLOWED SIGNERS file. GPG and Sigstore/SLSA
 * attestations are deliberately out of scope for now (documented in
 * docs/team-workflow.md).
 *
 * What is signed: the canonical JSON of the approval entry (key + record,
 * minus the signature itself), in the "targate-approval" namespace so a
 * signature can never be replayed from/to another context (git commits,
 * other tools) even with the same key.
 */

/** SSH signature namespace — domain-separates approvals from any other use of the key. */
export const SIGNING_NAMESPACE = "targate-approval";

/** Committed trust anchor (standard OpenSSH ALLOWED SIGNERS format). */
export const ALLOWED_SIGNERS_FILE = path.join(".targate", "allowed-signers");

export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigningError";
  }
}

/** Recursively sort object keys so the signed payload is byte-stable. */
function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortDeep(v)]),
    );
  }
  return value;
}

/**
 * The exact bytes an approval signature covers: the "name@version" key plus
 * the record with keys sorted at every depth and the signature field removed.
 * Any tampering with the entry (mode, date, context) invalidates it.
 */
export function canonicalApprovalPayload(key: string, record: ApprovalRecord): string {
  const { signature: _signature, ...rest } = record;
  return JSON.stringify(sortDeep({ key, ...rest })) + "\n";
}

async function gitConfig(name: string, cwd: string): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync("git", ["config", "--get", name], {
      cwd,
      timeout: 5_000,
    });
    const value = stdout.trim();
    return value.length > 0 ? value : undefined;
  } catch {
    return undefined;
  }
}

function expandHome(p: string): string {
  return p.startsWith("~/") || p === "~" ? path.join(homedir(), p.slice(1)) : p;
}

export interface SigningKey {
  /** Path to the key file handed to ssh-keygen -f. */
  keyPath: string;
  /** True when keyPath is a PUBLIC key and the private half lives in ssh-agent
   *  (ssh-keygen -U mode) — how git's ssh signing handles agent-held keys. */
  viaAgent: boolean;
}

/**
 * Which SSH key signs approvals, first match wins:
 *   1. $TARGATE_SIGNING_KEY (a key file path)
 *   2. git config user.signingkey — a path when it points at a file; a literal
 *      "ssh-ed25519 AAAA…" public key is materialized and signed via ssh-agent
 *   3. the conventional default keys under ~/.ssh
 * Throws a SigningError with setup guidance when nothing is found.
 */
export async function resolveSigningKey(
  cwd: string = process.cwd(),
  env: NodeJS.ProcessEnv = process.env,
): Promise<SigningKey> {
  const fromEnv = env.TARGATE_SIGNING_KEY;
  if (fromEnv) {
    const p = expandHome(fromEnv);
    if (!existsSync(p)) {
      throw new SigningError(`TARGATE_SIGNING_KEY points at "${fromEnv}", which does not exist.`);
    }
    return { keyPath: p, viaAgent: p.endsWith(".pub") };
  }

  const gitKey = await gitConfig("user.signingkey", cwd);
  if (gitKey) {
    if (gitKey.startsWith("ssh-") || gitKey.startsWith("sk-ssh-")) {
      // Literal public key (the common gpg.format=ssh setup): write it to a
      // temp file and let ssh-agent hold the private half.
      const dir = await mkdtemp(path.join(tmpdir(), "targate-sign-"));
      const pub = path.join(dir, "signingkey.pub");
      await writeFile(pub, gitKey + "\n");
      return { keyPath: pub, viaAgent: true };
    }
    const p = expandHome(gitKey);
    if (existsSync(p)) return { keyPath: p, viaAgent: p.endsWith(".pub") };
  }

  for (const candidate of ["id_ed25519", "id_ecdsa", "id_rsa"]) {
    const p = path.join(homedir(), ".ssh", candidate);
    if (existsSync(p)) return { keyPath: p, viaAgent: false };
  }

  throw new SigningError(
    "No SSH signing key found. Set TARGATE_SIGNING_KEY to a key file, configure `git config user.signingkey`, or create ~/.ssh/id_ed25519.",
  );
}

/** Identity recorded in the signature and matched against allowed-signers. */
export async function signerIdentity(cwd: string = process.cwd()): Promise<string> {
  return (
    (await gitConfig("user.email", cwd)) ?? process.env.USER ?? process.env.USERNAME ?? "unknown"
  );
}

/**
 * Sign a payload with ssh-keygen. Uses a temp file for the message (stdin
 * signing differs across OpenSSH versions; the file form is stable) and
 * returns the armored signature from the ".sig" ssh-keygen writes next to it.
 */
async function sshSign(payload: string, key: SigningKey): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "targate-sign-"));
  try {
    const msg = path.join(dir, "payload");
    await writeFile(msg, payload);
    const args = ["-Y", "sign", "-f", key.keyPath, "-n", SIGNING_NAMESPACE];
    if (key.viaAgent) args.push("-U");
    args.push(msg);
    try {
      await execFileAsync("ssh-keygen", args, { timeout: 15_000 });
    } catch (err) {
      const detail = err instanceof Error && "stderr" in err ? String((err as any).stderr).trim() : String(err);
      throw new SigningError(`ssh-keygen failed to sign the approval: ${detail || "unknown error"}`);
    }
    return await readFile(`${msg}.sig`, "utf8");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * The `sign` hook for recordApproval(): resolves the key and identity, then
 * signs the canonical payload of the exact record being written.
 */
export function approvalSigner(
  cwd: string = process.cwd(),
): (key: string, record: ApprovalRecord) => Promise<ApprovalSignature> {
  return async (key, record) => {
    const signingKey = await resolveSigningKey(cwd);
    const signer = await signerIdentity(cwd);
    const signature = await sshSign(canonicalApprovalPayload(key, record), signingKey);
    return { format: "ssh", signer, signature };
  };
}

export type SignatureStatus =
  | "valid" // signature verifies against .targate/allowed-signers
  | "invalid" // signature present but does NOT verify (tampered or untrusted key)
  | "unsigned" // no signature on the entry
  | "no-allowed-signers" // signed, but the repo has no .targate/allowed-signers to verify against
  | "error"; // ssh-keygen unavailable or crashed — verification could not run

export interface SignatureVerification {
  status: SignatureStatus;
  signer?: string;
  detail?: string;
}

export function allowedSignersPath(cwd: string = process.cwd()): string {
  return path.join(cwd, ALLOWED_SIGNERS_FILE);
}

/** Verify one approval entry's signature against .targate/allowed-signers. */
export async function verifyApprovalSignature(
  key: string,
  record: ApprovalRecord,
  cwd: string = process.cwd(),
): Promise<SignatureVerification> {
  if (!record.signature) return { status: "unsigned" };
  const { signer, signature, format } = record.signature;
  if (format !== "ssh") {
    return { status: "error", signer, detail: `unknown signature format "${format}"` };
  }
  const signersFile = allowedSignersPath(cwd);
  if (!existsSync(signersFile)) return { status: "no-allowed-signers", signer };

  const dir = await mkdtemp(path.join(tmpdir(), "targate-verify-"));
  try {
    const sig = path.join(dir, "payload.sig");
    await writeFile(sig, signature);
    try {
      // The message being verified is fed on stdin, per ssh-keygen -Y verify.
      await execWithInput(
        "ssh-keygen",
        ["-Y", "verify", "-f", signersFile, "-I", signer, "-n", SIGNING_NAMESPACE, "-s", sig],
        canonicalApprovalPayload(key, record),
      );
      return { status: "valid", signer };
    } catch (err) {
      const detail =
        err instanceof Error && "stderr" in err ? String((err as any).stderr).trim() : String(err);
      if (err instanceof Error && (err as NodeJS.ErrnoException).code === "ENOENT") {
        return { status: "error", signer, detail: "ssh-keygen not found on PATH" };
      }
      return { status: "invalid", signer, detail: detail || undefined };
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Verify every entry in an approvals map. */
export async function verifyApprovals(
  approvals: ApprovalsMap,
  cwd: string = process.cwd(),
): Promise<Record<string, SignatureVerification>> {
  const out: Record<string, SignatureVerification> = {};
  for (const [key, record] of Object.entries(approvals)) {
    out[key] = await verifyApprovalSignature(key, record, cwd);
  }
  return out;
}

/**
 * Enforce `requireSignedApprovals`: keep only approvals whose signature
 * verifies; everything else (unsigned, invalid, unverifiable) is dropped —
 * the affected packages simply ask for approval again, the fail-safe
 * direction. Dropped entries are reported so the run says WHY.
 */
export async function enforceSignedApprovals(
  approvals: ApprovalsMap,
  cwd: string = process.cwd(),
): Promise<{ kept: ApprovalsMap; dropped: { key: string; verification: SignatureVerification }[] }> {
  const kept: ApprovalsMap = {};
  const dropped: { key: string; verification: SignatureVerification }[] = [];
  const results = await verifyApprovals(approvals, cwd);
  for (const [key, record] of Object.entries(approvals)) {
    const verification = results[key];
    if (verification.status === "valid") kept[key] = record;
    else dropped.push({ key, verification });
  }
  return { kept, dropped };
}

/**
 * Apply the `requireSignedApprovals` policy to a loaded approvals map: a
 * no-op when the policy is off; otherwise only verified entries survive, and
 * every dropped entry is reported on stderr (stdout may be --json).
 */
export async function applySignedApprovalsPolicy(
  approvals: ApprovalsMap,
  requireSigned: boolean | undefined,
  cwd: string = process.cwd(),
): Promise<ApprovalsMap> {
  if (!requireSigned) return approvals;
  const { kept, dropped } = await enforceSignedApprovals(approvals, cwd);
  for (const { key, verification } of dropped) {
    console.error(
      `[targate] approval for ${key} ignored (requireSignedApprovals): ${verification.status}` +
        (verification.detail ? ` — ${verification.detail}` : ""),
    );
  }
  return kept;
}
