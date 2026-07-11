import { loadApprovals, type ApprovalRecord } from "../approvals.js";
import { printJson } from "../json-output.js";
import { parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import {
  allowedSignersPath,
  verifyApprovals,
  type SignatureVerification,
} from "../signing.js";

export interface HistoryOptions {
  /** Optional "pkg" or "pkg@version" filter. */
  spec?: string;
  json: boolean;
  /** Verify each entry's signature against .targate/allowed-signers. */
  verify: boolean;
}

interface HistoryEntry {
  key: string;
  name: string;
  version: string;
  record: ApprovalRecord;
  verification?: SignatureVerification;
}

/** Split an approvals key back into name + version ("@scope/pkg@1.0.0" safe). */
function splitKey(key: string): { name: string; version: string } {
  const at = key.lastIndexOf("@");
  return at > 0
    ? { name: key.slice(0, at), version: key.slice(at + 1) }
    : { name: key, version: "" };
}

function renderContextLines(record: ApprovalRecord): string[] {
  const c = record.context;
  const lines: string[] = [];
  if (!c) return lines;
  const verdict = [
    c.decision ? `decision at review: ${c.decision}` : null,
    c.risk ? `risk ${c.risk}` : null,
    c.score !== undefined ? `score ${c.score}/100` : null,
  ].filter(Boolean);
  const engine = c.aiProvider
    ? `${c.aiProvider}${c.aiModel ? `/${c.aiModel}` : ""}`
    : c.source === "rules"
      ? "rules engine"
      : null;
  const tooling = [
    c.targateVersion ? `targate ${c.targateVersion}` : null,
    engine,
    c.policyFile
      ? `policy ${c.policyFile}${c.policyHash ? `#${c.policyHash.slice(0, 12)}` : ""}`
      : "no policy file",
  ].filter(Boolean);
  if (verdict.length > 0) lines.push(dim(`      ${verdict.join(" · ")}`));
  if (tooling.length > 0) lines.push(dim(`      ${tooling.join(" · ")}`));
  for (const reason of c.reasons ?? []) lines.push(dim(`      - ${reason}`));
  return lines;
}

function renderVerification(v: SignatureVerification): string {
  switch (v.status) {
    case "valid":
      return green(`✓ signature valid (${v.signer})`);
    case "invalid":
      return red(`✗ signature INVALID (${v.signer})${v.detail ? ` — ${v.detail}` : ""}`);
    case "unsigned":
      return yellow("⚠ unsigned");
    case "no-allowed-signers":
      return yellow(`⚠ signed (${v.signer}) but no .targate/allowed-signers to verify against`);
    case "error":
      return red(`✗ verification error${v.detail ? ` — ${v.detail}` : ""}`);
  }
}

/**
 * `targate history [pkg[@version]]` — the trust history: every recorded
 * approval, who made it, when, under which policy/tool/AI, newest first.
 * With --verify, each entry's SSH signature is checked against the committed
 * .targate/allowed-signers file (exit 2 when any signature is invalid or
 * errored — an unsigned entry alone does not fail).
 */
export async function historyCommand(opts: HistoryOptions): Promise<number> {
  const cwd = process.cwd();
  const approvals = await loadApprovals(cwd);
  const filter = opts.spec ? parsePackageSpec(opts.spec) : null;

  const verifications = opts.verify ? await verifyApprovals(approvals, cwd) : null;

  const entries: HistoryEntry[] = Object.entries(approvals)
    .map(([key, record]) => ({ key, ...splitKey(key), record }))
    .filter(
      (e) =>
        !filter ||
        (e.name === filter.name && (!filter.version || e.version === filter.version)),
    )
    .map((e) => ({ ...e, verification: verifications?.[e.key] }))
    // Newest approvals first; entries without a date sort last.
    .sort((a, b) => (b.record.approvedAt ?? "").localeCompare(a.record.approvedAt ?? ""));

  const invalid = entries.filter(
    (e) => e.verification && (e.verification.status === "invalid" || e.verification.status === "error"),
  );

  if (opts.json) {
    printJson("history", {
      package: filter?.name,
      total: entries.length,
      allowedSigners: opts.verify ? allowedSignersPath(cwd) : undefined,
      entries: entries.map(({ key, name, version, record, verification }) => ({
        key,
        name,
        version,
        ...record,
        verification,
      })),
      exitCode: invalid.length > 0 ? 2 : 0,
    });
    return invalid.length > 0 ? 2 : 0;
  }

  if (entries.length === 0) {
    console.log(
      yellow(
        filter
          ? `No recorded approvals for ${filter.name}${filter.version ? `@${filter.version}` : ""}.`
          : "No recorded approvals — nothing in .targate/approvals.*.",
      ),
    );
    console.log(dim("Approvals are recorded by `targate approve <pkg>` and the install pickers."));
    return 0;
  }

  console.log(
    bold(`\nTrust history`) +
      dim(
        ` — ${entries.length} approval(s)${filter ? ` for ${filter.name}` : ""}, newest first`,
      ),
  );
  console.log("");
  for (const e of entries) {
    const who = e.record.approvedBy ?? "unknown";
    const when = e.record.approvedAt ? e.record.approvedAt.slice(0, 19).replace("T", " ") : "unknown date";
    console.log(
      `  ${cyan(e.key)}  ${dim(`(${e.record.mode})`)}\n      ${bold(who)} ${dim(`on ${when}`)}${
        e.verification ? `  ${renderVerification(e.verification)}` : e.record.signature ? `  ${dim("(signed — run with --verify)")}` : ""
      }`,
    );
    for (const line of renderContextLines(e.record)) console.log(line);
    console.log("");
  }
  console.log(
    dim(
      "  The committed .targate/approvals.json is the source of truth — `git log -- .targate/approvals.json` shows who committed each change.",
    ),
  );

  if (invalid.length > 0) {
    console.log(
      red(bold(`\n${invalid.length} approval(s) failed signature verification.`)) +
        dim(" Under requireSignedApprovals these entries are ignored."),
    );
    return 2;
  }
  return 0;
}
