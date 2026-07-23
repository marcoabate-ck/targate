/**
 * PreToolUse hook — the deterministic security gate for a local worker.
 *
 * Claude Code runs this before every tool call, passing the tool name and
 * input on stdin. It emits an allow/deny decision. Workers run under
 * `--permission-mode bypassPermissions` (a non-interactive process cannot
 * answer prompts), so THIS hook — not the interactive permission system — is
 * what actually authorises each action. It is deny-by-default: only the safe
 * tool/command surface for the worker's role is allowed.
 *
 * Role and scope arrive via the worker environment (set by worker.ts):
 *   LOCAL_AGENT_ROLE, LOCAL_AGENT_READONLY ("1"|"0"), LOCAL_AGENT_SCOPES.
 */

import { classifyCommand } from "./command-guard.js";
import { isWithinScopes } from "./paths.js";
import { writeSync } from "node:fs";
import path from "node:path";

// FAIL CLOSED. A PreToolUse hook that exits non-zero with code 2 blocks the
// tool call regardless of permission mode. Any crash before we emit an explicit
// decision must therefore become an exit-2 block, never a silent pass.
process.on("uncaughtException", () => process.exit(2));
process.on("unhandledRejection", () => process.exit(2));

interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
}

type Decision = "allow" | "deny";

const READ_TOOLS = new Set([
  "Read",
  "Grep",
  "Glob",
  "LS",
  "NotebookRead",
  "TodoWrite",
]);

const WRITE_TOOLS = new Set(["Edit", "Write", "MultiEdit"]);
const NOTEBOOK_WRITE = new Set(["NotebookEdit"]);
const DENIED_TOOLS = new Set(["Task", "WebFetch", "WebSearch"]);

function emit(decision: Decision, reason: string): never {
  const payload =
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }) + "\n";
  // Synchronous write + exit: the decision is flushed and execution stops here
  // (no code after an emit() call ever runs). Exit 0: the JSON carries the
  // verdict.
  try {
    writeSync(1, payload);
  } catch {
    // If we cannot even write the decision, fail closed.
    process.exit(2);
  }
  process.exit(0);
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    // If nothing arrives, do not hang forever.
    setTimeout(() => resolve(data), 2_000).unref?.();
  });
}

function scopes(): string[] {
  const raw = process.env.LOCAL_AGENT_SCOPES ?? process.cwd();
  return raw.split(path.delimiter).filter(Boolean);
}

function filePathsFrom(tool: string, input: Record<string, unknown>): string[] {
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === "string" && v.length > 0) out.push(v);
  };
  if (tool === "NotebookEdit") push(input.notebook_path);
  else push(input.file_path);
  return out;
}

async function main(): Promise<void> {
  const readOnly = process.env.LOCAL_AGENT_READONLY === "1";
  let input: HookInput = {};
  try {
    const raw = await readStdin();
    if (raw.trim()) input = JSON.parse(raw) as HookInput;
  } catch {
    emit("deny", "guard could not parse hook input");
  }

  const tool = input.tool_name ?? "";
  const toolInput = input.tool_input ?? {};

  if (READ_TOOLS.has(tool)) emit("allow", "read-only tool");
  if (DENIED_TOOLS.has(tool)) emit("deny", `${tool} is not permitted for local workers`);

  if (tool === "Bash") {
    const command = typeof toolInput.command === "string" ? toolInput.command : "";
    const verdict = classifyCommand(command, { readOnly });
    emit(verdict.decision, verdict.reason);
  }

  if (WRITE_TOOLS.has(tool) || NOTEBOOK_WRITE.has(tool)) {
    if (readOnly) emit("deny", `${tool} denied: this role is read-only`);
    const targets = filePathsFrom(tool, toolInput);
    if (targets.length === 0) emit("deny", `${tool} without a file path`);
    const allowed = scopes();
    for (const t of targets) {
      if (!isWithinScopes(allowed, path.resolve(t))) {
        emit("deny", `${tool} target is outside the assigned scope: ${t}`);
      }
    }
    emit("allow", "write within scope");
  }

  // Unknown tool: fail closed.
  emit("deny", `tool "${tool}" is not on the worker allowlist`);
}

main().catch(() => process.exit(2));
