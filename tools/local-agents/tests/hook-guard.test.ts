import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

const GUARD = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "hook-guard.ts");
const SCOPE = "/tmp/la-scope";

interface HookOutcome {
  decision: string | null;
  code: number | null;
}

/** Invoke the real hook-guard process with a tool payload and env. */
function invoke(payload: unknown, readOnly: boolean): Promise<HookOutcome> {
  return new Promise((resolve) => {
    const child = execFile(
      "node",
      ["--import", "tsx", GUARD],
      {
        env: {
          ...process.env,
          LOCAL_AGENT_READONLY: readOnly ? "1" : "0",
          LOCAL_AGENT_SCOPES: SCOPE,
        },
      },
      (err, stdout) => {
        let decision: string | null = null;
        try {
          decision = JSON.parse(stdout).hookSpecificOutput.permissionDecision;
        } catch {
          decision = null;
        }
        const code = err && typeof (err as { code?: number }).code === "number" ? (err as { code: number }).code : 0;
        resolve({ decision, code });
      },
    );
    child.stdin?.end(typeof payload === "string" ? payload : JSON.stringify(payload));
  });
}

describe("hook-guard (real subprocess)", () => {
  it("allows a read tool", async () => {
    const r = await invoke({ tool_name: "Read", tool_input: { file_path: "/x" } }, true);
    expect(r.decision).toBe("allow");
  });

  it("denies a destructive bash command", async () => {
    const r = await invoke({ tool_name: "Bash", tool_input: { command: "rm -rf /tmp/x" } }, false);
    expect(r.decision).toBe("deny");
  });

  it("allows a read-only bash command for a read-only role", async () => {
    const r = await invoke({ tool_name: "Bash", tool_input: { command: "git status" } }, true);
    expect(r.decision).toBe("allow");
  });

  it("denies a write outside the assigned scope", async () => {
    const r = await invoke({ tool_name: "Write", tool_input: { file_path: "/etc/passwd" } }, false);
    expect(r.decision).toBe("deny");
  });

  it("allows a write inside the assigned scope for a writer", async () => {
    const r = await invoke({ tool_name: "Write", tool_input: { file_path: path.join(SCOPE, "a.ts") } }, false);
    expect(r.decision).toBe("allow");
  });

  it("denies Edit for a read-only role", async () => {
    const r = await invoke({ tool_name: "Edit", tool_input: { file_path: path.join(SCOPE, "a.ts") } }, true);
    expect(r.decision).toBe("deny");
  });

  it("fails closed on garbage input", async () => {
    const r = await invoke("this is not json", false);
    expect(r.decision === "deny" || r.code === 2).toBe(true);
  });

  it("allows the StructuredOutput harness tool (used by --json-schema)", async () => {
    const r = await invoke({ tool_name: "StructuredOutput", tool_input: { status: "completed", summary: "x" } }, true);
    expect(r.decision).toBe("allow");
  });

  it("denies an unknown tool", async () => {
    const r = await invoke({ tool_name: "Frobnicate", tool_input: {} }, false);
    expect(r.decision).toBe("deny");
  });
}, 30_000);
