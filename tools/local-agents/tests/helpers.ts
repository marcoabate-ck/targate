import { EventEmitter } from "node:events";

/** A fake ChildProcess for driving worker.ts without spawning a real process. */
export interface FakeSpawnScript {
  stdout?: string;
  stderr?: string;
  exitCode?: number | null;
  /** Emit an 'error' event (e.g. ENOENT) instead of running. */
  spawnError?: Error;
  /** Never emit 'close' — used to exercise the timeout path. */
  hang?: boolean;
  /** Delay before emitting close, ms. */
  delayMs?: number;
}

export function fakeSpawn(script: FakeSpawnScript) {
  return function spawn() {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: (sig?: string) => boolean;
      killed: boolean;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.killed = false;
    child.kill = (_sig?: string) => {
      child.killed = true;
      // A well-behaved process exits after SIGTERM.
      setImmediate(() => child.emit("close", null));
      return true;
    };

    setImmediate(() => {
      if (script.spawnError) {
        child.emit("error", script.spawnError);
        return;
      }
      if (script.stdout) child.stdout.emit("data", Buffer.from(script.stdout));
      if (script.stderr) child.stderr.emit("data", Buffer.from(script.stderr));
      if (script.hang) return; // never close
      const emitClose = () => child.emit("close", script.exitCode ?? 0);
      if (script.delayMs) setTimeout(emitClose, script.delayMs);
      else emitClose();
    });

    return child as never;
  };
}

/** Build a Claude Code JSON wrapper around a worker body. */
export function claudeWrapper(body: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: "result",
    subtype: "success",
    is_error: false,
    result: typeof body === "string" ? body : JSON.stringify(body),
    session_id: "test",
    num_turns: 3,
    usage: { input_tokens: 100, output_tokens: 50 },
    ...extra,
  });
}

export const VALID_BODY = {
  status: "completed",
  summary: "did the thing",
  filesRead: ["src/a.ts"],
  filesChanged: [],
  commandsExecuted: [{ command: "git status", exitCode: 0 }],
  findings: [],
  questions: [],
  errors: [],
};
