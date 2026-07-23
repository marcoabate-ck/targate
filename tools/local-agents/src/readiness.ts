/**
 * Fast Ollama readiness probe.
 *
 * Spawning a worker only to have Claude Code retry for a minute against a dead
 * endpoint is a poor failure mode. This cheap check (a single short GET) lets
 * the CLI fail fast with an actionable message before any worker starts, and
 * lets the worker runner translate a connection error into a clear hint.
 */

export interface ReadinessResult {
  ok: boolean;
  message: string;
}

/** Probe `<baseUrl>/api/version`. Never throws — returns ok:false on failure. */
export async function probeOllama(
  baseUrl: string,
  opts: { fetchFn?: typeof fetch; timeoutMs?: number } = {},
): Promise<ReadinessResult> {
  const f = opts.fetchFn ?? fetch;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), opts.timeoutMs ?? 2_500);
  try {
    const res = await f(`${baseUrl}/api/version`, { signal: ac.signal });
    if (res.status === 200) return { ok: true, message: "Ollama is reachable" };
    return { ok: false, message: `Ollama returned HTTP ${res.status} from /api/version` };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      message:
        `Ollama is not reachable at ${baseUrl} (${detail}). ` +
        "Start it with `ollama serve`, then run `local-agents doctor`.",
    };
  } finally {
    clearTimeout(timer);
  }
}

/** True when stderr from a worker indicates the local endpoint was unreachable. */
export function isConnectionError(stderr: string): boolean {
  return /econnrefused|connection refused|connect econn|fetch failed|socket hang up|econnreset|network error/i.test(
    stderr,
  );
}
