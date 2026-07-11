/**
 * The stable `--json` output contract.
 *
 * Every machine-readable payload targate prints is a single JSON document on
 * stdout, wrapped in a flat envelope: `{ schemaVersion, command, ...payload }`.
 * The envelope is additive on purpose — existing consumers that read
 * `assessment.decision` (etc.) at the top level keep working.
 *
 * Stability rules (documented in docs/cli-reference.md):
 * - within a schemaVersion, changes are ADDITIVE ONLY — consumers must ignore
 *   unknown keys;
 * - any removal, rename, or type change bumps JSON_SCHEMA_VERSION.
 */

export const JSON_SCHEMA_VERSION = 1;

export type JsonCommand =
  | "add"
  | "approve"
  | "install"
  | "ci"
  | "cache"
  | "doctor"
  | "explain"
  | "diff"
  | "monitor"
  | "sandbox"
  | "history"
  | "recommend"
  | "graph";

/** Payload keys may not collide with envelope keys — enforced at the type level. */
type EnvelopeSafe = object & { schemaVersion?: never; command?: never };

export interface JsonEnvelope {
  schemaVersion: typeof JSON_SCHEMA_VERSION;
  command: JsonCommand;
}

export function toJsonEnvelope<T extends EnvelopeSafe>(
  command: JsonCommand,
  payload: T,
): JsonEnvelope & T {
  return { schemaVersion: JSON_SCHEMA_VERSION, command, ...payload };
}

/** The single stdout JSON emission path: exactly one console.log, 2-space indent. */
export function printJson<T extends EnvelopeSafe>(command: JsonCommand, payload: T): void {
  console.log(JSON.stringify(toJsonEnvelope(command, payload), null, 2));
}
