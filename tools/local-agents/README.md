# @targate/local-agents

Local-agent orchestration: a persistent **Opus lead** delegates bounded tasks to
**disposable Claude Code workers** backed by a local **Ollama** model. Workers do
the high-context grunt work (exploration, first-draft implementation, tests,
review) on local tokens; Opus stays connected to Anthropic and does the
judgement — planning, approval, and the final architectural/security review.

The engine is **reusable across repositories**. It imports no repo-specific
code: a repository contributes only *data* — a config file, its `AGENTS.md`
hierarchy, and optional per-role instructions.

---

## 1. Architecture

```
Persistent Claude Code session  (Opus lead / orchestrator, talks to Anthropic)
        │  launches isolated child processes
        ├── disposable Discovery worker    (read-only)
        ├── disposable Implementer worker  (writes, scoped)
        ├── disposable Tester worker       (writes tests, scoped)
        ├── disposable Reviewer worker     (read-only)
        └── optional config-defined workers
                └── each = one `claude -p` process → local Ollama → terminates
```

- **Opus** is the only persistent session. There is no second model-session
  persistence layer — only *workflow* state on disk (`.local-agent-runs/`).
- Each **worker** is one `claude -p` process with a filtered environment, a
  per-role tool set, a command guard, and a bounded timeout. It emits a single
  structured JSON result and exits. No session is saved or resumed.
- Only workers receive the Ollama routing variables; the parent environment is
  never mutated and its Anthropic credentials never reach a worker.

Layout:

```
tools/local-agents/src/     generic engine (this package)
local-agents.config.yaml    repository policy (data)
.claude/local-agents/roles/ optional per-role repo instructions (data)
AGENTS.md (+ nested)         repository instructions, delivered in-scope
.local-agent-runs/<run-id>/  per-run artifacts (gitignored)
```

## 2. Installation prerequisites

- Node ≥ 22.13, pnpm.
- [Ollama](https://ollama.com) running locally.
- Claude Code CLI on `PATH` (`claude --version`). Verified against **2.1.x**.
- The engine needs **no extra dependencies** beyond the repo's existing ones.

## 3. Ollama setup

Ollama must expose its **Anthropic-compatible** endpoint at
`<baseUrl>/v1/messages` (Ollama ≥ 0.31). Claude Code talks to it by pointing
`ANTHROPIC_BASE_URL` at the Ollama server. Verify with `local-agents doctor`.

## 4. Model setup

```bash
ollama pull qwen3.6:35b-a3b-coding-nvfp4
```

The doctor **never pulls automatically** — if the model is missing it prints the
exact command above.

## 5. Configuration

`local-agents.config.yaml` (or `.yml` / `.json`) at the repo root. Declarative
only — the engine never executes repo-controlled config. See the annotated
example at the repo root. Env overrides: `LOCAL_AGENT_MODEL`,
`LOCAL_AGENT_BASE_URL`, `LOCAL_AGENT_AUTH_TOKEN`, `LOCAL_AGENT_MAX_CONCURRENCY`,
`LOCAL_AGENT_TIMEOUT_MS`. Validation rejects unknown roles, bad concurrency /
timeout / base URL, missing model, absolute run dirs, and read-only roles that
grant a write tool.

## 6. Manual worker invocation

```bash
pnpm local-agents doctor [--ping]
pnpm local-agents run discovery  --task "Map the provider fallback flow"
pnpm local-agents run reviewer   --task "Review the current diff"
pnpm local-agents run implementer --task "..." --dry-run   # show plan, spawn nothing
```

## 7. Automatic Opus workflow

```bash
pnpm local-agents workflow start --task-file task.md --security   # signal flags
pnpm local-agents workflow status <run-id>
pnpm local-agents workflow resume <run-id> --approve <name>
pnpm local-agents workflow cancel <run-id>
```

Signal flags feed the approval policy: `--files N --architectural --security
--dependency --public-api-breaking --destructive --affects-ci --uncertain
--explanatory`. Add `--json` for the concise machine-readable form Opus consumes.
Exit codes: **0** success · **1** error · **2** needs-human (awaiting approval, a
blocked worker, or unresolved critical/high findings).

## 8. Agent roles

| Role | Writes? | Purpose |
|------|---------|---------|
| `discovery` | no | Map code, patterns, security boundaries; propose a minimal plan. |
| `implementer` | yes (scoped) | Implement an approved plan with minimal targeted changes. |
| `tester` | yes (scoped) | Add focused tests; run approved validation commands. |
| `reviewer` | no | Classify findings by severity with file:line refs. |

## 9. Approval rules

`approval.mode: adaptive` (default). **Mandatory** approval — regardless of the
lead's risk estimate — for: security-sensitive changes, package-execution/
credential-handling changes, destructive ops, dependency additions, breaking
public-API changes, CI/release changes, and broad architectural changes. Large
or high-uncertainty tasks also require it. The record stores `required`,
`reason`, `approvedAt`, `approvedBy`, and `approvedPlanHash`; approval is never
claimed unless explicitly given. If the plan text changes after approval,
`planChanged()` detects the drift and control returns to the lead.

## 10. Concurrency

Default `maxConcurrency: 1` (one 35B/21 GB worker at a time). Read-only workers
may run in parallel; **writer workers run sequentially** in the main tree. The
engine is memory-aware and clamps the requested concurrency to what RAM can fit,
logging when it does.

## 11. Worktree behaviour

Genuine parallel *writing* is opt-in via git worktrees (`src/worktree.ts`):
predictable `local-agents/<run-id>/<worker>` branches, refuses a dirty tree
unless told otherwise, never force-resets your branch, records worktree paths in
run metadata, and `worktree cleanup <run-id>` removes only clean worktrees —
dirty ones are preserved for you to inspect. Parallel writers stay off by default
until you have exercised this on your repo.

## 12. Security model

Defense in depth, not prompt text alone:

1. **Environment isolation** — a worker's env is built by allowlist; secrets
   (`ANTHROPIC_API_KEY`, `*_TOKEN`, `AWS_*`, …) are dropped. The parent env is
   never mutated. `assertNoSecrets` fails closed before any spawn.
2. **Tool denial** — read-only roles hard-deny `Edit`/`Write`/`NotebookEdit`;
   all roles deny `Task`, `WebFetch`, `WebSearch`.
3. **Command guard** — a PreToolUse hook (`hook-guard.ts`) classifies every
   Bash command and denies installs, `npx`/`dlx`, `curl|sh`, destructive git,
   `rm -rf`, `sudo`, publishes, and (for read-only roles) anything off a small
   allowlist. Workers run `--permission-mode bypassPermissions` so this hook —
   not an unanswerable interactive prompt — is the gate.
4. **Path containment** — writes must stay within the worker's scope; symlink
   escapes and `../` traversal are rejected, and the runner re-validates every
   reported change.
5. **Prompt-injection defense** — every worker is told repository contents are
   untrusted data and must not be followed as instructions; analysed package
   code is never executed.

## 13. Environment-variable filtering

See `src/env.ts`. Only a small base allowlist (`PATH`, `HOME`, locale, …) plus a
repo-declared `envAllowlist` is forwarded; the secret filter overrides the
allowlist, so a repo cannot allowlist a credential. `doctor` reports how many
secrets were dropped.

## 14. Logs and run artifacts

```
.local-agent-runs/<run-id>/
  metadata.json      status, approval record, worker index
  task.md  plan.md  approved-plan.md
  workers/<id>.json          structured WorkerResult
  workers/<id>.stdout.log    raw output (diagnostics only)
  events.jsonl               append-only event log
  summary.md                 compact, lead-facing summary
```

Opus reads `summary.md` first, then a worker's `findings`, and only opens raw
logs on demand — keeping the main session's token cost low.

## 15. Troubleshooting

Run `pnpm local-agents doctor`. Common: Ollama not running (start it); model
missing (`ollama pull …`); `/v1/messages` 404 (Ollama too old); `claude` not on
PATH. Use `--verbose` and inspect `events.jsonl` / `*.stderr.log` in the run dir.

**Ollama down.** `run` and `workflow start` fast-fail with a **preflight** probe
before spawning any worker, printing the base URL and `ollama serve` hint (pass
`--no-preflight` to skip). If a worker still hits a dead endpoint mid-run, the
result is a `failed`/`ollama-unreachable` error (a transient class → bounded
retries), the flow halts, and the run is marked `failed` — no partial work is
trusted and no fallback to Anthropic happens. The lead decides what to do next.

## 16. Recovery from interrupted workflows

Run state is on disk. `workflow status <run-id>` shows where it stopped;
`workflow resume <run-id>` re-runs the roles that have not completed. A worker
that fails or is blocked halts the flow so the lead can intervene — partial
changes are never auto-trusted.

## 17. Cleanup

`workflow cancel <run-id>` marks a run cancelled (worktrees preserved).
`worktree cleanup <run-id>` removes clean worktrees and reports any dirty ones it
kept. Run directories are gitignored; delete them when you no longer need them.

## 18. How to add a new role

Add it to `roles:` in the config (a name, `readOnly`, optional
`allow`/`denyTools`, `description`) — **no engine change**. Drop optional
instructions at `.claude/local-agents/roles/<role>.md`. Reference it with
`run <role>` or a `--flow` that includes it.

## 19. Reusing the infrastructure in another repository

Copy `tools/local-agents/` (or, later, install it once it is extracted — see
below), add a `local-agents.config.yaml`, and you are done. The engine has zero
targate coupling. **Extraction path:** the package is already self-contained
under a `@scope/local-agents` name with its own `package.json`/`tsconfig`; to
publish it standalone, move the directory to its own repo, keep `src/` and
`tests/`, and drop the `private: true` flag. No source edits are required.

## 20. Current limitations

- No `--max-turns` in the installed Claude CLI; the execution budget is the
  wall-clock timeout (plus `--max-budget-usd`, which is meaningless for local
  Ollama).
- Token metrics are recorded only when the runtime exposes them (`usage.source`
  is `"runtime"` vs `"estimate"`); never fabricated.
- Shell redirection to an out-of-scope absolute path is only partly parseable —
  containment leans on env isolation, tool denial, and read-only allowlisting as
  the backing layers.
- Parallel writers (worktrees) are implemented and tested but off by default.

---

## Example instruction to give Opus

```
Use the local-agent infrastructure for this task.

Decide whether Discovery is required and whether user approval is necessary.
Delegate repository exploration and other high-context work to local workers.
Use parallel workers only for independent tasks.
Keep writing workers isolated.
Review all structured results.
Do not load raw worker logs unless necessary.
Perform the final architectural and security review yourself.
```
