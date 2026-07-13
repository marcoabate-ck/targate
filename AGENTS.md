# Dependency installs — use targate

`targate` is a pre-install security gate for npm packages. Installing a package runs its install-time lifecycle scripts on this machine, so every new dependency must be analyzed by `targate` **before** it is installed.

## The rule

Whenever you would run `npm install <pkg>`, `pnpm add <pkg>`, or `yarn add <pkg>` — or the user asks you to add a package — run this instead:

```bash
targate add <package>[@version] --yes
```

- `--yes` lets targate install packages it rates `allow` / `allow_with_warnings` automatically, while it will **never** auto-install a package rated `require_approval` or `block` — those always require a human.
- Add `--deep` for production/runtime dependencies to also analyze the full transitive tree: `targate add <pkg> --yes --deep`.
- Add `--json` when you need to parse the verdict programmatically (prints `{ schemaVersion, command, metadata, signals, assessment, score, deep, install }`; the decision is `assessment.decision`, while `install.status` is the actual install outcome; new keys may be added within a schemaVersion — ignore unknown keys).
- Inspect `signals.artifact.trust` in JSON when artifact provenance matters. `mutated` is a non-overridable hard block; `unverified`, `private-only`, and `public-unavailable` are explicit weaker-trust states, never proof of authenticity.
- If `signals.analysisDegraded` is present, treat every listed item as **UNKNOWN**, not clean. Resource-limit results require human approval; do not raise limits or reinterpret placeholder `false` fields to make the install pass.
- Add `--no-cache` to force a fresh analysis, ignoring any cached verdict — e.g. when re-checking a package you suspect changed. Different tarball bytes always invalidate automatically because the SHA-512 artifact digest is part of the cache key.

To install **all** dependencies of a project (e.g. after cloning), run `targate install` instead. It reviews the exact committed lockfile and installs it immutably with scripts disabled by default. Use `--update-lockfile` only when you explicitly want targate to stage, review, and apply a lockfile update. It refuses (exit 2) if any package is blocked or needs approval. Same exit-code contract as below.

## Interpret the exit code

- **0** — proceed. The package was installed (or, with `--dry-run`, analyzed cleanly).
- **2** — STOP. The package is blocked or needs human approval. Surface `assessment.reasons` and any `assessment.suggestedAlternatives` to the user and let them decide. Do **not** install it.
- **1** — an error occurred (e.g. package not found). Report it; do not install.

## Read-only helpers

These analyze and report but never install and never record anything — use them to give the user context:

- `targate recommend "<need>"` — when the user asks for a library and hasn't named one ("add a date-formatting lib"), suggest candidates first: npm-search results plus AI-proposed names (hallucinated names are rejected on registry lookup), each analyzed with the full deterministic pipeline and ranked safest-first, with security scores and reasons. The AI only contributes candidate names — scoring and ranking are deterministic. Pick from the recommendations (or present them), then gate the actual install with `targate add`.
- `targate diff <pkg>` — before **upgrading** an existing dependency: what changed between the installed and latest version (lifecycle scripts, dependencies, maintainers, advisories, size) with an upgrade-risk rating. `targate diff <pkg>@<from> <pkg>@<to>` compares two explicit versions. Exit 2 means the diff risk is at/above `--fail-on` (default: high) — treat it like a gate: report, don't proceed.
- `targate explain <pkg>` — why a package would be allowed or blocked, in plain language (`targate explain --last` re-explains the run that just finished, offline).
- `targate history <pkg>` — the team's trust history: who approved which version, when, and under which policy/AI model. Useful when a gate stops you on a package the team has approved before at a different version.
- `targate graph --why <pkg>` — every dependency chain that pulls a package into the tree, risk-annotated ("why is this here?"). `targate graph` writes an interactive HTML risk graph of the whole tree when the user asks for an overview.

## Hard guardrails

- **Never bypass a targate BLOCK** by calling `npm`/`pnpm`/`yarn` directly. If targate refuses a package, that decision stands until a human overrides it.
- **Do not run `targate approve` to get past a gate.** `targate approve <pkg>` records a human approval without installing — it is a **human** affordance for clearing a `require_approval` / soft block. When targate exits 2, surface the reasons and let a person decide; don't approve on their behalf.
- **Never manufacture trust.** Do not edit `.targate/approvals.json`, `.targate/artifacts.json`, `.targate/allowed-signers`, the team policy, or `.npmrc` to change what passes the gate, and never run `targate approve --sign` — a signature asserts a **human** identity with that person's SSH key. Artifact-identity mismatches cannot be cleared with `targate approve`.
- **Do not disable analysis** (`--no-ai` only changes the reasoning layer; it does not weaken the deterministic security floor — but there is no flag that turns the gate off, and you should not try to find one).
- **Do not enable executable repository config.** Never set `TARGATE_ALLOW_EXEC_CONFIG=1` on the user's behalf. YAML/JSON is the safe default; running legacy JS/TS policy is a human trust decision.
- **Do not choose targate's AI provider.** Run `targate` with no `--provider` flag: it auto-detects a configured model from the environment, or falls back to its built-in deterministic rules engine. It works fully offline.

## In CI

Do not use `targate add` in CI pipelines. Use the CI check, which reviews the dependencies a change adds or updates and fails the build on a blocked/unapproved package:

```bash
targate ci --fail-on-osv-error
```

## Hardening a repo for agent installs

If the user asks to set up or tighten dependency policy for a repo where agents install packages, suggest `targate policy init --preset ai-agent` — a ready-made policy pack that stops the agent on anything needing human judgment (young packages, native code, lifecycle scripts, missing repos). Only scaffold it when the user asks; policy is a team decision.
