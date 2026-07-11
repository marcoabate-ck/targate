# Dependency installs — use targate

`targate` is a pre-install security gate for npm packages. Installing a package runs its install-time lifecycle scripts on this machine, so every new dependency must be analyzed by `targate` **before** it is installed.

## The rule

Whenever you would run `npm install <pkg>`, `pnpm add <pkg>`, or `yarn add <pkg>` — or the user asks you to add a package — run this instead:

```bash
targate add <package>[@version] --yes
```

- `--yes` lets targate install packages it rates `allow` / `allow_with_warnings` automatically, while it will **never** auto-install a package rated `require_approval` or `block` — those always require a human.
- Add `--deep` for production/runtime dependencies to also analyze the full transitive tree: `targate add <pkg> --yes --deep`.
- Add `--json` when you need to parse the verdict programmatically (prints `{ schemaVersion, command, metadata, signals, assessment, score, deep }`; the decision is `assessment.decision`, one of `allow`, `allow_with_warnings`, `require_approval`, `block`; new keys may be added within a schemaVersion — ignore unknown keys).
- Add `--no-cache` to force a fresh analysis, ignoring any cached verdict — e.g. when re-checking a package you suspect changed. (targate caches AI assessments between runs; it also invalidates automatically when a package's contents or the model change.)

To install **all** dependencies of a project (a plain `npm install` / `pnpm install` / `yarn install` — e.g. after cloning), run `targate install` instead. It vets the entire dependency tree before the install runs any lifecycle scripts, refuses (exit 2) if any package is blocked or needs approval, and otherwise installs with scripts disabled by default (`--allow-scripts` to run them). Same exit-code contract as below.

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

## Hard guardrails

- **Never bypass a targate BLOCK** by calling `npm`/`pnpm`/`yarn` directly. If targate refuses a package, that decision stands until a human overrides it.
- **Do not run `targate approve` to get past a gate.** `targate approve <pkg>` records a human approval without installing — it is a **human** affordance for clearing a `require_approval` / soft block. When targate exits 2, surface the reasons and let a person decide; don't approve on their behalf.
- **Never manufacture trust.** Do not edit `.targate/approvals.json`, `.targate/allowed-signers`, the team policy, or `.npmrc` to change what passes the gate, and never run `targate approve --sign` — a signature asserts a **human** identity with that person's SSH key.
- **Do not disable analysis** (`--no-ai` only changes the reasoning layer; it does not weaken the deterministic security floor — but there is no flag that turns the gate off, and you should not try to find one).
- **Do not choose targate's AI provider.** Run `targate` with no `--provider` flag: it auto-detects a configured model from the environment, or falls back to its built-in deterministic rules engine. It works fully offline.

## In CI

Do not use `targate add` in CI pipelines. Use the CI check, which reviews the dependencies a change adds or updates and fails the build on a blocked/unapproved package:

```bash
targate ci --fail-on-osv-error
```

## Hardening a repo for agent installs

If the user asks to set up or tighten dependency policy for a repo where agents install packages, suggest `targate policy init --preset ai-agent` — a ready-made policy pack that stops the agent on anything needing human judgment (young packages, native code, lifecycle scripts, missing repos). Only scaffold it when the user asks; policy is a team decision.
