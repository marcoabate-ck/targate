---
name: targate
description: >-
  Gate npm dependency installs through the targate security CLI. Use whenever
  installing, adding, or upgrading an npm/pnpm/yarn package (npm install,
  pnpm add, yarn add) or when the user asks to add a dependency. Runs a
  pre-install analysis and refuses malicious or high-risk packages.
---

# Gate npm installs through targate

`targate` is a pre-install security gate for npm packages. Installing a package runs its install-time lifecycle scripts on this machine, so every new dependency must be analyzed by `targate` **before** it is installed.

## The rule

Whenever you would run `npm install <pkg>`, `pnpm add <pkg>`, or `yarn add <pkg>` — or the user asks you to add a package — run this instead:

```bash
targate add <package>[@version] --yes
```

- `--yes` lets targate install packages it rates `allow` / `allow_with_warnings` automatically, while it will **never** auto-install a package rated `require_approval` or `block` — those always require a human.
- Add `--deep` for production/runtime dependencies to also analyze the full transitive tree: `targate add <pkg> --yes --deep`.
- Add `--json` when you need to parse the verdict programmatically (prints `{ metadata, signals, assessment, deep }`; the decision is `assessment.decision`, one of `allow`, `allow_with_warnings`, `require_approval`, `block`).

To install **all** dependencies of a project (a plain `npm install` / `pnpm install` / `yarn install` — e.g. after cloning), run `targate install` instead. It vets the entire dependency tree before the install runs any lifecycle scripts, refuses (exit 2) if any package is blocked or needs approval, and otherwise installs with scripts disabled by default (`--allow-scripts` to run them). Same exit-code contract as below.

## Interpret the exit code

- **0** — proceed. The package was installed (or, with `--dry-run`, analyzed cleanly).
- **2** — STOP. The package is blocked or needs human approval. Surface `assessment.reasons` and any `assessment.suggestedAlternatives` to the user and let them decide. Do **not** install it.
- **1** — an error occurred (e.g. package not found). Report it; do not install.

## Hard guardrails

- **Never bypass a targate BLOCK** by calling `npm`/`pnpm`/`yarn` directly. If targate refuses a package, that decision stands until a human overrides it.
- **Do not run `targate approve` to get past a gate.** `targate approve <pkg>` records a human approval without installing — it is a **human** affordance for clearing a `require_approval` / soft block. When targate exits 2, surface the reasons and let a person decide; don't approve on their behalf.
- **Do not disable analysis** (`--no-ai` only changes the reasoning layer; it does not weaken the deterministic security floor — but there is no flag that turns the gate off, and you should not try to find one).
- **Do not choose targate's AI provider.** Run `targate` with no `--provider` flag: it auto-detects a configured model from the environment, or falls back to its built-in deterministic rules engine. It works fully offline.

## In CI

Do not use `targate add` in CI pipelines. Use the CI check, which reviews the dependencies a change adds or updates and fails the build on a blocked/unapproved package:

```bash
targate ci --fail-on-osv-error
```
