# Contributing to targate

Thanks for your interest. targate is a security tool, so the bar for changes —
especially anything touching the decision path — is deliberately high. This guide
explains how to get a change merged.

> Reporting a **security vulnerability**? Do not open an issue or PR. Follow
> [SECURITY.md](SECURITY.md) instead.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Open an issue before a large change so we can agree on the approach first.
- Keep pull requests focused: one logical change per PR.

## Development setup

Requires **Node ≥ 22.13** and **pnpm** (the repo pins the version via
`packageManager`).

```bash
pnpm install
pnpm build
pnpm dev add <pkg> --dry-run   # run from source (tsx)
```

## The gate — run these before you push

Every one of these runs in CI on Node 22 and 24 across Linux and Windows. Run them
locally first:

```bash
pnpm typecheck      # tsc --strict, no errors
pnpm test           # full vitest suite
pnpm format:check   # zero-dependency whitespace/format gate
pnpm docs:check     # generated CLI docs, examples, and local links are consistent
pnpm pack:check     # the published tarball ships only the intended files and the bin runs
pnpm audit          # runtime dependency advisories (high and above)
```

Notes:

- **No external linter/formatter.** Type safety is `tsc`; formatting is
  `format:check`. Do not add a toolchain dependency to bypass this.
- **Docs are generated.** The command tables in `README.md` and
  `docs/cli-reference.md` are produced from `src/command-registry.ts`. Change the
  registry, then regenerate/update the committed blocks so `docs:check` passes — do
  not hand-edit inside the `<!-- targate:*:start/end -->` markers to diverge from the
  registry.
- **Snapshots.** Help output is snapshot-tested (`test/command-registry.test.ts`). If
  you intentionally change help text, update snapshots with `pnpm exec vitest run -u`
  and review the diff.

## Tests are required

- New behavior needs tests. Bug fixes need a regression test.
- **Security-relevant code (`src/rules.ts`, `src/trust-decision.ts`, `src/network.ts`,
  `src/quarantine.ts`, `src/signing.ts`, the providers) must be tested adversarially** —
  prove the bad input is rejected, not just that the happy path works. The clamp
  (`clampDecision`) must never be downgradable by AI output; add a test if you touch it.
- Tests must be deterministic and offline. Network is mocked (`vi.stubGlobal("fetch",
  …)` or the registry fixtures) — do not hit the real npm registry or OSV in a test.

## Commit and PR conventions

- Conventional-commit prefixes are used: `feat`, `fix`, `docs`, `chore`,
  `refactor`, `test`, `ci`. Security fixes use `fix(security): …`.
- Fill in the pull-request template. Describe what changed, why, and how you verified
  it. Link the issue.
- The `version` in `package.json` is **not** bumped by hand — releases set it from the
  git tag.

## What makes a change easy to accept

- It keeps the deterministic security floor intact (the AI can only make a verdict
  stricter).
- It fails safe / fails closed on bad input, and says why in the output.
- It does not widen the attack surface (no new `curl | sh`, no new executable-config
  path, no unpinned CI action).
- It is documented where a user would look, and the docs match the implementation.
