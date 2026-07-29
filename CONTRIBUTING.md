# Contributing to targate

Thanks for your interest. targate is an install-time supply-chain security tool, so the bar for changes —
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

## Try it as a collaborator (pre-release feedback)

targate is not published yet. To try it as a real CLI and send feedback, build
and link it from a clone:

```bash
git clone https://github.com/marcoabate-ck/targate.git
cd targate
git checkout develop          # or the branch under test
pnpm install
pnpm build
node dist/cli.js --help       # run it in place — no global setup needed
```

To type `targate` directly instead of `node dist/cli.js`, register its bin on your PATH:

```bash
pnpm setup           # one-time: creates pnpm's global bin dir on PATH (restart your shell afterwards)
pnpm add -g .        # pnpm ≥ 11, from the repo root — registers the built `targate` bin globally
# pnpm ≤ 10:  pnpm link --global   (removed in pnpm 11 — use `pnpm add -g .` instead)
targate --help
```

Exercise it against a throwaway project (nothing installs without confirmation):

```bash
mkdir /tmp/targate-trial && cd /tmp/targate-trial && npm init -y
targate add lodash --dry-run                # ALLOW (deterministic)
targate add react-native-mmkv --dry-run     # REQUIRE APPROVAL (native surface)
targate add flatmap-stream --dry-run        # BLOCK (known-malicious OSV record)
```

Notes:

- **Without an AI key** targate runs on the deterministic rules engine. To exercise
  the AI reasoning, export a provider key (`ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`,
  `OPENAI_API_KEY`, or point at a local Ollama). Use your **own** key.
- The `brew` / `npm i -g targate` / install-script methods do **not** work yet (no
  published release) — only this build-and-link flow.
- Unlink when done: `pnpm uninstall --global targate`.

Please send feedback via a **Feedback** issue (the template prompts for DX, verdict
clarity, and any false positive/negative). Security problems go through
[SECURITY.md](SECURITY.md), never a public issue.

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
