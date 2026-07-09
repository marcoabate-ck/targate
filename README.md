# targate — gate every dependency before it runs

AI-gated package installation built on top of React Native teams' needs. `targate` analyzes an npm package **before** it touches your machine — metadata, lifecycle scripts, tarball contents, React Native native surface, and known malicious-package records — then produces an allow / warn / approve / block decision and only runs the real install if the package passes.

Installing a package runs its lifecycle scripts on your machine. `targate` gates that moment.

## Quick start

```bash
pnpm install
pnpm build

# Analyze without installing (pure preview)
pnpm dev add react-native-mmkv --dry-run

# Full flow (analysis + gated install)
pnpm dev add react-native-mmkv
```

Or link the binary: `pnpm link --global` → `targate add <package>`.

## How it works

```
developer intent → package inspection → AI risk reasoning → safe install decision
```

targate resolves the package from npm, extracts the tarball into quarantine (scripts never run), statically inspects lifecycle scripts and contents, checks OSV/OpenSSF for malicious records, maps the React Native native surface, then reasons over every signal — with an AI provider if one is configured, or a deterministic rules engine otherwise. **Every deterministic BLOCK is a hard floor the AI can never downgrade.** Full walkthrough: [docs/how-it-works.md](docs/how-it-works.md).

## Commands at a glance

| Command | What it does |
|---|---|
| `targate add <pkg>` | Analyze one package, then gate the install (`--deep` for its whole tree) |
| `targate approve <pkg>` | Record a committable approval **without** installing |
| `targate install` | Vet the **entire** dependency tree, then gate a full install |
| `targate sandbox <pkg>` | Trial-install in a disposable Docker container |
| `targate ci` | Analyze the dependencies a PR adds/updates; fail the build on a bad one |
| `targate policy init` | Scaffold the team policy file |
| `targate agents init` | Scaffold instruction files so AI coding agents gate installs through targate |

Exit codes: `0` ok · `1` error · `2` blocked (or suspicious sandbox / failed CI check). Full flags and options: [docs/cli-reference.md](docs/cli-reference.md).

## Key guarantees

- **Deterministic security floor.** The rules engine decides first; the AI can only make a verdict *stricter*. A jailbroken or prompt-injected model cannot turn a rules-engine BLOCK into an allow. See [docs/decisions.md](docs/decisions.md).
- **Hard vs soft blocks.** Known-malicious and remote-code-execution blocks can never be overridden; heuristic ("soft") blocks can be deliberately cleared by a committed approval or allow-list entry.
- **Nothing untrusted executes during analysis.** Tarballs are checksum-verified against the registry manifest, extracted into quarantine with strict path checking, and only ever *read* — lifecycle scripts never run. (One caveat: `.ts`/`.js` **config** files do execute; set `TARGATE_NO_EXEC_CONFIG=1` in repos you don't trust — see [docs/security.md](docs/security.md).)
- **Works offline.** With no AI provider configured, targate runs entirely on the rules engine — no network call to any model.
- **Fail-closed option.** `--fail-on-osv-error` escalates when the malicious-package lookup can't complete, so a package is never silently trusted while the strongest check was skipped.

## Documentation

Full specifications live in [`docs/`](docs/README.md):

| Topic | Page |
|---|---|
| The analysis pipeline | [how-it-works.md](docs/how-it-works.md) |
| Every command, flag, exit code | [cli-reference.md](docs/cli-reference.md) |
| Decision policy · hard vs soft blocks | [decisions.md](docs/decisions.md) |
| AI providers · reasoning support | [ai-providers.md](docs/ai-providers.md) |
| AI response cache | [ai-cache.md](docs/ai-cache.md) |
| `--deep` & `targate install` | [transitive-and-install.md](docs/transitive-and-install.md) |
| Approvals · pnpm builds · team policy | [team-workflow.md](docs/team-workflow.md) |
| React Native hardening | [react-native.md](docs/react-native.md) |
| Sandboxed trial install | [sandbox.md](docs/sandbox.md) |
| CI integration | [ci.md](docs/ci.md) |
| AI coding agents | [agents.md](docs/agents.md) |
| Security model, scope & limitations | [security.md](docs/security.md) |

## Development

```bash
pnpm test        # vitest suite (298 tests, incl. end-to-end CI and full-install checks on fixture repos)
pnpm typecheck
pnpm dev add <pkg>   # run from source
```
