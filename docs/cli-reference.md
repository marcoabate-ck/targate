# CLI reference

## Commands

```
targate add <package>[@version]         Analyze a package, then gate the install
(targate <package> without a subcommand is a shorthand for targate add)
targate approve <package>[@version]     Analyze and record a committable approval WITHOUT installing
targate install                         Vet the whole dependency tree, then gate a full install
targate sandbox <package>[@version]     Trial install in a disposable Docker container
targate ci [--base-ref <ref>]           Analyze dependencies changed vs a git ref (for PRs)
targate ci init                         Scaffold .github/workflows/targate.yml
targate policy init [--format <fmt>]    Scaffold the team policy (yaml | json | js | ts)
targate cache info                      Show the AI response cache location + size
targate cache clear [--scope <s>]       Delete the AI response cache (user | project)
targate agents init [--format <list>]   Scaffold agent-instruction files (skill, agents,
                                    cursor, windsurf, copilot, cline, or all)
```

| Command | What it gates | Docs |
|---|---|---|
| `add` | one new package (+ `--deep` for its tree) | [Transitive & install](transitive-and-install.md) |
| `approve` | records a committable approval without installing | [Team workflow](team-workflow.md#approving-a-package--targate-approve) |
| `install` | a full-project install (the whole tree at once) | [Transitive & install](transitive-and-install.md#full-tree-install--targate-install) |
| `sandbox` | a disposable Docker trial install | [Sandbox](sandbox.md) |
| `ci` | dependencies a change adds/updates, in a PR | [CI integration](ci.md) |
| `policy init` | scaffolds the team policy file | [Team workflow](team-workflow.md#team-policy--targatepolicy) |
| `cache` | inspect / clear the AI response cache | [AI response cache](ai-cache.md#invalidating-the-cache) |
| `agents init` | scaffolds agent-instruction files | [AI coding agents](agents.md) |

## Options (add & ci)

```
--package-manager <pm>  Force pnpm | npm | yarn (default: auto-detect from lockfile)
--json                  Machine-readable output (metadata + signals + assessment)
--dry-run               Analyze and report only — never prompt, never install
                        (to approve without installing, use `targate approve`)
--yes                   Skip confirmation for allow/allow-with-warnings
                        (approve: skip the lifecycle-scripts prompt)
--no-ai                 Skip the AI reasoning layer, use rules only
--no-cache              Ignore cached AI assessments for this run (recompute);
                        fresh results still refresh the cache
--provider <name>       anthropic | deepseek | openai | ollama | custom
--model <name>          Override the model for the selected provider
--base-url <url>        API base URL (required for --provider custom)
--api-key <key>         API key (prefer env vars over this flag)
--reasoning             Enable model reasoning where the provider supports it
                        (see ai-providers.md#reasoning-support---reasoning)
--deep                  (add, approve) Also analyze the full transitive dependency
                        tree; the strictest verdict in the tree gates it
--concurrency <n>       (add --deep, install) Packages analyzed in parallel
                        (default: 16). Lower it if a cloud AI provider rate-limits you.
--no-ai-batch           (add --deep, install) Assess each package in its own AI
                        request instead of batching several per request (stricter
                        per-package isolation; slower/costlier)
--allow-scripts         (approve) Record the approval as scripts-allowed (default:
                        no-scripts) — (install) run lifecycle scripts
--frozen-lockfile       (install) Immutable install (npm ci / --frozen-lockfile)
--base-ref <ref>        (ci) Git ref to diff against (default: origin/main)
```

## Options (sandbox)

```
--image <image>         Docker image (default: node:20-alpine)
--timeout <seconds>     Kill the sandbox after N seconds (default: 300)
--network <mode>        open (default, full egress) | none (offline trial)
```

## Exit codes

`0` ok, `1` error, `2` blocked (or suspicious sandbox / failed CI check).

`--dry-run` is a pure preview: analyze and report only — it never prompts, never installs, and records nothing. To approve a package without installing it, use [`targate approve`](team-workflow.md#approving-a-package--targate-approve).
