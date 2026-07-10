# Using targate with AI coding agents

AI coding agents install dependencies on your behalf — and `npm install <pkg>` is the exact moment a package's lifecycle scripts run on your machine. `targate agents init` scaffolds instruction files that make an agent route every install through targate instead:

```bash
targate agents init                       # writes skills/targate/SKILL.md and AGENTS.md
targate agents init --format all          # also cursor, windsurf, copilot, cline
```

Existing files are never overwritten. Commit the results so every agent working in the repo is bound by the same contract, which is:

- **Before adding any dependency, run `targate add <pkg> --yes`** (add `--deep` for production deps) instead of `npm`/`pnpm`/`yarn add`. With `--yes`, targate installs `allow` / `allow_with_warnings` packages automatically but **never** auto-installs `require_approval` / `block` — those still need a human.
- **To install a whole project's dependencies** (a bare `npm`/`pnpm`/`yarn install`, e.g. after cloning), run **`targate install`** instead — it vets the entire tree before any script runs.
- **Read the exit code**: `0` proceed, `2` stop (blocked or needs approval — surface the reasons), `1` error.
- **Never bypass a BLOCK** by calling the package manager directly. This is the load-bearing guardrail; without it an agent will "just try npm" the moment targate refuses.
- **`targate approve` is a human affordance**, not an agent one — agents must not run it to get past a gate. When targate exits `2`, surface the reasons and let a person decide.
- targate stays **provider-agnostic**: the skill never sets `--provider`, so targate auto-detects a model from the environment or falls back to its deterministic rules engine (no AI provider needed).

One canonical contract is rendered per ecosystem:

| `--format` | File | Serves |
|---|---|---|
| `skill` | `skills/targate/SKILL.md` | Claude Code, Claude Agent SDK, claude.ai |
| `agents` | `AGENTS.md` | Codex / "ChatGPT", Cursor, Continue, and other agents that read AGENTS.md |
| `cursor` | `.cursor/rules/targate.mdc` | Cursor |
| `windsurf` | `.windsurf/rules/targate.md` | Windsurf |
| `copilot` | `.github/copilot-instructions.md` | GitHub Copilot |
| `cline` | `.clinerules` | Cline |

The default (`skill,agents`) covers the two most widely-read formats; the thin adapters carry the core rule and point back to `AGENTS.md`.
