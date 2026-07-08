# targate documentation

Detailed specifications for [`targate`](../README.md). Start with the root README for an overview and quick start; these pages go deep on each topic.

## Concepts

- [How it works](how-it-works.md) — the pre-install analysis pipeline, step by step.
- [Decision policy](decisions.md) — how a verdict is chosen, and the hard-vs-soft-block distinction.
- [Security model, scope & limitations](security.md) — what targate does and does not guarantee, OSV failure handling, compatibility notes.

## Commands & usage

- [CLI reference](cli-reference.md) — every command, option, and exit code.
- [Transitive dependencies & full-tree install](transitive-and-install.md) — `--deep` and `targate install`.
- [Sandboxed trial install](sandbox.md) — `targate sandbox` in a disposable Docker container.
- [CI integration](ci.md) — `targate ci` for pull requests.

## Configuration & workflow

- [AI providers](ai-providers.md) — anthropic, deepseek, openai, ollama, custom; reasoning support.
- [AI response cache](ai-cache.md) — how re-reviews are cached, and how to configure it.
- [Team workflow](team-workflow.md) — approving packages, the approvals cache, pnpm `approve-builds`, and the team policy file.
- [Using targate with AI coding agents](agents.md) — `targate agents init` and the agent contract.

## Ecosystem-specific

- [React Native hardening](react-native.md) — Podspec / Gradle / permissions / native-surface review.
