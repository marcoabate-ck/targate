# targate documentation

Detailed specifications for [`targate`](../README.md). Start with the root README for an overview and quick start; these pages go deep on each topic.

## Start here

- [Why targate](why.md) — the problem it solves: lifecycle-script risk, typosquatting, compromised packages, unreviewed AI-agent installs.
- [Full review example](examples/full-review.md) — an allow, a require-approval, and a block, with real output.

## Concepts

- [Architecture](architecture.md) — the pipeline as a map, and the line between deterministic and probabilistic.
- [Performance benchmarks](../benchmarks/README.md) — repeatable cold/warm targets for 10–1000 packages.
- [How it works](how-it-works.md) — the pre-install analysis pipeline, step by step.
- [Decision policy](decisions.md) — how a verdict is chosen, and the hard-vs-soft-block distinction.
- [Threat model](threat-model.md) — what targate helps catch and what it does not guarantee.
- [Security model, scope & limitations](security.md) — the mechanical detail behind those limits: OSV failure handling, scan bounds, compatibility.

## Commands & usage

- [CLI reference](cli-reference.md) — every command, option, and exit code.
- [Dependency graph](dependency-graph.md) — `targate graph`: the tree as an interactive risk graph (filters, workspaces, CI artifacts, `--why`).
- [Transitive dependencies & full-tree install](transitive-and-install.md) — `--deep` and `targate install`.
- [Sandboxed trial install](sandbox.md) — `targate sandbox` in a disposable Docker container.
- [CI integration](ci.md) — `targate ci` for pull requests.
- [Monitoring risk over time](team-workflow.md#monitoring-risk-over-time--targate-monitor) — `targate monitor` and the risk baseline.
- [Trust history & signed approvals](team-workflow.md#trust-history--targate-history) — `targate history`, SSH-signed approvals, `requireSignedApprovals`.

## Configuration & workflow

- [AI providers](ai-providers.md) — anthropic, deepseek, openai, ollama, custom; reasoning support.
- [AI response cache](ai-cache.md) — how re-reviews are cached, and how to configure it.
- [Team workflow](team-workflow.md) — approving packages, the approvals cache, pnpm `approve-builds`, and the team policy file.
- [Policy reference](policy-reference.md) — the full policy schema: every field, default, precedence, and validation rule.
- [Private registries](private-registries.md) — `.npmrc` scoped registries, credentials, and `internalScopes` name privacy.
- [Using targate with AI coding agents](agents.md) — `targate agents init` and the agent contract.

## Ecosystem-specific

- [React Native hardening](react-native.md) — Podspec / Gradle / permissions / native-surface review.

## Roadmap

- [What's next](whats-next.md) — the phased feature roadmap we tick off as it ships.
