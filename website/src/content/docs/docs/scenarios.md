---
title: Scenarios
description: Real workflows — CI gating, private registries, monorepos, coding agents, sandboxing, and upgrade review.
---

## Gate a pull request in CI

Fail a PR when it introduces a risky dependency change, before it merges.

```bash
targate ci init                                   # scaffold a workflow
targate ci --base-ref origin/main --fail-on-osv-error
```

`targate ci` compares the dependency changes against a Git ref and exits `2` when the new or changed dependencies don't pass. Because approvals are **read** in CI but never **created** there, a package only passes if a committed, reviewed approval covers it — see **[Approvals & policy](/docs/concepts/approvals-and-policy/)**. To vet the entire tree instead of just the diff, use `targate install --dry-run`.

## Review an upgrade (yours, Renovate's, Dependabot's)

```bash
targate diff lodash@4.17.20 lodash@4.17.21   # two explicit versions
targate diff lodash                          # lockfile-installed → latest
targate diff lodash --fail-on medium         # exit 2 at medium risk or above
```

`diff` is a statement of **facts** with a deterministic risk rubric — no AI, no policy escalation. It compares lifecycle scripts, dependencies (flagging non-registry specifiers like `git+`/`file:`), maintainers, repository, native surface, advisories (new and resolved), size, provenance, deprecation, and the security score. New lifecycle scripts, a new hard block, or a dependency moved to a non-registry source are HIGH risk.

## Private registries

targate honors your `.npmrc`: default and per-scope registries, global overrides, and nerf-darted `_authToken` / `_auth` / `username+_password` credentials with `${ENV}` expansion, for both metadata and tarball fetches. Declare **internal scopes** in policy so your own private package names are never sent to third-party lookups (OSV, download stats, GitHub) — the skip is shown in the report and score.

## Monorepos & workspaces

`targate install` understands workspace lockfiles, and `targate graph` renders per-workspace views:

```bash
targate graph --only high-risk,scripts        # interactive HTML risk graph
targate graph --why minimist                  # why is this package in my tree?
targate graph --format mermaid                 # paste into a GitHub PR / step summary
```

## Coding agents

Make AI coding agents gate their own installs instead of running `npm install` blind:

```bash
targate agents init                 # scaffold agent instructions
targate agents init --format all
```

This drops instructions that steer agents to `targate add`/`install`, so an agent that adds a dependency runs it through the gate. The `ai-agent` policy preset (`targate policy init --preset ai-agent`) pairs well here.

## Observe a suspicious package in a sandbox

When you want to *watch* what a package does rather than only statically analyze it:

```bash
targate sandbox suspicious-package
targate sandbox esbuild --network none        # no network egress
```

The package is trial-installed in a disposable Docker container; targate captures behavior and reports it. A suspicious observation exits `2`.

## Watch trusted packages for drift

```bash
targate monitor            # re-check trusted packages, report increased risk
targate monitor --all --no-update
```

`monitor` re-runs analysis over packages you already trust and flags any that became riskier (a new advisory, a new maintainer, a changed script), so a package you approved last month doesn't quietly become a liability.
