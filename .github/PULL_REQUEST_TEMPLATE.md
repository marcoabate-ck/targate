<!--
  Reporting a security vulnerability? Do NOT open a PR — see SECURITY.md.
-->

## What

<!-- What does this change do? One or two sentences. -->

## Why

<!-- The problem it solves. Link the issue: Closes #123 -->

## How verified

<!-- Commands you ran and what you observed. -->

## Checklist

- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes (added/updated tests for the change)
- [ ] `pnpm format:check` passes
- [ ] `pnpm docs:check` passes (regenerated command tables if the registry changed)
- [ ] `pnpm pack:check` passes (if packaging/files changed)
- [ ] Docs updated where a user would look, and they match the implementation
- [ ] Security-relevant change: added an adversarial test proving bad input is rejected
- [ ] The deterministic floor is intact — AI/policy can only make a verdict stricter
