# CI integration

```bash
targate ci --base-ref origin/main --fail-on-osv-error   # in a PR: analyze added/updated dependencies
targate ci init                                          # scaffold .github/workflows/targate.yml
```

`targate ci` diffs `package.json` against the base ref, resolves the **exact version that will be installed** from the lockfile (`pnpm-lock.yaml` / `package-lock.json` / `yarn.lock`) when present, runs the full analysis pipeline on every added/updated dependency, and fails the build (exit `2`) when a package is **blocked** or **requires an approval that is not in the committed `.targate/approvals.json`** (approval drift). Without a lockfile it analyzes the declared version range and logs that it did so. The generated GitHub Actions workflow triggers on PRs touching `package.json` or a lockfile, passes `--fail-on-osv-error`, and can take a provider API key secret to enable AI reasoning. The same command works on any CI system via exit codes and `--json`.

> CI protects the repository. The local gate protects the developer — `targate ci` is the second line of defense, not a replacement for `targate add <pkg>`.

`targate ci` never uses the [AI response cache](ai-cache.md) — a CI verdict is always a fresh assessment. Pass `--fail-on-osv-error` (set by the generated workflow) so an unreachable OSV lookup fails the check closed rather than silently trusting the package — see [OSV lookup failures](security.md#osv-lookup-failures).
