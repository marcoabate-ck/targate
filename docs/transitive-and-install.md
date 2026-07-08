# Transitive dependencies & full-tree install

`targate add <pkg>` gates a single new package. Two flows extend coverage to more of the tree.

## Transitive dependencies — `--deep`

```bash
targate add glob --deep --dry-run
```

By default targate analyzes only the package you named. With `--deep` it first resolves the **exact dependency tree** a real install would produce — npm itself does the resolution (`--package-lock-only --ignore-scripts` in a throwaway directory: only a lockfile is generated, no `node_modules`, nothing from the tree executes) — then runs the same per-package pipeline (quarantine, OSV, signals, AI/rules, team policy) on **every unique `name@version`** in the tree, a few packages at a time.

The final decision is the **strictest verdict across the whole tree**: a blocked transitive dependency blocks the install exactly like a blocked root; a `require_approval` anywhere in the tree escalates the run. Flagged packages are listed in the reasons (`--json` includes the full per-package results under `deep`).

Cost: a deep run downloads and analyzes N tarballs and, with an AI provider configured, makes up to N model calls — the [AI response cache](ai-cache.md) makes repeated and shared dependencies cheap. If npm cannot resolve the tree, the run fails loudly rather than silently degrading to top-level-only coverage.

`--deep` also works with `targate approve`: a hard block anywhere in the tree makes the whole package un-approvable.

## Full-tree install — `targate install`

`targate add` gates a single new package; `targate ci` gates the deps a change touches. Neither covers the highest-exposure moment: a plain `pnpm install` / `npm install` on a fresh clone or in CI, which restores the **entire** tree and runs **every** package's lifecycle scripts at once. `targate install` is the gate for that.

```bash
targate install                 # vet the whole tree, then install (scripts disabled)
targate install --dry-run       # vet only; print the recommended install command
targate install --frozen-lockfile   # immutable install (npm ci / pnpm|yarn --frozen-lockfile)
targate install --allow-scripts     # run lifecycle scripts after the tree passes
```

What it does:

1. **Enumerates the whole tree.** Prefers the committed lockfile (`pnpm-lock.yaml` / `package-lock.json` / `yarn.lock`) as the source of truth for what will land on disk; with no lockfile, npm resolves the manifest in a throwaway directory (`--package-lock-only --ignore-scripts`, nothing executes) — the report shows `source: lockfile` or `resolved`.
2. **Vets every unique `name@version`** through the same pipeline as `--deep` (quarantine, OSV, signals, AI/rules, team policy), a few at a time, reusing the [AI response cache](ai-cache.md).
3. **Gates the install.** If any package is `block`, or `require_approval` and not in the committed `.targate/approvals.json`, targate **refuses** and exits `2` — it never runs the install. Otherwise it runs the real install.
4. **Scripts off by default.** The actual install runs with `--ignore-scripts`; approve individual packages' build scripts via pnpm's `onlyBuiltDependencies` (see [Team workflow](team-workflow.md#pnpm-approve-builds-integration)) or re-run with `--allow-scripts` once reviewed.

Exit codes: `0` vetted (and installed, unless `--dry-run`), `2` refused (blocked/unapproved package in the tree), `1` error. `--json` prints the full report (`{ packageManager, source, total, results, decision, exitCode }`).

**Caveats.** A first cold scan of a large tree is heavy (N tarballs + OSV lookups; the cache amortizes re-runs). And targate vets *before* executing, so it is meaningful on a clean or `--frozen-lockfile` install — it cannot retroactively un-run scripts for packages already present in `node_modules`.
