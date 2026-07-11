# Dependency graph — `targate graph`

Your dependency tree as a **risk graph**: every resolved package analyzed with the same deterministic pipeline as `targate install --no-ai` (signals → security score → rules verdict — no AI, so the picture is reproducible), drawn as a layered DAG you can explore.

```bash
targate graph                      # the current project (lockfile tree) → targate-graph.html
targate graph react-native-mmkv    # a package you are CONSIDERING, and its whole tree
targate graph --only high-risk,scripts --format svg
targate graph --why minimist       # every chain that pulls a package in
```

## The interactive HTML (default)

`targate graph` writes **one self-contained `targate-graph.html`** — inline CSS/JS, embedded data, **zero external requests** — so it works offline, survives CI artifact storage, and passes a strict CSP. (Package names are attacker-controlled strings; everything interpolated into the page is escaped, and the embedded JSON cannot break out of its script block.)

Built in:

- **Pan & zoom** over the layered graph — roots on top, dependency arrows always point down.
- **Filters** that never lose context: *high-risk*, *lifecycle scripts*, *native code*, *deprecated*, *no provenance*, *risk increased* — a filtered view keeps every ancestor path, so it still shows **how** each risky package got into the tree. Plus free-text search and (in monorepos) a workspace selector.
- **Click a node** → detail panel (risk, decision, security score, advisories, provenance, top reasons, dependent/dependency counts) and every chain from that node back to the root highlighted.
- **Badges:** ⚙ lifecycle scripts · ⬢ native code · ⚠ deprecated · ☠ known-malicious; node color = risk (green → red); a dashed red ring = risk increased since the monitor baseline.
- Stats header, legend, dark/light theme.

## Formats

| `--format` | What you get | Default destination |
|---|---|---|
| `html` (default) | the interactive page above | `targate-graph.html` |
| `svg` | static drawing, embeddable in wikis/READMEs | `targate-graph.svg` |
| `dot` | Graphviz interchange for your own tooling | stdout |
| `mermaid` | GitHub-native diagram (PRs, step summaries) | stdout |
| `json` | nodes + edges + stats in the [stable envelope](cli-reference.md#json-output-schema) | stdout |

`--output <path>` overrides the destination (`-` forces stdout); `--open` opens the written html/svg. Formats that default to stdout keep it clean — progress goes nowhere machine-readable output could be polluted.

## Filters — `--only`

For static formats, `--only high-risk,scripts,native,deprecated,malicious,no-provenance,risk-increased` (any subset) prunes the graph to matching nodes **plus their paths to the root**. The same filters are live toggles in the HTML.

## Monorepos / workspaces

pnpm (`pnpm-workspace.yaml`) and npm/yarn (`package.json` `workspaces`) monorepos get one root node per workspace package; the HTML gains a workspace selector that narrows the graph to that workspace's reachable subtree, and each node records which workspaces use it. Glob support is deliberately minimal — exact directories and `dir/*` patterns (the forms real configs use); deeper patterns are skipped, not guessed.

## "Why is this in my tree?" — `--why`

```text
$ targate graph --why repeat-string

Why is repeat-string in the tree? 1 chain(s):

  1.
  project:graph-demo  (root)
    └─ pad-left@2.1.0  low
      └─ repeat-string@1.6.1  low
```

Like `pnpm why`, but every hop is risk-annotated (and ⚙/☠ badged). Capped at 50 chains.

## Risk-increased overlay

When `.targate/monitor-baseline.json` exists (see [`targate monitor`](team-workflow.md#monitoring-risk-over-time--targate-monitor)), every node is compared against its baseline snapshot: a new advisory, a fresh malicious record, a new deprecation, or lost provenance marks the node **risk increased** — a dashed red ring in the drawing, a dedicated filter, and the reasons in the detail panel. No baseline → no overlay (the stats say so via `baselineCompared`).

## CI artifacts

```yaml
- name: Dependency risk graph
  if: always()
  run: |
    npx targate graph --output targate-graph.html
    npx targate graph --format mermaid --only high-risk,scripts >> "$GITHUB_STEP_SUMMARY"
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: targate-graph
    path: targate-graph.html
```

The artifact is the full interactive page; the step summary renders the risky subgraph **directly on the Actions run page**. `targate ci init` scaffolds these steps (commented) into `.github/workflows/targate.yml`. Mermaid output is capped at 150 nodes — narrow it with `--only` (the output says when it truncated).

## Honesty notes

- **Edges are declared relationships** (dependencies + optionalDependencies + peerDependencies from each packument) resolved against the versions present in the tree. When several versions of a package coexist, an edge is drawn to every present version that could satisfy the declaration — a deliberate over-approximation that never hides a real edge, but can show one that npm deduplicated away.
- **The graph is a lens, not a gate.** It always exits `0` on success (1 on operational errors) — blocking belongs to `targate add` / `install` / `ci`. A ☠ node in the picture is a reason to run them, not a substitute.
- A package whose analysis failed is drawn gray with a `?` badge and the error in its panel — unknown is never rendered as clean.
