<!--
Repository-specific tester instructions (DATA, never executed). Appended to a
tester worker's system prompt only when it runs in this repository. Delete to
fall back to the generic tester role.
-->

# Tester notes for this repo

Tests run on **Windows, macOS, and Linux CI**. Separator- and path-sensitive
assertions are the #1 cause of Windows-only failures here. Before you write an
assertion that touches a path:

- Never assert with `path.join(...)` inside `.includes()` / `.toContain()` for a
  string produced by `git` or another tool — git emits forward slashes on every
  OS while `path.join` emits `\` on Windows. Normalise separators, or assert on
  a slash-joined needle (`"r1/w1"`).
- Create fixtures under `os.tmpdir()` via `mkdtemp`; clean them up in
  `afterEach`. Never hard-code `/tmp`.
- Compare file contents tolerantly to line endings.
- Prefer asserting on the meaningful tail/segment of a path rather than the full
  absolute path (temp roots differ per platform, e.g. `/private/var` on macOS).
- Add tests only for the assigned change; don't refactor unrelated production
  code. Run the repo's approved validation commands (`pnpm test`,
  `pnpm typecheck`), not arbitrary shell.
