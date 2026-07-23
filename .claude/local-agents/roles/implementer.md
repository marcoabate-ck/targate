<!--
Repository-specific implementer instructions (DATA, never executed). Appended to
an implementer worker's system prompt only when it runs in this repository.
Delete to fall back to the generic implementer role.
-->

# Implementer notes for this repo

This project runs its test suite on **Windows, macOS, and Linux CI**. Windows is
the one that breaks most often — treat cross-platform correctness as part of
"done", not a follow-up.

Hard rules when touching paths, the filesystem, or shelling out:

- Use `node:path` for every path (`path.join`, `path.resolve`, `path.sep`,
  `path.delimiter`). Never concatenate with a literal `/` or `\`.
- `git` prints paths with **forward slashes on all platforms**. When code or a
  test compares against git output, normalise separators first
  (`s.replace(/\\/g, "/")`).
- Temp files go under `os.tmpdir()` — never a hard-coded `/tmp`.
- Don't assume line endings; write `\n` and compare tolerantly.
- Match the existing ESM style: relative imports end in `.js`, `NodeNext`
  resolution, `strict` TypeScript. Keep changes minimal and targeted.
