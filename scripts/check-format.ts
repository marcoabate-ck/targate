import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

/**
 * Zero-dependency formatting gate (Milestone 6.2).
 *
 * The project gates every dependency through targate, so it deliberately does
 * not pull in an external formatter. Instead this enforces the mechanical
 * whitespace invariants that a formatter would — the same ones `git diff
 * --check` catches on a diff, but across the whole tree:
 *
 *   - no CR (`\r`) — LF line endings only;
 *   - no trailing whitespace on any line;
 *   - a file ends with exactly one trailing newline (unless empty);
 *   - `.ts` source is indented with spaces, never hard tabs.
 *
 * Run with `pnpm format:check`.
 */

const ROOT = path.resolve(process.cwd());
const SCAN_DIRS = ["src", "test", "scripts", "benchmarks", "docs"];
const ROOT_FILES = ["README.md", "AGENTS.md", "tsconfig.json", "package.json"];
const EXTENSIONS = new Set([".ts", ".mts", ".cts", ".js", ".mjs", ".json", ".md", ".yml", ".yaml"]);
const IGNORED_DIRS = new Set(["node_modules", "dist", ".git", "__snapshots__"]);

async function collect(dir: string, out: string[]): Promise<void> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      await collect(path.join(dir, entry.name), out);
    } else if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name))) {
      out.push(path.join(dir, entry.name));
    }
  }
}

function checkFile(relPath: string, content: string): string[] {
  const problems: string[] = [];
  if (content.includes("\r")) problems.push(`${relPath}: contains a carriage return (use LF line endings)`);

  const lines = content.split("\n");
  lines.forEach((line, index) => {
    if (/[ \t]+$/.test(line)) problems.push(`${relPath}:${index + 1}: trailing whitespace`);
  });

  if (/\.(ts|mts|cts)$/.test(relPath)) {
    lines.forEach((line, index) => {
      if (/^\t/.test(line) || /^ *\t/.test(line)) {
        problems.push(`${relPath}:${index + 1}: hard tab in indentation (use spaces)`);
      }
    });
  }

  if (content.length > 0) {
    if (!content.endsWith("\n")) problems.push(`${relPath}: missing final newline`);
    else if (content.endsWith("\n\n")) problems.push(`${relPath}: more than one trailing newline`);
  }
  return problems;
}

const files: string[] = [];
for (const dir of SCAN_DIRS) {
  await collect(path.join(ROOT, dir), files).catch(() => {});
}
for (const file of ROOT_FILES) files.push(path.join(ROOT, file));

const problems: string[] = [];
for (const file of files) {
  const content = await readFile(file, "utf8").catch(() => null);
  if (content === null) continue;
  problems.push(...checkFile(path.relative(ROOT, file), content));
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`- ${problem}`);
  console.error(`\n${problems.length} formatting problem(s) found.`);
  process.exitCode = 1;
} else {
  console.log(`Formatting is clean across ${files.length} files.`);
}
