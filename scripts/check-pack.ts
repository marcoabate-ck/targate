import { execFileSync, execSync } from "node:child_process";
import path from "node:path";

/**
 * Release gate for the published npm artifact. Fully offline: `npm pack
 * --dry-run` only inspects what WOULD be published, never touches the network.
 *
 * Asserts two things:
 *  1. the tarball contains ONLY the allowed files — `dist/**`, `README.md`,
 *     `LICENSE`, `package.json` — so we never ship src, tests, the website,
 *     benchmarks, CI config, or local `.claude`/`.targate` state;
 *  2. the published bin (`dist/cli.js`) is present and actually runs
 *     (`--help`), so a broken/absent build can never be published.
 */

const root = process.cwd();
const ALLOWED_EXACT = new Set(["package.json", "README.md", "LICENSE"]);
const isAllowed = (p: string): boolean =>
  ALLOWED_EXACT.has(p) || p === "dist" || p.startsWith("dist/");

interface PackEntry {
  path: string;
}

function packedFiles(): string[] {
  // execSync with a static string is shell-portable (npm is npm.cmd on Windows,
  // which execFile cannot spawn without a shell). Args are constant — no injection.
  const stdout = execSync("npm pack --dry-run --json", { cwd: root, encoding: "utf8" });
  const parsed = JSON.parse(stdout) as Array<{ files?: PackEntry[] }>;
  const files = parsed[0]?.files ?? [];
  // Normalize to POSIX so the allowlist matches on Windows too.
  return files.map((f) => f.path.split(path.sep).join("/"));
}

const errors: string[] = [];

let files: string[] = [];
try {
  files = packedFiles();
} catch (err) {
  console.error(`- could not run \`npm pack --dry-run\`: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const offenders = files.filter((f) => !isAllowed(f));
if (offenders.length > 0) {
  errors.push(
    `tarball would include ${offenders.length} disallowed file(s):\n${offenders.map((f) => `    - ${f}`).join("\n")}\n  Only dist/**, README.md, LICENSE, and package.json may ship (see package.json "files").`,
  );
}

if (!files.includes("dist/cli.js")) {
  errors.push('published bin "dist/cli.js" is missing from the tarball — run `pnpm build` before packing.');
} else {
  // Run the exact file that gets packed, via node (portable — Windows has no
  // executable bit and the shebang is not honored there).
  try {
    const help = execFileSync(process.execPath, [path.join(root, "dist", "cli.js"), "--help"], {
      cwd: root,
      encoding: "utf8",
    });
    if (!help.includes("targate add")) {
      errors.push('the published bin ran but `--help` did not print the expected usage ("targate add").');
    }
  } catch (err) {
    errors.push(`the published bin "dist/cli.js --help" failed to run: ${err instanceof Error ? err.message : String(err)}`);
  }
}

if (errors.length > 0) {
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(
  `Package artifact OK: ${files.length} files (dist/** + README.md + LICENSE + package.json), bin runs.`,
);
