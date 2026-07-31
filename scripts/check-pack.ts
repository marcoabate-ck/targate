import { execFileSync, execSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
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
  // Use a throwaway npm cache so a read-only/locked user cache (seen on some
  // dev machines and locked-down CI) can't fail the check — npm pack does no
  // network work here, but it still touches the cache dir. execSync with a
  // static string is shell-portable (npm is npm.cmd on Windows, which execFile
  // cannot spawn without a shell); the only interpolated value is a temp path
  // we created, quoted, so there is no injection surface.
  const cache = mkdtempSync(path.join(tmpdir(), "targate-packcache-"));
  try {
    const stdout = execSync(`npm pack --dry-run --json --cache "${cache}"`, {
      cwd: root,
      encoding: "utf8",
    });
    // `npm pack --json` output shape differs by npm major: npm <=11 returns an
    // array `[{ files }]`; npm >=12 returns an object keyed by package name
    // `{ "<pkg>": { files } }`. Accept both so an npm upgrade cannot silently
    // empty the file list (which would misreport the bin as missing).
    const parsed = JSON.parse(stdout) as unknown;
    const entries = (Array.isArray(parsed) ? parsed : Object.values(parsed as Record<string, unknown>)) as Array<{
      files?: PackEntry[];
    }>;
    const files = entries[0]?.files ?? [];
    // Normalize to POSIX so the allowlist matches on Windows too.
    return files.map((f) => f.path.split(path.sep).join("/"));
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
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
