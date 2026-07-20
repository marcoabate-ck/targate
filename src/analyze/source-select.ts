import path from "node:path";
import { CODE_EXTENSIONS, scanSource } from "./content.js";
import { referencedScriptFiles } from "./scripts.js";
import { readIndexedFile, type IndexedFile, type PackageFileIndex } from "./file-index.js";
import { resolveResourceLimits, type ResolvedResourceLimits } from "../resource-limits.js";

/**
 * Pick the bounded, RISKY subset of a package's source to hand to the AI
 * source-code audit (--audit-code). Sending the whole module is expensive and
 * mostly wasteful — the deterministic scanners already point at the suspicious
 * surface, so we rank by that and fill a byte/file budget. Anything left out is
 * recorded in `dropped`; a "clean" audit must never quietly mean "we only looked
 * at half the package".
 *
 * Ranking (high → low):
 *   1. files a lifecycle install script references (install-time code runs on
 *      the consumer's machine — the highest-value thing to read),
 *   2. files that trip a static heuristic (process.env / child_process /
 *      network / eval / minified),
 *   3. declared entry points (main / bin).
 * Files with no signal at all are not audited.
 */

export interface AuditFileExcerpt {
  /** POSIX package-relative path. */
  relPath: string;
  /** The exact text sent to the model (possibly a head+tail slice). */
  content: string;
  /** Byte length of `content`. */
  bytes: number;
  /** True when the file was larger than its budget and only a slice was sent. */
  truncated: boolean;
}

export interface AuditSelection {
  files: AuditFileExcerpt[];
  /** Candidates deliberately not sent, each with a human-readable reason. */
  dropped: { count: number; reason: string }[];
  /** Number of signal-bearing candidate files before the budget was applied. */
  totalCandidates: number;
}

const SCORE_INSTALL_TIME = 100;
const SCORE_ENTRY_POINT = 20;
const SCORE_PER_FLAG = 5;
const SCORE_MINIFIED = 10;
/** Never bother sending a slice smaller than this — too little context to judge. */
const MIN_SLICE_BYTES = 512;

interface RankedFile {
  file: IndexedFile;
  score: number;
}

function normalizeSet(paths: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const p of paths) out.add(path.posix.normalize(p));
  return out;
}

/** Head+tail slice so the interesting top of a file and its tail both survive. */
function sliceExcerpt(source: string, budgetBytes: number): string {
  if (Buffer.byteLength(source) <= budgetBytes) return source;
  const head = Math.floor(budgetBytes * 0.6);
  const tail = budgetBytes - head;
  return (
    source.slice(0, head) +
    `\n\n/* … targate: ${source.length - head - tail} bytes elided … */\n\n` +
    source.slice(source.length - tail)
  );
}

export async function selectAuditFiles(
  index: PackageFileIndex,
  lifecycleScripts: Record<string, string>,
  entryPoints: string[] = [],
  limits: ResolvedResourceLimits = resolveResourceLimits(),
): Promise<AuditSelection> {
  const installTimeFiles = normalizeSet(
    Object.values(lifecycleScripts).flatMap((command) => referencedScriptFiles(command)),
  );
  const entryPointFiles = normalizeSet(entryPoints);

  const codeFiles = index.files.filter((file) => CODE_EXTENSIONS.has(file.extension));
  const ranked: RankedFile[] = [];
  for (const file of codeFiles) {
    const source = await readIndexedFile(file);
    if (!source) continue;
    const scan = scanSource(file.relPath, source);
    const flags =
      Number(scan.processEnv) +
      Number(scan.childProcess) +
      Number(scan.network) +
      Number(scan.evalUsage);
    const normalized = path.posix.normalize(file.relPath);
    const installTime = installTimeFiles.has(normalized);
    const entryPoint = entryPointFiles.has(normalized);
    const score =
      (installTime ? SCORE_INSTALL_TIME : 0) +
      (entryPoint ? SCORE_ENTRY_POINT : 0) +
      flags * SCORE_PER_FLAG +
      (scan.minified ? SCORE_MINIFIED : 0);
    if (score > 0) ranked.push({ file, score });
  }

  // Highest risk first; ties broken by smaller size (fit more) then path (stable).
  ranked.sort(
    (a, b) =>
      b.score - a.score || a.file.size - b.file.size || a.file.relPath.localeCompare(b.file.relPath),
  );

  const files: AuditFileExcerpt[] = [];
  const dropped: { count: number; reason: string }[] = [];
  let remainingBytes = limits.maxAuditBytes;
  let budgetDropped = 0;

  for (const { file } of ranked) {
    if (files.length >= limits.maxAuditFiles || remainingBytes < MIN_SLICE_BYTES) {
      budgetDropped++;
      continue;
    }
    const source = await readIndexedFile(file);
    if (!source) continue;
    const take = Math.min(Buffer.byteLength(source), remainingBytes);
    const content = sliceExcerpt(source, take);
    const bytes = Buffer.byteLength(content);
    files.push({
      relPath: file.relPath,
      content,
      bytes,
      truncated: bytes < Buffer.byteLength(source),
    });
    remainingBytes -= bytes;
  }

  if (budgetDropped > 0) {
    dropped.push({
      count: budgetDropped,
      reason: `exceeded audit budget (${limits.maxAuditFiles} files / ${limits.maxAuditBytes} bytes)`,
    });
  }
  if (index.truncated) {
    dropped.push({
      count: 0,
      reason: `package file index was truncated (${index.truncationReason ?? "file-count"}) before selection`,
    });
  }

  return { files, dropped, totalCandidates: ranked.length };
}
