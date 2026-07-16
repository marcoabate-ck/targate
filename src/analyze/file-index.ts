import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import {
  ResourceLimitError,
  resolveResourceLimits,
  type ResolvedResourceLimits,
} from "../resource-limits.js";

export interface IndexedFile {
  /** Absolute path inside the extracted package root. */
  fullPath: string;
  /** Package-root-relative path, always POSIX (`/`) separated so analysis and
   *  findings are identical on Windows and Linux. */
  relPath: string;
  basename: string;
  extension: string;
  size: number;
}

export interface PackageFileIndex {
  root: string;
  files: IndexedFile[];
  byBasename: Map<string, IndexedFile[]>;
  totalFiles: number;
  totalBytes: number;
  truncated: boolean;
  truncationReason?: "file-count" | "extracted-size";
}

/**
 * Traverse an extracted package once and retain only bounded file metadata.
 * File contents stay on disk and are read lazily by the analyzers that need
 * them, keeping the shared index useful even for large packages.
 */
export async function buildPackageFileIndex(
  packageDir: string,
  limits: ResolvedResourceLimits = resolveResourceLimits(),
): Promise<PackageFileIndex> {
  const index: PackageFileIndex = {
    root: packageDir,
    files: [],
    byBasename: new Map(),
    totalFiles: 0,
    totalBytes: 0,
    truncated: false,
  };

  const walk = async (directory: string): Promise<void> => {
    if (index.truncated) return;
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      if (index.truncated) return;
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules") await walk(fullPath);
        continue;
      }
      // Symlinks, sockets and other non-regular objects are intentionally not
      // followed. Quarantine rejects them; this also protects direct callers.
      if (!entry.isFile()) continue;

      if (index.totalFiles >= limits.maxFiles) {
        index.truncated = true;
        index.truncationReason = "file-count";
        return;
      }
      const info = await stat(fullPath);
      if (info.size > limits.maxFileBytes) {
        throw new ResourceLimitError(
          "file-size",
          `${path.relative(packageDir, fullPath)} exceeds ${limits.maxFileBytes} bytes`,
        );
      }
      if (index.totalBytes + info.size > limits.maxExtractedBytes) {
        index.truncated = true;
        index.truncationReason = "extracted-size";
        return;
      }

      const file: IndexedFile = {
        fullPath,
        // Host-relative path, then forced to POSIX separators: archive paths
        // are logically `/`-separated and downstream matching/output must not
        // vary with path.sep (a `\` on Windows breaks `/`-based patterns).
        relPath: path.relative(packageDir, fullPath).split(path.sep).join("/"),
        basename: entry.name,
        extension: path.extname(entry.name),
        size: info.size,
      };
      index.files.push(file);
      index.totalFiles++;
      index.totalBytes += info.size;
      const matches = index.byBasename.get(file.basename) ?? [];
      matches.push(file);
      index.byBasename.set(file.basename, matches);
    }
  };

  await walk(packageDir);
  return index;
}

/** A partial index must never be interpreted as a clean package analysis. */
export function assertCompleteFileIndex(index: PackageFileIndex): void {
  if (!index.truncated) return;
  const kind = index.truncationReason ?? "file-count";
  throw new ResourceLimitError(
    kind,
    kind === "file-count"
      ? `package file index exceeded its file-count budget after ${index.totalFiles} files`
      : `package file index exceeded its extracted-size budget after ${index.totalBytes} bytes`,
  );
}

export async function readIndexedFile(file: IndexedFile): Promise<string> {
  return readFile(file.fullPath, "utf8").catch(() => "");
}

export async function resolveFileIndex(
  input: string | PackageFileIndex,
  limits: ResolvedResourceLimits = resolveResourceLimits(),
): Promise<PackageFileIndex> {
  const index = typeof input === "string" ? await buildPackageFileIndex(input, limits) : input;
  assertCompleteFileIndex(index);
  return index;
}
