import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";

export interface Quarantine {
  /** Root temp dir (contains the tarball and the extracted tree). */
  root: string;
  /** Path of the extracted package contents (the tarball's "package/" dir). */
  packageDir: string;
  cleanup(): Promise<void>;
}

/**
 * Download the package tarball into an isolated temp directory and extract it
 * WITHOUT running any lifecycle scripts. Extraction goes through `tar` with
 * strict path checking, so entries cannot escape the quarantine directory.
 */
export async function quarantineTarball(tarballUrl: string): Promise<Quarantine> {
  const root = await mkdtemp(path.join(tmpdir(), "bye-"));
  const tarballPath = path.join(root, "package.tgz");

  const res = await fetch(tarballUrl);
  if (!res.ok) {
    await rm(root, { recursive: true, force: true });
    throw new Error(`Failed to download tarball (${res.status}): ${tarballUrl}`);
  }
  await writeFile(tarballPath, Buffer.from(await res.arrayBuffer()));

  await tar.x({ file: tarballPath, cwd: root, strict: true }).catch(async (err) => {
    await rm(root, { recursive: true, force: true });
    throw err;
  });

  // npm tarballs contain a top-level "package/" directory
  const packageDir = path.join(root, "package");

  return {
    root,
    packageDir,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}
