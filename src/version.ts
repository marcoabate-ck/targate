import { createRequire } from "node:module";

/**
 * The running targate version, read from package.json at load time — the
 * single source of truth. Works from both src/ (tsx) and dist/ because both
 * sit one level below package.json.
 */
export const TARGATE_VERSION: string = createRequire(import.meta.url)("../package.json").version;
