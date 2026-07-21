import { mapLimit } from "./concurrency.js";
import type { MaliciousRecord } from "./types.js";
import { fetchWithTimeout, readResponseJson } from "./network.js";
import { networkBudget, type ResourceLimits } from "./resource-limits.js";

const OSV_API = "https://api.osv.dev/v1/query";
const OSV_BATCH_API = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_API = "https://api.osv.dev/v1/vulns";
/** OSV's querybatch accepts up to 1000 queries per request. */
const OSV_BATCH_CHUNK = 1000;
/** Bound the follow-up per-vuln detail fetches (only for packages with hits). */
const OSV_DETAIL_CONCURRENCY = 8;

function osvKey(name: string, version: string): string {
  return `${name}@${version}`;
}

export interface OsvResult {
  knownMalicious: boolean;
  maliciousRecords: MaliciousRecord[];
  advisories: MaliciousRecord[];
  /** Set when the lookup failed — the result is "unknown", not "clean". */
  unavailable: boolean;
  /** Set when the lookup was deliberately NOT made (policy internalScopes —
   *  querying would leak a private package name). Also "unknown, not clean",
   *  but by choice, so --fail-on-osv-error does not escalate it. */
  skipped?: boolean;
}

/** Result to use when OSV cannot be reached. Fails OPEN by default but is
 * explicitly marked unavailable so callers can choose to fail closed. */
export function osvUnavailable(): OsvResult {
  return { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: true };
}

/** Result for a package whose name must not be sent to OSV (internal scope). */
export function osvSkipped(): OsvResult {
  return {
    knownMalicious: false,
    maliciousRecords: [],
    advisories: [],
    unavailable: false,
    skipped: true,
  };
}

/**
 * OSV reports npm malware two ways: OpenSSF records with a MAL- prefix, and
 * GitHub (GHSA) advisories whose text identifies the package as malware.
 */
export function isMaliciousRecord(vuln: {
  id: string;
  summary?: string;
  details?: string;
}): boolean {
  if (vuln.id.startsWith("MAL-")) return true;
  // Only statements that the PACKAGE ITSELF is malware count. Ordinary
  // vulnerability advisories often use the word "malicious" for attacker
  // input ("a malicious payload"), which must not trigger a block.
  const summary = (vuln.summary ?? "").toLowerCase();
  // "Malicious code in <pkg>" is the exact title GitHub gives every GHSA npm
  // malware advisory. It is ANCHORED to the start of the summary: an ordinary
  // advisory that merely says "…allows an attacker to execute malicious code in
  // the browser…" must NOT be classified as a package-is-malware hard block
  // (which allowKnownPackages can never clear).
  if (
    /\bmalware\b|malicious package|embedded malicious code/.test(summary) ||
    /^malicious code in\b/.test(summary)
  ) {
    return true;
  }
  const details = (vuln.details ?? "").toLowerCase();
  // No unanchored "malicious code in" here — details is long prose where the
  // false match is most likely.
  return /contain(s|ed) (malware|malicious code)|is malware|package (is|was) malicious/.test(
    details,
  );
}

/**
 * Query OSV (which includes the OpenSSF Malicious Packages repository) for
 * known records about this package. Records with a MAL- prefix are entries
 * from the malicious-packages database; anything else is a vulnerability
 * advisory.
 */
export async function queryOsv(name: string, version: string, limits?: ResourceLimits): Promise<OsvResult> {
  const budget = networkBudget(limits);
  const res = await fetchWithTimeout(OSV_API, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      package: { name, ecosystem: "npm" },
      version,
    }),
  }, budget);
  if (!res.ok) {
    throw new Error(`OSV API responded with ${res.status}`);
  }
  const data = await readResponseJson<{
    vulns?: Array<{ id: string; summary?: string; details?: string }>;
  }>(res, budget.maxResponseBytes, "OSV response");

  const maliciousRecords: MaliciousRecord[] = [];
  const advisories: MaliciousRecord[] = [];
  for (const vuln of data.vulns ?? []) {
    const record = { id: vuln.id, summary: vuln.summary };
    if (isMaliciousRecord(vuln)) maliciousRecords.push(record);
    else advisories.push(record);
  }

  return {
    knownMalicious: maliciousRecords.length > 0,
    maliciousRecords,
    advisories,
    unavailable: false,
  };
}

/**
 * Query OSV for a whole set of packages in one round-trip via the batch
 * endpoint, instead of one POST per package. This is the dominant OSV cost on
 * a `--deep` / `targate install` run over a large tree.
 *
 * `querybatch` returns vuln IDs only, so detection parity with queryOsv is
 * preserved as follows: a MAL- ID is malicious from the ID alone (no detail
 * fetch); every other ID is fetched from /v1/vulns/{id} (deduped across the
 * tree, bounded concurrency) and classified with the same isMaliciousRecord.
 * Most packages have zero vulns, so the detail fetches are few.
 *
 * Failure is explicit, never silent: a per-vuln detail fetch that fails marks
 * that package `unavailable` (unknown, not clean); a failing batch request
 * throws so the caller can fall back to per-package queryOsv.
 */
export async function queryOsvBatch(
  packages: { name: string; version: string }[],
  limits?: ResourceLimits,
): Promise<Map<string, OsvResult>> {
  const out = new Map<string, OsvResult>();
  if (packages.length === 0) return out;
  const budget = networkBudget(limits);

  // 1. Batch query -> vuln IDs per package (aligned by index within a chunk).
  const idsByKey = new Map<string, string[]>();
  for (let i = 0; i < packages.length; i += OSV_BATCH_CHUNK) {
    const chunk = packages.slice(i, i + OSV_BATCH_CHUNK);
    const res = await fetchWithTimeout(OSV_BATCH_API, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: "npm" },
          version: p.version,
        })),
      }),
    }, budget);
    if (!res.ok) throw new Error(`OSV batch API responded with ${res.status}`);
    const data = await readResponseJson<{
      results?: Array<{ vulns?: Array<{ id: string }> }>;
    }>(res, budget.maxResponseBytes, "OSV batch response");
    const results = data.results ?? [];
    chunk.forEach((p, idx) => {
      idsByKey.set(osvKey(p.name, p.version), (results[idx]?.vulns ?? []).map((v) => v.id));
    });
  }

  // 2. Fetch + classify every unique non-MAL vuln (MAL- needs no detail).
  const needDetail = new Set<string>();
  for (const ids of idsByKey.values()) {
    for (const id of ids) if (!id.startsWith("MAL-")) needDetail.add(id);
  }
  const detail = new Map<string, { malicious: boolean; summary?: string } | "error">();
  await mapLimit([...needDetail], OSV_DETAIL_CONCURRENCY, async (id) => {
    try {
      const res = await fetchWithTimeout(`${OSV_VULN_API}/${encodeURIComponent(id)}`, {}, budget);
      if (!res.ok) throw new Error(`OSV vuln API responded with ${res.status}`);
      const vuln = await readResponseJson<{ id: string; summary?: string; details?: string }>(
        res, budget.maxResponseBytes, "OSV vulnerability response",
      );
      detail.set(id, { malicious: isMaliciousRecord(vuln), summary: vuln.summary });
    } catch {
      detail.set(id, "error");
    }
  });

  // 3. Assemble each package's result.
  for (const p of packages) {
    const key = osvKey(p.name, p.version);
    const maliciousRecords: MaliciousRecord[] = [];
    const advisories: MaliciousRecord[] = [];
    let unavailable = false;
    for (const id of idsByKey.get(key) ?? []) {
      if (id.startsWith("MAL-")) {
        maliciousRecords.push({ id });
        continue;
      }
      const d = detail.get(id);
      if (!d || d === "error") {
        // Couldn't classify this advisory — treat the package as "unknown",
        // never silently clean (--fail-on-osv-error can escalate it).
        unavailable = true;
        continue;
      }
      (d.malicious ? maliciousRecords : advisories).push({ id, summary: d.summary });
    }
    out.set(key, {
      knownMalicious: maliciousRecords.length > 0,
      maliciousRecords,
      advisories,
      unavailable,
    });
  }
  return out;
}
