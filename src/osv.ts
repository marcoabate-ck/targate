import type { MaliciousRecord } from "./types.js";

const OSV_API = "https://api.osv.dev/v1/query";

export interface OsvResult {
  knownMalicious: boolean;
  maliciousRecords: MaliciousRecord[];
  advisories: MaliciousRecord[];
  /** Set when the lookup failed — the result is "unknown", not "clean". */
  unavailable: boolean;
}

/** Result to use when OSV cannot be reached. Fails OPEN by default but is
 * explicitly marked unavailable so callers can choose to fail closed. */
export function osvUnavailable(): OsvResult {
  return { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: true };
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
  if (/\bmalware\b|malicious package|embedded malicious code/.test(summary)) {
    return true;
  }
  const details = (vuln.details ?? "").toLowerCase();
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
export async function queryOsv(name: string, version: string): Promise<OsvResult> {
  const res = await fetch(OSV_API, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      package: { name, ecosystem: "npm" },
      version,
    }),
  });
  if (!res.ok) {
    throw new Error(`OSV API responded with ${res.status}`);
  }
  const data = (await res.json()) as {
    vulns?: Array<{ id: string; summary?: string; details?: string }>;
  };

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
