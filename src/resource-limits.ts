/** Resource budgets applied to every untrusted network/package input. */
export interface ResourceLimits {
  /** Total time allowed for a network response, including reading its body. */
  networkTimeoutMs?: number;
  /** Maximum bytes accepted from non-tarball HTTP responses. */
  maxResponseBytes?: number;
  /** Maximum compressed tarball bytes downloaded. */
  maxTarballBytes?: number;
  /** Maximum total uncompressed bytes extracted from one package. */
  maxExtractedBytes?: number;
  /** Maximum archive entries / extracted filesystem objects. */
  maxFiles?: number;
  /** Maximum uncompressed size of one extracted file. */
  maxFileBytes?: number;
  /** Maximum duration of static package-content analysis, in milliseconds. */
  maxScanDuration?: number;
  /** Maximum files sent to the AI source-code audit (--audit-code). */
  maxAuditFiles?: number;
  /** Maximum total source bytes sent to the AI source-code audit. */
  maxAuditBytes?: number;
}

export interface ResolvedResourceLimits {
  networkTimeoutMs: number;
  maxResponseBytes: number;
  maxTarballBytes: number;
  maxExtractedBytes: number;
  maxFiles: number;
  maxFileBytes: number;
  maxScanDuration: number;
  maxAuditFiles: number;
  maxAuditBytes: number;
}

export const DEFAULT_RESOURCE_LIMITS: ResolvedResourceLimits = {
  networkTimeoutMs: 15_000,
  maxResponseBytes: 16 * 1024 * 1024,
  maxTarballBytes: 64 * 1024 * 1024,
  maxExtractedBytes: 256 * 1024 * 1024,
  maxFiles: 20_000,
  maxFileBytes: 32 * 1024 * 1024,
  maxScanDuration: 20_000,
  maxAuditFiles: 15,
  maxAuditBytes: 256 * 1024,
};

export function resolveResourceLimits(limits?: ResourceLimits): ResolvedResourceLimits {
  return { ...DEFAULT_RESOURCE_LIMITS, ...limits };
}

export function networkBudget(limits?: ResourceLimits): {
  timeoutMs: number;
  maxResponseBytes: number;
} {
  const resolved = resolveResourceLimits(limits);
  return {
    timeoutMs: resolved.networkTimeoutMs,
    maxResponseBytes: resolved.maxResponseBytes,
  };
}

export type ResourceLimitKind =
  | "network-timeout"
  | "response-size"
  | "tarball-size"
  | "extracted-size"
  | "file-count"
  | "file-size"
  | "scan-timeout"
  | "unsafe-path";

/** A bounded operation stopped safely. Callers turn this into UNKNOWN. */
export class ResourceLimitError extends Error {
  constructor(
    readonly kind: ResourceLimitKind,
    message: string,
  ) {
    super(message);
    this.name = "ResourceLimitError";
  }
}

export async function withScanBudget<T>(
  operation: Promise<T>,
  durationMs: number,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ResourceLimitError("scan-timeout", `static analysis exceeded ${durationMs}ms`)),
          durationMs,
        );
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
