import type { MonitorEvent } from "../monitor.js";
import { cyan, dim, red, yellow } from "./colors.js";

const ICON = { critical: "✗", warn: "⚠", info: "ℹ" } as const;
const PAINT = { critical: red, warn: yellow, info: cyan } as const;

export function renderMonitorEvent(event: MonitorEvent): string {
  const known = event.alreadyKnown ? dim(" (already known)") : "";
  return PAINT[event.severity](`  ${ICON[event.severity]} ${event.package}: ${event.detail}`) + known;
}

export function monitorSeverityRank(severity: MonitorEvent["severity"]): number {
  return severity === "critical" ? 2 : severity === "warn" ? 1 : 0;
}

