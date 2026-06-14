import { Badge, EmptyState } from "./ui";
import type { SignalRecord } from "../lib/events";
import {
  eventTypeLabels,
  formatTimestamp,
  riskLevelTone,
  trustLevelLabels,
} from "../lib/format";
import type { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";

// Signal-level table for the tenant drill-down: one row per risk event with its
// time, type, fused risk level, originating app, and observed region.
export function SignalsTable({ signals }: { signals: readonly SignalRecord[] }) {
  if (signals.length === 0) {
    return <EmptyState>No risk signals for this tenant in the current view.</EmptyState>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr>
            <th className="th">Time (UTC)</th>
            <th className="th">Signal</th>
            <th className="th">Risk</th>
            <th className="th">App</th>
            <th className="th">Region</th>
          </tr>
        </thead>
        <tbody>
          {signals.map((s) => (
            <tr key={s.id} className="border-t border-line hover:bg-hover">
              <td className="td whitespace-nowrap tabular-nums text-muted">
                {formatTimestamp(s.timestampMs)}
              </td>
              <td className="td">{eventTypeLabels[s.eventType as EventType] ?? "Unspecified"}</td>
              <td className="td">
                <Badge tone={riskLevelTone(s.riskLevel as TrustLevel)}>
                  {trustLevelLabels[s.riskLevel as TrustLevel] ?? "Unspecified"}
                </Badge>
              </td>
              <td className="td font-mono">
                <span className="block max-w-[12rem] truncate" title={s.appId}>
                  {s.appId || "—"}
                </span>
              </td>
              <td className="td text-muted">{s.region || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
