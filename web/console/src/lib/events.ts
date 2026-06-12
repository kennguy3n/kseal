import type { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";
import type { EventRecord } from "../gen/kseal/v1/query_service_pb";

// Client-side filter applied to an already-fetched page of events. The same
// criteria are also sent to QueryService.ListEvents for server-side narrowing;
// this keeps multi-select toggles instant and acts as defense-in-depth so a
// broader server response is never shown unfiltered.
export interface EventFilter {
  // Empty arrays mean "no constraint" (match all).
  eventTypes: EventType[];
  riskLevels: TrustLevel[];
  // Inclusive bounds in unix milliseconds; undefined means unbounded.
  startTime?: number;
  endTime?: number;
}

export const emptyEventFilter: EventFilter = {
  eventTypes: [],
  riskLevels: [],
};

export function isEventFilterActive(f: EventFilter): boolean {
  return (
    f.eventTypes.length > 0 ||
    f.riskLevels.length > 0 ||
    f.startTime !== undefined ||
    f.endTime !== undefined
  );
}

function withinTimeRange(
  ts: bigint,
  start: number | undefined,
  end: number | undefined,
): boolean {
  if (start !== undefined && ts < BigInt(Math.trunc(start))) return false;
  if (end !== undefined && ts > BigInt(Math.trunc(end))) return false;
  return true;
}

export function filterEvents(
  events: readonly EventRecord[],
  filter: EventFilter,
): EventRecord[] {
  const typeSet = new Set(filter.eventTypes);
  const riskSet = new Set(filter.riskLevels);
  return events.filter((e) => {
    if (typeSet.size > 0 && !typeSet.has(e.eventType)) return false;
    if (riskSet.size > 0 && !riskSet.has(e.riskLevel)) return false;
    if (!withinTimeRange(e.timestamp, filter.startTime, filter.endTime)) {
      return false;
    }
    return true;
  });
}

// Newest first; stable for equal timestamps via id as a tiebreaker.
export function sortEventsByTimeDesc(events: readonly EventRecord[]): EventRecord[] {
  return [...events].sort((a, b) => {
    if (a.timestamp === b.timestamp) {
      if (a.id === b.id) return 0;
      return a.id < b.id ? -1 : 1;
    }
    return a.timestamp > b.timestamp ? -1 : 1;
  });
}
