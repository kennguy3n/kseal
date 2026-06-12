import { useMemo, useState } from "react";
import { useEvents } from "../hooks/queries";
import { Card, EmptyState, ErrorNotice, Spinner, Badge } from "../components/ui";
import { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";
import {
  eventTypeLabels,
  formatTimestamp,
  riskLevelTone,
  trustLevelLabels,
} from "../lib/format";
import { filterEvents, sortEventsByTimeDesc } from "../lib/events";

const eventTypeChoices: EventType[] = [
  EventType.RUNTIME_TAMPER,
  EventType.DEBUGGER,
  EventType.ROOT_RISK,
  EventType.ATTESTATION_FAIL,
  EventType.NETWORK_MITM,
  EventType.POLICY_DECISION,
  EventType.HOOKING_DETECTED,
  EventType.APP_INTEGRITY_FAIL,
  EventType.ENVIRONMENT_RISK,
];

const riskLevelChoices: TrustLevel[] = [
  TrustLevel.TRUSTED,
  TrustLevel.LOW_RISK,
  TrustLevel.MEDIUM_RISK,
  TrustLevel.HIGH_RISK,
  TrustLevel.CRITICAL,
];

function toMillis(local: string): number | undefined {
  if (!local) return undefined;
  const ms = new Date(local).getTime();
  return Number.isNaN(ms) ? undefined : ms;
}

function toggle<T>(arr: T[], value: T): T[] {
  return arr.includes(value)
    ? arr.filter((v) => v !== value)
    : [...arr, value];
}

export function EventsPage() {
  const [eventTypes, setEventTypes] = useState<EventType[]>([]);
  const [riskLevels, setRiskLevels] = useState<TrustLevel[]>([]);
  const [startLocal, setStartLocal] = useState("");
  const [endLocal, setEndLocal] = useState("");

  const startTime = toMillis(startLocal);
  const endTime = toMillis(endLocal);

  // Only the time range drives the server query; event-type and risk-level
  // toggles are applied purely client-side (below) for instant feedback with
  // no per-toggle network round-trip.
  const events = useEvents({ startTime, endTime });

  // The time range is already applied server-side by ListEvents, so the
  // client-side pass only refines by event type and risk level.
  const visible = useMemo(() => {
    if (!events.data) return [];
    return sortEventsByTimeDesc(
      filterEvents(events.data, { eventTypes, riskLevels }),
    );
  }, [events.data, eventTypes, riskLevels]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Events</h1>
        <p className="text-sm text-slate-400">
          Risk events across the tenant. Filter by type, risk level and time.
        </p>
      </header>

      <Card title="Filters">
        <div className="space-y-4">
          <div>
            <div className="label">Event type</div>
            <div className="flex flex-wrap gap-2">
              {eventTypeChoices.map((t) => {
                const active = eventTypes.includes(t);
                return (
                  <button
                    key={t}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setEventTypes((s) => toggle(s, t))}
                    className={`badge ${
                      active
                        ? "border-indigo-500/40 bg-indigo-500/20 text-indigo-200"
                        : "border-slate-700 text-slate-300"
                    }`}
                  >
                    {eventTypeLabels[t]}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <div className="label">Risk level</div>
            <div className="flex flex-wrap gap-2">
              {riskLevelChoices.map((r) => {
                const active = riskLevels.includes(r);
                return (
                  <button
                    key={r}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setRiskLevels((s) => toggle(s, r))}
                    className={`badge ${
                      active ? riskLevelTone(r) : "border-slate-700 text-slate-300"
                    }`}
                  >
                    {trustLevelLabels[r]}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="startTime" className="label">
                From
              </label>
              <input
                id="startTime"
                type="datetime-local"
                className="input"
                value={startLocal}
                onChange={(e) => setStartLocal(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="endTime" className="label">
                To
              </label>
              <input
                id="endTime"
                type="datetime-local"
                className="input"
                value={endLocal}
                onChange={(e) => setEndLocal(e.target.value)}
              />
            </div>
          </div>

          {(eventTypes.length > 0 ||
            riskLevels.length > 0 ||
            startLocal ||
            endLocal) && (
            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                setEventTypes([]);
                setRiskLevels([]);
                setStartLocal("");
                setEndLocal("");
              }}
            >
              Clear filters
            </button>
          )}
        </div>
      </Card>

      <Card
        title={
          <span>
            Events{" "}
            <span className="text-slate-500">({visible.length})</span>
          </span>
        }
      >
        {events.isLoading ? (
          <Spinner />
        ) : events.isError ? (
          <ErrorNotice error={events.error} />
        ) : visible.length === 0 ? (
          <EmptyState>No events match the current filters.</EmptyState>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="th">Time</th>
                <th className="th">Type</th>
                <th className="th">Risk</th>
                <th className="th">Build</th>
                <th className="th">Region</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => (
                <tr key={e.id} className="border-b border-slate-800/60">
                  <td className="td font-mono text-xs text-slate-400">
                    {formatTimestamp(e.timestamp)}
                  </td>
                  <td className="td">{eventTypeLabels[e.eventType]}</td>
                  <td className="td">
                    <Badge tone={riskLevelTone(e.riskLevel)}>
                      {trustLevelLabels[e.riskLevel]}
                    </Badge>
                  </td>
                  <td className="td font-mono text-xs text-slate-500">
                    {e.appBuildHash ? `${e.appBuildHash.slice(0, 12)}…` : "—"}
                  </td>
                  <td className="td text-slate-400">
                    {e.countryOrRegion ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
