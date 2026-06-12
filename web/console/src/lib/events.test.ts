import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";
import {
  EventRecordSchema,
  type EventRecord,
} from "../gen/kseal/v1/query_service_pb";
import {
  emptyEventFilter,
  filterEvents,
  isEventFilterActive,
  sortEventsByTimeDesc,
} from "./events";

function ev(
  partial: Partial<{
    id: string;
    eventType: EventType;
    riskLevel: TrustLevel;
    timestamp: number;
  }>,
): EventRecord {
  return create(EventRecordSchema, {
    id: partial.id ?? "e",
    eventType: partial.eventType ?? EventType.ROOT_RISK,
    riskLevel: partial.riskLevel ?? TrustLevel.MEDIUM_RISK,
    timestamp: BigInt(partial.timestamp ?? 1_000),
  });
}

const sample: EventRecord[] = [
  { id: "a", eventType: EventType.ROOT_RISK, riskLevel: TrustLevel.HIGH_RISK, timestamp: 300 },
  { id: "b", eventType: EventType.DEBUGGER, riskLevel: TrustLevel.LOW_RISK, timestamp: 100 },
  { id: "c", eventType: EventType.ROOT_RISK, riskLevel: TrustLevel.CRITICAL, timestamp: 200 },
].map(ev);

describe("filterEvents", () => {
  it("returns all events for an empty filter", () => {
    expect(filterEvents(sample, emptyEventFilter)).toHaveLength(3);
  });

  it("filters by event type", () => {
    const out = filterEvents(sample, {
      eventTypes: [EventType.ROOT_RISK],
      riskLevels: [],
    });
    expect(out.map((e) => e.id).sort()).toEqual(["a", "c"]);
  });

  it("filters by risk level", () => {
    const out = filterEvents(sample, {
      eventTypes: [],
      riskLevels: [TrustLevel.CRITICAL, TrustLevel.LOW_RISK],
    });
    expect(out.map((e) => e.id).sort()).toEqual(["b", "c"]);
  });

  it("combines type and risk constraints (AND semantics)", () => {
    const out = filterEvents(sample, {
      eventTypes: [EventType.ROOT_RISK],
      riskLevels: [TrustLevel.CRITICAL],
    });
    expect(out.map((e) => e.id)).toEqual(["c"]);
  });

  it("filters by inclusive time range", () => {
    const out = filterEvents(sample, {
      eventTypes: [],
      riskLevels: [],
      startTime: 150,
      endTime: 300,
    });
    expect(out.map((e) => e.id).sort()).toEqual(["a", "c"]);
  });

  it("treats range bounds as inclusive", () => {
    const out = filterEvents(sample, {
      eventTypes: [],
      riskLevels: [],
      startTime: 100,
      endTime: 100,
    });
    expect(out.map((e) => e.id)).toEqual(["b"]);
  });
});

describe("isEventFilterActive", () => {
  it("is false for the empty filter", () => {
    expect(isEventFilterActive(emptyEventFilter)).toBe(false);
  });
  it("is true when any constraint is set", () => {
    expect(
      isEventFilterActive({ eventTypes: [EventType.DEBUGGER], riskLevels: [] }),
    ).toBe(true);
    expect(
      isEventFilterActive({ eventTypes: [], riskLevels: [], startTime: 1 }),
    ).toBe(true);
  });
});

describe("sortEventsByTimeDesc", () => {
  it("orders newest first without mutating the input", () => {
    const out = sortEventsByTimeDesc(sample);
    expect(out.map((e) => e.id)).toEqual(["a", "c", "b"]);
    expect(sample.map((e) => e.id)).toEqual(["a", "b", "c"]);
  });

  it("breaks ties deterministically by id", () => {
    const tied = [
      ev({ id: "x", timestamp: 500 }),
      ev({ id: "y", timestamp: 500 }),
    ];
    expect(sortEventsByTimeDesc(tied).map((e) => e.id)).toEqual(["x", "y"]);
  });
});
