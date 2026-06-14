import { describe, expect, it } from "vitest";
import {
  bucketSignals,
  isElevated,
  isHighRisk,
  observedRegions,
  primaryRegion,
} from "./events";
import { makeSignal } from "../test/fixtures";

describe("risk classification", () => {
  it("treats medium+ as elevated and high+ as high-risk", () => {
    expect(isElevated(2)).toBe(false); // low_risk
    expect(isElevated(3)).toBe(true); // medium_risk
    expect(isHighRisk(3)).toBe(false);
    expect(isHighRisk(4)).toBe(true); // high_risk
    expect(isHighRisk(5)).toBe(true); // critical
  });
});

describe("bucketSignals", () => {
  const now = 1_000_000_000_000;
  const span = 60_000; // 1 minute window

  it("returns all-zero buckets of the requested length for no signals", () => {
    const buckets = bucketSignals([], now, span, 6);
    expect(buckets).toHaveLength(6);
    expect(buckets.every((b) => b.total === 0 && b.highRisk === 0)).toBe(true);
    // Buckets are ordered oldest-first and evenly spaced.
    expect(buckets[0].startMs).toBe(now - span);
    expect(buckets[1].startMs - buckets[0].startMs).toBe(span / 6);
  });

  it("places signals into the correct slot and counts high-risk", () => {
    const buckets = bucketSignals(
      [
        makeSignal({ timestampMs: now - span + 1, riskLevel: 1 }), // first slot
        makeSignal({ timestampMs: now - 1, riskLevel: 4 }), // last slot, high-risk
        makeSignal({ timestampMs: now - 1, riskLevel: 5 }), // last slot, critical
      ],
      now,
      span,
      6,
    );
    expect(buckets[0].total).toBe(1);
    expect(buckets[0].highRisk).toBe(0);
    expect(buckets[5].total).toBe(2);
    expect(buckets[5].highRisk).toBe(2);
  });

  it("ignores signals outside the window or with no timestamp", () => {
    const buckets = bucketSignals(
      [
        makeSignal({ timestampMs: 0 }),
        makeSignal({ timestampMs: now - span - 1 }),
        makeSignal({ timestampMs: now + 1 }),
      ],
      now,
      span,
      4,
    );
    expect(buckets.reduce((a, b) => a + b.total, 0)).toBe(0);
  });

  it("never produces fewer than one bucket", () => {
    expect(bucketSignals([], now, span, 0)).toHaveLength(1);
  });
});

describe("region derivation", () => {
  it("returns the most-observed region, breaking ties alphabetically", () => {
    const signals = [
      makeSignal({ region: "US" }),
      makeSignal({ region: "US" }),
      makeSignal({ region: "DE" }),
      makeSignal({ region: "" }),
    ];
    expect(primaryRegion(signals)).toBe("US");
    // Tie between AU and DE -> alphabetical AU.
    expect(primaryRegion([makeSignal({ region: "DE" }), makeSignal({ region: "AU" })])).toBe("AU");
    expect(primaryRegion([])).toBe("");
  });

  it("collects sorted, de-duplicated observed regions", () => {
    expect(
      observedRegions([
        makeSignal({ region: "US" }),
        makeSignal({ region: "DE" }),
        makeSignal({ region: "US" }),
        makeSignal({ region: "" }),
      ]),
    ).toEqual(["DE", "US"]);
  });
});
