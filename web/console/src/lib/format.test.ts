import { describe, expect, it } from "vitest";
import { formatEpochSeconds, formatTimestamp } from "./format";

describe("formatTimestamp (unix millis)", () => {
  it("renders millis to second precision in UTC", () => {
    expect(formatTimestamp(1781549428000)).toBe("2026-06-15 18:50:28Z");
  });

  it("accepts bigint", () => {
    expect(formatTimestamp(1781549428000n)).toBe("2026-06-15 18:50:28Z");
  });

  it("returns em dash for zero/empty", () => {
    expect(formatTimestamp(0)).toBe("—");
    expect(formatTimestamp(0n)).toBe("—");
  });
});

describe("formatEpochSeconds (unix seconds)", () => {
  it("renders seconds to the correct year (not 1970)", () => {
    // Regression: registry created_at is EXTRACT(EPOCH ...) seconds; passing it
    // to a millis formatter rendered 1970. It must scale to millis first.
    expect(formatEpochSeconds(1781549428)).toBe("2026-06-15 18:50:28Z");
    expect(formatEpochSeconds(1781549428n)).toBe("2026-06-15 18:50:28Z");
  });

  it("returns em dash for zero/empty", () => {
    expect(formatEpochSeconds(0)).toBe("—");
    expect(formatEpochSeconds(0n)).toBe("—");
  });
});
