import { describe, expect, it } from "vitest";
import { EnforcementMode } from "../gen/kseal/v1/common_pb";
import { parseModules, parsePolicyForm, type PolicyFormState } from "./policy";

const base: PolicyFormState = {
  name: "Baseline",
  appId: "app-1",
  enforcementMode: EnforcementMode.OBSERVE,
  modulesText: "root, debugger\nhooking",
  riskThresholdsJson: '{"MEDIUM_RISK": 40}',
  rulesJson: "{}",
};

describe("parseModules", () => {
  it("splits on commas and whitespace and dedupes", () => {
    expect(parseModules("root, debugger\nhooking root")).toEqual([
      "root",
      "debugger",
      "hooking",
    ]);
  });

  it("returns an empty array for blank input", () => {
    expect(parseModules("   \n ")).toEqual([]);
  });
});

describe("parsePolicyForm", () => {
  it("produces a draft for valid input", () => {
    const res = parsePolicyForm(base);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.draft.name).toBe("Baseline");
      expect(res.draft.modulesEnabled).toEqual([
        "root",
        "debugger",
        "hooking",
      ]);
      expect(res.draft.enforcementMode).toBe(EnforcementMode.OBSERVE);
      expect(JSON.parse(res.draft.riskThresholds)).toEqual({ MEDIUM_RISK: 40 });
      expect(res.draft.rules).toBe("{}");
    }
  });

  it("requires a name", () => {
    const res = parsePolicyForm({ ...base, name: "  " });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.name).toBeDefined();
  });

  it("rejects UNSPECIFIED enforcement mode", () => {
    const res = parsePolicyForm({
      ...base,
      enforcementMode: EnforcementMode.UNSPECIFIED,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.enforcementMode).toBeDefined();
  });

  it("rejects malformed threshold JSON", () => {
    const res = parsePolicyForm({ ...base, riskThresholdsJson: "{not json" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.riskThresholdsJson).toContain("Invalid JSON");
  });

  it("rejects non-object JSON (arrays/primitives)", () => {
    const res = parsePolicyForm({ ...base, rulesJson: "[1, 2, 3]" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors.rulesJson).toBe("Expected a JSON object");
  });

  it("treats empty JSON fields as empty objects", () => {
    const res = parsePolicyForm({
      ...base,
      riskThresholdsJson: "",
      rulesJson: "  ",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.draft.riskThresholds).toBe("{}");
      expect(res.draft.rules).toBe("{}");
    }
  });

  it("canonicalizes JSON (strips insignificant whitespace)", () => {
    const res = parsePolicyForm({
      ...base,
      riskThresholdsJson: '{  "HIGH_RISK" :  70 }',
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.draft.riskThresholds).toBe('{"HIGH_RISK":70}');
  });
});
