import { afterEach, describe, expect, it } from "vitest";
import {
  clearSession,
  loadSession,
  normalizeTenantIds,
  parseTenantIds,
  saveSession,
} from "./auth";

afterEach(() => {
  localStorage.clear();
});

describe("normalizeTenantIds", () => {
  it("trims, drops blanks, de-dups, preserves order", () => {
    expect(normalizeTenantIds([" t1 ", "t2", "t1", "", "  ", "t3"])).toEqual([
      "t1",
      "t2",
      "t3",
    ]);
  });
});

describe("parseTenantIds", () => {
  it("splits on newlines and commas", () => {
    expect(parseTenantIds("t1\nt2, t3\n\nt2")).toEqual(["t1", "t2", "t3"]);
  });
});

describe("session persistence", () => {
  it("round-trips a valid session", () => {
    saveSession({ apiKey: "ksk_x", tenantIds: ["a", "b"], apiBaseUrl: "http://h" });
    expect(loadSession()).toEqual({
      apiKey: "ksk_x",
      tenantIds: ["a", "b"],
      apiBaseUrl: "http://h",
    });
  });

  it("rejects a session with no tenants", () => {
    localStorage.setItem(
      "kseal.partner.session.v1",
      JSON.stringify({ apiKey: "ksk_x", tenantIds: [], apiBaseUrl: "http://h" }),
    );
    expect(loadSession()).toBeNull();
  });

  it("rejects a session with an empty key", () => {
    localStorage.setItem(
      "kseal.partner.session.v1",
      JSON.stringify({ apiKey: "", tenantIds: ["a"], apiBaseUrl: "http://h" }),
    );
    expect(loadSession()).toBeNull();
  });

  it("normalizes tenant ids loaded from storage", () => {
    localStorage.setItem(
      "kseal.partner.session.v1",
      JSON.stringify({ apiKey: "k", tenantIds: [" a ", "a", "b"], apiBaseUrl: "http://h" }),
    );
    expect(loadSession()?.tenantIds).toEqual(["a", "b"]);
  });

  it("clears a session", () => {
    saveSession({ apiKey: "k", tenantIds: ["a"], apiBaseUrl: "http://h" });
    clearSession();
    expect(loadSession()).toBeNull();
  });

  it("returns null on malformed JSON", () => {
    localStorage.setItem("kseal.partner.session.v1", "{not json");
    expect(loadSession()).toBeNull();
  });
});
