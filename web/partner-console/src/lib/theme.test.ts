import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyTheme,
  loadThemePref,
  resolveTheme,
  saveThemePref,
} from "./theme";

beforeEach(() => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("theme preference storage", () => {
  it("defaults to system and round-trips a saved preference", () => {
    expect(loadThemePref()).toBe("system");
    saveThemePref("light");
    expect(loadThemePref()).toBe("light");
  });

  it("ignores a corrupt stored value", () => {
    localStorage.setItem("kseal.partner.theme.v1", "neon");
    expect(loadThemePref()).toBe("system");
  });
});

describe("resolveTheme", () => {
  it("returns explicit choices verbatim", () => {
    expect(resolveTheme("light")).toBe("light");
    expect(resolveTheme("dark")).toBe("dark");
  });

  it("consults the OS for system", () => {
    vi.spyOn(window, "matchMedia").mockReturnValue({
      matches: true,
      media: "(prefers-color-scheme: dark)",
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      onchange: null,
      dispatchEvent: vi.fn(),
    } as unknown as MediaQueryList);
    expect(resolveTheme("system")).toBe("dark");
  });
});

describe("applyTheme", () => {
  it("toggles the dark class on the document element", () => {
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    applyTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});
