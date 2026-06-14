import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { applyTheme, resolveInitialTheme, useTheme } from "./theme";

const STORAGE_KEY = "kseal.console.theme";

afterEach(() => {
  document.documentElement.classList.remove("dark");
  vi.unstubAllGlobals();
});

// jsdom has no real matchMedia; stub it so the system-preference branch is
// deterministic.
function stubMatchMedia(matches: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn().mockReturnValue({
      matches,
      media: "(prefers-color-scheme: dark)",
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }),
  );
}

describe("theme", () => {
  it("prefers an explicit stored choice over the system preference", () => {
    stubMatchMedia(true); // system = dark
    localStorage.setItem(STORAGE_KEY, "light");
    expect(resolveInitialTheme()).toBe("light");
  });

  it("falls back to the system preference when nothing is stored", () => {
    stubMatchMedia(true);
    expect(resolveInitialTheme()).toBe("dark");
    stubMatchMedia(false);
    expect(resolveInitialTheme()).toBe("light");
  });

  it("applyTheme toggles the .dark class on <html>", () => {
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    applyTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("useTheme persists the toggled value and updates the DOM", () => {
    stubMatchMedia(false);
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("light");

    act(() => result.current.toggleTheme());

    expect(result.current.theme).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem(STORAGE_KEY)).toBe("dark");
  });
});
