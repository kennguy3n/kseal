// Theme preference handling for the partner console. Pure + DOM-only (no React)
// so the resolution logic is unit-testable and can run before React mounts
// (main.tsx applies the stored/system theme synchronously to avoid a flash).
//
// Three user choices are stored; "system" follows the OS via
// prefers-color-scheme and live-updates when the OS theme changes.

export type ThemePref = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "kseal.partner.theme.v1";

export const THEME_PREFS: readonly ThemePref[] = ["system", "light", "dark"];

function isThemePref(v: unknown): v is ThemePref {
  return v === "system" || v === "light" || v === "dark";
}

/** Reads the stored preference, defaulting to "system". Never throws. */
export function loadThemePref(): ThemePref {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return isThemePref(raw) ? raw : "system";
  } catch {
    return "system";
  }
}

export function saveThemePref(pref: ThemePref): void {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    // Storage may be unavailable (private mode); theme still applies in-memory.
  }
}

/** True when the OS currently prefers a dark color scheme. */
export function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

/** Resolves a preference to a concrete theme, consulting the OS for "system". */
export function resolveTheme(pref: ThemePref): ResolvedTheme {
  if (pref === "system") return systemPrefersDark() ? "dark" : "light";
  return pref;
}

/** Reflects the resolved theme onto <html> (the `dark` class drives Tailwind). */
export function applyTheme(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.style.colorScheme = resolved;
}

/** Loads + applies the stored preference. Call once before React mounts. */
export function initTheme(): ResolvedTheme {
  const resolved = resolveTheme(loadThemePref());
  applyTheme(resolved);
  return resolved;
}
