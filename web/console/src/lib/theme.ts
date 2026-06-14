import { createContext, useContext } from "react";

// Color theme handling. The active theme is persisted in localStorage and
// applied as a `.dark` class on <html> (Tailwind's class-based dark mode). An
// inline script in index.html applies the same precedence before first paint
// to avoid a flash. The single source of truth at runtime is ThemeProvider
// (see ThemeProvider.tsx): every consumer shares one piece of state, and a
// `storage` listener keeps other tabs in sync.

export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "kseal.console.theme";

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

// True when the user has made an explicit, persisted theme choice. Until then
// the app follows the OS preference dynamically rather than locking it in.
export function hasStoredThemeChoice(): boolean {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored === "light" || stored === "dark";
  } catch {
    return false;
  }
}

// The current OS color-scheme preference as a Theme.
export function systemTheme(): Theme {
  return systemPrefersDark() ? "dark" : "light";
}

// Resolve the initial theme: an explicit stored choice wins, otherwise fall
// back to the OS preference (and finally light).
//
// NOTE: the no-flash inline <script> in index.html intentionally duplicates
// this precedence (explicit "light"/"dark" → OS preference) so the .dark class
// is set before first paint. Any change to the resolution order here MUST be
// mirrored there, and vice versa.
export function resolveInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* localStorage unavailable (private mode, SSR) — fall through. */
  }
  return systemTheme();
}

export function applyTheme(theme: Theme): void {
  if (typeof document === "undefined") return;
  document.documentElement.classList.toggle("dark", theme === "dark");
}

export interface ThemeContextValue {
  theme: Theme;
  toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return ctx;
}
