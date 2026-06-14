import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  applyTheme,
  hasStoredThemeChoice,
  resolveInitialTheme,
  systemTheme,
  THEME_STORAGE_KEY,
  ThemeContext,
  type Theme,
  type ThemeContextValue,
} from "./theme";

// Owns the one authoritative copy of the theme. Mount once near the root so
// every toggle reads and writes the same state.
//
// Persistence is deliberately *lazy*: we only write to localStorage once the
// user makes an explicit choice. A first-time visitor's OS-inferred theme is
// never locked in, so the app keeps following their OS preference (including
// live changes) until they actually pick one — matching the precedence
// documented in resolveInitialTheme() and index.html.
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(resolveInitialTheme);
  // Whether the user has made an explicit choice. Drives both persistence and
  // whether we keep tracking the OS preference.
  const [explicit, setExplicit] = useState<boolean>(hasStoredThemeChoice);

  const choose = useCallback((next: Theme) => {
    setExplicit(true);
    setTheme(next);
  }, []);

  // Reflect the active theme on <html>. Persist only once the user has chosen.
  useEffect(() => {
    applyTheme(theme);
    if (!explicit) return;
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      /* ignore persistence failures (private mode, SSR) */
    }
  }, [theme, explicit]);

  // While no explicit choice exists, follow the OS preference as it changes.
  useEffect(() => {
    if (explicit) return;
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) =>
      setTheme(e.matches ? "dark" : "light");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [explicit]);

  // Sync across tabs: when another tab writes the theme, adopt it here too;
  // when it clears the choice, revert to following the OS preference.
  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (e.key !== THEME_STORAGE_KEY) return;
      if (e.newValue === "light" || e.newValue === "dark") {
        setExplicit(true);
        setTheme(e.newValue);
      } else if (e.newValue === null) {
        setExplicit(false);
        setTheme(systemTheme());
      }
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const toggleTheme = useCallback(() => {
    choose(theme === "dark" ? "light" : "dark");
  }, [choose, theme]);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, toggleTheme }),
    [theme, toggleTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}
