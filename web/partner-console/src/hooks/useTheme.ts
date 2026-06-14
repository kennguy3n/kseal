import { useCallback, useEffect, useState } from "react";
import {
  applyTheme,
  loadThemePref,
  resolveTheme,
  saveThemePref,
  type ResolvedTheme,
  type ThemePref,
} from "../lib/theme";

export interface UseThemeResult {
  pref: ThemePref;
  resolved: ResolvedTheme;
  setPref: (pref: ThemePref) => void;
}

/**
 * Theme state hook: persists the operator's choice and applies it to <html>.
 * When the choice is "system" it tracks the OS preference live via a
 * matchMedia listener, so toggling the OS theme updates the console instantly.
 */
export function useTheme(): UseThemeResult {
  const [pref, setPrefState] = useState<ThemePref>(() => loadThemePref());
  const [resolved, setResolved] = useState<ResolvedTheme>(() =>
    resolveTheme(loadThemePref()),
  );

  const setPref = useCallback((next: ThemePref) => {
    saveThemePref(next);
    setPrefState(next);
    const r = resolveTheme(next);
    setResolved(r);
    applyTheme(r);
  }, []);

  useEffect(() => {
    if (pref !== "system" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      const r = resolveTheme("system");
      setResolved(r);
      applyTheme(r);
    };
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, [pref]);

  return { pref, resolved, setPref };
}
