import { useCallback, useEffect, useState } from "react";

// Color theme handling. The active theme is persisted in localStorage and
// applied as a `.dark` class on <html> (Tailwind's class-based dark mode). An
// inline script in index.html applies the same precedence before first paint
// to avoid a flash; this hook keeps the toggle and any cross-tab changes in
// sync at runtime.

export type Theme = "light" | "dark";

const STORAGE_KEY = "kseal.console.theme";

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

// Resolve the initial theme: an explicit stored choice wins, otherwise fall
// back to the OS preference (and finally light).
export function resolveInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* localStorage unavailable (private mode, SSR) — fall through. */
  }
  return systemPrefersDark() ? "dark" : "light";
}

export function applyTheme(theme: Theme): void {
  if (typeof document === "undefined") return;
  document.documentElement.classList.toggle("dark", theme === "dark");
}

export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  const [theme, setTheme] = useState<Theme>(resolveInitialTheme);

  // Keep the DOM class and persisted value in step with state.
  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* ignore persistence failures */
    }
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  }, []);

  return { theme, toggleTheme };
}
