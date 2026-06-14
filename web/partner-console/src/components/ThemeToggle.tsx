import { useTheme } from "../hooks/useTheme";
import { THEME_PREFS, type ThemePref } from "../lib/theme";

const LABELS: Record<ThemePref, string> = {
  system: "Auto",
  light: "Light",
  dark: "Dark",
};

const ICONS: Record<ThemePref, string> = {
  system: "🖥",
  light: "☀",
  dark: "🌙",
};

// Segmented theme switch (Auto / Light / Dark). Auto follows the OS and
// live-updates. Rendered in the sidebar footer.
export function ThemeToggle() {
  const { pref, setPref } = useTheme();
  return (
    <div
      role="radiogroup"
      aria-label="Color theme"
      className="flex rounded-lg border border-line-strong bg-field p-0.5"
    >
      {THEME_PREFS.map((p) => {
        const active = pref === p;
        return (
          <button
            key={p}
            type="button"
            role="radio"
            aria-checked={active}
            title={`${LABELS[p]} theme`}
            onClick={() => setPref(p)}
            className={`focus-ring flex flex-1 items-center justify-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
              active
                ? "bg-accent text-accent-fg"
                : "text-muted hover:bg-hover hover:text-content"
            }`}
          >
            <span aria-hidden="true">{ICONS[p]}</span>
            <span>{LABELS[p]}</span>
          </button>
        );
      })}
    </div>
  );
}
