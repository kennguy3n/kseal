import type { HealthBand } from "./rollup";

// Tailwind badge classes per health band, escalating with severity. Mirrors the
// risk-tone palette used across the kseal consoles.
export function healthBandTone(band: HealthBand): string {
  switch (band) {
    case "healthy":
      return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300";
    case "watch":
      return "bg-amber-500/10 text-amber-700 border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-300";
    case "at-risk":
      return "bg-rose-500/10 text-rose-700 border-rose-500/30 dark:bg-rose-500/15 dark:text-rose-300";
    default:
      return "bg-slate-500/10 text-slate-600 border-slate-500/30 dark:bg-slate-500/15 dark:text-slate-300";
  }
}

export function healthBandLabel(band: HealthBand): string {
  switch (band) {
    case "healthy":
      return "Healthy";
    case "watch":
      return "Watch";
    case "at-risk":
      return "At risk";
    default:
      return "Unknown";
  }
}
