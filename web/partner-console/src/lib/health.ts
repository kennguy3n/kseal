import type { HealthBand } from "./rollup";

// Tailwind badge classes per health band, escalating with severity. Mirrors the
// risk-tone palette used across the kseal consoles.
export function healthBandTone(band: HealthBand): string {
  switch (band) {
    case "healthy":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    case "watch":
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    case "at-risk":
      return "bg-rose-500/15 text-rose-300 border-rose-500/30";
    default:
      return "bg-slate-500/15 text-slate-300 border-slate-500/30";
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
