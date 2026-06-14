// Shared severity palette (solid CSS colors) for stacked bars and legend dots.
// Mirrors the escalating risk-tone scale used for badges. Kept out of the
// component file so React Fast Refresh stays happy (component files should
// only export components).

export const TRUST_LEVEL_COLORS: Record<string, string> = {
  TRUSTED: "rgb(16 185 129)", // emerald-500
  LOW_RISK: "rgb(14 165 233)", // sky-500
  MEDIUM_RISK: "rgb(245 158 11)", // amber-500
  HIGH_RISK: "rgb(249 115 22)", // orange-500
  CRITICAL: "rgb(244 63 94)", // rose-500
};

export const HEALTH_BAND_COLORS: Record<string, string> = {
  healthy: "rgb(16 185 129)", // emerald-500
  watch: "rgb(245 158 11)", // amber-500
  "at-risk": "rgb(244 63 94)", // rose-500
  unknown: "rgb(100 116 139)", // slate-500
};
