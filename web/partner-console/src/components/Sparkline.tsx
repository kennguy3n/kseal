import { useId } from "react";
import type { SignalBucket } from "../lib/events";

// Inline SVG sparkline of recent signal activity. Renders total volume as a
// filled area with the high/critical share overlaid, so an operator sees both
// "how much" and "how bad" at a glance. Purely presentational; the buckets are
// computed by lib/events.bucketSignals. Accessible via role="img" + a textual
// summary; decorative when there is no activity.
export function Sparkline({
  buckets,
  label,
  width = 120,
  height = 32,
  className = "",
}: {
  buckets: readonly SignalBucket[];
  label: string;
  width?: number;
  height?: number;
  className?: string;
}) {
  const gradientId = useId();
  const total = buckets.reduce((acc, b) => acc + b.total, 0);
  const elevated = buckets.reduce((acc, b) => acc + b.elevated, 0);

  if (buckets.length === 0 || total === 0) {
    return (
      <span className={`text-xs text-subtle ${className}`} aria-label={`${label}: no recent activity`}>
        No recent activity
      </span>
    );
  }

  const max = Math.max(...buckets.map((b) => b.total), 1);
  const n = buckets.length;
  const stepX = n > 1 ? width / (n - 1) : 0;
  const y = (v: number) => height - (v / max) * (height - 2) - 1;
  const pointsFor = (pick: (b: SignalBucket) => number) =>
    buckets.map((b, i) => `${(i * stepX).toFixed(2)},${y(pick(b)).toFixed(2)}`);

  const totalPts = pointsFor((b) => b.total);
  const elevatedPts = pointsFor((b) => b.elevated);
  const areaPath = `M0,${height} L${totalPts.join(" L")} L${(width).toFixed(2)},${height} Z`;

  return (
    <svg
      role="img"
      aria-label={`${label}: ${total} signals in window, ${elevated} high-risk`}
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      preserveAspectRatio="none"
      className={`overflow-visible ${className}`}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(var(--c-accent))" stopOpacity="0.35" />
          <stop offset="100%" stopColor="rgb(var(--c-accent))" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${gradientId})`} />
      <polyline
        points={totalPts.join(" ")}
        fill="none"
        stroke="rgb(var(--c-accent))"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {elevated > 0 && (
        <polyline
          points={elevatedPts.join(" ")}
          fill="none"
          stroke="rgb(244 63 94)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      )}
    </svg>
  );
}
