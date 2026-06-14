export interface BarSegment {
  key: string;
  label: string;
  value: number;
  /** CSS color (e.g. an `rgb(...)` literal) for the segment fill. */
  color: string;
}

// Horizontal stacked bar for a categorical distribution (trust-level mix,
// health-band mix). Renders proportional segments with an accessible legend
// listing each category's label and count. Zero-total collapses to an empty
// track so layout stays stable.
export function SeverityBar({
  segments,
  ariaLabel,
}: {
  segments: readonly BarSegment[];
  ariaLabel: string;
}) {
  const total = segments.reduce((acc, s) => acc + Math.max(0, s.value), 0);
  return (
    <div>
      <div
        role="img"
        aria-label={`${ariaLabel}: ${segments
          .filter((s) => s.value > 0)
          .map((s) => `${s.label} ${s.value}`)
          .join(", ") || "no data"}`}
        className="flex h-2.5 w-full overflow-hidden rounded-full bg-raised"
      >
        {total > 0 &&
          segments.map((s) =>
            s.value > 0 ? (
              <div
                key={s.key}
                style={{
                  width: `${(s.value / total) * 100}%`,
                  backgroundColor: s.color,
                }}
                title={`${s.label}: ${s.value}`}
              />
            ) : null,
          )}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {segments.map((s) => (
          <li key={s.key} className="flex items-center gap-1.5 text-muted">
            <span
              aria-hidden="true"
              className="h-2 w-2 rounded-full"
              style={{ backgroundColor: s.color }}
            />
            <span>{s.label}</span>
            <span className="font-medium tabular-nums text-content">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
