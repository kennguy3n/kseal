import { useId } from "react";
import {
  hasActiveThresholds,
  type AlertThresholds,
} from "../lib/thresholds";

// Lets an MSSP operator set client-side alert bounds. Rates are entered as
// whole percentages for readability and stored as [0,1] fractions. An empty
// field disables that bound. Purely presentational — breaches only highlight
// tenants; nothing is sent to the server.
export function ThresholdsEditor({
  thresholds,
  onChange,
}: {
  thresholds: AlertThresholds;
  onChange: (next: AlertThresholds) => void;
}) {
  const healthId = useId();
  const highRiskId = useId();
  const attestId = useId();
  const active = hasActiveThresholds(thresholds);

  const setField = (patch: Partial<AlertThresholds>) => {
    onChange({ ...thresholds, ...patch });
  };

  const pctValue = (rate: number | undefined) =>
    rate === undefined ? "" : String(Math.round(rate * 100));

  const onPctChange =
    (key: "maxHighRiskRate" | "maxAttestationFailureRate") =>
    (raw: string) => {
      if (raw.trim() === "") {
        const next = { ...thresholds };
        delete next[key];
        onChange(next);
        return;
      }
      const n = Number(raw);
      if (!Number.isFinite(n)) return;
      // Round to a whole percent before storing (the field is integer-percent,
      // step=1) so the persisted rate always matches what the input redisplays —
      // no lossy round-trip where e.g. "0.5" stores 0.005 but shows as "1".
      const pct = Math.min(100, Math.max(0, Math.round(n)));
      setField({ [key]: pct / 100 });
    };

  return (
    <fieldset className="rounded-lg border border-line bg-panel p-4">
      <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-muted">
        Alert thresholds {active && <span className="text-accent-strong">· active</span>}
      </legend>
      <p className="mb-3 mt-1 text-xs text-subtle">
        Highlight tenants that breach any bound. Leave a field blank to ignore it.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div>
          <label htmlFor={healthId} className="label">
            Min health score
          </label>
          <input
            id={healthId}
            className="input"
            type="number"
            inputMode="numeric"
            min={0}
            max={100}
            step={1}
            placeholder="e.g. 50"
            value={thresholds.minHealthScore ?? ""}
            onChange={(e) => {
              if (e.target.value.trim() === "") {
                const next = { ...thresholds };
                delete next.minHealthScore;
                onChange(next);
                return;
              }
              const n = Number(e.target.value);
              if (Number.isFinite(n)) {
                setField({ minHealthScore: Math.min(100, Math.max(0, Math.round(n))) });
              }
            }}
          />
        </div>
        <div>
          <label htmlFor={highRiskId} className="label">
            Max high-risk %
          </label>
          <input
            id={highRiskId}
            className="input"
            type="number"
            inputMode="numeric"
            min={0}
            max={100}
            step={1}
            placeholder="e.g. 10"
            value={pctValue(thresholds.maxHighRiskRate)}
            onChange={(e) => onPctChange("maxHighRiskRate")(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor={attestId} className="label">
            Max attest-fail %
          </label>
          <input
            id={attestId}
            className="input"
            type="number"
            inputMode="numeric"
            min={0}
            max={100}
            step={1}
            placeholder="e.g. 5"
            value={pctValue(thresholds.maxAttestationFailureRate)}
            onChange={(e) =>
              onPctChange("maxAttestationFailureRate")(e.target.value)
            }
          />
        </div>
      </div>
    </fieldset>
  );
}
