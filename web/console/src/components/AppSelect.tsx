import { useApps } from "../hooks/queries";

// Shared tenant-scoped app picker used by the per-app compliance views
// (data-processing registry, kill switch, canary monitor). An empty value means
// "all apps / tenant-wide". Mirrors the inline selector on the Policies page.
export function AppSelect({
  id,
  value,
  onChange,
  allLabel = "All apps",
  label = "App",
}: {
  id: string;
  value: string;
  onChange: (appId: string) => void;
  allLabel?: string;
  label?: string;
}) {
  const apps = useApps();
  return (
    <div>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <select
        id={id}
        className="input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={apps.isLoading}
      >
        <option value="">{allLabel}</option>
        {apps.data?.map((a) => (
          <option key={a.id} value={a.id}>
            {a.name}
          </option>
        ))}
      </select>
    </div>
  );
}
