import { useMemo, useState, type FormEvent } from "react";
import {
  useActivatePolicy,
  useApps,
  useCreatePolicy,
  usePolicies,
} from "../hooks/queries";
import { Card, EmptyState, ErrorNotice, Spinner, Badge } from "../components/ui";
import { EnforcementMode } from "../gen/kseal/v1/common_pb";
import { enforcementModeLabels } from "../lib/format";
import {
  enforcementModeOptions,
  parsePolicyForm,
  type PolicyFormState,
} from "../lib/policy";

const initialForm: PolicyFormState = {
  name: "",
  appId: "",
  enforcementMode: EnforcementMode.OBSERVE,
  modulesText: "root, debugger, hooking",
  riskThresholdsJson: '{\n  "MEDIUM_RISK": 40,\n  "HIGH_RISK": 70\n}',
  rulesJson: "{}",
};

export function PolicyEditorPage() {
  const apps = useApps();
  const [appId, setAppId] = useState("");
  const policies = usePolicies(appId);
  const createPolicy = useCreatePolicy();
  const activatePolicy = useActivatePolicy();

  const [form, setForm] = useState<PolicyFormState>(initialForm);
  const [errors, setErrors] = useState<
    Partial<Record<keyof PolicyFormState, string>>
  >({});
  const [submitError, setSubmitError] = useState<unknown>(null);

  const activePolicyId = useMemo(
    () => policies.data?.find((p) => p.isActive)?.id,
    [policies.data],
  );

  function update<K extends keyof PolicyFormState>(
    key: K,
    value: PolicyFormState[K],
  ) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitError(null);
    const result = parsePolicyForm({ ...form, appId });
    if (!result.ok) {
      setErrors(result.errors);
      return;
    }
    setErrors({});
    try {
      await createPolicy.mutateAsync({
        appId,
        name: result.draft.name,
        enforcementMode: result.draft.enforcementMode,
        rules: result.draft.rules,
        riskThresholds: result.draft.riskThresholds,
        modulesEnabled: result.draft.modulesEnabled,
      });
      // Reset the authoring fields; the selected app scope lives in its own
      // `appId` state and is intentionally left untouched.
      setForm(initialForm);
    } catch (err) {
      setSubmitError(err);
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-fg-strong">Policies</h1>
        <p className="text-sm text-fg-muted">
          Author and activate enforcement policies. Empty app selection targets
          the tenant-wide default.
        </p>
      </header>

      <Card title="Scope">
        <label htmlFor="policyApp" className="label">
          App
        </label>
        <select
          id="policyApp"
          className="input"
          value={appId}
          onChange={(e) => setAppId(e.target.value)}
        >
          <option value="">Tenant-wide default</option>
          {apps.data?.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Policies">
          {policies.isLoading ? (
            <Spinner />
          ) : policies.isError ? (
            <ErrorNotice error={policies.error} />
          ) : !policies.data || policies.data.length === 0 ? (
            <EmptyState>No policies yet for this scope.</EmptyState>
          ) : (
            <ul className="space-y-2">
              {policies.data.map((p) => (
                <li
                  key={p.id}
                  className="flex items-center justify-between rounded-lg border border-line p-3"
                >
                  <div>
                    <div className="flex items-center gap-2 text-sm text-fg-strong">
                      {p.name}
                      <span className="text-xs text-fg-subtle">v{p.version}</span>
                      {p.isActive && (
                        <Badge tone="bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300">
                          active
                        </Badge>
                      )}
                    </div>
                    <div className="mt-1 text-xs text-fg-muted">
                      {enforcementModeLabels[p.enforcementMode]}
                    </div>
                  </div>
                  <button
                    className="btn-ghost"
                    disabled={
                      p.id === activePolicyId || activatePolicy.isPending
                    }
                    onClick={() => activatePolicy.mutate({ policyId: p.id, appId })}
                  >
                    {p.id === activePolicyId ? "Active" : "Activate"}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {activatePolicy.isError && (
            <div className="mt-3">
              <ErrorNotice error={activatePolicy.error} />
            </div>
          )}
        </Card>

        <Card title="New policy">
          <form onSubmit={onSubmit} className="space-y-3">
            <div>
              <label htmlFor="policyName" className="label">
                Name
              </label>
              <input
                id="policyName"
                className="input"
                value={form.name}
                onChange={(e) => update("name", e.target.value)}
              />
              {errors.name && (
                <p className="mt-1 text-xs text-rose-600 dark:text-rose-300">{errors.name}</p>
              )}
            </div>

            <div>
              <label htmlFor="policyMode" className="label">
                Enforcement mode
              </label>
              <select
                id="policyMode"
                className="input"
                value={form.enforcementMode}
                onChange={(e) =>
                  update("enforcementMode", Number(e.target.value))
                }
              >
                {enforcementModeOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              {errors.enforcementMode && (
                <p className="mt-1 text-xs text-rose-600 dark:text-rose-300">
                  {errors.enforcementMode}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="policyModules" className="label">
                Enabled modules
              </label>
              <input
                id="policyModules"
                className="input"
                value={form.modulesText}
                onChange={(e) => update("modulesText", e.target.value)}
                placeholder="root, debugger, hooking"
              />
            </div>

            <div>
              <label htmlFor="policyThresholds" className="label">
                Risk thresholds (JSON)
              </label>
              <textarea
                id="policyThresholds"
                className="input font-mono text-xs"
                rows={4}
                value={form.riskThresholdsJson}
                onChange={(e) => update("riskThresholdsJson", e.target.value)}
              />
              {errors.riskThresholdsJson && (
                <p className="mt-1 text-xs text-rose-600 dark:text-rose-300">
                  {errors.riskThresholdsJson}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="policyRules" className="label">
                Rules (JSON)
              </label>
              <textarea
                id="policyRules"
                className="input font-mono text-xs"
                rows={4}
                value={form.rulesJson}
                onChange={(e) => update("rulesJson", e.target.value)}
              />
              {errors.rulesJson && (
                <p className="mt-1 text-xs text-rose-600 dark:text-rose-300">{errors.rulesJson}</p>
              )}
            </div>

            {submitError != null && <ErrorNotice error={submitError} />}

            <button
              type="submit"
              className="btn-primary w-full"
              disabled={createPolicy.isPending}
            >
              {createPolicy.isPending ? "Creating…" : "Create policy"}
            </button>
          </form>
        </Card>
      </div>
    </div>
  );
}
