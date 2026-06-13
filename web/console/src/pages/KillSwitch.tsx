import { useState } from "react";
import {
  useKillSwitchState,
  useRequestKillSwitchChange,
} from "../hooks/compliance";
import {
  Badge,
  Card,
  ErrorNotice,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { AppSelect } from "../components/AppSelect";
import { KillSwitchStatus } from "../gen-local/kseal/consolelocal/v1/compliance_pb";
import {
  formatTimestamp,
  killSwitchStatusLabels,
  killSwitchStatusTone,
} from "../lib/format";
import { isUnavailableError } from "../lib/availability";

export function KillSwitchPage() {
  const [appId, setAppId] = useState("");
  const state = useKillSwitchState(appId);
  const requestChange = useRequestKillSwitchChange();

  // Two-step confirm: the operator must enter a reason and explicitly confirm
  // before a signed change is requested (fail-safe against accidental trips).
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState<KillSwitchStatus | null>(null);

  const current = state.data ?? null;
  const isArmed = current?.status === KillSwitchStatus.ARMED;
  // Default the proposed change to the opposite of the current state.
  const target = isArmed ? KillSwitchStatus.DISABLED : KillSwitchStatus.ARMED;

  function resetRequest() {
    setPending(null);
    setReason("");
    requestChange.reset();
  }

  async function onConfirm() {
    if (pending === null || reason.trim().length === 0) return;
    try {
      await requestChange.mutateAsync({
        appId,
        desiredStatus: pending,
        reason: reason.trim(),
      });
      resetRequest();
    } catch {
      // surfaced via requestChange.isError below
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Kill switch</h1>
        <p className="text-sm text-slate-400">
          View and request signed enable/disable of protection enforcement.
          Signing and authority are server-side; the console only requests the
          change.
        </p>
      </header>

      <Card title="Scope">
        <AppSelect
          id="ksScope"
          value={appId}
          onChange={(v) => {
            setAppId(v);
            resetRequest();
          }}
          allLabel="Tenant-wide"
          disabled={requestChange.isPending}
        />
      </Card>

      <Card title="Current state">
        {state.isLoading ? (
          <Spinner />
        ) : state.isError && isUnavailableError(state.error) ? (
          <UnavailableNotice feature="The kill switch" />
        ) : state.isError ? (
          <ErrorNotice error={state.error} />
        ) : !current ? (
          <p className="text-sm text-slate-400">
            No kill-switch state reported for this scope.
          </p>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <Badge tone={killSwitchStatusTone(current.status)}>
                {killSwitchStatusLabels[current.status]}
              </Badge>
              <span className="text-sm text-slate-400">
                {isArmed
                  ? "Protection is enforcing normally."
                  : "Protection enforcement is disabled (observe-only)."}
              </span>
            </div>
            <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="label">Last changed by</dt>
                <dd className="text-slate-300">
                  {current.lastChangedBy || "—"}
                </dd>
              </div>
              <div>
                <dt className="label">Last changed</dt>
                <dd className="font-mono text-xs text-slate-400">
                  {formatTimestamp(current.lastChangedAt)}
                </dd>
              </div>
              <div>
                <dt className="label">Signing key</dt>
                <dd className="font-mono text-xs text-slate-400">
                  {current.signingKeyId || "—"}
                </dd>
              </div>
              <div>
                <dt className="label">Reason</dt>
                <dd className="text-slate-300">{current.reason || "—"}</dd>
              </div>
            </dl>
          </div>
        )}
      </Card>

      {current && (
        <Card
          title={
            target === KillSwitchStatus.DISABLED
              ? "Disable protection"
              : "Re-arm protection"
          }
        >
          {requestChange.isError && (
            <div className="mb-3">
              <ErrorNotice error={requestChange.error} />
            </div>
          )}
          {pending === null ? (
            <div className="space-y-3">
              <p className="text-sm text-slate-400">
                {target === KillSwitchStatus.DISABLED
                  ? "Requests a signed kill switch that disables enforcement for this scope. Use only for incident response."
                  : "Requests a signed change that re-arms enforcement for this scope."}
              </p>
              <button
                type="button"
                className={
                  target === KillSwitchStatus.DISABLED
                    ? "btn-danger"
                    : "btn-primary"
                }
                onClick={() => setPending(target)}
              >
                {target === KillSwitchStatus.DISABLED
                  ? "Disable enforcement…"
                  : "Re-arm enforcement…"}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <label htmlFor="ksReason" className="label">
                Reason (required, recorded in the audit trail)
              </label>
              <textarea
                id="ksReason"
                className="input min-h-20"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g. INC-1234: false-positive block storm on release 4.2"
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  className={
                    pending === KillSwitchStatus.DISABLED
                      ? "btn-danger"
                      : "btn-primary"
                  }
                  disabled={
                    reason.trim().length === 0 || requestChange.isPending
                  }
                  onClick={() => void onConfirm()}
                >
                  {requestChange.isPending
                    ? "Requesting…"
                    : `Confirm: ${killSwitchStatusLabels[pending]}`}
                </button>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={resetRequest}
                  disabled={requestChange.isPending}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
