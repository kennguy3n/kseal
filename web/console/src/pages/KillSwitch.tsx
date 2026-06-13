import { useState } from "react";
import { useIssueKillSwitch, useKillSwitchState } from "../hooks/compliance";
import {
  Badge,
  Card,
  ErrorNotice,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { AppSelect } from "../components/AppSelect";
import { KillSwitchCommand } from "../gen/kseal/v1/compliance_pb";
import {
  formatTimestamp,
  killSwitchCommandLabels,
  killSwitchCommandTone,
} from "../lib/format";
import { isUnavailableError } from "../lib/availability";

export function KillSwitchPage() {
  const [appId, setAppId] = useState("");
  const state = useKillSwitchState(appId);
  const issue = useIssueKillSwitch();

  // Two-step confirm: the operator must enter a reason and explicitly confirm
  // before a signed command is issued (fail-safe against accidental trips).
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState<KillSwitchCommand | null>(null);

  // The effective command defaults to ENABLE (armed) when nothing is set, so
  // the response is always present unless the RPC itself is unavailable.
  const effective = state.data?.effectiveCommand ?? KillSwitchCommand.UNSPECIFIED;
  const active = state.data?.active ?? null;
  const isArmed = effective !== KillSwitchCommand.DISABLE;
  // Default the proposed command to the opposite of the current state.
  const target = isArmed ? KillSwitchCommand.DISABLE : KillSwitchCommand.ENABLE;

  function resetRequest() {
    setPending(null);
    setReason("");
    issue.reset();
  }

  async function onConfirm() {
    if (pending === null || reason.trim().length === 0) return;
    try {
      await issue.mutateAsync({
        appId,
        command: pending,
        reason: reason.trim(),
      });
      resetRequest();
    } catch {
      // surfaced via issue.isError below
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Kill switch</h1>
        <p className="text-sm text-slate-400">
          View and issue a signed enable/disable of protection enforcement.
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
          disabled={issue.isPending}
        />
      </Card>

      <Card title="Current state">
        {state.isLoading ? (
          <Spinner />
        ) : state.isError && isUnavailableError(state.error) ? (
          <UnavailableNotice feature="The kill switch" />
        ) : state.isError ? (
          <ErrorNotice error={state.error} />
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <Badge tone={killSwitchCommandTone(effective)}>
                {killSwitchCommandLabels[effective]}
              </Badge>
              <span className="text-sm text-slate-400">
                {isArmed
                  ? "Protection is enforcing normally."
                  : "Protection enforcement is disabled (observe-only)."}
              </span>
            </div>
            {active ? (
              <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                <div>
                  <dt className="label">Issued</dt>
                  <dd className="font-mono text-xs text-slate-400">
                    {formatTimestamp(active.issuedAt)}
                  </dd>
                </div>
                <div>
                  <dt className="label">Version</dt>
                  <dd className="font-mono text-xs text-slate-400">
                    {active.version.toString()}
                  </dd>
                </div>
                <div>
                  <dt className="label">Signing key</dt>
                  <dd className="font-mono text-xs text-slate-400">
                    {active.keyId || "—"}
                  </dd>
                </div>
                <div>
                  <dt className="label">Reason</dt>
                  <dd className="text-slate-300">{active.reason || "—"}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-sm text-slate-400">
                No signed command in effect for this scope (armed by default).
              </p>
            )}
          </div>
        )}
      </Card>

      {!state.isError && (
        <Card
          title={
            target === KillSwitchCommand.DISABLE
              ? "Disable protection"
              : "Re-arm protection"
          }
        >
          {issue.isError && (
            <div className="mb-3">
              <ErrorNotice error={issue.error} />
            </div>
          )}
          {pending === null ? (
            <div className="space-y-3">
              <p className="text-sm text-slate-400">
                {target === KillSwitchCommand.DISABLE
                  ? "Issues a signed kill switch that disables enforcement for this scope. Use only for incident response."
                  : "Issues a signed command that re-arms enforcement for this scope."}
              </p>
              <button
                type="button"
                className={
                  target === KillSwitchCommand.DISABLE
                    ? "btn-danger"
                    : "btn-primary"
                }
                onClick={() => setPending(target)}
              >
                {target === KillSwitchCommand.DISABLE
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
                    pending === KillSwitchCommand.DISABLE
                      ? "btn-danger"
                      : "btn-primary"
                  }
                  disabled={reason.trim().length === 0 || issue.isPending}
                  onClick={() => void onConfirm()}
                >
                  {issue.isPending
                    ? "Requesting…"
                    : `Confirm: ${killSwitchCommandLabels[pending]}`}
                </button>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={resetRequest}
                  disabled={issue.isPending}
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
