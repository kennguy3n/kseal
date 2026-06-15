import { useState, type FormEvent } from "react";
import {
  useDeleteWebhook,
  useRegisterWebhook,
  useWebhooks,
} from "../hooks/queries";
import {
  Card,
  EmptyState,
  ErrorNotice,
  PageHeader,
  SkeletonRows,
  Badge,
} from "../components/ui";
import { EventType } from "../gen/kseal/v1/common_pb";
import { eventTypeLabels, formatEpochSeconds } from "../lib/format";

const eventTypeChoices: EventType[] = [
  EventType.RUNTIME_TAMPER,
  EventType.DEBUGGER,
  EventType.ROOT_RISK,
  EventType.ATTESTATION_FAIL,
  EventType.NETWORK_MITM,
  EventType.POLICY_DECISION,
  EventType.HOOKING_DETECTED,
  EventType.APP_INTEGRITY_FAIL,
  EventType.ENVIRONMENT_RISK,
];

function isValidHttpsUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

export function WebhooksPage() {
  const webhooks = useWebhooks();
  const register = useRegisterWebhook();
  const remove = useDeleteWebhook();

  const [url, setUrl] = useState("");
  const [selected, setSelected] = useState<EventType[]>([]);
  const [error, setError] = useState<string | null>(null);

  function toggle(t: EventType) {
    setSelected((s) => (s.includes(t) ? s.filter((v) => v !== t) : [...s, t]));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!isValidHttpsUrl(url.trim())) {
      setError("Enter a valid http(s) URL.");
      return;
    }
    if (selected.length === 0) {
      setError("Select at least one event type.");
      return;
    }
    try {
      await register.mutateAsync({ url: url.trim(), eventTypes: selected });
      setUrl("");
      setSelected([]);
    } catch {
      // surfaced via register.isError below
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhooks"
        description="Fan out signed event deliveries to your endpoints. Each payload is signed so you can verify it came from kseal."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Registered webhooks">
          {webhooks.isLoading ? (
            <SkeletonRows rows={3} />
          ) : webhooks.isError ? (
            <ErrorNotice
              error={webhooks.error}
              onRetry={() => void webhooks.refetch()}
            />
          ) : !webhooks.data || webhooks.data.length === 0 ? (
            <EmptyState>No webhooks registered.</EmptyState>
          ) : (
            <ul className="space-y-2">
              {webhooks.data.map((w) => (
                <li
                  key={w.id}
                  className="rounded-lg border border-line p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate font-mono text-sm text-fg-strong">
                        {w.url}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {w.eventTypes.map((t) => (
                          <Badge key={t}>{eventTypeLabels[t]}</Badge>
                        ))}
                      </div>
                      <div className="mt-1 text-xs text-fg-subtle">
                        {w.isActive ? "active" : "inactive"} ·{" "}
                        {formatEpochSeconds(w.createdAt)}
                      </div>
                    </div>
                    <button
                      className="btn-danger"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(w.id)}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {remove.isError && (
            <div className="mt-3">
              <ErrorNotice error={remove.error} />
            </div>
          )}
        </Card>

        <Card title="Add webhook">
          <form onSubmit={onSubmit} className="space-y-3">
            <div>
              <label htmlFor="webhookUrl" className="label">
                Endpoint URL
              </label>
              <input
                id="webhookUrl"
                className="input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/kseal/webhook"
              />
            </div>

            <div>
              <div className="label">Event types</div>
              <div className="flex flex-wrap gap-2">
                {eventTypeChoices.map((t) => {
                  const active = selected.includes(t);
                  return (
                    <button
                      key={t}
                      type="button"
                      aria-pressed={active}
                      onClick={() => toggle(t)}
                      className={`badge ${
                        active
                          ? "border-accent-strong/40 bg-accent-strong/15 text-accent"
                          : "border-line-strong text-fg"
                      }`}
                    >
                      {eventTypeLabels[t]}
                    </button>
                  );
                })}
              </div>
            </div>

            {error && (
              <div role="alert" className="text-sm text-rose-600 dark:text-rose-300">
                {error}
              </div>
            )}
            {register.isError && <ErrorNotice error={register.error} />}

            <button
              type="submit"
              className="btn-primary w-full"
              disabled={register.isPending}
            >
              {register.isPending ? "Registering…" : "Register webhook"}
            </button>
          </form>
        </Card>
      </div>
    </div>
  );
}
