import { useState, type FormEvent } from "react";
import {
  useDeleteSiemConnector,
  useRegisterSiemConnector,
  useSiemConnectors,
} from "../hooks/queries";
import {
  Card,
  EmptyState,
  ErrorNotice,
  PageHeader,
  SkeletonRows,
  Badge,
} from "../components/ui";
import { SiemKind } from "../gen/kseal/v1/siem_pb";
import { formatEpochSeconds } from "../lib/format";

const kindLabels: Record<SiemKind, string> = {
  [SiemKind.UNSPECIFIED]: "Unspecified",
  [SiemKind.SPLUNK_HEC]: "Splunk HEC",
  [SiemKind.SENTINEL]: "Microsoft Sentinel",
  [SiemKind.ELASTIC]: "Elastic (ECS)",
};

const kindChoices: SiemKind[] = [
  SiemKind.SPLUNK_HEC,
  SiemKind.SENTINEL,
  SiemKind.ELASTIC,
];

// Canonical, non-PII export fields. Mirrors the server privacy contract in
// server/data-plane/siem/allowlist.go; an empty selection means "the full
// minimized contract".
const canonicalFields = [
  "tenant_id",
  "app_id",
  "event_type",
  "risk_level",
  "risk_bits",
  "confidence",
  "build_hash",
  "policy_hash",
  "install_key_hash",
  "coarse_time_bucket",
  "country_or_region",
];

const secretLabels: Record<SiemKind, string> = {
  [SiemKind.UNSPECIFIED]: "Auth secret",
  [SiemKind.SPLUNK_HEC]: "HEC token",
  [SiemKind.SENTINEL]: "Bearer token",
  [SiemKind.ELASTIC]: "API key",
};

function isValidHttpsUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

export function SiemConnectorsPage() {
  const connectors = useSiemConnectors();
  const register = useRegisterSiemConnector();
  const remove = useDeleteSiemConnector();

  const [kind, setKind] = useState<SiemKind>(SiemKind.SPLUNK_HEC);
  const [endpoint, setEndpoint] = useState("");
  const [secret, setSecret] = useState("");
  const [allow, setAllow] = useState<string[]>([]);
  const [splunkIndex, setSplunkIndex] = useState("");
  const [splunkSourcetype, setSplunkSourcetype] = useState("");
  const [dcrId, setDcrId] = useState("");
  const [streamName, setStreamName] = useState("");
  const [elasticIndex, setElasticIndex] = useState("");
  const [error, setError] = useState<string | null>(null);

  function toggleField(f: string) {
    setAllow((s) => (s.includes(f) ? s.filter((v) => v !== f) : [...s, f]));
  }

  function reset() {
    setEndpoint("");
    setSecret("");
    setAllow([]);
    setSplunkIndex("");
    setSplunkSourcetype("");
    setDcrId("");
    setStreamName("");
    setElasticIndex("");
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!isValidHttpsUrl(endpoint.trim())) {
      setError("Enter a valid http(s) endpoint URL.");
      return;
    }
    if (secret.trim().length === 0) {
      setError("Enter the connector auth secret.");
      return;
    }
    if (kind === SiemKind.SENTINEL && (!dcrId.trim() || !streamName.trim())) {
      setError("Sentinel connectors require a DCR immutable id and stream name.");
      return;
    }
    if (kind === SiemKind.ELASTIC && !elasticIndex.trim()) {
      setError("Elastic connectors require a target index.");
      return;
    }
    try {
      await register.mutateAsync({
        kind,
        endpoint: endpoint.trim(),
        authSecret: secret,
        fieldAllowList: allow,
        splunkIndex: splunkIndex.trim(),
        splunkSourcetype: splunkSourcetype.trim(),
        sentinelDcrImmutableId: dcrId.trim(),
        sentinelStreamName: streamName.trim(),
        elasticIndex: elasticIndex.trim(),
      });
      reset();
    } catch {
      // surfaced via register.isError below
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="SIEM connectors"
        description="Stream privacy-minimized trust/risk events to Splunk HEC, Microsoft Sentinel, or Elastic. Secrets are sealed server-side and never shown."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Registered connectors">
          {connectors.isLoading ? (
            <SkeletonRows rows={3} />
          ) : connectors.isError ? (
            <ErrorNotice
              error={connectors.error}
              onRetry={() => void connectors.refetch()}
            />
          ) : !connectors.data || connectors.data.length === 0 ? (
            <EmptyState>No SIEM connectors registered.</EmptyState>
          ) : (
            <ul className="space-y-2">
              {connectors.data.map((c) => (
                <li
                  key={c.id}
                  className="rounded-lg border border-line p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge>{kindLabels[c.kind]}</Badge>
                        <span className="text-xs text-fg-subtle">
                          {c.isActive ? "active" : "inactive"}
                        </span>
                      </div>
                      <div className="mt-1 truncate font-mono text-sm text-fg-strong">
                        {c.endpoint}
                      </div>
                      <div className="mt-1 text-xs text-fg-subtle">
                        secret: <span className="font-mono">{c.authSecretRef}</span>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {c.fieldAllowList.map((f) => (
                          <Badge key={f}>{f}</Badge>
                        ))}
                      </div>
                      <div className="mt-1 text-xs text-fg-subtle">
                        {formatEpochSeconds(c.createdAt)}
                      </div>
                    </div>
                    <button
                      className="btn-danger"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(c.id)}
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

        <Card title="Add connector">
          <form onSubmit={onSubmit} className="space-y-3">
            <div>
              <label htmlFor="siemKind" className="label">
                Sink
              </label>
              <select
                id="siemKind"
                className="input"
                value={kind}
                onChange={(e) => setKind(Number(e.target.value) as SiemKind)}
              >
                {kindChoices.map((k) => (
                  <option key={k} value={k}>
                    {kindLabels[k]}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="siemEndpoint" className="label">
                Endpoint URL
              </label>
              <input
                id="siemEndpoint"
                className="input"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://collector.example:8088"
              />
            </div>

            <div>
              <label htmlFor="siemSecret" className="label">
                {secretLabels[kind]}
              </label>
              <input
                id="siemSecret"
                type="password"
                autoComplete="off"
                className="input"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="write-only — never displayed after saving"
              />
            </div>

            {kind === SiemKind.SPLUNK_HEC && (
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label htmlFor="splunkIndex" className="label">
                    Index (optional)
                  </label>
                  <input
                    id="splunkIndex"
                    className="input"
                    value={splunkIndex}
                    onChange={(e) => setSplunkIndex(e.target.value)}
                    placeholder="kseal"
                  />
                </div>
                <div>
                  <label htmlFor="splunkSourcetype" className="label">
                    Sourcetype (optional)
                  </label>
                  <input
                    id="splunkSourcetype"
                    className="input"
                    value={splunkSourcetype}
                    onChange={(e) => setSplunkSourcetype(e.target.value)}
                    placeholder="kseal:trust"
                  />
                </div>
              </div>
            )}

            {kind === SiemKind.SENTINEL && (
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label htmlFor="dcrId" className="label">
                    DCR immutable id
                  </label>
                  <input
                    id="dcrId"
                    className="input"
                    value={dcrId}
                    onChange={(e) => setDcrId(e.target.value)}
                    placeholder="dcr-xxxxxxxx"
                  />
                </div>
                <div>
                  <label htmlFor="streamName" className="label">
                    Stream name
                  </label>
                  <input
                    id="streamName"
                    className="input"
                    value={streamName}
                    onChange={(e) => setStreamName(e.target.value)}
                    placeholder="Custom-KsealTrust_CL"
                  />
                </div>
              </div>
            )}

            {kind === SiemKind.ELASTIC && (
              <div>
                <label htmlFor="elasticIndex" className="label">
                  Target index / data stream
                </label>
                <input
                  id="elasticIndex"
                  className="input"
                  value={elasticIndex}
                  onChange={(e) => setElasticIndex(e.target.value)}
                  placeholder="kseal-trust-000001"
                />
              </div>
            )}

            <div>
              <div className="label">
                Field allow-list{" "}
                <span className="text-fg-subtle">
                  (none selected = full minimized contract)
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {canonicalFields.map((f) => {
                  const active = allow.includes(f);
                  return (
                    <button
                      key={f}
                      type="button"
                      aria-pressed={active}
                      onClick={() => toggleField(f)}
                      className={`badge ${
                        active
                          ? "border-accent-strong/40 bg-accent-strong/15 text-accent"
                          : "border-line-strong text-fg"
                      }`}
                    >
                      {f}
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
              {register.isPending ? "Registering…" : "Register connector"}
            </button>
          </form>
        </Card>
      </div>
    </div>
  );
}
