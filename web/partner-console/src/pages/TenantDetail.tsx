import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card, EmptyState, ErrorNotice, LoadMore, Spinner, Stat } from "../components/ui";
import { Badge } from "../components/ui";
import { SeverityBar } from "../components/SeverityBar";
import { TRUST_LEVEL_COLORS } from "../lib/palette";
import { Sparkline } from "../components/Sparkline";
import { SignalsTable } from "../components/SignalsTable";
import { useTenantEvents, useTenantSnapshot } from "../hooks/tenant";
import { useSession } from "../state/useAuth";
import {
  formatRate,
  tenantHealthFromSnapshot,
  TRUST_LEVEL_KEYS,
  type TrustLevelKey,
} from "../lib/rollup";
import { bucketSignals } from "../lib/events";
import { healthBandLabel, healthBandTone } from "../lib/health";
import { trustLevelLabels } from "../lib/format";
import { TrustLevel } from "../gen/kseal/v1/common_pb";

const ACTIVITY_SPAN_MS = 24 * 60 * 60 * 1000;
const ACTIVITY_BUCKETS = 24;

const RISK_FILTERS: { level: TrustLevel; label: string }[] = [
  { level: TrustLevel.MEDIUM_RISK, label: "Medium" },
  { level: TrustLevel.HIGH_RISK, label: "High" },
  { level: TrustLevel.CRITICAL, label: "Critical" },
];

const TRUST_LEVEL_ENUM: Record<TrustLevelKey, TrustLevel> = {
  TRUSTED: TrustLevel.TRUSTED,
  LOW_RISK: TrustLevel.LOW_RISK,
  MEDIUM_RISK: TrustLevel.MEDIUM_RISK,
  HIGH_RISK: TrustLevel.HIGH_RISK,
  CRITICAL: TrustLevel.CRITICAL,
};

export function TenantDetailPage() {
  const params = useParams();
  const tenantId = params.tenantId ?? "";
  const { tenantIds } = useSession();
  const managed = tenantIds.includes(tenantId);

  const [riskFilter, setRiskFilter] = useState<TrustLevel[]>([]);

  const snapshotQuery = useTenantSnapshot(tenantId, managed);
  const events = useTenantEvents(tenantId, riskFilter, managed);

  const health = useMemo(
    () => (snapshotQuery.data ? tenantHealthFromSnapshot(snapshotQuery.data) : null),
    [snapshotQuery.data],
  );

  if (!managed) {
    return (
      <div className="space-y-4">
        <BackLink />
        <EmptyState>
          <p className="font-medium text-content">Tenant not in your fleet</p>
          <p className="mt-1">
            <span className="font-mono">{tenantId || "(none)"}</span> is not one of
            your managed tenants. Add it on the sign-in screen to view it.
          </p>
        </EmptyState>
      </div>
    );
  }

  if (snapshotQuery.isLoading) {
    return (
      <div className="space-y-4">
        <BackLink />
        <div className="py-12">
          <Spinner label="Loading tenant…" />
        </div>
      </div>
    );
  }

  const snapshot = snapshotQuery.data;
  const overview = snapshot?.overview;
  const trust = snapshot?.trust;
  const buckets = bucketSignals(
    snapshot?.recentSignals ?? [],
    Date.now(),
    ACTIVITY_SPAN_MS,
    ACTIVITY_BUCKETS,
  );

  const trustSegments = TRUST_LEVEL_KEYS.map((key) => ({
    key,
    label: trustLevelLabels[TRUST_LEVEL_ENUM[key]],
    value: trust?.sessionsByTrustLevel[key] ?? 0,
    color: TRUST_LEVEL_COLORS[key],
  }));

  const toggleRisk = (level: TrustLevel) => {
    setRiskFilter((prev) =>
      prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level],
    );
  };

  return (
    <div className="space-y-6">
      <BackLink />

      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="break-all font-mono text-xl font-semibold text-heading">
            {tenantId}
          </h1>
          <p className="mt-1 text-sm text-muted">
            Read-only tenant drill-down · derived health and recent signals.
          </p>
        </div>
        {health && (
          <Badge tone={healthBandTone(health.band)}>
            {healthBandLabel(health.band)} · {health.healthScore}
          </Badge>
        )}
      </header>

      {snapshot && snapshot.errors.length > 0 && (
        <div
          role="alert"
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-700 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-200"
        >
          Some reads for this tenant were incomplete: {snapshot.errors.join("; ")}.
          Values below reflect whatever the tenant returned.
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat label="Apps" value={overview?.appCount ?? 0} />
        <Stat label="Builds" value={overview?.buildCount ?? 0} />
        <Stat label="Active policies" value={overview?.activePolicyCount ?? 0} />
        <Stat label="Webhooks" value={overview?.webhookCount ?? 0} />
        <Stat label="Events (24h)" value={overview?.eventsLast24h ?? 0} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Enforcement pressure">
          {health ? (
            <dl className="space-y-3 text-sm">
              <Row label="High-risk session rate" value={formatRate(health.highRiskRate)} />
              <Row label="Step-up session rate (proxy)" value={formatRate(health.mediumRiskRate)} />
              <Row
                label="Attestation failure rate"
                value={formatRate(health.attestationFailureRate)}
              />
              <Row label="Trust sessions" value={health.sessions} />
            </dl>
          ) : (
            <EmptyState>No trust-session data.</EmptyState>
          )}
        </Card>

        <Card title="Trust-level distribution">
          <SeverityBar segments={trustSegments} ariaLabel="Trust-level distribution" />
        </Card>
      </div>

      <Card
        title="Recent activity (24h)"
        actions={
          <span className="text-xs text-subtle">
            {(snapshot?.recentSignals?.length ?? 0)} recent signals
          </span>
        }
      >
        <Sparkline
          buckets={buckets}
          label="Recent signal activity"
          width={640}
          height={56}
          className="w-full"
        />
      </Card>

      <Card
        title="Signals"
        actions={
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter signals by risk">
            <span className="text-xs text-subtle">Risk</span>
            {RISK_FILTERS.map((r) => {
              const on = riskFilter.includes(r.level);
              return (
                <button
                  key={r.level}
                  type="button"
                  aria-pressed={on}
                  onClick={() => toggleRisk(r.level)}
                  className={`badge focus-ring ${
                    on
                      ? "border-accent/40 bg-accent/15 text-accent-strong"
                      : "border-line-strong text-muted hover:bg-hover"
                  }`}
                >
                  {r.label}
                </button>
              );
            })}
          </div>
        }
      >
        {events.isError ? (
          <ErrorNotice error={events.error} />
        ) : events.isLoading ? (
          <div className="py-8">
            <Spinner label="Loading signals…" />
          </div>
        ) : (
          <>
            <SignalsTable signals={events.signals} />
            <LoadMore
              hasNextPage={events.hasNextPage}
              isFetchingNextPage={events.isFetchingNextPage}
              onClick={events.fetchNextPage}
            />
          </>
        )}
      </Card>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/tenants"
      className="focus-ring inline-flex items-center gap-1 rounded text-sm text-accent-strong hover:underline"
    >
      ← Back to tenants
    </Link>
  );
}

function Row({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-muted">{label}</dt>
      <dd className="font-medium tabular-nums text-content">{value}</dd>
    </div>
  );
}
