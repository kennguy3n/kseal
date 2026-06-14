import { Link } from "react-router-dom";
import { Card, EmptyState, Spinner, Stat } from "../components/ui";
import { TenantHealthTable } from "../components/TenantHealthTable";
import { SeverityBar } from "../components/SeverityBar";
import { HEALTH_BAND_COLORS, TRUST_LEVEL_COLORS } from "../lib/palette";
import { Sparkline } from "../components/Sparkline";
import { ExportMenu } from "../components/ExportMenu";
import { useFleet } from "../hooks/fleet";
import { formatRate, TRUST_LEVEL_KEYS, type HealthBand } from "../lib/rollup";
import { bucketSignals } from "../lib/events";
import { healthBandLabel } from "../lib/health";
import { trustLevelLabels } from "../lib/format";
import { TrustLevel } from "../gen/kseal/v1/common_pb";

const TRUST_LEVEL_ENUM: Record<string, TrustLevel> = {
  TRUSTED: TrustLevel.TRUSTED,
  LOW_RISK: TrustLevel.LOW_RISK,
  MEDIUM_RISK: TrustLevel.MEDIUM_RISK,
  HIGH_RISK: TrustLevel.HIGH_RISK,
  CRITICAL: TrustLevel.CRITICAL,
};

const BAND_ORDER: HealthBand[] = ["at-risk", "watch", "healthy", "unknown"];
const ATTENTION_PREVIEW = 8;
const ACTIVITY_SPAN_MS = 24 * 60 * 60 * 1000;

export function FleetOverviewPage() {
  const { rollup, isLoading, isFetching, refetch } = useFleet();

  if (isLoading) {
    return (
      <div className="py-12">
        <Spinner label="Loading fleet…" />
      </div>
    );
  }

  if (rollup.tenantCount === 0) {
    return (
      <div className="space-y-6">
        <Header isFetching={isFetching} refetch={refetch} tenantCount={0} />
        <EmptyState>
          <p className="font-medium text-content">No managed tenants</p>
          <p className="mt-1">
            Sign out and add tenant IDs to start monitoring your fleet.
          </p>
        </EmptyState>
      </div>
    );
  }

  const bandSegments = BAND_ORDER.map((band) => ({
    key: band,
    label: healthBandLabel(band),
    value: rollup.bandCounts[band],
    color: HEALTH_BAND_COLORS[band],
  }));

  const trustSegments = TRUST_LEVEL_KEYS.map((key) => ({
    key,
    label: trustLevelLabels[TRUST_LEVEL_ENUM[key]],
    value: rollup.sessionsByTrustLevel[key],
    color: TRUST_LEVEL_COLORS[key],
  }));

  const buckets = bucketSignals(rollup.recentSignals, Date.now(), ACTIVITY_SPAN_MS, 24);
  const attention = rollup.tenants.slice(0, ATTENTION_PREVIEW);

  return (
    <div className="space-y-6">
      <Header
        isFetching={isFetching}
        refetch={refetch}
        tenantCount={rollup.tenantCount}
        rollup={rollup}
      />

      <section
        aria-label="Fleet totals"
        className="grid grid-cols-2 gap-4 md:grid-cols-4"
      >
        <Stat label="Managed tenants" value={rollup.tenantCount} />
        <Stat label="Apps" value={rollup.totalApps} />
        <Stat label="Events (24h)" value={rollup.totalEvents24h} />
        <Stat label="Trust sessions" value={rollup.totalSessions} />
      </section>

      {rollup.degradedTenants > 0 && (
        <div
          role="alert"
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-700 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-200"
        >
          {rollup.degradedTenants} of {rollup.tenantCount} tenants returned
          incomplete data; their rows show the reason below. Aggregates include
          whatever each tenant did return.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Fleet health">
          <SeverityBar segments={bandSegments} ariaLabel="Tenant health distribution" />
        </Card>
        <Card title="Recent signal activity (24h)">
          <Sparkline
            buckets={buckets}
            label="Fleet recent signal activity"
            width={520}
            height={56}
            className="w-full"
          />
          <p className="mt-3 text-xs text-subtle">
            Derived from each tenant's most recent risk events; the red line is the
            high/critical share.
          </p>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Enforcement pressure">
          <dl className="space-y-3 text-sm">
            <Row label="High-risk session rate" value={formatRate(rollup.highRiskSessionRate)} />
            <Row
              label="Step-up session rate (proxy)"
              value={formatRate(rollup.mediumRiskSessionRate)}
            />
            <Row
              label="Attestation failure rate"
              value={formatRate(rollup.attestationFailureRate)}
            />
          </dl>
          <p className="mt-4 text-xs text-subtle">
            The server does not expose explicit block / step-up decision counts,
            so these are approximated from the trust-level session distribution
            and attestation failures (see docs/mssp-console.md).
          </p>
        </Card>

        <Card title="Trust-level distribution">
          <SeverityBar segments={trustSegments} ariaLabel="Trust-level session distribution" />
        </Card>
      </div>

      <Card
        title="Tenant health"
        actions={
          <Link
            to="/tenants"
            className="focus-ring rounded text-sm text-accent-strong hover:underline"
          >
            View all {rollup.tenantCount} tenants →
          </Link>
        }
      >
        <TenantHealthTable tenants={attention} />
        {rollup.tenants.length > ATTENTION_PREVIEW && (
          <p className="mt-3 text-xs text-subtle">
            Showing the {ATTENTION_PREVIEW} tenants needing the most attention.
            Use the Tenants view to filter, search, set alert thresholds, and
            export.
          </p>
        )}
      </Card>
    </div>
  );
}

function Header({
  isFetching,
  refetch,
  tenantCount,
  rollup,
}: {
  isFetching: boolean;
  refetch: () => void;
  tenantCount: number;
  rollup?: import("../lib/rollup").FleetRollup;
}) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-heading">Fleet overview</h1>
        <p className="mt-1 text-sm text-muted">
          Aggregated client-side across {tenantCount} managed tenant
          {tenantCount === 1 ? "" : "s"}.
        </p>
      </div>
      <div className="flex items-center gap-2">
        {rollup && <ExportMenu rollup={rollup} tenants={rollup.tenants} />}
        <button className="btn-ghost focus-ring" onClick={refetch} disabled={isFetching}>
          {isFetching ? "Refreshing…" : "Refresh"}
        </button>
      </div>
    </header>
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
