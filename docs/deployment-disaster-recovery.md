# kseal disaster recovery runbook

Backup/restore, region failover, and RTO/RPO targets for the kseal data plane.
Applies to the managed multi-region deployment ([multi-region.md](./multi-region.md))
and, where noted, the on-prem bundle ([deployment-onprem.md](./deployment-onprem.md)).

- [What state exists](#what-state-exists)
- [RTO / RPO targets](#rto--rpo-targets)
- [Backups](#backups)
- [Restore: Postgres](#restore-postgres)
- [Restore: analytics cold tier](#restore-analytics-cold-tier)
- [Region failover (promote a replica)](#region-failover-promote-a-replica)
- [Region failback](#region-failback)
- [On-prem DR](#on-prem-dr)
- [Secrets & keys](#secrets--keys)
- [Drills](#drills)

---

## What state exists

| Store | Authority | Recoverable from | Loss tolerance |
| --- | --- | --- | --- |
| **Postgres** | source of truth (registry, policies, key refs) | automated backups + PITR; cross-region read replicas | low — RPO minutes |
| **Analytics cold tier (S3)** | derived telemetry/aggregates | versioned bucket + cross-region replication | low for aggregates |
| **Analytics hot tier (ClickHouse)** | derived, reproducible | rebuildable from cold tier + Postgres | high — ephemeral |
| **Redis** | ephemeral (TTL'd nonces, rate-limit counters) | nothing — repopulates itself | total — by design |
| **KEK / secrets** | external secret store / KMS | secret store backups (out of band) | none — must survive |

The data plane is derived and reproducible by design (see
[ARCHITECTURE.md](../ARCHITECTURE.md)), which is what keeps the recovery surface
small: protect Postgres + the cold tier + the keys, and everything else rebuilds.

---

## RTO / RPO targets

| Scenario | RTO (time to recover) | RPO (data loss) |
| --- | --- | --- |
| Single AZ failure (primary region) | automatic (Multi-AZ standby), < 2 min | 0 (synchronous standby) |
| Primary Postgres corruption (PITR) | ≤ 60 min | ≤ 5 min (backup + WAL) |
| Full primary-region loss → failover to replica | ≤ 30 min | ≤ 60 s (async replica lag) |
| Analytics cold-tier object loss | ≤ 15 min (version/replica restore) | 0 for replicated objects |
| Redis loss | automatic | 0 (ephemeral, repopulates) |

Async cross-region replica lag is the dominant RPO term for a full-region
failover; monitor `ReplicaLag` and alert when it exceeds the 60 s budget.

---

## Backups

- **Postgres:** automated backups are on (`backup_retention_period`, 14 days in
  the multi-region module) with PITR via WAL, plus `copy_tags_to_snapshot` and a
  final snapshot on deletion. Replica regions keep their own read replicas hot.
- **Analytics S3:** versioning is enabled on every bucket and the primary
  replicates cross-region, so both accidental deletes (restore prior version)
  and a region loss (read from a replica bucket) are covered.
- **On-prem:** schedule `pg_dump`/`pg_basebackup` of the Compose `pgdata` volume
  to the customer's backup target; the analytics tier is local disk — back it up
  with the host's normal regime.

---

## Restore: Postgres

**Point-in-time (corruption / bad migration / accidental delete):**

```bash
# Restore the primary to a new instance at a timestamp before the incident.
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier kseal-prod-us-east-1-pg \
  --target-db-instance-identifier kseal-prod-us-east-1-pg-pitr \
  --restore-time 2025-01-01T12:00:00Z
# Verify, then repoint KSEAL_POSTGRES_DSN (external secret) at the restored host.
```

**On-prem:**

```bash
docker compose -f deploy/onprem/docker-compose.yml stop kseal-server
gunzip -c backup.sql.gz | docker compose -f deploy/onprem/docker-compose.yml \
  exec -T postgres psql -U kseal -d kseal
docker compose -f deploy/onprem/docker-compose.yml start kseal-server
```

After any restore, roll the server pods so connection pools reconnect.

---

## Restore: analytics cold tier

- **Single object / prefix:** restore the prior version (versioning is on), e.g.
  copy the last non-delete-marker version back over the current key.
- **Region loss:** read from a replica region's bucket (replicated copy) until
  the source region is rebuilt, then re-replicate.

---

## Region failover (promote a replica)

On a full primary-region loss, promote a replica to writer. Route53 health
checks already withdraw the dead region from DNS automatically; promotion
restores the **write** path.

1. **Confirm** the primary region is truly down (not a transient health-check
   flap). Check `ReplicaLag` on the chosen replica to quantify RPO.
2. **Promote** the replica to a standalone writable instance:
   ```bash
   aws rds promote-read-replica \
     --db-instance-identifier kseal-prod-eu-west-1-pg-replica --region eu-west-1
   ```
3. **Repoint writes:** update the write DSN in the external secret store so the
   promoted instance is the new primary; roll the server pods in the surviving
   regions.
4. **Region pins:** update `tenant_region_pins` (and re-apply
   `global-routing`) so tenants pinned to the lost region fail over to the new
   primary region.
5. **Rebuild analytics replication:** re-run Terraform so the new primary's
   analytics bucket becomes the replication source.
6. **Communicate** the failover + measured RPO to affected tenants.

> Promotion is irreversible for that instance — it becomes a standalone writer.
> Do it deliberately once the primary is confirmed lost, not on a flap.

---

## Region failback

When the original primary region returns:

1. Stand the region back up via Terraform (it rejoins as a replica of the new
   primary).
2. Let replication catch up; verify `ReplicaLag` ≈ 0.
3. During a maintenance window, optionally promote it back and repoint writes —
   same procedure, reversed. Failback is planned, never automatic.

---

## On-prem DR

- **Backups** of the `pgdata` volume + analytics directory are the customer's
  responsibility; document RPO with them.
- **Restore** uses the `pg` restore flow above.
- **No region failover** in single-site on-prem; for HA, the customer runs the
  Kubernetes variant across racks/AZs with a managed/HA Postgres.

---

## Secrets & keys

- The **KEK** and DSNs live in the external secret store / KMS, never in git or
  the chart. Back up the secret store independently — **losing the KEK means
  envelope-encrypted rows are unrecoverable.**
- For BYOK/CMK tenants, key custody and backup follow the customer's KMS/HSM
  policy (`KSEAL_CMK_KMS_URI`).

---

## Drills

Exercise recovery on a cadence so RTO/RPO stay real, not aspirational:

- **Quarterly:** Postgres PITR restore into a scratch instance; verify the
  server boots + `/readyz` passes against it.
- **Semi-annually:** game-day region failover in staging (promote a replica,
  repoint writes, measure actual RTO/RPO against the targets above).
- **Per release:** confirm `make bundle-onprem` produces a loadable bundle and
  the on-prem stack reaches `/readyz`.
