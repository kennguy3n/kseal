# kseal on-prem / air-gapped deployment

How to run a customer-hosted kseal attestation verifier inside a regulated or
air-gapped environment. This is the deployment narrative; the runnable bundle
lives in [`deploy/onprem/`](../deploy/onprem) and the operational
backup/restore/failover procedures are in
[deployment-disaster-recovery.md](./deployment-disaster-recovery.md).

- [When to use this](#when-to-use-this)
- [Bundle contents](#bundle-contents)
- [Air-gap model](#air-gap-model)
- [Install: Docker](#install-docker)
- [Install: Kubernetes](#install-kubernetes)
- [Mirroring images](#mirroring-images)
- [Packaging the bundle](#packaging-the-bundle)
- [Security & privacy](#security--privacy)
- [Validation](#validation)

---

## When to use this

The **Regulated** isolation tier (fintech / health / gov) requires data to stay
inside the customer's perimeter. The on-prem verifier complements the other two
halves of that tier:

- **Private link** — no public network path ([deployment-private-link.md](./deployment-private-link.md)).
- **Customer-managed keys (CMK)** — `KSEAL_CMK_KMS_URI` for BYOK envelope
  encryption (wired in the chart + compose).
- **On-prem verifier (this doc)** — the verifier itself runs on customer
  infrastructure, optionally fully air-gapped.

---

## Bundle contents

```
deploy/onprem/
├── docker-compose.yml     # single-host: server + Postgres + Redis + console
├── values-onprem.yaml     # Helm values variant (no ESO, no public ingress)
├── images.txt             # images to mirror into the internal registry
├── mirror-images.sh       # pull / save / load-push across the air gap
├── .env.example           # Docker secrets + tuning template
└── README.md
```

---

## Air-gap model

Everything that would normally reach the internet is off by default:

| Concern | Air-gapped default | Knob |
| --- | --- | --- |
| Container images | internal registry only | `KSEAL_REGISTRY` / `image.registry` |
| Trace export | disabled | `KSEAL_OTLP_ENDPOINT` (empty) |
| Key management | platform KEK you supply | `KSEAL_CMK_KMS_URI` (empty) + `KSEAL_KEK` |
| Cloud attestation (Play Integrity / App Attest) | unconfigured — offline proof paths only | n/a |
| Public ingress | none (loopback bind / Ingress disabled) | `KSEAL_BIND_ADDR` / `ingress.enabled` |
| External webhook / SIEM egress | none | `networkPolicy.egress.siemSinks: []` |

The server runs in **prod mode** (`KSEAL_ENV=prod`), so the KEK is mandatory and
the process fails closed if it is missing.

---

## Install: Docker

```bash
cd deploy/onprem
cp .env.example .env
# set KSEAL_REGISTRY, KSEAL_KEK (base64 32 bytes), KSEAL_PG_PASSWORD
docker compose --env-file .env up -d --wait
curl -fsS http://127.0.0.1:8080/readyz && echo
```

The server applies its embedded SQL migrations on startup; no init scripts are
needed. Postgres data persists in the `pgdata` volume (back it up — see DR).

## Install: Kubernetes

```bash
kubectl create namespace kseal
kubectl -n kseal create secret generic kseal-onprem-secrets \
  --from-literal=KSEAL_KEK="$(head -c 32 /dev/urandom | base64)" \
  --from-literal=KSEAL_POSTGRES_DSN='postgres://kseal:...@postgres:5432/kseal?sslmode=disable' \
  --from-literal=KSEAL_REDIS_ADDR='redis:6379'

helm upgrade --install kseal deploy/helm/kseal -n kseal \
  -f deploy/onprem/values-onprem.yaml
```

Set the NetworkPolicy egress CIDRs in `values-onprem.yaml` to your cluster's pod
CIDR so the server can reach the in-cluster Postgres/Redis under default-deny.

---

## Mirroring images

```bash
# internet-connected host:
./deploy/onprem/mirror-images.sh save ./kseal-images.tar
#   transfer kseal-images.tar across the air gap, then inside the enclave:
./deploy/onprem/mirror-images.sh load-push registry.internal.example.com ./kseal-images.tar
```

Pin `images.txt` to immutable digests before transfer. See
[`deploy/onprem/README.md`](../deploy/onprem/README.md) for the connected-mirror
variant.

---

## Packaging the bundle

```bash
make bundle-onprem
# -> deploy/onprem/dist/kseal-onprem-<version>.tgz (+ .sha256)
```

The tarball is reproducible (sorted entries, fixed owner/mtime) and bundles the
Compose stack, the packaged Helm chart, `images.txt`, the mirror script, and the
deployment + DR docs — everything needed to stand the verifier up offline.

---

## Security & privacy

- **No PII leaves the enclave:** no cloud telemetry, KMS, or webhook egress.
- **Fail closed:** prod mode requires the KEK; missing secrets stop startup.
- **Hardened runtime:** non-root, read-only rootfs, all caps dropped,
  `no-new-privileges`, resource limits (Compose + chart alike).
- **Least exposure:** loopback bind / no Ingress; reach the verifier through the
  customer's own internal LB or private link.
- **BYOK ready:** point `KSEAL_CMK_KMS_URI` at an in-enclave KMS/HSM to keep key
  custody with the customer.

---

## Validation

```bash
docker compose -f deploy/onprem/docker-compose.yml --env-file deploy/onprem/.env.example config -q
helm lint deploy/helm/kseal -f deploy/onprem/values-onprem.yaml
helm template kseal deploy/helm/kseal -f deploy/onprem/values-onprem.yaml \
  | kubeconform -strict -ignore-missing-schemas
bash -n deploy/onprem/mirror-images.sh
make bundle-onprem
```
