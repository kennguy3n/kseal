# kseal on-prem / air-gapped verifier bundle

A self-contained, customer-hosted deployment of the kseal attestation verifier
(server + Postgres + Redis + console) for the **Regulated** isolation tier. Runs
with **no internet egress**: all images are mirrored into an internal registry,
and every external third-party provider (Play Integrity, App Attest, cloud KMS,
OTLP) is left off by default.

This bundle pairs with [private link](../../docs/deployment-private-link.md) and
customer-managed keys to keep regulated data inside the customer's perimeter.
Operational backup/restore + RTO/RPO targets are in
[deployment-disaster-recovery.md](../../docs/deployment-disaster-recovery.md); the full narrative is in
[deployment-onprem.md](../../docs/deployment-onprem.md).

## Contents

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Single-host Docker deployment (server + Postgres + Redis + console). |
| `values-onprem.yaml` | Helm values variant for an on-prem Kubernetes cluster. |
| `images.txt` | The image list to mirror into the internal registry. |
| `mirror-images.sh` | Pull / save / load-push the images across the air gap. |
| `.env.example` | Template for the Docker deployment's secrets + tuning. |

## What "air-gapped" means here

- **Images** come only from your internal registry (`KSEAL_REGISTRY`).
- **No cloud telemetry:** `KSEAL_OTLP_ENDPOINT` is empty (tracing disabled).
- **No cloud KMS:** `KSEAL_CMK_KMS_URI` is empty — envelope encryption uses the
  platform KEK you supply (`KSEAL_KEK`).
- **No external attestation calls:** cloud attestation providers are the only
  internet-dependent verifiers; in an enclave the verifier relies on the offline
  paths (signed request proofs, signed config, on-device signal bits). Cloud
  providers stay unconfigured.
- **No public ingress:** Compose binds to loopback by default
  (`KSEAL_BIND_ADDR`); the Helm variant disables Ingress.

## Quick start (Docker, single host)

1. Mirror images into your internal registry (see below).
2. Configure + launch:
   ```bash
   cd deploy/onprem
   cp .env.example .env
   # edit .env: set KSEAL_REGISTRY, KSEAL_KEK (base64 32 bytes), KSEAL_PG_PASSWORD
   docker compose --env-file .env up -d --wait
   curl -fsS http://127.0.0.1:8080/readyz && echo
   ```

## Quick start (Kubernetes)

```bash
kubectl create namespace kseal
kubectl -n kseal create secret generic kseal-onprem-secrets \
  --from-literal=KSEAL_KEK="$(head -c 32 /dev/urandom | base64)" \
  --from-literal=KSEAL_POSTGRES_DSN='postgres://kseal:...@postgres:5432/kseal?sslmode=disable' \
  --from-literal=KSEAL_REDIS_ADDR='redis:6379'

helm upgrade --install kseal deploy/helm/kseal -n kseal \
  -f deploy/onprem/values-onprem.yaml
```

(Postgres + Redis themselves are deployed by the customer — managed appliance,
operator, or the Compose stack above — and referenced via the Secret's DSN /
addr. Set the NetworkPolicy egress CIDRs in `values-onprem.yaml` to your cluster
pod CIDR.)

## Mirroring images across the air gap

Edit `images.txt` to pin digests, then:

```bash
# On an internet-connected host:
./mirror-images.sh save ./kseal-images.tar     # pull + docker save

# transfer kseal-images.tar into the enclave, then inside it:
./mirror-images.sh load-push registry.internal.example.com ./kseal-images.tar
```

Or, from a mirror host with line-of-sight to both registries:

```bash
./mirror-images.sh push registry.internal.example.com
```

Each image keeps its short name under the destination registry (e.g.
`ghcr.io/kennguy3n/kseal-server:0.1.0` → `registry.internal.example.com/kseal-server:0.1.0`),
which is exactly what `docker-compose.yml` and `values-onprem.yaml` expect.

## Packaging

`make bundle-onprem` (from the repo root) packages this directory, the Helm
chart, the image list, and the deployment + DR docs into a single, verifiable
tarball under `deploy/onprem/dist/` for transfer into the enclave.
