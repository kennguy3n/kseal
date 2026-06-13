#!/usr/bin/env bash
# kind-based smoke test for the kseal Helm chart.
#
# Spins up a local kind cluster, builds + loads the server image, deploys
# Postgres + Redis + the chart, and asserts the server reaches /readyz. Tears
# everything down on exit. Requires: docker, kind, kubectl, helm.
#
#   ./deploy/kind/smoke.sh
#
# Skips cleanly (exit 0) if kind/docker are unavailable so it is safe to call
# from environments without a cluster runtime.
set -euo pipefail

CLUSTER="kseal-smoke"
NS="kseal-smoke"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="${REPO_ROOT}/deploy/kind"
IMAGE="kseal-server:kind"

for bin in docker kind kubectl helm; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "SKIP: '$bin' not found — cluster runtime unavailable, skipping smoke test."
    exit 0
  fi
done

cleanup() {
  echo "==> tearing down kind cluster ${CLUSTER}"
  kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> creating kind cluster ${CLUSTER}"
kind create cluster --name "${CLUSTER}" --config "${HERE}/kind-config.yaml" --wait 120s

echo "==> building server image"
docker build -f "${REPO_ROOT}/server/Dockerfile" -t "${IMAGE}" "${REPO_ROOT}"
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

kubectl create namespace "${NS}"

echo "==> deploying Postgres + Redis"
kubectl -n "${NS}" apply -f "${HERE}/deps.yaml"
kubectl -n "${NS}" rollout status deploy/postgres --timeout=120s
kubectl -n "${NS}" rollout status deploy/redis --timeout=120s

echo "==> creating smoke secret"
kubectl -n "${NS}" create secret generic kseal-smoke-secrets \
  --from-literal=KSEAL_KEK="$(head -c 32 /dev/urandom | base64)" \
  --from-literal=KSEAL_POSTGRES_DSN="postgres://kseal:kseal@postgres:5432/kseal?sslmode=disable" \
  --from-literal=KSEAL_REDIS_ADDR="redis:6379"

echo "==> installing kseal chart"
helm install kseal "${REPO_ROOT}/deploy/helm/kseal" \
  -n "${NS}" \
  -f "${HERE}/values-kind.yaml" \
  --wait --timeout 180s

echo "==> asserting server /readyz"
kubectl -n "${NS}" rollout status deploy/kseal-server --timeout=120s
kubectl -n "${NS}" run smoke-curl --image=curlimages/curl:8.10.1 --restart=Never --rm -i --quiet -- \
  curl -fsS "http://kseal-server:8080/readyz"

echo "SMOKE OK: server reached /readyz"
