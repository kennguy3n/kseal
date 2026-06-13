#!/usr/bin/env bash
# Mirror the on-prem bundle's container images into an air-gapped environment.
#
# Three workflows:
#
#   # 1) Connected mirror host with line-of-sight to BOTH registries:
#   ./mirror-images.sh push registry.internal.example.com
#
#   # 2) True air-gap — stage 1, on an internet-connected host:
#   ./mirror-images.sh save ./kseal-images.tar
#   #    (transfer kseal-images.tar across the air gap)
#
#   # 3) True air-gap — stage 2, inside the enclave:
#   ./mirror-images.sh load-push registry.internal.example.com ./kseal-images.tar
#
# Images are read from images.txt next to this script. Each image keeps its
# short name (name:tag or name@sha256:...) under the destination registry, e.g.
# ghcr.io/kennguy3n/kseal-server:0.1.0 -> <dest>/kseal-server:0.1.0
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_LIST="${IMAGE_LIST:-${HERE}/images.txt}"

die() {
  echo "error: $*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || die "docker is required"
[[ -f "${IMAGE_LIST}" ]] || die "image list not found: ${IMAGE_LIST}"

# Read non-comment, non-blank lines into SRC_IMAGES.
mapfile -t SRC_IMAGES < <(grep -vE '^[[:space:]]*(#|$)' "${IMAGE_LIST}")
[[ ${#SRC_IMAGES[@]} -gt 0 ]] || die "no images listed in ${IMAGE_LIST}"

# Short name (final path component incl. tag/digest), e.g.
# ghcr.io/kennguy3n/kseal-server:0.1.0 -> kseal-server:0.1.0
short_name() {
  echo "${1##*/}"
}

dest_ref() {
  local dest_registry="$1" src="$2"
  echo "${dest_registry%/}/$(short_name "${src}")"
}

cmd_pull() {
  for img in "${SRC_IMAGES[@]}"; do
    echo "==> pull ${img}"
    docker pull "${img}"
  done
}

cmd_save() {
  local tarball="${1:?usage: mirror-images.sh save <tarball>}"
  cmd_pull
  echo "==> saving ${#SRC_IMAGES[@]} images to ${tarball}"
  docker save -o "${tarball}" "${SRC_IMAGES[@]}"
  echo "saved ${tarball} ($(du -h "${tarball}" | cut -f1)). Transfer it across the air gap, then run: load-push <dest_registry> ${tarball}"
}

cmd_push() {
  local dest_registry="${1:?usage: mirror-images.sh push <dest_registry>}"
  cmd_pull
  retag_and_push "${dest_registry}"
}

cmd_load_push() {
  local dest_registry="${1:?usage: mirror-images.sh load-push <dest_registry> <tarball>}"
  local tarball="${2:?usage: mirror-images.sh load-push <dest_registry> <tarball>}"
  [[ -f "${tarball}" ]] || die "tarball not found: ${tarball}"
  echo "==> loading ${tarball}"
  docker load -i "${tarball}"
  retag_and_push "${dest_registry}"
}

retag_and_push() {
  local dest_registry="$1" dest
  for img in "${SRC_IMAGES[@]}"; do
    dest="$(dest_ref "${dest_registry}" "${img}")"
    echo "==> tag ${img} -> ${dest}"
    docker tag "${img}" "${dest}"
    echo "==> push ${dest}"
    docker push "${dest}"
  done
  echo "done. Set KSEAL_REGISTRY=${dest_registry%/} for docker-compose, or image.registry / *.image.repository in values-onprem.yaml."
}

case "${1:-}" in
  pull)      cmd_pull ;;
  save)      cmd_save "${2:-}" ;;
  push)      cmd_push "${2:-}" ;;
  load-push) cmd_load_push "${2:-}" "${3:-}" ;;
  *)
    cat >&2 <<EOF
usage: mirror-images.sh <command>
  pull                              pull all images locally
  save <tarball>                    pull + docker save to a tarball (stage 1)
  load-push <dest_registry> <tar>   docker load + retag + push (stage 2)
  push <dest_registry>              pull + retag + push (connected mirror host)
EOF
    exit 2
    ;;
esac
