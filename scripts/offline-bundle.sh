#!/usr/bin/env bash
# Prepares, on a machine WITH Internet access, an update bundle for an air-gapped SAYTU installation:
#   * the Trivy vulnerability database (downloaded with the Trivy of the worker image: same version);
#   * the optional Opengrep rule packs of ./data/rules (scripts/fetch-opengrep-rules.sh);
#   * with --images: the Docker images of the stack (docker save), for a first install or an upgrade.
#   scripts/offline-bundle.sh [--images] [output.tar]        (default: saytu-offline-YYYYmmdd.tar)
# Only public data is downloaded (advisories, rules, images): no code, token or repository is involved.
# On the isolated server: scripts/offline-import.sh <bundle.tar>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

with_images=false
if [[ "${1:-}" == "--images" ]]; then with_images=true; shift; fi
out="${1:-saytu-offline-$(date +%Y%m%d).tar}"
version="$(grep -E '^SAYTU_VERSION=' .env 2>/dev/null | cut -d= -f2- || true)"
worker_image="saytu/worker:${version:-dev}"

docker image inspect "$worker_image" >/dev/null 2>&1 || {
  echo "image $worker_image not found: run 'docker compose build worker' first" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/bundle/trivy"
chmod -R 0777 "$stage/bundle/trivy"   # written by the container

echo "== Trivy vulnerability database"
proxy_env=()
for v in HTTPS_PROXY https_proxy NO_PROXY no_proxy; do [[ -n "${!v:-}" ]] && proxy_env+=(-e "$v=${!v}"); done
docker run --rm --network bridge --user 0 --read-only --tmpfs /tmp "${proxy_env[@]}" \
  -v "$stage/bundle/trivy:/out" --entrypoint /opt/saytu/tools/trivy "$worker_image" \
  image --download-db-only --cache-dir /out --no-progress --quiet --disable-telemetry --skip-version-check \
  ${SAYTU_TRIVY_DB_REPOSITORY:+--db-repository "$SAYTU_TRIVY_DB_REPOSITORY"}
[[ -s "$stage/bundle/trivy/db/trivy.db" ]] || { echo "Trivy database download failed" >&2; exit 1; }
docker run --rm --user 0 -v "$stage/bundle/trivy:/out" --entrypoint /bin/sh "$worker_image" \
  -c "tar -C /out -cf /out/trivy-db.tar db && rm -rf /out/db && chmod 0644 /out/trivy-db.tar"
docker run --rm --user 0 -v "$stage/bundle/trivy:/out" --entrypoint /opt/saytu/tools/trivy "$worker_image" \
  --version > "$stage/bundle/trivy/trivy-version.txt" 2>&1 || true

if [[ -d data/rules ]] && find data/rules -mindepth 1 -print -quit | grep -q .; then
  echo "== Opengrep rule packs (data/rules)"
  tar -C data -cf "$stage/bundle/rules.tar" rules
fi

if $with_images; then
  echo "== Docker images"
  mapfile -t images < <(docker compose config --images | sort -u)
  for img in "${images[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
  done
  docker save -o "$stage/bundle/images.tar" "${images[@]}"
  printf '%s\n' "${images[@]}" > "$stage/bundle/images.txt"
fi

{
  echo "format=saytu-offline/1"
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "saytu_version=${version:-dev}"
  (cd "$stage/bundle" && find . -type f ! -name manifest.txt -print0 | sort -z | xargs -0 sha256sum)
} > "$stage/bundle/manifest.txt"

tar -C "$stage" -cf "$out" bundle
sha256sum "$out" > "$out.sha256"
echo "bundle: $out ($(du -h "$out" | cut -f1)); checksum: $out.sha256"
echo "copy both files to the isolated server, then: scripts/offline-import.sh $(basename "$out")"
