#!/usr/bin/env bash
# Software bill of materials (CycloneDX 1.6 JSON) and license inventory of the SAYTU images, produced with
# the Trivy embedded in the worker image, without network access (--network none):
#   sbom/<version>/<image>.cdx.json        every OS package, JAR (including those inside saytu.jar), Python and
#                                          Node module found in the image
#   sbom/<version>/<image>.licenses.txt    licenses by Trivy category (forbidden / restricted / reciprocal /
#                                          notice / permissive / unknown)
#   sbom/<version>/frontend-build.cdx.json npm packages installed when building the web interface (the web
#                                          image only contains them as minified bundles); rebuilds the
#                                          "build" stage of frontend/Dockerfile (uses the npm cache)
#   scripts/sbom.sh [--all] [--strict]
#     --all     also the third-party images (postgres, keycloak, ollama)
#     --strict  exit with status 3 when a license classified "forbidden" is found
# See docs/licenses.md for the review of each component.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

all=false strict=false
for a in "$@"; do
  case "$a" in
    --all) all=true ;;
    --strict) strict=true ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done
version="$(grep -E '^SAYTU_VERSION=' .env 2>/dev/null | cut -d= -f2- || true)"
version="${version:-dev}"
worker_image="saytu/worker:$version"
docker image inspect "$worker_image" >/dev/null 2>&1 || {
  echo "image $worker_image not found: run 'docker compose build' first" >&2; exit 1; }

out="$ROOT/sbom/$version"
mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
chmod 0755 "$stage"

trivy() { # trivy in the worker image, no network; /in = stage (read-only), /out = output directory
  docker run --rm --network none --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:size=2g \
    -e HOME=/tmp -e TRIVY_CACHE_DIR=/tmp/trivy -v "$stage:/in:ro" -v "$out:/out" \
    --entrypoint /opt/saytu/tools/trivy "$worker_image" "$@" \
    --offline-scan --skip-db-update --skip-java-db-update --skip-check-update --disable-telemetry --skip-version-check \
    --quiet
}

mapfile -t images < <(docker compose config --images | sort -u)
forbidden=0
for img in "${images[@]}"; do
  if ! $all && [[ "$img" != saytu/* ]]; then continue; fi
  docker image inspect "$img" >/dev/null 2>&1 || { echo "skip $img (not present locally)"; continue; }
  name="$(echo "${img%%:*}" | tr '/' '-')"
  echo "== $img"
  docker save -o "$stage/$name.tar" "$img"
  chmod 0644 "$stage/$name.tar"
  trivy image --input "/in/$name.tar" --format cyclonedx --output "/out/$name.cdx.json"
  trivy image --input "/in/$name.tar" --scanners license --format table --output "/out/$name.licenses.txt"
  set +e
  trivy image --input "/in/$name.tar" --scanners license --severity CRITICAL --format table --exit-code 3 \
    --output /tmp/forbidden.txt >/dev/null 2>&1
  rc=$?
  set -e
  if [[ $rc -eq 3 ]]; then
    forbidden=1
    echo "   license classified 'forbidden' found: see $out/$name.licenses.txt (CRITICAL)"
  fi
  rm -f "$stage/$name.tar"
done

echo "== npm packages of the web interface (build stage)"
ca_dir="${SAYTU_CA_DIR:-./data/ca}"
mkdir -p "$ca_dir"
docker build --quiet --target build --build-context "ca=$ca_dir" -t "saytu/web-build:$version" frontend >/dev/null
docker save -o "$stage/web-build.tar" "saytu/web-build:$version"
chmod 0644 "$stage/web-build.tar"
trivy image --input /in/web-build.tar --format cyclonedx --output /out/frontend-build.cdx.json
trivy image --input /in/web-build.tar --scanners license --format table --output /out/frontend-build.licenses.txt

echo "SBOMs and license inventories written to sbom/$version/"
if $strict && [[ $forbidden -eq 1 ]]; then
  exit 3
fi
