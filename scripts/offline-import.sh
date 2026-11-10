#!/usr/bin/env bash
# Imports, on an air-gapped SAYTU server, a bundle made by scripts/offline-bundle.sh: checks every
# checksum, loads the images (if any), replaces the Trivy vulnerability database atomically and installs the
# rule packs. Set SAYTU_TRIVY_DB_AUTO_UPDATE=false in .env on such a server.
#   scripts/offline-import.sh <bundle.tar>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bundle="$(cd "$(dirname "${1:?usage: scripts/offline-import.sh <bundle.tar>}")" && pwd)/$(basename "$1")"
cd "$ROOT"

if [[ -f "$bundle.sha256" ]]; then
  (cd "$(dirname "$bundle")" && sha256sum -c "$(basename "$bundle").sha256")
fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
tar -C "$stage" -xf "$bundle"
b="$stage/bundle"
grep -qx 'format=saytu-offline/1' "$b/manifest.txt" || { echo "not a SAYTU offline bundle" >&2; exit 1; }
echo "== checksums"
if ! (cd "$b" && grep -E '^[0-9a-f]{64}  ' manifest.txt | sha256sum -c --quiet -); then
  echo "bundle altered or incomplete: nothing imported" >&2
  exit 1
fi
echo "all files intact"
grep -E '^(created|saytu_version)=' "$b/manifest.txt"

if [[ -f "$b/images.tar" ]]; then
  echo "== Docker images"
  docker load -i "$b/images.tar"
fi

if [[ -f "$b/rules.tar" ]]; then
  echo "== Opengrep rule packs -> data/rules"
  mkdir -p data
  rm -rf data/rules.new && mkdir data/rules.new
  tar -C data/rules.new -xf "$b/rules.tar" --strip-components=1
  rm -rf data/rules.old; [[ -d data/rules ]] && mv data/rules data/rules.old
  mv data/rules.new data/rules && rm -rf data/rules.old
fi

if [[ -f "$b/trivy/trivy-db.tar" ]]; then
  echo "== Trivy vulnerability database"
  docker compose up -d worker >/dev/null
  # extracted next to the current database, then swapped: a running audit never sees a half-written file
  docker compose exec -T -u 0 worker sh -ec '
    cd /var/lib/saytu/trivy
    rm -rf db.new db.old && mkdir db.new
    tar -C db.new -xf - --strip-components=1
    test -s db.new/trivy.db && test -s db.new/metadata.json
    [ -d db ] && mv db db.old
    mv db.new db && rm -rf db.old
    chmod -R a+rX,go-w db
    cat db/metadata.json; echo' < "$b/trivy/trivy-db.tar"
fi

echo "== done; restart with 'docker compose up -d' if images or rules were updated"
