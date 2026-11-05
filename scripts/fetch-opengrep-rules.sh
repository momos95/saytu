#!/usr/bin/env bash
# Downloads optional Opengrep rule packs into data/rules/opengrep/<pack> (read by the worker).
# These packs are NOT shipped with SAYTU because of their licences, see scanners/opengrep/rules/README.md.
#
#   scripts/fetch-opengrep-rules.sh trailofbits
#   scripts/fetch-opengrep-rules.sh semgrep --accept-semgrep-rules-license
#   scripts/fetch-opengrep-rules.sh --remove semgrep
#
# Air-gapped site: run it on a connected machine and copy data/rules/opengrep/<pack> over.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/data/rules/opengrep"

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[[ $# -ge 1 ]] || usage

if [[ "$1" == "--remove" ]]; then
  [[ $# -eq 2 && "$2" =~ ^[a-z]+$ ]] || usage
  rm -rf "${DEST:?}/$2"; echo "removed $DEST/$2"; exit 0
fi

pack="$1"; shift
case "$pack" in
  semgrep)
    url=https://github.com/semgrep/semgrep-rules.git
    [[ "${1:-}" == "--accept-semgrep-rules-license" ]] || {
      cat >&2 <<'MSG'
The Semgrep rules are licensed under the "Semgrep Rules License v1.0": internal business use only;
you may not distribute them or make them available to others as a service.
Re-run with --accept-semgrep-rules-license if your use complies.
MSG
      exit 3; }
    ;;
  trailofbits) url=https://github.com/trailofbits/semgrep-rules.git ;;
  *) echo "unknown pack: $pack (semgrep | trailofbits)" >&2; exit 2 ;;
esac

command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
git -c core.hooksPath=/dev/null clone --quiet --depth 1 --no-tags "$url" "$tmp/src"
commit="$(git -C "$tmp/src" rev-parse HEAD)"
rm -rf "$tmp/src/.git" "$tmp/src/.github"

# Keep only rule files: YAML documents with a top-level "rules:" key. Test targets written in YAML
# (rules for Kubernetes, GitHub Actions...) and metadata files would otherwise be loaded as rules.
find "$tmp/src" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 | while IFS= read -r -d '' f; do
  case "$f" in *.test.yaml|*.test.yml|*.fixed.*) rm -f "$f"; continue ;; esac
  grep -q '^rules:' "$f" || rm -f "$f"
done
find "$tmp/src" -type f ! \( -name '*.yaml' -o -name '*.yml' -o -iname 'LICENSE*' -o -iname 'README*' \) -delete
find "$tmp/src" -type d -empty -delete
count="$(find "$tmp/src" -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l)"
printf '%s\n' "pack=$pack" "source=$url" "commit=$commit" "fetched_at=$(date -u +%FT%TZ)" "rule_files=$count" > "$tmp/src/SAYTU-PACK.txt"

mkdir -p "$DEST"
rm -rf "${DEST:?}/$pack"
mv "$tmp/src" "$DEST/$pack"
echo "$pack: $count rule files, commit ${commit:0:12} -> $DEST/$pack"
echo "Taken into account by the next scans (no restart needed)."
