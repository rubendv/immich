#!/usr/bin/env bash
# Deterministic CRA due-diligence harness driver.
#
# Runs one dedicated sub-agent process per top-level dependency from the SBOM
# (security/sbom/immich-top-level.cdx.json), then lints every produced
# assessment document against security/harness/assessment.schema.json.
#
# Usage: ./run_harness.sh [--scope required|optional|excluded|all] [--lint-only]

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBOM="$HARNESS_DIR/../sbom/immich-top-level.cdx.json"
OUT_DIR="$HARNESS_DIR/assessments"
LINT="$HARNESS_DIR/lint_assessments.py"
SCOPE="all"
LINT_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2 ;;
    --lint-only) LINT_ONLY=1; shift ;;
    -h|--help) grep '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "$LINT_ONLY" == "1" ]]; then
  exec python3 "$LINT"
fi

mkdir -p "$OUT_DIR"

# Start from a clean, deterministic state: previous runs are removed so the
# assessment set always equals exactly one document per assessed component.
rm -f "$OUT_DIR"/*.json

FILTER='.components[]'
if [[ "$SCOPE" != "all" ]]; then
  FILTER=".components[] | select(.scope == \"$SCOPE\")"
fi

# jq filter arg to avoid shell-quoting pitfalls
mapfile -t PURLS < <(jq -r "$FILTER | .purl" "$SBOM")

if [[ ${#PURLS[@]} -eq 0 ]]; then
  echo "no components selected (scope=$SCOPE)" >&2
  exit 2
fi

echo "assessing ${#PURLS[@]} component(s) (scope=$SCOPE), one sub-agent process per component"
rc=0
for purl in "${PURLS[@]}"; do
  if ! python3 "$HARNESS_DIR/assess_component.py" "$purl"; then
    echo "sub-agent FAILED for $purl" >&2
    rc=1
  fi
done

if [[ $rc -ne 0 ]]; then
  echo "one or more sub-agents failed" >&2
  exit $rc
fi

echo "all sub-agents completed; linting (${#PURLS[@]} documents)"
python3 "$LINT"
