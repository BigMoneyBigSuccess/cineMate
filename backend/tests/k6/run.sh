#!/usr/bin/env bash
# Usage: ./k6/run.sh [suite] [mode]
#
#   suite — auth | movies | watchlist | reviews | social | recommendations | full | all
#           default: full
#
#   mode  — smoke | load | stress
#           default: load
#           smoke  → 5 VUs, 30 s   (quick sanity)
#           load   → use the stages defined inside each script
#           stress → 200 VUs, 5 min (override scripts' own stages)
#
# Examples:
#   ./k6/run.sh                         # full-flow, load mode
#   ./k6/run.sh movies stress           # movies suite, stress override
#   ./k6/run.sh all smoke               # every suite, smoke mode
#   BASE_URL=http://staging:8080 ./k6/run.sh auth load

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8080}"

SUITE="${1:-full}"
MODE="${2:-load}"

# ── k6 binary detection ──────────────────────────────────────────────────────
if command -v k6 &>/dev/null; then
  K6="k6"
elif command -v docker &>/dev/null; then
  K6="docker run --rm -i --network host -e BASE_URL=${BASE_URL} grafana/k6"
  # When using Docker we pass the script via stdin, handled per-run below
  USE_DOCKER=1
else
  echo "ERROR: k6 not found. Install it (brew install k6) or have Docker available." >&2
  exit 1
fi
USE_DOCKER="${USE_DOCKER:-0}"

# ── Stage overrides per mode ─────────────────────────────────────────────────
case "$MODE" in
  smoke)  STAGE_ARGS="--stage 30s:5" ;;
  load)   STAGE_ARGS="" ;;           # scripts define their own stages
  stress) STAGE_ARGS="--stage 1m:50 --stage 3m:200 --stage 1m:0" ;;
  *)
    echo "Unknown mode '$MODE'. Use: smoke | load | stress" >&2
    exit 1
    ;;
esac

ALL_SUITES="auth movies watchlist reviews social recommendations full"

# ── Suite name → file ────────────────────────────────────────────────────────
suite_file() {
  case "$1" in
    auth)            echo "auth.stress.js" ;;
    movies)          echo "movies.stress.js" ;;
    watchlist)       echo "watchlist.stress.js" ;;
    reviews)         echo "reviews.stress.js" ;;
    social)          echo "social.stress.js" ;;
    recommendations) echo "recommendations.stress.js" ;;
    full)            echo "full-flow.stress.js" ;;
    *)               echo "" ;;
  esac
}

# ── Runner ───────────────────────────────────────────────────────────────────
run_suite() {
  local name="$1"
  local filename
  filename="$(suite_file "$name")"

  if [[ -z "$filename" ]]; then
    echo "Unknown suite '$name'. Use: $ALL_SUITES | all" >&2
    return 1
  fi

  local file="${DIR}/${filename}"
  if [[ ! -f "$file" ]]; then
    echo "ERROR: file not found: $file" >&2
    return 1
  fi

  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  Suite : $name  |  Mode : $MODE  |  URL : $BASE_URL"
  echo "════════════════════════════════════════════════════════"

  if [[ "$USE_DOCKER" == "1" ]]; then
    # shellcheck disable=SC2086
    $K6 run $STAGE_ARGS -e BASE_URL="${BASE_URL}" - < "$file"
  else
    # shellcheck disable=SC2086
    k6 run $STAGE_ARGS -e BASE_URL="${BASE_URL}" "$file"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
if [[ "$SUITE" == "all" ]]; then
  FAILED=""
  for s in $ALL_SUITES; do
    if ! run_suite "$s"; then
      FAILED="$FAILED $s"
    fi
  done

  echo ""
  if [[ -z "$FAILED" ]]; then
    echo "All suites passed."
  else
    echo "Failed suites:$FAILED" >&2
    exit 1
  fi
else
  run_suite "$SUITE"
fi
