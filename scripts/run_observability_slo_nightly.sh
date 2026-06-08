#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TODAY_JST="$(TZ=Asia/Tokyo date +%F)"
WEEK_STAMP="$(TZ=Asia/Tokyo date +%G-W%V)"

OUT_DIR="docs/shigoku/reports"
mkdir -p "$OUT_DIR"

DAILY_JSON="${OUT_DIR}/observability_daily_${TODAY_JST}.json"
WEEKLY_MD="${OUT_DIR}/observability_weekly_${WEEK_STAMP}.md"
WEEKLY_REVIEW_JSON="${OUT_DIR}/observability_weekly_review_${WEEK_STAMP}.json"
WEEKLY_REVIEW_MD="${OUT_DIR}/observability_weekly_review_${WEEK_STAMP}.md"

python3 scripts/observability_slo_rollup.py \
  --days 7 \
  --daily-json-out "$DAILY_JSON" \
  --weekly-md-out "$WEEKLY_MD"

python3 scripts/review_observability_slo_weekly.py \
  --daily-json "$DAILY_JSON" \
  --min-sample-count 100 \
  --min-eligible-days 3 \
  --schema-severity-required \
  --schema-severity-warn-only \
  --out-json "$WEEKLY_REVIEW_JSON" \
  --out-md "$WEEKLY_REVIEW_MD"

echo "daily_json=${DAILY_JSON}"
echo "weekly_md=${WEEKLY_MD}"
echo "weekly_review_json=${WEEKLY_REVIEW_JSON}"
echo "weekly_review_md=${WEEKLY_REVIEW_MD}"
