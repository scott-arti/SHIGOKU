---
task_id: SGK-2026-0221-S03
doc_type: work_report
status: active
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s03_groupc_regression-observability_subtask_plan.md
- docs/shigoku/reports/observability_daily_2026-05-21.json
- docs/shigoku/reports/observability_weekly_2026-W21.md
- docs/shigoku/reports/observability_weekly_review_2026-W21.json
title: 'Weekly SLO Threshold Review (2026-W21)'
created_at: '2026-05-21'
updated_at: '2026-05-21'
tags:
- shigoku
- observability
- slo
- weekly-review
---

# Weekly SLO Threshold Review (2026-W21)

## Decision
- しきい値は以下で固定する。
  - `unknown_rate <= 0.05`
  - `p95 <= 900s`
  - `p99 <= 1200s`
  - `min_sample_count >= 100`
- ただし今週の判定は `provisional`（参考値）とする。

## Measured Result (Source: observability_weekly_review_2026-W21.json)
- status: `provisional`
- decision: `thresholds_fixed_but_not_enforced_for_slo`
- eligible_days: `0`
- reference_days: `3`
- unknown_rate_week: `0.0000`
- p95_max_observed_seconds: `0.00`
- p99_max_observed_seconds: `0.00`
- violations: `[]`

## CTO Assessment
- 閾値固定そのものは妥当。
- ただし `sample_count` が不足しているため、SLO遵守の合否判定は次週以降に持ち越す。
- 現段階では「閾値固定済み・運用データ収集中」の状態。

## Fixed Policy (Phase3)
- 日次: `scripts/run_observability_slo_nightly.sh` を実行し、daily/weekly成果物を `docs/shigoku/reports/` へ保存。
- 週次: `scripts/review_observability_slo_weekly.py` でレビューJSONを生成し、合否/保留を判断。
- 品質ガード: `sample_count < 100` は reference 扱い。`sample_count` を必ず併記。

## Next Week Go/No-Go Rule
- Go（SLO enforce）:
  - `eligible_days >= 3` かつ `violations` なし。
- No-Go（継続観測）:
  - `eligible_days < 3` または `violations` あり。

