---
task_id: SGK-2026-0026
doc_type: work_report
status: done
parent_task_id: null
related_docs: []
created_at: '2026-05-11'
updated_at: '2026-05-19'
---

# Report Loop KPI Baseline (2026-05-11)

## Purpose
- `scripts/shigoku_ops_cli.py report loop` の導入効果を、同一 report/session で継続比較するための基準を残す。

## Baseline Command

```bash
python3 scripts/shigoku_ops_cli.py \
  --json report loop \
  --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260510_142342.md \
  --include-findings \
  --max-findings 5 \
  --finding-fields title,target_url
```

## Baseline Snapshot
- date: `2026-05-11`
- report: `haddix_report_20260510_142342.md`
- exit_code: `0`
- top_status: `ok`
- stage_statuses:
  - consistency: `consistent`
  - gate: `pass`
  - findings: `ok`
- findings_count: `4`
- elapsed_ms: `146.41`
- payload_bytes: `11056`
- command_count: `1`

## KPI Fields To Track
- elapsed_ms
- command_count (manual steps)
- payload_bytes (stdout JSON size)
- rerun_required (consistency result)
- reason_codes count

## Notes
- 次回比較では、同じ report path と同じ options を使うこと。
- `max-findings` と `finding-fields` を変えると payload 比較が不公平になる。

## 1-Week Tracking Table

| date | exit_code | top_status | elapsed_ms | payload_bytes | command_count | memo |
| :-- | :-- | :-- | --: | --: | --: | :-- |
| 2026-05-11 | 0 | ok | 146.41 | 11056 | 1 | baseline |
| 2026-05-12 |  |  |  |  |  |  |
| 2026-05-13 |  |  |  |  |  |  |
| 2026-05-14 |  |  |  |  |  |  |
| 2026-05-15 |  |  |  |  |  |  |
| 2026-05-16 |  |  |  |  |  |  |
| 2026-05-17 |  |  |  |  |  |  |

## Daily Collection Command

```bash
python3 scripts/shigoku_ops_cli.py \
  --json report loop \
  --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260510_142342.md \
  --include-findings \
  --max-findings 5 \
  --finding-fields title,target_url
```
