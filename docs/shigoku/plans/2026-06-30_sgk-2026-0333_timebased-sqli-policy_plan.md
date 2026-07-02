---
task_id: SGK-2026-0333
doc_type: plan
status: active
parent_task_id: SGK-2026-0330
related_docs:
  - docs/shigoku/reports/2026-06-30_SGK-2026-0330_work_report.md
created_at: '2026-06-30'
updated_at: '2026-07-02'
---

# time-based SQLi policyのデフォルト有効化

## 概要

time-based SQLi policy は `PayloadRiskPolicy` に hook があるが現時点ではデフォルト無効。
policy matrix の設計とデフォルト有効化を行う。

## 背景

SGK-2026-0330 の work report で deferred task として記録。
`PayloadRiskPolicy._time_based_block_enabled` は現在 `False`。

## スコープ

- policy matrix の design doc 作成
- 有効化条件の決定
- デフォルト有効化の実装とテスト
