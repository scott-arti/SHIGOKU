---
task_id: SGK-2026-0223
doc_type: plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s02_groupb_discovery-graphql_subtask_plan.md
- docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
- docs/shigoku/reports/2026-05-26_sgk-2026-0223_graphql-longrun-regression-test_work_report.md
- docs/shigoku/worklogs/2026-05-26_sgk-2026-0223_graphql-longrun-regression-test_work_log.md
title: 'GraphQL Runtime 長時間回帰テスト計画（連続実行/状態リーク/劣化監視）'
created_at: '2026-05-21'
updated_at: '2026-07-02'
tags:
- shigoku
- graphql
- regression
- reliability
---

# Objective
- GraphQL Runtime制御（QPS/backpressure/quarantine/half-open）が長時間運用で劣化しないことを継続的に検証する。

# Test Matrix
1. 連続成功シナリオ:
   - 同一ホスト100〜500回実行で `inflight=0` 復帰、host stateリークなし。
2. 混在負荷シナリオ:
   - 遅延ホスト/失敗ホスト/健全ホスト混在で、backpressureとquarantineの挙動が仕様どおり。
3. half-open回復シナリオ:
   - quarantine満了後の最古ホスト優先試験、成功時解除、失敗時再隔離を確認。
4. unknown category監視シナリオ:
   - `internal_error_category=other` の比率計算が期待どおりに動く。

# Execution Strategy
1. PRゲート:
   - 短時間版（100回）を毎PRで実行。
2. Nightly:
   - 長時間版（500回 + 混在負荷）を毎日実行。
3. Weekly Burn-in:
   - 連続実行 + プロセス再起動混在シナリオを週次実行。

# Pass / Fail Criteria
1. 連続成功シナリオで状態リークなし（`_inflight==0`, quarantine/failure mapが期待どおり）。
2. 混在負荷で誤分類なし（`backpressure_rejected`, `host_quarantined` のカテゴリ一致）。
3. Nightly失敗時は自動でwarning発火し、失敗ログと再現コマンドを残す。

# Deliverables
- `tests/core/agents/swarm/test_discovery_graphql_longrun.py`（新規）
- CIジョブ:
  - `graphql-longrun-pr`
  - `graphql-longrun-nightly`
  - `graphql-longrun-weekly`
