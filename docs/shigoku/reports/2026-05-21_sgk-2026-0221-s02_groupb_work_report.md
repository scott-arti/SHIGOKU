---
task_id: SGK-2026-0221-S02
doc_type: work_report
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s02_groupb_discovery-graphql_subtask_plan.md
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
- docs/shigoku/plans/2026-05-21_sgk-2026-0223_graphql-longrun-regression-test_plan.md
created_at: '2026-05-21'
updated_at: '2026-07-02'
---

# Work Report: SGK-2026-0221-S02 GroupB Discovery GraphQL 本実装接続

## 実装内容
- `src/core/agents/swarm/discovery/graphql.py` を Skeleton 判定から実HTTP検査へ置換。
- `contract_version` / `error_policy_version` を含む返却契約を導入し、`error_code` / `internal_error_detail` / `internal_error_category` を正規化。
- スケーラビリティ制御を実装:
  - admission/backpressure
  - QPS制御
  - host quarantine
  - circuit breaker
  - half-open recovery（最古待機ホスト優先）
- 構造化イベントを導入:
  - `graphql_probe_event`
  - `graphql_probe_alert`（15分窓で `internal_error_category=other` 比率を評価）
- `src/core/agents/swarm/discovery/manager.py` に契約正規化アダプタを実装し、例外時も規定フォーマット返却に統一。
- CI運用化:
  - `.github/workflows/graphql-runtime-ci.yml` を追加
  - PR/Nightly/Weekly の3系統ジョブと失敗通知（PRコメント/Issue起票）を実装。

## 判断理由
- BugBounty用途で必要な「検出精度」と「運用安定性」を同時に満たすため、Phase 1/4/5 を先行完了。
- 互換性維持を優先し、公開 `error_code` は維持しつつ内部原因は `internal_error_detail/category` へ分離。
- 運用での劣化検知を早めるため、`other_rate` しきい値判定と通知導線を実装。

## 検証結果
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_graphql_contract.py -q` → `9 passed`
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_graphql_alerting.py -q` → `5 passed`
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_graphql_longrun.py -q` → `3 passed`
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_manager.py -q` → `1 passed`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_graphql.py -q` → `12 passed`

## リスク評価
- 解消済み:
  - URL文字列擬似判定依存
  - 例外時返却フォーマット崩壊
  - 負荷時の無制限滞留リスク（基本制御）
- 残リスク:
  - 分散実行時の制御一貫性（プロセス間共有）は未実装
  - 長時間運用の通知チューニング（誤警報抑制）は運用データで継続調整が必要

## deferred_tasks
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0221-S02-D01
    title: 分散ランタイム制御の全体共通基盤化
    reason: 本タスクは単一プロセス中心の制御実装までをスコープとしたため
    impact: high
    recommended_next_action: SGK-2026-0222 で Redis 等を用いた共有制御バックエンドを実装
  - deferred_id: SGK-2026-0221-S02-D02
    title: 長時間回帰ジョブの運用チューニング
    reason: PR/Nightly/Weekly は実装済みだが、通知閾値と運用ノイズ最適化が残るため
    impact: medium
    recommended_next_action: SGK-2026-0223 で失敗頻度/ノイズを観測し通知ポリシーを調整
  - deferred_id: SGK-2026-0221-S02-D03
    title: 認証後Surface探索の本格展開
    reason: GroupB範囲は基盤整備優先であり、全認証フロー拡張は段階導入としたため
    impact: medium
    recommended_next_action: 認証方式別の再認証レート制御と監査ログ要件を拡張実装
```

