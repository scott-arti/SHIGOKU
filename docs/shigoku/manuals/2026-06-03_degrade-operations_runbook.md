---
task_id: SGK-2026-0255
doc_type: manual
doc_usage: reference_manual
status: active
parent_task_id: SGK-2026-0251
related_docs:
  - docs/shigoku/subtasks/2026-06-02_degrade-runbook_subtask_plan.md
  - docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md
  - docs/shigoku/plans/2026-06-01_task_plan.md
created_at: '2026-06-03'
updated_at: '2026-06-03'
---

# 脆弱性チェーン degrade 運用 Runbook

## 目的
- component 障害時に `continue` / `defer` / `blocked` の判定を固定し、submit block・replay・rollback を安全に運用する。
- `AuditLogger` / `DecisionTracer` / Runbook / `work_report` の証跡粒度をそろえる。

## 対象 component contract
| component | health_state | allowed_fallback | recovery_precondition | ttl | rollback_trigger |
| --- | --- | --- | --- | --- | --- |
| `program_memory` | `healthy` / `degraded` / `ttl_expired` | `in_memory_only` | `memory_backend_restored` | `15m` | `ttl_expired` |
| `audit_logger` | `healthy` / `degraded` / `dependency_failure` | `buffered_events` | `audit_pipeline_restored` | `10m` | `buffer_flush_failed` |
| `report_adapter` | `healthy` / `degraded` / `dependency_failure` | `canonical_payload_only` | `adapter_health_restored` | `30m` | `submit_path_unavailable` |
| unknown component | `healthy` / `degraded` | `best_effort` | `manual_verification_required` | `inherit_default` | `manual_review` |

## Failure mode table
| signal / failure_mode | state | submit | replay | primary action |
| --- | --- | --- | --- | --- |
| isolated `degraded` | `continue` | allow | not required | fallback を適用して継続 |
| `report_adapter=degraded` | `continue` | blocked | required | `canonical_report_payload` を保存し、復旧後 replay |
| `dependency_failure` | `defer` | blocked | required | 外部依存復旧まで提出を保留 |
| `ttl_expired` | `defer` | blocked | required | rollback 実施後に再判定 |
| `scope_violation` | `blocked` | blocked | not allowed | 即時停止し再開しない |
| repeated `waf_repeat` | `blocked` | blocked | not allowed | 即時停止し調査へ切替 |

## No-Go 条件
- `scope_violation`
- repeated `waf_repeat`
- `report_adapter` 不完全時の platform submit 実行
- audit trace 欠落で復旧判断の根拠を再構成できない場合

## 監視項目
- `correlation_id`
- `component_before`
- `component_after`
- `selected_fallback`
- `policy_version`
- `decision_reason`
- `recovery_reason`
- `recovery_outcome`
- `submit_blocked`
- `replay_verdict`

## 推奨アラート
- `report_adapter=degraded` が 5 分継続
- `dependency_failure` により `defer` が連続 3 回発生
- `ttl_expired` による rollback が 1 回でも発生
- `submit_blocked=false` かつ `report_adapter=degraded` が観測された場合

## 実行手順
1. 異常検知
- alert または audit event から `failure_mode` を特定する。
- `correlation_id` を採番し、Runbook と監査ログへ残す。

2. state 判定
- `scope_violation` / repeated `waf_repeat` は `blocked` とする。
- `dependency_failure` / `ttl_expired` は `defer` とする。
- `report_adapter=degraded` 単独は `continue` だが submit は block する。

3. fallback 適用
- `program_memory`: `in_memory_only`
- `audit_logger`: `buffered_events`
- `report_adapter`: `canonical_payload_only`
- unknown component: `best_effort`

4. submit / replay 制御
- `report_adapter=degraded` 時は platform submit を実行しない。
- `canonical_report_payload` を保存し、`adapter_health_restored` 後に replay する。
- 既定の保存先は `workspace/runtime/report_adapter_replay_queue.jsonl` とし、`replay_status=pending` で JSONL 追記する。
- 復旧後 replay は `PlatformIntegrationManager.replay_pending_submissions()` を使い、`pending -> completed|failed` を queue 上で更新する。
- `report_adapter=healthy` で新規 submit が走るとき、同 platform の `pending` queue があれば現在の submit 前に自動 replay を試行する。
- 手動 replay は `python -m src.main --report-replay --report-replay-platform <hackerone|bugcrowd> [--report-replay-queue PATH] [--report-replay-limit N]` を使う。
- queue 内容の確認は `python -m src.main --report-replay-list --report-replay-platform <hackerone|bugcrowd> [--report-replay-queue PATH] [--report-replay-limit N] [--report-replay-queue-id <queue_id>] [--report-replay-status <pending|failed|completed>]` を使う。
- `failed` レコードを再試行対象へ戻すときは `python -m src.main --report-retry-failed --report-replay-platform <hackerone|bugcrowd> [--report-replay-queue PATH] [--report-replay-limit N]` を使い、`failed -> pending` へ戻す。
- 特定 1 件だけ戻す場合は `--report-replay-queue-id <queue_id>` を併用する。
- `blocked` 判定時は replay を行わない。

5. recovery / rollback
- `dependency_failure`: 依存復旧後に state を再評価する。
- `ttl_expired`: `rollback_to_last_consistent_snapshot` を実施してから再評価する。
- `audit_logger`: buffered event flush 完了後に復旧扱いとする。

6. close out
- 結果を `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md` 形式で残す。
- `work_report` へ `scenario_id`、`triggered_component`、`expected_state / observed_state`、`submit_blocked`、`replay_verdict` を転記する。

## Drill シナリオ
1. isolated `program_memory=degraded`
2. `audit_logger=dependency_failure` + `report_adapter=degraded`
3. `report_adapter=degraded` 単独で submit block と replay 要求を確認
4. `scope_violation` と `dependency_failure` の衝突時に `blocked` が優先されることを確認
5. `program_memory=ttl_expired` で rollback と `defer` を確認
6. unknown component が `best_effort` で継続することを確認

## Drill 証跡
- `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md` を使用する。

## `work_report` 転記時の確認ポイント
- `expected_state` と `observed_state` の一致/差分
- `submit_blocked` が期待どおりか
- `replay_verdict` が期待どおりか
- 差分がある場合に doc / test / code のどこを修正すべきか
