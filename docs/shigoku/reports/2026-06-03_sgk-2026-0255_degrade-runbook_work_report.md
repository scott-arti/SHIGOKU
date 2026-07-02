---
task_id: SGK-2026-0255
doc_type: work_report
status: done
parent_task_id: SGK-2026-0251
related_docs:
  - docs/shigoku/subtasks/2026-06-02_sgk-2026-0255_degrade-runbook_subtask_plan.md
  - docs/shigoku/manuals/2026-06-03_degrade-operations_runbook.md
  - docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md
  - docs/shigoku/worklogs/2026-06-03_sgk-2026-0255_degrade-runbook_work_log.md
title: SGK-2026-0255 degrade 設計と運用 Runbook 完了報告
created_at: '2026-06-03'
updated_at: '2026-07-02'
---

# SGK-2026-0255 degrade 設計と運用 Runbook 完了報告

## 実装内容
- `src/core/engine/master_conductor.py` の degrade 契約を拡張し、`reason`, `submit_blocked`, `replay_verdict`, `recovery_actions`, `component_contract`, `no_go_conditions`, `policy_version` を返すようにした。
- `emit_degradation_audit_record()` を追加し、component degradation の判断を `AuditLogger` と `DecisionTracer` の両方へ結び付けられるようにした。
- `src/core/reporting/platform_integration.py` の本番 submit 経路に `report_adapter=degraded` ガードを接続し、submit block 時に `emit_degradation_audit_record()` を発火させるようにした。
- `src/core/reporting/platform_integration.py` に最小 replay queue を追加し、submit block 時に `canonical_report_payload` を `workspace/runtime/report_adapter_replay_queue.jsonl` へ JSONL で永続化するようにした。
- `src/core/reporting/platform_integration.py` に `replay_pending_submissions()` を追加し、queue 上の `pending` レコードを復旧後に `completed` / `failed` へ更新できるようにした。
- `src/core/reporting/platform_integration.py` の healthy submit 経路で、同 platform の `pending` queue を現在 submit 前に自動 replay する recovery hook を追加した。
- `src/main.py` に `--report-replay` を追加し、queue replay を CLI から手動実行できるようにした。
- `src/core/reporting/platform_integration.py` に `retry_failed_report_adapter_replay()` を追加し、`failed` レコードを `pending` へ戻せるようにした。
- `src/main.py` に `--report-retry-failed` を追加し、failed queue の手動 reset を CLI から実行できるようにした。
- `src/core/reporting/platform_integration.py` と `src/main.py` に `queue_id` フィルタを追加し、特定 1 件の failed レコードだけを retry 対象へ戻せるようにした。
- `src/core/reporting/platform_integration.py` に `list_report_adapter_replay_queue()` を追加し、queue の一覧/絞り込み結果を返せるようにした。
- `src/main.py` に `--report-replay-list` を追加し、operator が queue 一覧を見て `queue_id` を選べるようにした。
- `src/core/reporting/platform_integration.py` と `src/main.py` に `status` フィルタを追加し、`pending|failed|completed` 別に queue 一覧を絞れるようにした。
- `tests/core/intelligence/test_phase2_risk_clearance_checklist.py` に isolated / multi / unknown / collision / `report_adapter=degraded` / `ttl_expired` / degradation audit linkage の回帰を追加した。
- `tests/unit/reporting/test_platform_integration_degradation.py` を追加し、submit block 時に platform API を呼ばず audit を出すこと、healthy 時は通常 submit することを固定した。
- `tests/unit/reporting/test_platform_integration_degradation.py` で replay queue への追記と `canonical_payload` 必須化も固定した。
- `tests/unit/reporting/test_platform_integration_degradation.py` で replay 成功時の `completed` 遷移と、platform failure 時の `failed` 遷移も固定した。
- `tests/unit/reporting/test_platform_integration_degradation.py` で healthy submit 時の auto replay hook も固定した。
- `tests/unit/main/test_main_report_replay.py` を追加し、`--report-replay` の JSON 出力と未設定 manager のエラー表示を固定した。
- `tests/unit/main/test_main_report_replay.py` で `--report-retry-failed` の JSON 出力も固定した。
- `tests/unit/main/test_main_report_replay.py` と `tests/unit/reporting/test_platform_integration_degradation.py` で `queue_id` 指定 reset も固定した。
- `tests/unit/main/test_main_report_replay.py` と `tests/unit/reporting/test_platform_integration_degradation.py` で replay queue list の JSON 出力と filter 動作も固定した。
- `tests/unit/main/test_main_report_replay.py` と `tests/unit/reporting/test_platform_integration_degradation.py` で `status` フィルタの list 動作も固定した。
- `docs/shigoku/manuals/2026-06-03_degrade-operations_runbook.md` を追加し、component contract、failure mode table、No-Go 条件、submit/replay/rollback の運用手順を固定した。
- `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md` を追加し、Step 7 で使う drill 証跡フォーマットを固定した。

## 主な変更ファイル
- `src/core/engine/master_conductor.py`
- `src/core/reporting/platform_integration.py`
- `tests/core/intelligence/test_phase2_risk_clearance_checklist.py`
- `tests/unit/reporting/test_platform_integration_degradation.py`
- `docs/shigoku/subtasks/2026-06-02_sgk-2026-0255_degrade-runbook_subtask_plan.md`
- `docs/shigoku/manuals/2026-06-03_degrade-operations_runbook.md`
- `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md`

## 判断理由
- unknown component は本 subtask では `best_effort` 互換を維持し、fail-closed 方向の仕様変更はスコープ外にした。
- `report_adapter=degraded` は処理継続を許しつつ submit を block し、`canonical_report_payload` の replay を要求する方針に統一した。
- submit 実行境界は `PlatformIntegrationManager.create_draft_on_platform()` に寄せ、degradation 判定と audit emission を同じ場所で成立させた。
- `scope_violation` と repeated `waf_repeat` は経営ガードレールとして `blocked` を優先し、replay も許可しない方針にした。
- drill 証跡は manual と `work_report` の両方で再利用できるように、共通テンプレートを 1 枚に寄せた。

## 検証
- `.venv/bin/pytest tests/core/intelligence/test_phase2_risk_clearance_checklist.py -q`
  - 結果: `16 passed`
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py`
  - 結果: `10 passed`
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py tests/unit/main/test_main_report_replay.py`
  - 結果: `15 passed`
- `.venv/bin/pytest -q tests/core/intelligence/test_phase2_risk_clearance_checklist.py tests/core/engine/test_mc_intelligence_integration.py`
  - 結果: `29 passed`
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py tests/core/intelligence/test_phase2_risk_clearance_checklist.py tests/core/engine/test_mc_intelligence_integration.py`
  - 結果: `44 passed`
- `python3 scripts/validate_shigoku_docs.py`
  - 結果: `FRONT_MATTER_ISSUES=0`, `BROKEN_LINKS=0`, `REGISTRY_ISSUES=0`, `DEFERRED_LINK_ISSUES=0`

## Drill Evidence Summary
- scenario_id: `DRILL-20260603-01`
- triggered_component: `report_adapter`
- expected_state / observed_state: `continue / continue`
- submit_blocked: `true`
- replay_verdict: `required`
- followup_action: Runbook に `report_adapter=degraded` 時の replay 要求を固定済み

## リスク
- `graphify update .` は AST 再抽出の途中出力までは確認したが、完了メッセージまでは取得できていない。
- `emit_degradation_audit_record()` の submit 境界への接続は `platform_integration` に入れたが、他の提出経路が増える場合は同等ガードの横展開が必要。
- 自動 replay hook は `report_adapter=healthy` の submit 経路に限定しているため、別系統の recovery イベントや外部 scheduler 連携はまだ未実装。
- `--report-retry-failed` は状態 reset のみで、失敗原因の分類や backoff 管理まではまだ持っていない。
