---
task_id: SGK-2026-0255
doc_type: work_log
status: done
parent_task_id: SGK-2026-0251
related_docs:
  - docs/shigoku/subtasks/2026-06-02_sgk-2026-0255_degrade-runbook_subtask_plan.md
  - docs/shigoku/reports/2026-06-03_sgk-2026-0255_degrade-runbook_work_report.md
title: SGK-2026-0255 degrade 設計と運用 Runbook 作業ログ
created_at: '2026-06-03'
updated_at: '2026-06-30'
---

# SGK-2026-0255 degrade 設計と運用 Runbook 作業ログ

1. RED テストを追加
- `tests/core/intelligence/test_phase2_risk_clearance_checklist.py` に degradation contract の不足分を追加した。
- isolated / multi / unknown / collision / `report_adapter=degraded` / `ttl_expired` / degradation audit linkage を先に固定した。

2. `master_conductor` を実装
- `resolve_component_degradation()` に state / reason / submit block / replay / recovery metadata を追加した。
- `emit_degradation_audit_record()` を追加し、component degradation の audit / decision trace 連携を実装した。

3. submit 本番経路へ接続
- `src/core/reporting/platform_integration.py` の `PlatformIntegrationManager.create_draft_on_platform()` に degradation 判定を追加した。
- `report_adapter=degraded` かつ `submit_blocked=true` のときは platform API 呼び出しを行わず、audit を出して `RuntimeError` で停止するようにした。
- `canonical_report_payload` を必須入力にし、submit block 時は `workspace/runtime/report_adapter_replay_queue.jsonl` へ JSONL 追記する最小 replay queue を追加した。
- `replay_pending_submissions()` を追加し、復旧後の replay で `pending -> completed|failed` を queue 上で更新する処理を入れた。
- healthy submit 経路で、同 platform の `pending` queue を現在 submit 前に自動 replay する recovery hook を追加した。
- `tests/unit/reporting/test_platform_integration_degradation.py` を追加し、blocked / healthy の両経路、queue 追記、`canonical_payload` 必須化、replay 成功/失敗、自動 replay hook の状態遷移を固定した。

4. replay CLI を追加
- `src/main.py` に `--report-replay` / `--report-replay-platform` / `--report-replay-queue` / `--report-replay-limit` を追加した。
- `tests/unit/main/test_main_report_replay.py` を追加し、JSON 出力と未設定 manager 時の失敗表示を固定した。

5. failed retry reset を追加
- `src/core/reporting/platform_integration.py` に `retry_failed_report_adapter_replay()` を追加し、`failed` レコードを `pending` へ戻す helper を実装した。
- `src/main.py` に `--report-retry-failed` を追加し、failed queue の手動 reset を CLI から実行できるようにした。
- `queue_id` フィルタも追加し、特定 1 件の failed レコードだけを `pending` へ戻せるようにした。
- `tests/unit/reporting/test_platform_integration_degradation.py` と `tests/unit/main/test_main_report_replay.py` で reset 結果、`queue_id` 指定、JSON 出力を固定した。

6. replay queue list を追加
- `src/core/reporting/platform_integration.py` に `list_report_adapter_replay_queue()` を追加し、platform / `queue_id` / limit で queue を一覧できるようにした。
- `src/main.py` に `--report-replay-list` を追加し、operator が queue 一覧を確認してから retry 対象を選べるようにした。
- `status` フィルタも追加し、`pending|failed|completed` 別に queue を絞れるようにした。
- `tests/unit/reporting/test_platform_integration_degradation.py` と `tests/unit/main/test_main_report_replay.py` で list の filter と JSON 出力を固定した。

7. Runbook と drill テンプレートを整備
- `docs/shigoku/manuals/2026-06-03_degrade-operations_runbook.md` を作成した。
- `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md` を Step 7 用テンプレートとして関連付けた。

8. 回帰確認を実施
- `.venv/bin/pytest tests/core/intelligence/test_phase2_risk_clearance_checklist.py -q` で `16 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `2 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `5 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `6 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `7 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `8 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `9 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py` で `10 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py tests/unit/main/test_main_report_replay.py` で `15 passed` を確認した。
- `.venv/bin/pytest -q tests/core/intelligence/test_phase2_risk_clearance_checklist.py tests/core/engine/test_mc_intelligence_integration.py` で `29 passed` を確認した。
- `.venv/bin/pytest -q tests/unit/reporting/test_platform_integration_degradation.py tests/unit/main/test_main_report_replay.py tests/core/intelligence/test_phase2_risk_clearance_checklist.py tests/core/engine/test_mc_intelligence_integration.py` で `44 passed` を確認した。
- `python3 scripts/validate_shigoku_docs.py` で docs 整合エラーがないことを確認した。

9. 完了反映
- subtask plan を `done` に更新した。
- work_report / work_log / manuals を追加した。
- registry / ledger を `done` へ更新した。

10. クローズ確認
- 参照先: `docs/shigoku/subtasks/2026-06-02_sgk-2026-0255_degrade-runbook_subtask_plan.md`, `docs/shigoku/reports/2026-06-03_sgk-2026-0255_degrade-runbook_work_report.md`
- 変更要約: degrade 契約、submit block、replay queue、retry/list CLI、Runbook、drill 証跡、回帰テストまで反映済み。
- 次アクション: 本 task は `done` とし、追加改善は必要時に follow-up task として分離起票する。
