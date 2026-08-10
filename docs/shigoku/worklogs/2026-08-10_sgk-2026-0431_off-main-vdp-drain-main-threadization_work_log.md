---
task_id: SGK-2026-0431
doc_type: work_log
status: done
parent_task_id: SGK-2026-0430
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0431_parallel-executor-vdp-followup-drain-rehoming_plan.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0431_off-main-vdp-drain-main-threadization_work_report.md
created_at: '2026-08-10'
updated_at: '2026-08-10'
tags:
- shigoku
- vdp
---

# 作業ログ: SGK-2026-0431（off-main VDP drain の main-thread 化）

## 実施内容

1. **棚卸し（explorer）**: drain callsite は 3 箇所のみ（7667 未ガード /
   6702 main 参照 / 11695 ガード済み）。`execute_parallel`・`resume_session` は
   drain 呼び出しなし。7667 が並列 executor ワーカーで off-main 発火 → assert。
2. **修正 1（fixer）**: 7667 を 11695 と同型の main-thread ガードに統一
   （off-main では buffer 保持 → 6702 で委譲 drain）。
3. **修正 2（完了条件 3）**: execute_with_replan の batch 例外ハンドラに
   main-thread drain を追加（非タイムアウト例外 / 空 recovery でも合流点を保証）。
4. **修正 3（修正項目 4）**: off-main task_queue mutation 9 サイトを
   `_add_tasks_main_safe`（新規安全入口）に統一。main → 即時 / off-main →
   buffer → `_apply_post_batch_feedback`（+例外経路）で drain。
5. **テスト（fixer）**: 新規 7 テスト（自己検証: 修正なしで FAILED を確認）。
   回帰 18 + 広域 40 + recon 129 pass（既存 failure は stash baseline で
   pre-existing 確認）。
6. **独立検証（orchestrator）**: 7/18/40 passed を再実行で確認。
   task_queue.py diff 0・preflight exit 0（token hit 0）。
7. **封印 run**: 新 session（session_20260810_012214.json）で
   **PCR-P1 0・critical failure 0・Scenario Coverage 8/12**（0437 の 1/12 から
   回復）。consistent・redaction 0・所有権 bbb。

## 観測メモ

- recon 経路の残存 off-main mutation は修正後 0（全 9 サイト委譲済み）。
  残る task_queue.add サイトは全て main-thread 専用経路。
- `execute_single_task`（インタラクティブ）はバッチループ外で合流点なし
  （src/ 内呼び出し元なし・喪失しない・次の confluence で drain）。
  deferred_followup として報告のみ。
- docs opaque 遵守（report/worklog に endpoint/product 名なし）。

## 成果物

- 変更: src/core/engine/master_conductor.py（+134）、src/recon/pipeline.py（+15）、
  src/recon/parallel_tasks.py（+16）、tests/recon 4 ファイル、新規テスト 1 ファイル
- session: workspace/projects/localhost:3000/sessions/session_20260810_012214.json
- report: workspace/projects/localhost:3000/reports/haddix_report_20260810_012214.md
- evaluator: /tmp/opencode/m5-out-0431/first_failure_juiceshop_v1.json
