---
task_id: SGK-2026-0426
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_report.md
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/reporting,config/diagnostics,tests
---

# 作業ログ: SGK-2026-0426（VDP improvement loop）

## 実施経過

1. **実装前監査**提出（通信0）→ 条件付きGO受領（§2実装スコープ・§3必須条件4点・§5 FOフロー）。
2. **0426計画書へ完了契約を反映**: §3.1（W1〜W4＋FO＋必須条件4点）・§6（テスト9-14）・§8（完了条件6/8/9、readinessはfuture-stage）。
3. **§3-#1 gate**: `test_mc_vdp_drain_main_thread.py` — drain地点（`_apply_post_batch_feedback`）がmain threadであることを前倒し証明（4 passed）。併せてSharedLoopManagerタスク本体が非main threadである前提も固定。
4. **W1**: taxonomy v1→v2 3ファイル連動＋`queue_mutation_off_main_thread`（C10）追加＋S05 failed eventへreason code付与（240 passed）。
5. **W2**: generic再現テスト（修正前FAIL→修正後PASS）→ counterfactual `thread_confinement` で **proven** → deferred injection buffer + main-thread drain実装（drain冒頭にPCR-P1同等assert・task_queue.py無改変）。
6. **W3**: FO-1（0427 sessionのfail-open形状を固定）→ FO-2（run_outcome/verdicts_finalized・report marker・consistency `vdp_run_failed_not_reflected`・required時Hold）→ FO-3（fault-injection fail-closed検証・healthy path回帰0・matrix test）。
7. **W4**: `_canonical_reach` のS09/S10/S11にattempts>0要求＋downstream整合table test（75 passed）。
8. **回帰**: VDP広域 1345 passed・0425 fixture eval accuracy 1.0（fixture taxonomy v2更新）・preflight exit 0。
9. **readiness evidence**（`readiness_sgk2026_0426.json`）産出・0424計画へfuture-stage注記。
10. docs: 本報告/log・計画done化・台帳更新・validator 0・graphify更新。

## 主要決定

- 修正は「main threadでdrainする」方向のみ。PCR-P1 assert（task_queue.py:382/426/554/603/648）は無改変。
- W3のrequired=true失敗表現はHold（decision trace＋session marker）でプロセスkillなし。
- 0424のreadiness依存充足は完了条件外（future-stage。0424計画書側へ記載）。
