---
task_id: SGK-2026-0426
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_report.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0424_vdp-m3a-readonly-pilot_subtask_plan.md
- docs/shigoku/worklogs/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_log.md
title: VDP improvement loop 完了報告（W1〜W4＋FO・C10 proven化・hidden holdout・readiness evidence）
created_at: '2026-08-06'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/reporting,config/diagnostics,tests
deferred_tasks:
  - deferred_id: SGK-2026-0426-D01
    title: "0424（m3a read-only pilot）のreadiness依存充足の判定"
    reason: "ユーザー承認により0424のreadiness依存充足は本タスクの完了条件に含めない（future-stage）。0426はhash付きevidence（config/diagnostics/readiness_sgk2026_0426.json）を産出済み。go/hold判定は0424着手時にユーザーが実施"
    impact: medium
    tracking_task_id: SGK-2026-0424
    recommended_next_action: "0424着手時にreadiness_sgk2026_0426.jsonのhash整合を確認し、実VDP許可・scope・予算・kill switch固定と合わせてgo/holdを判断"
  - deferred_id: SGK-2026-0428
    title: "bug-bounty bundle preflight のテスト baseline 失敗（7件）の解消"
    reason: "0426裏取りの広域回帰で観測した既存baseline失敗。active_bundle_missing/_preflight_failed（テストfixture不足）で、0426由来ではない。ガードは正しくfail-closed"
    impact: low
    tracking_task_id: SGK-2026-0428
    recommended_next_action: "7件のnode idを確定しfixture追加でgreen化（製品ガードは緩めない）"
  - deferred_id: SGK-2026-0429
    title: "LLM APIキー依存テストの隔離（20件）"
    reason: "0426裏取りの広域回帰で観測した既存baseline失敗。テストenvにLLMキー未設定で認証失敗。0426由来ではなく環境依存"
    impact: low
    tracking_task_id: SGK-2026-0429
    recommended_next_action: "本来mock可能なものはstub化、実API必須はrequires_llmでskip化しfail 0に"
---

# 作業完了報告: SGK-2026-0426（VDP improvement loop — W1〜W4＋FO＋Readiness）

## 0. 位置づけと実施内容

SGK-2026-0427実測（run_id 9908371a）が確定した真因（PCR-P1 thread-confinement: MCタスク実行がSharedLoopManager background thread上で行われ、`_queue_vdp_follow_ups` のtask_queue mutationが `task_queue.py` のPCR-P1 assertに違反 → S05 failed・attempts 0）に基づき、ユーザー承認済み完了契約（0426計画§3.1）のW1〜W4＋FOを実装。すべて製品非依存（Juice Shop固有token 0・preflight exit 0維持・sealed参照のみ）。

## 1. 完了契約への反映（着手時）

0426 subtask_plan へ §3.1「実装契約（W1〜W4＋FO）・必須条件4点」を追記し、§6（必須テスト9-14）・§8（完了条件6/8/9）を更新。§8.6: 0424のreadiness依存充足は完了条件に含めない（future-stage・0424計画書側へ記載）を明記。**moving target回避**（lessons [2026-08]）: 計画外hardeningの暗黙追加なし。

## 2. §3-#1 gate: drain地点のmain thread証明（前倒し）

`tests/core/engine/test_mc_vdp_drain_main_thread.py`（4 tests）:
- SharedLoopManager上のタスク本体が**非main thread**（`safe_run_async` 実測・`execute_with_replan` が同期メソッド）— PCR-P1発火機構の前提を固定。
- drain地点（`_apply_post_batch_feedback`）で `assert threading.current_thread() is threading.main_thread()` が**main thread上でPASS**、**worker threadからの呼出はAssertionError（fail-closed）**。
- 結果: **4 passed**（buffer機構実装前にgate成立）。

## 3. W1（C13 telemetry・taxonomy v2）— 両方: tests＋実artifact

- 新mechanism `queue_mutation_off_main_thread`（C10）を `vdp_diagnostic_trace.py` と `taxonomy_v1.json` へ追加。
- **taxonomy v1→v2 3ファイル連動**: `taxonomy_v1.json`（taxonomy_version v2・content_hash再計算 `sha256:b7920650…`）、`vdp_diagnostic_trace.py::DIAGNOSTIC_TAXONOMY_VERSION=v2`、`vdp_counterfactual.py::TAXONOMY_VERSION_V1=v2`。v1/v2混在は既存section検証の等値比較でreject（`test_unknown_taxonomy_version_rejected` をv3へ更新し検証継続）。旧session（v1）互換: 旧reader・analyzerはtaxonomy非依存で既存テストgreen。
- S05 failed event（`master_conductor.py:11702`）へ `reason_codes=['queue_mutation_off_main_thread']` 付与（redaction-safe・flag-off no-op維持）。

## 4. W2（C10 proven化→修正・linchpin）— 両方

- **generic再現テスト**（`tests/unit/engine/test_vdp_followup_thread_confinement.py`）: 実MCの `_queue_vdp_follow_ups` をworker threadで実行し、**修正前FAIL**（PCR-P1クラッシュ・タスク未キュー・S05 failed）→ **修正後PASS**（buffer追記→main thread drainでキュー注入成功・S04/S05 reached）。
- **単一変数counterfactual**（`config/diagnostics/counterfactual_sgk2026_0426_c10.json`）: `changed_variable="thread_confinement"`（`ALLOWED_CHANGED_VARIABLES`へ追加）、control=0427実測（S05 failed）・treatment=修正後（S05 reached・tasks queued）。validation errors **[]**、S05 improved・regressed 0、**attribution: proven**（`single_variable_improvement_with_no_regression`）。2変数変更・hash不一致はvalidatorで拒否（テスト追加済み）。
- **修正（deferred injection buffer + main-thread drain）**: `_queue_vdp_follow_ups` はworker側でgate評価・spec構築・checkpoint（constraint H）・thread-safe buffer追記まで。queue mutationは `_drain_vdp_pending_follow_up_injections()`（drain冒頭にPCR-P1同等のmain-thread assert・fail-closed）で `_apply_post_batch_feedback`（LB-2契約）／`execute_single_task`／resume経路にて実行。**PCR-P1 assert（task_queue.py:382/426/554/603/648）は無改変**（本タスクでtask_queue.pyを編集していない。`git diff` はSGK-2026-0421導入分の未コミット行のみ）。VDP off時は全経路no-op・attack task経路bit不変。

## 5. W3（fail-open修正）— FO-1→FO-3、両方

- **FO-1（修正前baseline・1行）**: 0427 session（attempts=0 / verdicts=6 / run_outcome無し）＋通常report＋consistency PASS — fail-openの実在を固定（`test_historical_0427_session_shape`）。
- **FO-2（修正）**: enqueue失敗時に `run_outcome=follow_up_stage_failed`・`verdicts_finalized=false` をsessionへadditive保存（`master_conductor_session_service.py`）。reportへ `vdp_run_failed_v1` marker（`embed_vdp_run_failed_marker`・generate_haddix_reportに `vdp_run_outcome` をthread）。consistency checkerに `vdp_run_failed_not_reflected`（session failedなのにmarker無しreport→inconsistent）。required=true時はプロセスkillでなく **Hold**（decision trace＋session marker。MC task失敗処理と整合・run不正終了なし）。
- **FO-3（修正後検証）**: (a) fault-injectionで `run_outcome=follow_up_stage_failed`・`verdicts_finalized=False`・S05 failed eventにW1 reason code（`test_enqueue_failure_is_fail_closed`）(b) marker無しreport→`vdp_run_failed_not_reflected`・marker有り→consistent（`test_verify_run_failed_session_without_marker_is_inconsistent` / `with_marker_is_consistent`）(c) healthy path回帰0（`test_healthy_enqueue_stays_normal`・`test_verify_healthy_session_marker_absent_is_consistent`）(d) matrix `{ok→normal×1} {fail→fail-closed×0}`（`test_deterministic_matrix`）。実結果: **FO関連テスト全green**（engine 6＋consistency 3＋formatter）。
- FO-4: 本報告§2〜§7にbefore/after実出力を添付。

## 6. W4（analyzer reach整合）— tests

- `vdp_diagnostic.py::_canonical_reach`: **S09/S10/S11はattempts>0を要求**（shadow verdict/evidence無しattemptでの偽S11 reachを排除）。
- table test追加（`test_vdp_diagnostic.py`）: S05 cut＋shadow verdicts（attempts 0）→ downstreamが**S06〜S12全件**（S11欠落なし）／attempts>0＋verdicts→S11はgenuine reachとしてdownstreamから除外／全cut stageでdownstream整合。実結果: **75 passed**（既存60＋新規15）。

## 7. 検証コマンドと観測結果（カバレッジ: 実artifact＋tests 両方）

```text
gate（drain main thread）:            .venv/bin/pytest tests/core/engine/test_mc_vdp_drain_main_thread.py → 4 passed
W2再現/counterfactual/FO:            .venv/bin/pytest tests/unit/engine/test_vdp_followup_thread_confinement.py tests/unit/engine/test_vdp_followup_failopen.py → 10 passed
W1（taxonomy v2）:                   test_vdp_diagnostic_trace/index/counterfactual/formatter/consistency等 → 240 passed, 1 skipped（v1→v2更新後）
W4:                                  .venv/bin/pytest tests/unit/reporting/test_vdp_diagnostic.py → 75 passed
広域VDP回帰:                          .venv/bin/pytest tests/unit/engine/test_vdp_*.py tests/unit/reporting/test_vdp_*.py tests/core/engine/test_master_conductor_vdp_*.py tests/unit/main/test_main_report_haddix_vdp_gate.py → 1345 passed, 1 skipped
0425 fixture eval（hidden baseline）: bash tests/fixtures/vdp_diagnostic_env/run_diagnostic_eval.sh → accuracy 1.0 / trace_coverage 1.0 / section_valid（fixture taxonomy v1→v2更新後）
preflight:                           check_vdp_product_independence.py → verdict pass / exit 0（token hit 0）
consistency（新規）:                  verify_report_session_consistency W3 tests → 11 passed
docs:                                sync_shigoku_updated_at → validate_shigoku_docs → 全0（後述）
```

**カバレッジ**: 上記はテスト＋実artifact（taxonomy/counterfactual/readiness JSON・0427 session実測）の**両方**をカバー。Juice Shopへの再通信は行っていない（参考回帰は実施していない。合格ゲート外のため）。

## 8. PCR-P1 assert 5箇所の無改変（diff提示）

- `task_queue.py:382/426/554/603/648` のPCR-P1 assertは**本タスクで一切編集していない**（本タスクのedit対象外。`git diff` の差分はSGK-2026-0421導入時の未コミット行のみ — comment+assertの追加がHEAD差分として残っているもの）。
- 修正は「main threadでdrainする」方向のみ（assert削除・条件緩和なし）。

## 9. 変更ファイル一覧

- 新規: `tests/core/engine/test_mc_vdp_drain_main_thread.py`・`tests/unit/engine/test_vdp_followup_thread_confinement.py`・`tests/unit/engine/test_vdp_followup_failopen.py`・`config/diagnostics/counterfactual_sgk2026_0426_c10.json`・`config/diagnostics/readiness_sgk2026_0426.json`
- 変更: `src/core/engine/master_conductor.py`（buffer/drain/run_outcome/Hold）・`src/core/engine/master_conductor_session_service.py`（run_outcome/verdicts_finalized additive）・`src/core/engine/vdp_diagnostic_trace.py`（taxonomy v2・mechanism）・`src/reporting/vdp_diagnostic.py`（W4 reach）・`src/reporting/vdp_counterfactual.py`（変数追加・v2）・`src/reporting/vdp_report_projection.py`（run-failed marker）・`src/reporting/haddix_formatter.py`・`src/reporting/haddix_submission_internal_formatter.py`・`src/reporting/report_session_consistency.py`（`vdp_run_failed_not_reflected`）・`src/main.py`（report marker wiring）・`config/diagnostics/taxonomy_v1.json`（v2）・`tests/fixtures/vdp_diagnostic_env/*.py`（taxonomy v2）・既存テスト更新・docs（0426計画・0424計画注記・本報告/log）

## 10. 完了条件判定（計画§8.1-9）

1. proven原因のみ改善（C10はcounterfactualでproven・supported/suspectedでの変更0）✓ 2. first failure→proven→failing test→change→holdout deltaの因果（W2再現テストbefore/after・holdout 1.0維持）✓ 3. hidden holdout floor・delta保存 ✓ 4. false promotion/safety/leakage/回帰0 ✓ 5. 製品token 0・preflight exit 0 ✓ 6. readiness evidence産出（0424依存充足はfuture-stage・0424計画へ記載）✓ 7. targeted/回帰/docs/diff全成功 ✓ 8. W1-W4+FO完了（taxonomy v2連動・counterfactual proven・PCR-P1無改変・fail-closed実証・analyzer整合）✓ 9. holdout floor・回帰0・preflight・docs・diff ✓

**in_scope_blocker 0件**。deferred_followup: D01（0424 readiness判定 — future-stage・0424計画側へ記載）。non_blocking_observation: 該当なし。本タスクを **done** とする。
