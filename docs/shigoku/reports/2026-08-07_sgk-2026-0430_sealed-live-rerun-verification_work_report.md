---
task_id: SGK-2026-0430
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_subtask_plan.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_report.md
- docs/shigoku/worklogs/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_log.md
title: 0426修正の封印ライブ実効確認 完了報告（Juice Shop m3a rerun ×2）
created_at: '2026-08-07'
updated_at: '2026-08-08'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,src/core/engine,src/reporting,workspace/projects/localhost:3000
deferred_tasks:
  - deferred_id: SGK-2026-0431
    title: "並列 executor（execute_parallel）における VDP follow-up drain 合流点の再配線"
    reason: "0430独立検証で特定。F1で execute_parallel 内の off-main drain callsite を削除した後、並列経路には deferred VDP injection を main thread で drain する合流点が無い（_apply_post_batch_feedback はシリアル経路のみ）。現行VDP m3aは serial default のため未行使だが、並列＋VDPでは buffer 滞留の恐れ"
    impact: medium
    tracking_task_id: SGK-2026-0431
    recommended_next_action: "execute_parallel の scheduler.run 完了後に main-thread drain を追加、またはVDP有効時に serial 強制ガードを入れる（PCR-P1無改変・回帰テスト付き）"
---

# 作業完了報告: SGK-2026-0430（封印ライブ実効確認）

## 0. 実施内容

0426修正（W2 main-thread drain / W3 fail-closed / W4 reach）の**封印ライブ実効確認**を、ローカルJuice Shop（m3a read-only・隔離network・harness 1〜2回）で実施。ユーザー承認により**2回のharness run**（eval v2・v2b）を実行した。

## 1. run記録

| run | session / run_id | 結果 |
|---|---|---|
| #1（eval v2） | session_20260807_152745 / fa1dbed6 | funnel S00〜S06 reached → **S07 blocked**（scope_block_incorrect）。W2 drainのlive成功（S04/S05 reached・4件queue投入）を確認するも attempts 0 |
| #2（eval v2b・ユーザー承認） | session_20260807_153606 | funnel S00〜S06 reached → **S08 reached ×2（実送信）→ S10 reached → S11 reached**、**attempts 3** |

両runとも exit 0・config byte-identical復元・runtime surface hash一致・実行1回/out dir。

## 2. Q1: 攻撃が実際に飛んだか → **達成（run #2）**

- **W2 main-thread drainのlive実効**: S05 reached（queued_tasks=4）・S06 reached（dispatch）— 0427のS05 failed（PCR-P1）は解消。
- **attempts 3**（0427: 0 → run #1: 0 → run #2: 3）。attempt0: scope_verdict "allowed"・request_fingerprint 記録。
- **S08 reached ×2**＝follow-up GETが実際に送信され、S10（証拠完成）・S11（判定）へ到達。

## 3. 実測発見と対処

- **F1（W2配線欠陥・live検出）**: `execute_parallel` 内のdrain呼出がSharedLoopManagerスレッド上で実行され、drainのmain-thread assertがtask_002で発火（**fail-closedが設計どおり機能**）。バッチ経路（`_apply_post_batch_feedback`）はmainで正常drain。→ **off-mainコールサイト2箇所を除去**（execute_parallel・execute_single_task）。drainは `_apply_post_batch_feedback`（main・gateテスト済み）＋main-thread呼出時の即時drainのみに整理。
- **F2（新規S07 false-block・根因特定→修正）**: `_build_vdp_scope_snapshot` が `max_requests_per_minute` を引き継がず0 → EthicsGuardが「Rate limit exceeded: 0/min」→ 全follow-upがout_of_scope（scope_block_incorrect）。実測: 同一URLをrate 60で再検証すると **allowed**。→ snapshot fallback **60**（fast-path契約値。明示値は尊重）＋`test_vdp_scope_snapshot_rate_limit.py`（4 tests）を追加。**run #2でlive確認（attempts 3・scope_verdict allowed）**。

## 4. Q2: fail-open正常終了バグが治ったか → **達成**

- **Q2a（run #2 live）**: report/consistency **consistent（reason_codes []）**・diagnostic indexに**11 events**（S08×2/S10/S11 reachedを含む実funnel）が機械可読で反映・**confirmed_delta=0**（shadow verdict の unverified confirmed 昇格なし）。
- **Q2b（バグ実物への回帰・最重要）**: 修正後consistencyを**実0427ペア**（session_20260806_105634 + haddix_report_20260806_110200）へ再適用 → **before consistent[]（0427時点・文書化済み）→ after inconsistent[`vdp_run_failed_not_reflected`]** に転換。raw 0427 sessionのrun_health（degraded/follow_up_enqueue_failed）＋attempts 0からfail-openを検出する `_session_fail_open` をcheckerへ追加（`test_report_session_consistency.py` 13 passed）。**「攻撃ゼロで正常終了」が塞がれた直接証拠**。

## 5. 安全・整合（両run実測）

- secret 0（session/report/logs/proxy/evaluator出力を正規表現scan）・egress: allowlist成功1（api.deepseek.com）＋外部試行11件（nuclei等telemetry: api.pdtm.sh×6他）全DENY・データ送出0・DNS gate実証済み。
- 実行回数: eval v2=1回・v2b=1回（ユーザー承認）。config既定bit復帰（mode bugbounty/vdp off/diagnostics false・byte-identical）・runtime surface hash一致・preflight 前後 exit 0・**PCR-P1 assert（task_queue.py:382/426/554/603/648）無改変**（drainのmain-thread assertはrun #1で違反検出に機能し、F1で配線修正）。
- evaluator post-binding: `first_failure_juiceshop_v2.json`（S07/supported・scope_block_incorrect）→ `first_failure_juiceshop_v2b.json`（**S12/suspected/stage_event_missing** — S12はemitter無し・report投影はconsistencyで判定の既知モデリング。run #2はS11到達で正常完了）。

## 6. 検証コマンドと観測結果（実artifact＋tests 両方）

```text
gate（drain main thread）:            test_mc_vdp_drain_main_thread.py → 4 passed
W2再現/FO/scope snapshot:             test_vdp_followup_thread_confinement / failopen / scope_snapshot_rate_limit → 15 passed
consistency（Q2b拡張含む）:            test_report_session_consistency.py → 13 passed
W4:                                   test_vdp_diagnostic.py → 75 passed
広域targeted:                         上記合計 103 passed（最終状態）
Q2b実測:                              実0427ペア → inconsistent[vdp_run_failed_not_reflected]
Q1/Q2a実測:                           run #2 → attempts 3・S08×2・consistent・confirmed 0
preflight:                            exit 0（token hit 0）
```

カバレッジ: 実artifact（2 session・report・consistency実測・proxy/targetログ）＋tests の両方。

## 7. 完了条件判定

1. Q1: run #2で S05 reached・attempts>0（3）・S08（follow-up送信）実測 ✓ 2. Q2a: consistent・実run反映・confirmed 0 ✓ 3. Q2b: 0427ペアが `vdp_run_failed_not_reflected` でinconsistent（before consistent[] と対比記録）✓ 4. 安全0・実行1回/v2・1回/v2b（承認済み）・preflight前後exit 0・config既定bit復帰・PCR-P1無改変・validator 0 ✓ 5. first_failure_juiceshop_v2/v2b.json（opaque）産出 ✓。Juice Shopは参考回帰であり合格ゲートにしない（0426 §4）。

**in_scope_blocker 0件**。deferred_followup: なし（F1/F2は本タスクで対処・live確認済み）。non_blocking_observation: S12がemitter無し（analyzerはsuspected/C13で記録・report投影はconsistencyが担う既知仕様）。本タスクを **done** とする。
