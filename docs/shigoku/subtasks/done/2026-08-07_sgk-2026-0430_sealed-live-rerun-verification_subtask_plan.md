---
task_id: SGK-2026-0430
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_work_report.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
- docs/shigoku/subtasks/done/2026-08-06_sgk-2026-0427_m5-sealed-audit-active-rerun_subtask_plan.md
title: 0426修正の封印ライブ実効確認（Juice Shop m3a rerun）
created_at: '2026-08-07'
updated_at: '2026-08-08'
tags:
- shigoku
target: tests/fixtures/vdp_juiceshop_sealed,src/reporting,workspace/projects/localhost:3000
---

# 実装計画書: 0426修正の封印ライブ実効確認（SGK-2026-0430）

## 0. 位置づけ

SGK-2026-0426の修正（W2 main-thread drain / W3 fail-closed / W4 reach）は unit / hidden holdout / counterfactual でのみ検証済みであり、**修正後のライブ rerun は未実施**。0427のライブrun（run_id 9908371a）は修正前を捕捉したもの（S05 failed / attempts 0 / verdicts 6 / consistency consistent[] ＝ fail-openの実物）。本タスクは封印ローカルJuice Shopで**1回のm3a rerun**を行い、修正の実効を実機で確認する（0426計画§7.2の参考回帰としての位置づけ。合格ゲートにはしない）。

## 1. 評価する2点（Q1/Q2）

- **Q1: 攻撃が実際に飛んだか** — S05がdrain（main thread）で成功し `attempts>0`（0427の0からの改善）。target_access.log に follow-up GET が記録される。
- **Q2: fail-open正常終了バグが治ったか**（2段）
  - Q2a（ライブ）: attempts>0 の正常完了が report/consistency に実runとして反映される（shadow verdict を confirmed にしない・unverified promotion 0）。
  - Q2b（バグ実物への回帰・最重要）: **0427のfail-open session（attempts=0・run_health degraded/follow_up_enqueue_failed）に修正後consistencyを再適用し、before consistent[] → after fail-closed（`vdp_run_failed_not_reflected`）に転じる**ことを実測（＝「攻撃ゼロで正常終了」が塞がれた直接証拠）。

## 2. 制約（固定）

- 封印ローカルJuice Shop（loopback/sealed network）・**m3a read-only（GETのみ）**。実VDP攻撃・POST系・m3b/m3c/m4 は対象外。
- 既存harness `bash tests/fixtures/vdp_juiceshop_sealed/run_m5_audit.sh` を**1回**実行。config snapshot→byte-identical復元（既定bit不変）。
- **PCR-P1 assert 無改変**。drainのmain-thread assertが発火しない（＝違反していない）ことを証跡に。
- 反curve-fitting: product-independence preflight exit 0維持、製品tokenをruntime/model-facing contextへ入れない、sealed opaque caseのみ。
- 安全0件（scope逸脱/secret漏洩/状態変更/予算超過/二重送信）。実行1回（eval version v2につき1回）。
- 既存未コミット変更へ触れない。commit/push/branch切替なし。

## 3. 実施ステップ

1. Q2b checker拡張: `_session_fail_open`（run_outcome または run_health degraded+attempts 0 からfail-open検出）をconsistencyへ追加＋table test（通信0）。**実0427ペアへの適用で consistent[]→inconsistent を実測**。
2. 台帳: SGK-2026-0430 採番・登録（本計画書）。
3. preflight exit 0 確認。
4. `run_m5_audit.sh` を1回実行（M5_OUT=/tmp/opencode/m5-out-0430、新eval version v2）。
5. 検証: Q1（attempts>0・S05 reached・target log follow-up GET）/ Q2a（report/consistency実run反映・confirmed 0）/ Q2b（実測済み）/ 安全0件 / config byte-identical復元 / preflight後exit 0。
6. evaluate_m5.py post-binding（eval v2）で opaque case別 first-failure を産出。
7. work_report/work_log作成・validator 0・graphify更新。

## 4. 完了条件

1. rerun sessionで S05 reached・attempts>0・follow-up GETがtargetログに記録される（Q1）。
2. rerunのreport/consistencyがconsistent（実run反映）且つunverified confirmed 0（Q2a）。
3. 0427ペアへの修正後consistency適用が `vdp_run_failed_not_reflected` でinconsistent（Q2b。before consistent[] と対比して記録）。
4. 安全0・実行1回・preflight前後exit 0・config既定bit復帰・PCR-P1 assert無改変・docs validator 0。
5. first_failure_juiceshop_v2.json（opaque）を産出。Juice Shopは参考回帰であり合格ゲートにしない。

## 5. NOT in scope

- 実VDP通信・POST系・m3b/m3c/m4・製品合わせ込み・0426完了契約の再変更（Q2b checker拡張のみadditive）。
