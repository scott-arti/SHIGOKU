---
task_id: SGK-2026-0432
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
title: 検出品質（深さ）の因果診断：candidate→confirmed gap-closure段
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: workspace/projects/localhost:3000,config/diagnostics
---

# 実装計画書: candidate→confirmed gap-closure 因果診断（SGK-2026-0432）

## 0. 位置づけ

0430実測（run #2: session_20260807_153606、attempts 3・S11到達）で「攻撃は飛ぶのに verdicts 6 = 全 candidate・confirmed 0」が確定。6 candidate を observation→hypothesis→verdict→next_action の同一IDで追跡し、どのstageでなぜgapが閉じなかったかを**機械可読に確定**する診断タスク。**診断ファースト（無闇にコードを変えない）**。

## 1. 診断対象（gap分布）

authz_impact_not_proven ×3 / payload_request_mismatch ×2 / insufficient_timing_validation ×1（next_action 6件。enforced 3件・shadow_only 3件）。

## 2. 分類基準（ユーザー指示）

- (H) 設計上正しい安全 hold — m3a read-only では原理的に証明不能 → 対処不要・必要条件を明記。
- (D) 本物のパイプライン drop — gap-closure probe が生成されたのに実行/再enqueueされずループが回らない → counterfactual proven化→最小修正→回帰。
- (C) 能力不足 — 第2アカウント/状態変更/タイミング基盤など m3a 範囲外 → deferred/別タスク。
- payload_request_mismatch は (D) の疑い濃厚として実 req/res で検証（S06 attempt の質）。

## 3. 不変条件

confirmed件数を成功指標にしない・証拠条件/Evidence Validatorを緩めない（無理なconfirmed化禁止）・反curve-fitting（preflight exit 0・製品token遮断・sealed opaqueのみ）・PCR-P1無改変・追加ライブrunなし（既存artifactのみで診断）。

## 4. 成果物

1. candidate×stage first-failure表（6行・分類H/D/C＋根拠ID）。
2. payload_request_mismatch の具体 req/res。
3. preflight exit 0・PCR-P1 diff（無改変）。
4. (D)があった場合のみ: 修正ファイル＋gap-closureループ実行の実測（counterfactual proven化→最小修正→回帰テスト）。(D)=0なら変更なしと明記。
5. work_report/work_log・deferred（実ID紐付け）・validator 0。

## 5. 完了条件

6 candidate 全行が H/D/C のいずれかに根拠ID付きで分類される／payload_request_mismatch の req/res が具体化される／(D)判定時のみ counterfactual→修正→回帰の因果がある／(D)=0 ならコード変更0・その旨明記／preflight exit 0・PCR-P1無改変・docs validator 0。

## 6. NOT in scope

confirmed件数を増やす施策・証拠条件緩和・製品合わせ込み・新規ライブrun・m3b/m3c/m4。
