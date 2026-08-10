---
task_id: SGK-2026-0438
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis_work_report.md
created_at: '2026-08-10'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
---

# 作業ログ: SGK-2026-0438（発射される follow-up の広さ診断）

## 実施内容

1. **一次診断（explorer）**: session_20260810_012214 の shadow_diff /
   diagnostics / admission イベントを突き合わせ。
   - **admission gate 仮説を棄却**: S05 blocked 0・admission_rejected 0・
     budget も原因でない（max_follow_ups 50・使用 0）。
   - **真因**: `_queue_vdp_follow_ups` の exact-replay skip
     （param 付き観測 3 案が未 queue）。
2. **(H)/(D)/(C) 分類 + 設計を提示** → ユーザー承認
   （比較型 gap に限り param skip 解除・fail-closed 維持）。
3. **(D) 修正（fixer）**: master_conductor.py 単一 hunk
   （has_auth_header/cookie は全 gap skip 維持・非比較 gap は param skip 維持・
   比較型 gap のみ param 値破棄でも queue）。
   counterfactual テストを先行作成（pre-fix 1 failed → post-fix 5 passed）。
4. **独立検証（orchestrator）**: 新テスト + 0431 テスト 12 passed・
   task_queue.py diff 0・preflight exit 0（token hit 0）・
   新テストの LSP 型警告 1 件をガード assert 追加で解消。
5. **封印 run（session_20260810_154740）**: **attempted 1 → 3**。
   発射3案全て cross_account_compared=true・越境なし hold（confirmed 0）。
   #1 timing は skip 維持・#3 payload は S07 block 維持。
   consistent（reason_codes 空）・redaction 0・所有権 bbb・GET only・実行1回。

## 観測メモ

- 比較型 gap の3番目（untested_no_second_account）は queue 時の
  precondition（authA_authB / owned_resources）不充足で設計どおり保留
  （D01 として SGK-2026-0418 へ記録）。
- 解放は「read-only で安全に実行可能なのに過剰に弾かれていた」ケースのみ。
  admission 安全判定・Evidence Validator・閾値・PCR-P1 は全て無変更。
- docs opaque 遵守（report/worklog に endpoint/product 名なし）。

## 成果物

- 変更: src/core/engine/master_conductor.py（13+/5-・単一 hunk）、
  新規テスト tests/unit/engine/test_vdp_comparison_param_skip_release.py
- session: workspace/projects/localhost:3000/sessions/session_20260810_154740.json
- report: workspace/projects/localhost:3000/reports/haddix_report_20260810_154740.md
- evaluator: /tmp/opencode/m5-out-0438/first_failure_juiceshop_v1.json
