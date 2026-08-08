---
task_id: SGK-2026-0434
doc_type: work_log
status: done
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0434_payload-mismatch-funnel-truth_plan.md
- docs/shigoku/reports/2026-08-09_sgk-2026-0434_payload-mismatch-funnel-truth_work_report.md
- config/diagnostics/counterfactual_sgk2026_0434_attempt.json
title: payload_request_mismatch probe の funnel-truth 改善 作業ログ
created_at: '2026-08-09'
updated_at: '2026-08-09'
tags:
- shigoku
target: src/core/engine
---

# 作業ログ: SGK-2026-0434（payload_request_mismatch probe の funnel-truth 改善）

## 実施項目

1. **穴の確定（recon）**: 0430 artifact（session_20260807_153606.json）で payload_request_mismatch 2 件を比較。row 5（opaque-ep search query param・param 有）は queue gate が skip＝正しい hold、row 3（opaque-ep search template param・param 空）は gate 通過→S07 チェック（material 有のみ block）も通過→probe 実行→S08/S10/S11 誤到達を確認。param 空＝破棄材ケースが穴。
2. **S07 判定修正（executor）**: payload_request_mismatch を無条件 S07 `exact_request_material_unavailable` block 化。payload 値は観測境界で常に破棄されるため exact material は構造的に再構成不能（param 有でも無でも）。不要 import（urlparse）削除。
3. **gap 発行条件修正（generator）**: observation が破棄材を持つ場合、required_evidence 先頭の payload_request_mismatch を末尾へ移動（集合は不変＝Evidence Validator 無改変）。m3a first-gap が次の required evidence になる。
4. **テスト整備**: 汎用 replay 機構テストの fixture デフォルト gap を healthy（authz_impact_not_proven）へ変更、payload 固有テストは明示 gap 化、drill/realpath/rollout 統合テストは同一タスクの gap 差し替えで dispatch 機構検証を維持。新規 82 tests。
5. **実測**: 0430 artifact の funnel を再評価 → first_failure S12（S08/S10/S11 誤到達）→ 修正後は S07（downstream S08..S12 not reached）。
6. **counterfactual**: changed_variable=attempt（probe_sent → probe_blocked_s07）artifact を作成・validate 0・stage delta で誤到達除去を提示。
7. **検証**: engine+reporting 2744 passed / preflight pass exit 0 / PCR-P1 diff 0 / diff --check clean。
8. **docs**: registry・ledger を done 化、plan を done/ へ移動（関連リンク更新含む）、work_report/work_log 作成。

## 検証コマンド（主要）

```text
.venv/bin/pytest tests/unit/engine/ tests/unit/reporting/ -q   → 2744 passed, 1 skipped
.venv/bin/pytest tests/unit/engine/test_vdp_follow_up_executor.py::TestFunnelTruthPayloadMismatch -q  → 3 passed
.venv/bin/python scripts/check_vdp_product_independence.py ... → verdict pass / exit 0 / token hits 0
git diff --check -- src/ tests/                              → clean
git diff --stat -- src/core/engine/task_queue.py             → 0 行（PCR-P1）
```

## 特記事項

- 事前提示（通信規律）: 着手前に「S07 判定・gap 発行条件の修正設計」と「破棄材ケース self-checking テスト（現行コードで RED＝穴の実証）」を提示済み。以降は通信 0 で実装→検証→報告。
- ライブ通信なし。既存 0430 artifact＋unit テスト＋counterfactual で完結。
- 安全 0 件（通信なし・kill switch 経路は既存テストで担保）。
- counterfactual artifact の evidence 注記に製品 token が混入し preflight fail となったため、token を含まない記述へ修正（fail-closed 検出の実例）。
