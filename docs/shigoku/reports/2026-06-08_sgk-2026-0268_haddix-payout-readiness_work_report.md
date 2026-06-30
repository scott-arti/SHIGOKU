---
task_id: SGK-2026-0268
doc_type: work_report
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-08_sgk-2026-0268_haddix-report-payout-readiness-output-improvements_plan.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: "Haddix report payout-readiness output improvements 実施報告"
created_at: "2026-06-08"
updated_at: '2026-06-30'
---

# 作業報告

## 実施内容
- `src/reporting/haddix_formatter.py` に `Submission Readiness` セクションを追加し、confirmed findings を submission-ready、candidate findings を hold-back appendix として明示分離した。
- confirmed finding 本文に `Response Evidence` ブロックを追加し、`poc_response` を Markdown 本文から直接確認できるようにした。
- `authz_differential` を持つ finding 向けに `Baseline vs Attack Comparison` テーブルを追加し、baseline status / attack status / resource ID transition / response length delta / differential signals を表示するようにした。
- 影響分析に `対象固有の影響` を追加し、`target_url` と `poc_response` の内容ヒントから、提出向けの資産・データ露出文を生成するようにした。
- `tests/unit/reporting/test_haddix_formatter_kpi.py` に 4 要件の回帰テストを追加し、既存 candidate appendix ラベル期待値も更新した。

## 判断理由
- 既存の confirmed / candidate 判定ロジックはそのまま残し、提出向けの読みやすさだけを上げる方が最小差分で安全だった。
- evidence JSON には既に replay 情報が存在するため、今回は schema 拡張ではなく Markdown の可視化を優先した。
- target-specific impact は完全な business context 推定までは広げず、`path + response field hints + authz differential` の範囲に限定して過剰推論を避けた。

## 変更ファイル
- `src/reporting/haddix_formatter.py`
- `tests/unit/reporting/test_haddix_formatter_kpi.py`
- `docs/shigoku/plans/2026-06-08_sgk-2026-0268_haddix-report-payout-readiness-output-improvements_plan.md`

## 検証
- `.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py -k 'submission or baseline_attack or target_specific or split_into_confirmed'`
- `.venv/bin/pytest -q tests/unit/reporting/test_haddix_formatter_kpi.py tests/unit/reporting/test_haddix_formatter_quality.py`
- `.venv/bin/pytest -q tests/unit/main/test_main_report_haddix.py -k 'prefers_latest_repairable_session or promotes_execution_note_candidates_when_findings_empty or heuristic_promoted_with_poc_becomes_confirmed or structured_evidence_is_promoted_to_poc_and_confirmed'`

## リスク
- `tests/unit/main/test_main_report_haddix.py::test_main_report_haddix_includes_authz_and_timeout_kpi` は今回差分とは別に、synthetic session 側に `scenario_coverage` が無いことで consistency gate が blocked になり、既存期待値とずれる。
- target-specific impact はレスポンス断片ベースのため、business impact の完全自動化までは行っていない。

