---
task_id: SGK-2026-0220
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-05-19_sgk-2026-0220_b-2-ssrf-tester_plan.md
- docs/shigoku/plans/2026-05-15_sgk-2026-0059_a2_b2_implementation_plan.md
- docs/shigoku/specs/standards/vulnerability_feature_implementation_spec.md
created_at: '2026-05-19'
updated_at: '2026-06-30'
---

# Work Report: SGK-2026-0220 B-2 SSRF 単体 Tester 実実装

## 実装内容
- `src/core/attack/ssrf_tester.py`
  - `_test_payload()` のプレースホルダーを `httpx` 実装へ置換
  - `scan_async()` 追加
  - `auth_headers` 対応
  - `BYPASS_VARIANTS` / IMDSv2 401系指標 / `_check_final_destination()` 追加
  - 監査性向上: `matched_variant`, `matched_variant_source` を結果へ追加
- `src/core/agents/swarm/injection/smart_ssrf.py` 新規作成
  - `run_as_tool()` / `execute()` / Finding変換を実装
  - `additional_info` に `poc_request`, `poc_response`, `poc_html`, `matched_variant` を格納
- `src/core/agents/swarm/injection/manager.py`
  - `specialists["ssrf"]` 登録
  - `run_ssrf_hunter()` 追加
  - `_classify_url()` で `ssrf_candidate` を優先
  - `_build_unknown_hypotheses()` で `ssrf -> ssrf` へルーティング修正
  - `PER_URL_TIMEOUT_BY_TYPE["ssrf"]` と risk-force allowlist 追加
- `config/tagging_rules.yaml`
  - `ssrf_param_hint` / `ssrf_body_hint` 追加
- `src/recon/pipeline.py`
  - `ssrf_candidate` のタグマップとタスクマップを追加
- テスト追加
  - `tests/helpers/ssrf_flask_target.py`
  - `tests/core/attack/test_ssrf_tester.py`
  - `tests/core/agents/swarm/injection/test_smart_ssrf.py`
  - `tests/core/agents/swarm/injection/test_ssrf_classification.py`
  - `tests/core/agents/swarm/injection/test_ssrf_pipeline.py`

## 判断理由
- 計画書のリスク項目を優先し、`cmd_ssrf` と独立した決定論SSRfルートを先に完成。
- 誤分類/競合を防ぐため、`ssrf_candidate` 優先と `specialist_map` 修正を先行。
- Ver.1 で必要な監査性を確保するため、検知根拠 (`matched_variant`) を追加。

## 検証結果
- SSRF関連テスト:
  - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q tests/core/attack/test_ssrf_tester.py tests/core/agents/swarm/injection/test_smart_ssrf.py tests/core/agents/swarm/injection/test_ssrf_classification.py tests/core/agents/swarm/injection/test_ssrf_pipeline.py`
  - `15 passed`
- Injection 回帰:
  - `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q tests/core/agents/swarm/injection/`
  - `143 passed`

## リスク評価
- クリア済み
  - `ssrf` が `cmd_ssrf` に吸われる競合
  - `redirect_params` の `url` 先取りによる SSRF スキップ
  - SSRF検知根拠の監査性不足
- 既知制約
  - `_check_final_destination()` は本文依存のため、本文に終点が出ない実装では検知が弱い
  - OOB 相関は Ver.1 方針により未実装

## deferred_tasks
- id: SGK-2026-0220-D1
  title: OOB相関（DNS/HTTP callback）連携
  reason: Ver.1 スコープ外（ユーザー合意）
  impact: 本文に終点痕跡が出ない SSRF の見逃し可能性
  planned_followup: LocalOOBListener/外部OOB連携を次フェーズで追加
