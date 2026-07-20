---
task_id: SGK-2026-0260
doc_type: work_log
status: active
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/reports/2026-07-18_sgk-2026-0260_signal-recipe-selector-bridge_work_report.md
title: "作業ログ: Recipe selector の Recon signal bridge + KG context + allowlist (phase 2)"
created_at: '2026-07-18'
updated_at: '2026-07-21'
---

# 作業ログ

## 2026-07-18 (phase 2: KG context, allowlist, suppression key, decision trace)

### 実施
- `src/core/engine/recipe_contracts.py` に `RECIPE_TO_SWARM_REASON_CODES`, `RECIPE_ADDITIVE_REASONS`, `RECIPE_SUPPRESSIVE_REASONS`, `RECIPE_FOLLOW_UP_REASONS`, `RECIPE_DECISION_OUTCOMES`, `SUPPRESSION_KEY_PREFIX_*` の固定語彙セットを追加した。
- `src/core/engine/recipe_loader.py` に `check_recipe_action_allowlist()`, `build_suppression_key()`, `is_recipe_suppressed()`, `_enrich_score_with_kg_context()` を追加した。
- `RecipeCandidate` に `suppressed`, `suppression_reason` フィールドを追加した。
- `match_recipes_to_context()` が `kg_context=`, `active_suppression_keys=` を受け付け、allowlist フィルタリング、KG score 調整、suppression key チェックを実施するよう強化した。
- `src/core/engine/master_conductor.py` の `_create_attack_tasks_from_recon()` に以下を追加：
  - `self.graph.get_tech_stack()` から KG context を構築し `match_recipes_to_context()` に渡す配線
  - `active_suppression_keys` による suppressed candidate の追跡と `run_recipe` task 化抑止
  - suppressed candidate の swarm fallback 時に `unsupported_action` / `suppression_active` の固定語彙 reason code を記録
  - `suppressed_recipe_count` のログ出力
- `tests/unit/engine/test_recipe_selector.py` に以下を追加（+17 tests）:
  - `test_allowlist_check_passes_for_valid_actions`
  - `test_allowlist_check_catches_unsupported_actions`
  - `test_allowlist_check_suppresses_unsupported_candidate`
  - `test_build_suppression_key_format`
  - `test_build_suppression_key_with_endpoint_prefix`
  - `test_is_recipe_suppressed_detects_active_key`
  - `test_is_recipe_suppressed_with_endpoint`
  - `test_suppression_key_blocks_candidate`
  - `test_kg_context_enrichment_high_freshness_adds_points`
  - `test_kg_context_enrichment_stale_freshness_penalizes`
  - `test_kg_context_previous_success_adds_points`
  - `test_kg_context_previous_failure_penalizes`
  - `test_kg_context_nearby_finding_confirms`
  - `test_kg_context_nearby_finding_mitigated`
  - `test_kg_context_nearby_auth_surface`
  - `test_kg_context_corroborating_surface`
  - `test_kg_context_integrated_in_match_recipes_to_context`
  - `test_recipe_candidate_suppression_trace_in_evidence`
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py` に以下を追加（+2 tests）:
  - `test_create_attack_tasks_from_recon_suppresses_unsupported_action_recipe`
  - `test_create_attack_tasks_from_recon_uses_fixed_vocabulary_in_swarm_reason`

### 検証
- `tests/unit/engine/test_recipe_selector.py`: 37 passed
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: 6 passed
- `tests/core/engine/test_master_conductor_api_candidate_routing.py`: 26 passed
- `tests/core/engine/test_master_conductor_scenario_probes.py`: 23 passed
- Total: 92 passed, 0 failed

### 次アクション
- follow-up swarm task の自動生成パイプライン
- `nearby_endpoints` の KG 実データ投入
- `0259` で auth/jwt/oauth Recipe YAML を追加

## 2026-07-18 (phase 3: follow-up decision + KG persistence)

### 実施
- `src/core/infra/knowledge_graph.py` に `store_recipe_run()`, `get_recipe_runs_for_domain()`, `get_nearby_findings()` を追加した。
  - `store_recipe_run()`: RecipeRun ノードを作成し `:EXECUTED_AGAINST` → `:Endpoint` で永続化
  - `get_recipe_runs_for_domain()`: ドメイン単位で実行済み recipe 名と成功/失敗 outcome を返す
  - `get_nearby_findings()`: 同一ドメインの Finding ノードを返す
- `src/core/engine/recipe_contracts.py` に `recipe_completed_cleanly`, `recipe_completely_blocked` を `RECIPE_FOLLOW_UP_REASONS` に追加した。
- `src/core/engine/master_conductor.py` に `_build_recipe_follow_up_decision()` を module-level で追加した。
  - recipe 全成功: `no_follow_up_needed` / `recipe_completed_cleanly`
  - 全ブロック: `no_follow_up_needed` / `recipe_completely_blocked`
  - 全失敗: `recommend_manual_review` / `recipe_failed`
  - 新 signal 発見: `recommend_specialized_swarm` / `new_signal_discovered`
  - 部分成功: `recommend_specialized_swarm` / `recipe_partial_success`
- `_execute_recipe_task()` を更新:
  - `_build_recipe_follow_up_decision()` を呼び出し、follow-up dict を戻り値に追加
  - `self.graph.store_recipe_run()` で KG に永続化
  - `self.run_ledger_recorder.record()` で suppression key を run ledger に記録
- `_create_attack_tasks_from_recon()` の KG context 構築を更新:
  - `self.graph.get_recipe_runs_for_domain()` から実データ取得
  - `self.graph.get_nearby_findings()` から signal URL 単位で findings 取得
  - KG の RecipeRun を `active_suppression_keys` にロード（クロスラン dedup）
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py` に follow-up decision tests 追加（+6 tests）:
  - `test_follow_up_decision_success_clean`
  - `test_follow_up_decision_all_blocked`
  - `test_follow_up_decision_all_failed`
  - `test_follow_up_decision_new_signal_discovered`
  - `test_follow_up_decision_partial_success`
  - `test_follow_up_decision_uses_fixed_vocabulary`

### 検証
- `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: 12 passed (+6)
- `tests/unit/engine/test_recipe_selector.py`: 37 passed
- `tests/core/engine/test_master_conductor_api_candidate_routing.py`: 26 passed
- `tests/core/engine/test_master_conductor_scenario_probes.py`: 23 passed
- Total: 98 passed, 0 failed

### 次アクション
- follow-up swarm task の自動生成パイプライン
- `nearby_endpoints` の KG 実データ投入
- `0259` で auth/jwt/oauth Recipe YAML を追加
