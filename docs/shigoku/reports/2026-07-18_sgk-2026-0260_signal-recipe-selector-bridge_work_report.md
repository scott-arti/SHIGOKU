---
task_id: SGK-2026-0260
doc_type: work_report
status: active
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0260_recipe-recon-swarm_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-03_sgk-2026-0259_recipe-auth-jwt-oauth_subtask_plan.md
- docs/shigoku/worklogs/2026-07-18_sgk-2026-0260_signal-recipe-selector-bridge_work_log.md
title: "Recipe selector: KG context, allowlist, suppression key, decision trace (phase 2)"
created_at: '2026-07-18'
updated_at: '2026-07-21'
---

# SGK-2026-0260 作業報告書（続き）

## この回の実装内容（phase 2: KG context, allowlist, suppression key）

### 1. 固定語彙（recipe_contracts.py）
- `RECIPE_TO_SWARM_REASON_CODES`: direct swarm に戻す際の固定 reason code set
- `RECIPE_ADDITIVE_REASONS`: 加点理由の controlled vocabulary
- `RECIPE_SUPPRESSIVE_REASONS`: 抑制理由の controlled vocabulary
- `RECIPE_FOLLOW_UP_REASONS`: follow-up decision の固定語彙
- `SUPPRESSION_KEY_PREFIX_SIGNAL` / `SUPPRESSION_KEY_PREFIX_ENDPOINT`: suppression key format
- `RECIPE_DECISION_OUTCOMES`: `run_recipe` / `direct_swarm` / `defer` 定数

### 2. KG supporting context による score 調整（recipe_loader.py）
- `_enrich_score_with_kg_context()`: KG freshness / previous RecipeRun / previous Finding / nearby Endpoint/AuthSurface を score に反映
- 加点・抑制理由を `RecipeCandidate.reasons` と `supporting_evidence._kg_*` trace に記録
- `match_recipes_to_context()` が `kg_context=` キーワード引数で KG 文脈を受け付ける

### 3. 個別の加点・抑制要素
- **KG freshness** (`kg_freshness_score >= 0.8`): +0.1, `high_freshness_score` 理由
- **KG freshness stale** (`< 0.3`): -0.15, `kg_context_stale` 理由
- **previous recipe success**: +0.05, `previous_recipe_succeeded` 理由
- **previous recipe failure**: -0.2, `previous_recipe_run_exists` / `previous_recipe_failed` 理由
- **nearby confirmed finding**: +0.1, `nearby_finding_confirms` 理由
- **nearby mitigated finding**: -0.1, `nearby_finding_mitigated` 理由
- **nearby auth surface**: +0.05, `nearby_auth_surface` 理由
- **nearby same surface type**: +0.05, `nearby_endpoint_corroborates` 理由
- **tech stack match**: +0.02, `tech_stack_match` 理由
- **high freshness** (takeover): `fresh_signal` 理由
- **high confidence** (attack surface): `high_confidence` 理由

### 4. Allowlist filtering（recipe_loader.py）
- `check_recipe_action_allowlist()`: recipe step の action を全件 allowlist 検査
- allowlist 外の action がある recipe は **suppressed=True** かつ **suppression_reason="unsupported_action:..."** で candidate 生成
- score -0.3 ペナルティと `"unsupported_step_action"` reason を同時に記録

### 5. Suppression key（recipe_loader.py）
- `build_suppression_key()`: `{prefix}:{recipe_name}:{signal_identity}` 形式
- `is_recipe_suppressed()`: signal key + endpoint key の両方を照合
- `match_recipes_to_context()` が `active_suppression_keys=` で受付
- suppressed candidate は `suppressed=True`, `suppression_reason="suppression_key_active"`

### 6. MasterConductor への配線（master_conductor.py）
- KG context 構築: `self.graph.get_tech_stack()` を `recipe_context` に追加
- `active_suppression_keys` の追跡と蓄積
- suppressed candidate は `run_recipe` task 化を抑止し、`recipe_to_swarm_reason` に固定語彙を記録
- `suppressed_recipe_count` のログ記録

### 7. Decision trace（master_conductor.py）
- `recipe_to_swarm_reason` / `recipe_to_swarm_reasons` に `RECIPE_TO_SWARM_REASON_CODES` 固定語彙を使用
- `recipe_to_swarm_reason`: `no_recipe_match`, `low_confidence`, `manual_review_required`, `unsupported_action`, `suppression_active`, `previous_run_exists`
- fixed vocabulary 準拠テスト追加

### 8. follow-up swarm decision（master_conductor.py）
- `_build_recipe_follow_up_decision()`: recipe 実行結果から follow-up 判定を生成
  - 全成功: `no_follow_up_needed` / `recipe_completed_cleanly`
  - 全ブロック: `no_follow_up_needed` / `recipe_completely_blocked`
  - 全失敗: `recommend_manual_review` / `recipe_failed`
  - 新 signal 発見: `recommend_specialized_swarm` / `new_signal_discovered`
  - 部分成功: `recommend_specialized_swarm` / `recipe_partial_success`
- `_execute_recipe_task()` の戻り値に `follow_up` dict を追加
- `RECIPE_FOLLOW_UP_REASONS` に `recipe_completed_cleanly`, `recipe_completely_blocked` 追加

### 9. KG persistence（knowledge_graph.py, master_conductor.py）
- `store_recipe_run()`: RecipeRun ノードを `:EXECUTED_AGAINST` → `:Endpoint` リレーションで永続化
- `get_recipe_runs_for_domain()`: ドメイン単位の既存 recipe 実行履歴を返す
- `get_nearby_findings()`: 同一ドメイン上の Finding ノードを返す
- `_execute_recipe_task()` 実行後、recipe result + suppression key を KG と run ledger に保存
- `_create_attack_tasks_from_recon()` で KG から実データ（previous_recipe_runs, nearby_findings）を取得して `kg_context` に投入
- KG の `RecipeRun` からクロスラン suppression key をロードし `active_suppression_keys` に追加

## 判断理由
- `SGK-2026-0260` 計画書 section 3.3 / 4.0 の「Recipe をどう選ぶか」を signal + KG + deterministic rule で説明可能にするため。
- allowlist は選抜時点で評価し、実行時に `UNSUPPORTED_ACTION` で失敗する前に抑止する設計。
- 固定語彙は decision trace の再現性とテスト容易性を確保するため。

## 検証
- `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`  (12 passed, +6 follow-up tests)
- `.venv/bin/pytest tests/unit/engine/test_recipe_selector.py -q`  (37 passed)
- `.venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py -q`  (26 passed)
- `.venv/bin/pytest tests/core/engine/test_master_conductor_scenario_probes.py -q`  (23 passed)
- `python3 scripts/sync_shigoku_updated_at.py` / `python3 scripts/validate_shigoku_docs.py`

## 残課題
- `nearby_endpoints` の KG 実データ投入（endpoint クラスタリング待ち）
- follow-up swarm task の自動生成パイプライン（`_execute_recipe_task()` の戻り値から MC 側で task 化）
- suppression key の neo4j に依存しない軽量永続化（run ledger JSONL 等）

## 次アクション
- `0259` で auth/jwt/oauth Recipe YAML を追加（共通層は 0260 で凍結済み）。
- follow-up swarm decision 生成ロジックを `_execute_recipe_task()` に統合。
- KG との suppression key / finding 永続化パイプライン整備。
